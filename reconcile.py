#!/usr/bin/env python3
"""
Reconcile container images running in AKS with Snyk projects.

Flow:
  1. Authenticate to Azure via DefaultAzureCredential (picks up `az login` session,
     environment variables, managed identity, etc. — no kubectl required).
  2. Discover all AKS clusters in the configured subscription (optionally scoped to
     a resource group) and fetch per-cluster kubeconfigs via the Azure API.
  3. Query pod images from each cluster (spec image + status containerStatuses image_id digests),
     from pods in **Running** phase only by default (avoids stale images from Succeeded/Failed Job pods).
  4. For every distinct cluster image (after digest dedupe), POST to the Snyk v1 import API using
     the integration that matches the image registry — **every run**, so Snyk re-scans/re-imports
     deployed images even when projects already exist.

Environment variables (set in .env):
  Required:
    SNYK_TOKEN             Snyk API token
    SNYK_ORG_ID            Snyk organization UUID
    SNYK_INTEGRATION_ID    Default Snyk registry integration UUID (ACR recommended)
    AZURE_SUBSCRIPTION_ID  Azure subscription to scan (comma-separated for multiple)

  Optional registry routing (falls back to SNYK_INTEGRATION_ID if unset):
    SNYK_INTEGRATION_ID_ACR        Azure Container Registry
    SNYK_INTEGRATION_ID_GCP        Google Artifact / Container Registry
    SNYK_INTEGRATION_ID_ECR        AWS Elastic Container Registry
    SNYK_INTEGRATION_ID_MCR        Microsoft Container Registry
    SNYK_INTEGRATION_ID_DOCKER_HUB Docker Hub

  Optional scoping:
    AZURE_RESOURCE_GROUP   Limit cluster discovery to one resource group
    INCLUDE_KUBE_SYSTEM    If 1/true/yes: include pods in kube-system (default: exclude them).
    INCLUDE_ALL_POD_PHASES If 1/true/yes: include images from pods in any phase (Succeeded, Failed,
                           Pending, etc.). Default: only Running pods — use only if you need legacy behavior.
    EXCLUDE_INIT_CONTAINERS If 1/true/yes: skip spec.initContainers and status.initContainerStatuses
                            (e.g. Online Boutique loadgenerator uses busybox:latest as an init image).

  Optional discovery / API:
    SNYK_REST_BASE         Snyk REST API base (default: https://api.snyk.io)
    SNYK_V1_BASE           Snyk v1 API base (default: https://snyk.io)
    SNYK_REST_VERSION      REST API version (default: 2024-10-15)
    SNYK_DEBUG             If 1/true: DEBUG logging (per-project keys during cleanup matching).

  Optional tagging (after each successful import job completes):
    SNYK_TAG_IMPORTED_PROJECTS  If unset or 1/true/yes: apply Snyk project tags (default on).
                                Set to 0/false/no to skip.
    SNYK_IMPORT_TAG_KEY       Tag key (default: image)
    SNYK_IMPORT_TAG_VALUE     Tag value (default: deployed)

  Cleanup (after imports): stale Snyk projects are those whose image identity does not match
    any running workload image (refs + digests from the Kubernetes API). By default, cleanup
    lists projects with the REST ``tags=key:value`` filter (same as SNYK_IMPORT_TAG_*) plus
    ``expand=target``. SNYK_CLEANUP_REQUIRE_TAG  If 0/false: list all projects and match images
    only (use with care in orgs that have other container projects).

Usage:
  1. az login  (or set AZURE_CLIENT_ID / AZURE_CLIENT_SECRET / AZURE_TENANT_ID for SP auth)
  2. Edit .env: SNYK_TOKEN, SNYK_ORG_ID, SNYK_INTEGRATION_ID, AZURE_SUBSCRIPTION_ID
  3. pip install -r requirements.txt
  4. python reconcile.py

Override cluster discovery with a static image list:
  python reconcile.py --images-file images.txt

Include addon/system images from kube-system (default is to skip that namespace):
  python reconcile.py --include-kube-system
  # or INCLUDE_KUBE_SYSTEM=1 in .env

Include images from non-Running pods (old Job pods, etc.; not recommended):
  python reconcile.py --all-pod-phases
  # or INCLUDE_ALL_POD_PHASES=1 in .env

Omit init container images (busybox in loadgenerator init, etc.):
  python reconcile.py --exclude-init-containers
  # or EXCLUDE_INIT_CONTAINERS=1 in .env

After imports, remove stale projects that were tagged by this tool (see cleanup in code).
Preview deletions without calling the API:
  python reconcile.py --dry-run

Debug (per-project matching keys during cleanup):
  python reconcile.py --debug
  # or SNYK_DEBUG=1

Cron (hourly):
  0 * * * * cd /path/to/snyk-image-coverage && .venv/bin/python reconcile.py >> /var/log/snyk-reconcile.log 2>&1
"""

from __future__ import annotations

import argparse
import base64
import json
import logging
import os
import re
import sys
import time
import yaml
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import requests
from dotenv import load_dotenv

# Named logger so `python reconcile.py` (__main__) still logs under a stable name.
log = logging.getLogger("reconcile")


def _configure_reconcile_logging(debug: bool) -> None:
    """Attach a single handler to ``reconcile`` only — avoids enabling DEBUG on Azure SDK / urllib3."""
    log.setLevel(logging.DEBUG if debug else logging.WARNING)
    if log.handlers:
        return
    h = logging.StreamHandler(sys.stdout)
    h.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    log.addHandler(h)
from urllib3.exceptions import MaxRetryError, ProtocolError

try:
    from azure.identity import DefaultAzureCredential
    from azure.mgmt.containerservice import ContainerServiceClient
except ImportError:
    print(
        "Install dependencies: pip install -r requirements.txt\n"
        "  (requires azure-identity, azure-mgmt-containerservice)",
        file=sys.stderr,
    )
    raise

try:
    from kubernetes import client as k8s_client
    from kubernetes.client.rest import ApiException
    from kubernetes.config import kube_config as kube_cfg
except ImportError:
    print("Install dependencies: pip install -r requirements.txt", file=sys.stderr)
    raise

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_REST_VERSION = "2024-10-15"
# Snyk REST GET /orgs/{{org_id}}/projects rejects limit < 10.
SNYK_REST_PROJECTS_PAGE_MIN_LIMIT = 10
V1_IMPORT_PATH = "/api/v1/org/{org_id}/integrations/{integration_id}/import"
V1_PROJECT_TAGS_PATH = "/api/v1/org/{org_id}/project/{project_id}/tags"
V1_PROJECT_DELETE_PATH = "/api/v1/org/{org_id}/project/{project_id}"
DEFAULT_IMPORT_TAG_KEY = "image"
DEFAULT_IMPORT_TAG_VALUE = "deployed"
KUBE_SYSTEM_NAMESPACE = "kube-system"


# ---------------------------------------------------------------------------
# Integration routing
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class IntegrationRouting:
    """Map image refs to Snyk registry integration IDs."""

    default: str
    acr: str | None = None
    gcp: str | None = None
    mcr: str | None = None
    docker_hub: str | None = None
    ecr: str | None = None


def _env_optional(key: str) -> str | None:
    v = os.environ.get(key, "").strip()
    return v or None


def _env_truthy(key: str, *, default: bool = True) -> bool:
    """Parse env var as boolean; unknown non-empty strings keep `default`."""
    raw = os.environ.get(key)
    if raw is None:
        return default
    s = raw.strip().lower()
    if s in ("0", "false", "no", "off", ""):
        return False
    if s in ("1", "true", "yes", "on"):
        return True
    return default


def load_integration_routing() -> IntegrationRouting | None:
    default = _env_optional("SNYK_INTEGRATION_ID")
    if not default:
        return None
    return IntegrationRouting(
        default=default,
        acr=_env_optional("SNYK_INTEGRATION_ID_ACR"),
        gcp=_env_optional("SNYK_INTEGRATION_ID_GCP"),
        mcr=_env_optional("SNYK_INTEGRATION_ID_MCR"),
        docker_hub=_env_optional("SNYK_INTEGRATION_ID_DOCKER_HUB"),
        ecr=_env_optional("SNYK_INTEGRATION_ID_ECR"),
    )


def integration_id_for_image(ref: str, routing: IntegrationRouting) -> str:
    """Choose integration UUID from registry hostname in the image reference."""
    n = normalize_image_ref(ref)
    if "azurecr.io" in n:
        return routing.acr or routing.default
    if "docker.pkg.dev" in n or ".gcr.io" in n or n.startswith("gcr.io/"):
        return routing.gcp or routing.default
    if "amazonaws.com" in n or ".ecr." in n:
        return routing.ecr or routing.default
    if "mcr.microsoft.com" in n:
        return routing.mcr or routing.default
    return routing.docker_hub or routing.default


# ---------------------------------------------------------------------------
# Azure + Kubernetes helpers
# ---------------------------------------------------------------------------

def _resource_group_from_id(arm_id: str) -> str:
    """Extract resource group name from an ARM resource ID."""
    # Azure may return /resourcegroups/ or /resourceGroups/ in the same id string.
    parts = re.split(r"/resourcegroups/", arm_id, maxsplit=1, flags=re.IGNORECASE)
    if len(parts) < 2:
        raise ValueError(f"Not a valid ARM resource id (no resourceGroups segment): {arm_id!r}")
    return parts[1].split("/", 1)[0]


def _kubeconfig_dict_from_azure_value(value: str | bytes) -> dict:
    """
    Azure SDK versions differ: kubeconfig may be raw YAML (bytes/str) or a base64-encoded blob.
    """
    if isinstance(value, str):
        raw = value.encode("utf-8")
    else:
        raw = value
    if raw.lstrip().startswith(b"apiVersion:"):
        text = raw.decode("utf-8")
    else:
        pad = b"=" * (-len(raw) % 4)
        text = base64.b64decode(raw + pad).decode("utf-8")
    doc = yaml.safe_load(text)
    if not isinstance(doc, dict):
        raise RuntimeError("Kubeconfig from Azure is not a YAML mapping")
    return doc


def make_k8s_core_v1(
    subscription_id: str,
    resource_group: str,
    cluster_name: str,
) -> k8s_client.CoreV1Api:
    """
    Return a Kubernetes CoreV1Api client for an AKS cluster.

    Fetches user credentials from the Azure API — no local kubectl or kubeconfig
    file needed. Uses DefaultAzureCredential (az login, env SP, managed identity).
    """
    credential = DefaultAzureCredential()
    acs = ContainerServiceClient(credential, subscription_id)
    result = acs.managed_clusters.list_cluster_user_credentials(resource_group, cluster_name)

    if not result.kubeconfigs:
        raise RuntimeError(
            f"No kubeconfig returned for cluster {cluster_name!r} "
            f"(resource group: {resource_group!r}). "
            "Check that your identity has at least 'Azure Kubernetes Service Cluster User Role'."
        )

    kubeconfig_dict = _kubeconfig_dict_from_azure_value(result.kubeconfigs[0].value)

    # Build an isolated client configuration so multiple clusters don't
    # interfere with each other via shared global state.
    cfg = k8s_client.Configuration()
    loader = kube_cfg.KubeConfigLoader(config_dict=kubeconfig_dict)
    loader.load_and_set(cfg)
    api_client = k8s_client.ApiClient(configuration=cfg)
    return k8s_client.CoreV1Api(api_client=api_client)


def discover_aks_clusters(
    subscription_id: str,
    resource_group: str | None = None,
) -> list[tuple[str, str, str]]:
    """
    Return a list of (subscription_id, resource_group, cluster_name) tuples
    for all AKS clusters visible in the subscription.
    """
    credential = DefaultAzureCredential()
    acs = ContainerServiceClient(credential, subscription_id)

    clusters = (
        acs.managed_clusters.list_by_resource_group(resource_group)
        if resource_group
        else acs.managed_clusters.list()
    )

    return [
        (subscription_id, _resource_group_from_id(c.id), c.name)
        for c in clusters
    ]


def collect_cluster_images(
    core_v1: k8s_client.CoreV1Api,
    *,
    include_kube_system: bool = False,
    only_running_pods: bool = True,
    exclude_init_containers: bool = False,
) -> set[str]:
    """
    Return unique image references from pods: spec image strings plus resolved
    content digests from status (containerStatuses[].image_id).

    When ``only_running_pods`` is True (default), only pods with
    ``status.phase == "Running"`` are considered. Otherwise completed or failed
    Job/CronJob pods (and other phases) still contribute their images — which
    often pulls in registry images that are no longer actually deployed.

    When ``exclude_init_containers`` is True, init container images are omitted
    (some demos use a minimal image like busybox only in ``initContainers``).

    By default, pods in the ``kube-system`` namespace are skipped to avoid
    continually importing cluster addon images. Set ``include_kube_system=True``
    to include them.
    """
    images: set[str] = set()
    try:
        pods = core_v1.list_pod_for_all_namespaces(watch=False)
    except ApiException as e:
        raise RuntimeError(f"Kubernetes list pods failed: {e}") from e
    except (MaxRetryError, ProtocolError, ConnectionError, OSError) as e:
        raise RuntimeError(f"Could not reach the cluster API server: {e}") from e

    for pod in pods.items:
        ns = (pod.metadata.namespace if pod.metadata else None) or ""
        if not include_kube_system and ns == KUBE_SYSTEM_NAMESPACE:
            continue
        if only_running_pods:
            phase = (pod.status.phase if pod.status else None) or ""
            if phase != "Running":
                continue
        spec = pod.spec
        if spec:
            spec_containers: list = list(spec.containers or [])
            if not exclude_init_containers:
                spec_containers += list(spec.init_containers or [])
            spec_containers += list(spec.ephemeral_containers or [])
            for container in spec_containers:
                if container.image:
                    images.add(container.image.strip())
        status = pod.status
        if status:
            statuses: list = list(status.container_statuses or [])
            if not exclude_init_containers:
                statuses += list(status.init_container_statuses or [])
            statuses += list(status.ephemeral_container_statuses or [])
            for cs in statuses:
                if cs.image_id:
                    images.add(strip_docker_pullable_prefix(cs.image_id))
    return images


def collect_all_images(
    subscription_ids: list[str],
    resource_group: str | None = None,
    *,
    include_kube_system: bool = False,
    only_running_pods: bool = True,
    exclude_init_containers: bool = False,
) -> set[str]:
    """
    Discover all AKS clusters across the given subscriptions and collect
    image references from each one (see ``collect_cluster_images``).
    """
    all_images: set[str] = set()

    for sub_id in subscription_ids:
        print(f"Discovering AKS clusters in subscription {sub_id}...", flush=True)
        try:
            clusters = discover_aks_clusters(sub_id, resource_group)
        except Exception as e:
            print(f"  Failed to list clusters: {e}", file=sys.stderr)
            continue

        if not clusters:
            print("  No AKS clusters found.")
            continue

        for sub, rg, name in clusters:
            print(f"  Collecting images from cluster: {name} (resource group: {rg})", flush=True)
            if not include_kube_system:
                print(
                    f"    (skipping namespace {KUBE_SYSTEM_NAMESPACE!r}; "
                    "use --include-kube-system or INCLUDE_KUBE_SYSTEM=1 to include)",
                    flush=True,
                )
            if only_running_pods:
                print(
                    "    (only pods with phase Running; "
                    "--all-pod-phases or INCLUDE_ALL_POD_PHASES=1 for all phases)",
                    flush=True,
                )
            if exclude_init_containers:
                print(
                    "    (excluding initContainer images; "
                    "--exclude-init-containers / EXCLUDE_INIT_CONTAINERS=1)",
                    flush=True,
                )
            try:
                core_v1 = make_k8s_core_v1(sub, rg, name)
                images = collect_cluster_images(
                    core_v1,
                    include_kube_system=include_kube_system,
                    only_running_pods=only_running_pods,
                    exclude_init_containers=exclude_init_containers,
                )
                print(f"    {len(images)} unique image references found.")
                all_images.update(images)
            except Exception as e:
                print(f"    Skipping {name}: {e}", file=sys.stderr)

    return all_images


# ---------------------------------------------------------------------------
# Image ref helpers
# ---------------------------------------------------------------------------

def normalize_image_ref(ref: str) -> str:
    s = ref.strip().lower()
    return re.sub(r"\s+", "", s)


_DOCKER_PULLABLE_PREFIX = "docker-pullable://"
_SHA256_DIGEST = re.compile(r"(?i)sha256:([a-f0-9]{64})")


def strip_docker_pullable_prefix(image_id: str) -> str:
    s = image_id.strip()
    if s.startswith(_DOCKER_PULLABLE_PREFIX):
        return s[len(_DOCKER_PULLABLE_PREFIX) :].strip()
    return s


def extract_sha256_digest(ref: str) -> str | None:
    """Return canonical ``sha256:<64-hex>`` if present, else None."""
    m = _SHA256_DIGEST.search(ref)
    if m:
        return f"sha256:{m.group(1).lower()}"
    return None


def strip_digest(ref: str) -> str:
    parts = re.split(r"@sha256:", ref, maxsplit=1, flags=re.IGNORECASE)
    return parts[0].strip()


def strip_registry_hostname(ref: str) -> str:
    """
    Remove registry hostname prefix for Snyk import API.

    The hostname is implied by the integration — passing the full reference
    causes 'Unauthorized access or resource does not exist' even with valid
    credentials. Only the repository path and tag should be sent as target.name.

    Examples:
      pwalshobaks2025.azurecr.io/microservices-demo/frontend:v0.10.5
        -> microservices-demo/frontend:v0.10.5
      us-central1-docker.pkg.dev/google-samples/microservices-demo/frontend:v0.10.5
        -> google-samples/microservices-demo/frontend:v0.10.5
      redis:alpine  (no hostname — returned unchanged)
        -> redis:alpine
    """
    parts = ref.split("/", 1)
    if len(parts) > 1 and ("." in parts[0] or ":" in parts[0]):
        return parts[1]
    return ref


def add_matching_keys_from_string(keys: set[str], raw: str) -> None:
    """
    Add normalized ref keys for Snyk-side strings (names, imageId, target refs),
    using the same rules as cluster-side tokens: strip docker-pullable,
    normalize, repo@tag without digest, and standalone sha256 digest.
    """
    if not raw.strip():
        return
    cleaned = strip_docker_pullable_prefix(raw.strip())
    if not cleaned:
        return
    keys.add(normalize_image_ref(cleaned))
    keys.add(normalize_image_ref(strip_digest(cleaned)))
    d = extract_sha256_digest(cleaned)
    if d:
        keys.add(d)


def cluster_image_matches_snyk(img: str, known: set[str]) -> bool:
    """True if this cluster image string matches any known Snyk key (ref or digest)."""
    cleaned = strip_docker_pullable_prefix(img.strip())
    n = normalize_image_ref(cleaned)
    n_base = normalize_image_ref(strip_digest(cleaned))
    digest = extract_sha256_digest(cleaned)
    if n in known or n_base in known or (digest and digest in known):
        return True
    if n.startswith("docker.io/"):
        short = n[len("docker.io/") :]
        sn = normalize_image_ref(short)
        sb = normalize_image_ref(strip_digest(short))
        sd = extract_sha256_digest(short)
        if sn in known or sb in known or (sd and sd in known):
            return True
    return False


def repo_base_image_path(ref: str) -> str:
    """
    Repository path without registry host, image tag, or digest — used to relate
    a ``repo:tag`` spec string to a ``repo@sha256:…`` runtime id for the same image.
    """
    s = strip_docker_pullable_prefix(ref.strip())
    if not s:
        return ""
    if re.fullmatch(r"(?i)sha256:[a-f0-9]{64}", s):
        return normalize_image_ref(s)
    s = strip_digest(s)
    s = strip_registry_hostname(s)
    if "/" in s:
        repo, last = s.rsplit("/", 1)
        if ":" in last:
            last = last.split(":", 1)[0]
        s = f"{repo}/{last}" if repo else last
    elif ":" in s:
        s = s.split(":", 1)[0]
    return normalize_image_ref(s)


def pick_representative_for_import(refs: list[str]) -> str:
    """Prefer a ``:tag`` style ref for Snyk import so the UI groups on a tag name."""
    if len(refs) == 1:
        return refs[0]

    def sort_key(r: str) -> tuple[int, int]:
        c = strip_docker_pullable_prefix(r.strip())
        before_at, _, tail = c.partition("@")
        has_tag = ":" in before_at and not re.match(r"(?i)^sha256:", before_at)
        # 0 = has tag before @, 1 = digest-only / bare repo@sha
        tier = 0 if has_tag else (1 if tail.lower().startswith("sha256:") else 2)
        return (tier, len(c))

    return sorted(refs, key=sort_key)[0]


def dedupe_cluster_images_by_content(refs: set[str]) -> set[str]:
    """
    Collapse tag + digest variants that refer to the same image (typical when
    mixing pod ``spec.image`` with ``status.image_id``) to one import target
    per content digest.
    """
    by_digest: dict[str, list[str]] = {}
    without_digest: list[str] = []

    for r in refs:
        d = extract_sha256_digest(r)
        if d:
            by_digest.setdefault(d, []).append(r)
        else:
            without_digest.append(r)

    digest_by_repo_base: dict[str, list[str]] = {}
    for d, group in by_digest.items():
        digest_by_repo_base.setdefault(repo_base_image_path(group[0]), []).append(d)

    out: set[str] = set()
    for group in by_digest.values():
        out.add(pick_representative_for_import(group))

    for r in without_digest:
        rb = repo_base_image_path(r)
        d_for_repo = digest_by_repo_base.get(rb, [])
        if len(d_for_repo) == 1:
            continue
        out.add(r)

    return out


# ---------------------------------------------------------------------------
# Snyk helpers
# ---------------------------------------------------------------------------

def snyk_project_image_keys(project: dict) -> set[str]:
    keys: set[str] = set()
    attrs = project.get("attributes") or {}
    log.debug(
        "project %s: attrs keys=%s name=%r (n=%d)",
        project.get("id"),
        list(attrs.keys()),
        attrs.get("name"),
        len(attrs),
    )
    name = attrs.get("name")
    if isinstance(name, str) and name:
        add_matching_keys_from_string(keys, name)
    for key in ("imageId", "image_id", "targetReference", "target_reference"):
        val = attrs.get(key)
        if isinstance(val, str) and val:
            add_matching_keys_from_string(keys, val)
    return keys


def iter_snyk_projects(
    session: requests.Session,
    rest_base: str,
    org_id: str,
    version: str,
    tags: list[str] | None = None,
    expand: list[str] | None = None,
) -> Iterable[dict]:
    """
    Paginate org projects. Optional ``tags`` REST filter uses ``key:value`` strings
    (projects must match all listed tags).

    Pass ``expand=[\"target\"]`` so each project includes ``relationships.target.data.id``
    (the list response often omits target linkage without it).
    """
    base = rest_base.rstrip("/")
    url = f"{base}/rest/orgs/{org_id}/projects"
    params_list: list[tuple[str, str | int]] = [
        ("version", version),
        ("limit", 100),
    ]
    if tags:
        for t in tags:
            params_list.append(("tags", t))
    if expand:
        for e in expand:
            params_list.append(("expand", e))
    params: list[tuple[str, str | int]] | None = params_list

    while url:
        r = session.get(url, params=params)
        r.raise_for_status()
        payload = r.json()
        for item in payload.get("data") or []:
            yield item
        links = payload.get("links") or {}
        next_href = links.get("next")
        if not next_href:
            break
        url = next_href if next_href.startswith("http") else f"{base}{next_href}" if next_href.startswith("/") else f"{base}/{next_href}"
        params = None


def is_likely_container_project(project: dict) -> bool:
    ptype = project.get("type")
    if ptype == "project":
        meta = project.get("meta") or {}
        pt = meta.get("project_type") or (project.get("attributes") or {}).get("type")
        if pt is None:
            return True
        if isinstance(pt, str):
            pl = pt.lower()
            # Snyk often uses project_type "linux" for container image scans.
            if pl == "linux" or "container" in pl:
                return True
        if pt in ("dockerfile", "helm", "kubernetes"):
            return True
        # apk/deb are OS layers inside container image scans (e.g. redis:alpine → apk).
        if pt in ("apk", "deb"):
            return True
        return "docker" in str(pt).lower() or "container" in str(pt).lower()
    return True


def import_image_v1(
    session: requests.Session,
    v1_base: str,
    org_id: str,
    integration_id: str,
    image_ref: str,
) -> tuple[bool, str | None]:
    url = f"{v1_base.rstrip('/')}" + V1_IMPORT_PATH.format(
        org_id=org_id, integration_id=integration_id
    )
    # Strip the registry hostname — Snyk's import API expects only the
    # repository path (e.g. "microservices-demo/frontend:v0.10.5").
    # Including the hostname causes "Unauthorized access or resource does not exist".
    target_name = strip_registry_hostname(image_ref)
    body = {"target": {"name": target_name}}
    r = session.post(url, json=body)
    if r.status_code == 201:
        loc = r.headers.get("Location")
        if loc and loc.startswith("/"):
            loc = f"{v1_base.rstrip('/')}{loc}"
        return True, loc
    return False, r.text


def project_ids_from_import_job(payload: dict) -> list[str]:
    """Collect Snyk project UUIDs from a finished import-job JSON body."""
    out: list[str] = []
    seen: set[str] = set()

    def add(pid: object) -> None:
        if isinstance(pid, str) and pid not in seen:
            seen.add(pid)
            out.append(pid)

    for list_key in ("projects", "createdProjects", "projectIds"):
        chunk = payload.get(list_key)
        if not isinstance(chunk, list):
            continue
        for item in chunk:
            if isinstance(item, str):
                add(item)
            elif isinstance(item, dict):
                if item.get("success") is False:
                    continue
                add(item.get("id") or item.get("projectId") or item.get("project_id"))

    for nest_key in ("log", "logs", "results", "projectsLog"):
        nested = payload.get(nest_key)
        if not isinstance(nested, list):
            continue
        for item in nested:
            if not isinstance(item, dict):
                continue
            sub = item.get("projects")
            if isinstance(sub, list):
                for p in sub:
                    if not isinstance(p, dict):
                        continue
                    if p.get("success") is False:
                        continue
                    add(p.get("projectId") or p.get("id") or p.get("project_id"))
            else:
                if item.get("success") is False:
                    continue
                add(item.get("projectId") or item.get("id") or item.get("project_id"))

    return out


def add_project_tags(
    session: requests.Session,
    v1_base: str,
    org_id: str,
    project_id: str,
    tags: list[tuple[str, str]],
) -> tuple[bool, str]:
    """
    POST key/value tags to one project (one tag per request).

    Snyk v1 expects each call as {"key": "...", "value": "..."}, not {"tags": [...]}.
    """
    url = f"{v1_base.rstrip('/')}" + V1_PROJECT_TAGS_PATH.format(
        org_id=org_id, project_id=project_id
    )
    for k, v in tags:
        r = session.post(url, json={"key": k, "value": v})
        if r.status_code in (200, 201, 204):
            continue
        if r.status_code == 409:
            continue
        if r.status_code == 422 and r.text and "already applied" in r.text:
            continue
        return False, r.text or r.reason
    return True, ""


def delete_project_v1(
    session: requests.Session,
    v1_base: str,
    org_id: str,
    project_id: str,
) -> tuple[bool, str]:
    url = f"{v1_base.rstrip('/')}" + V1_PROJECT_DELETE_PATH.format(
        org_id=org_id, project_id=project_id
    )
    r = session.delete(url)
    if r.status_code in (200, 204):
        return True, ""
    return False, r.text or r.reason


def get_project_target_id(project: dict) -> str | None:
    """Return ``relationships.target.data.id`` from a REST project resource (JSON:API)."""
    rel = (project.get("relationships") or {}).get("target") or {}
    data = rel.get("data")
    if not isinstance(data, dict):
        return None
    tid = data.get("id")
    return tid if isinstance(tid, str) and tid else None


def _log_resolve_target_relationships_debug(
    project_id: str | None,
    label: str,
    list_project: dict,
    full_project: dict | None,
) -> None:
    """Emit raw ``relationships`` from list and/or GET payloads when target id cannot be resolved."""
    try:
        list_rel = json.dumps(list_project.get("relationships"), sort_keys=True, default=str)
    except (TypeError, ValueError):
        list_rel = repr(list_project.get("relationships"))
    if full_project is not None:
        try:
            get_rel = json.dumps(full_project.get("relationships"), sort_keys=True, default=str)
        except (TypeError, ValueError):
            get_rel = repr(full_project.get("relationships"))
        print(
            f"  debug: resolve_project_target_id project_id={project_id!r} ({label}) "
            f"relationships[list]={list_rel} relationships[get]={get_rel}",
            flush=True,
        )
    else:
        print(
            f"  debug: resolve_project_target_id project_id={project_id!r} ({label}) "
            f"relationships[list]={list_rel}",
            flush=True,
        )


def fetch_project_rest(
    session: requests.Session,
    rest_base: str,
    org_id: str,
    version: str,
    project_id: str,
    *,
    expand: list[str] | None = None,
) -> dict | None:
    """GET ``/rest/orgs/{{org_id}}/projects/{{project_id}}``; return the JSON:API resource object."""
    base = rest_base.rstrip("/")
    url = f"{base}/rest/orgs/{org_id}/projects/{project_id}"
    params: list[tuple[str, str]] = [("version", version)]
    if expand:
        for e in expand:
            params.append(("expand", e))
    r = session.get(url, params=params)
    r.raise_for_status()
    payload = r.json()
    data = payload.get("data")
    return data if isinstance(data, dict) else None


def resolve_project_target_id(
    session: requests.Session,
    rest_base: str,
    org_id: str,
    version: str,
    project: dict,
) -> str | None:
    """
    Target id for orphan cleanup: prefer embedded relationship, else GET project with
    ``expand=target`` (list responses often omit ``relationships.target.data``).
    """
    pid = project.get("id")
    if not isinstance(pid, str) or not pid:
        _log_resolve_target_relationships_debug(
            None, "missing_project_id", project, None
        )
        return None

    tid = get_project_target_id(project)
    if tid:
        return tid

    try:
        full = fetch_project_rest(
            session, rest_base, org_id, version, pid, expand=["target"]
        )
    except requests.HTTPError as e:
        _log_resolve_target_relationships_debug(
            pid, f"fetch_project_http_error:{e}", project, None
        )
        return None
    except requests.RequestException as e:
        _log_resolve_target_relationships_debug(
            pid, f"fetch_project_error:{e}", project, None
        )
        return None

    tid = get_project_target_id(full) if full else None
    if tid:
        return tid

    _log_resolve_target_relationships_debug(
        pid, "no_target_id_after_embed_and_get", project, full
    )
    return None


def target_has_remaining_projects(
    session: requests.Session,
    rest_base: str,
    org_id: str,
    version: str,
    target_id: str,
) -> bool:
    """
    ``GET /rest/orgs/{{org_id}}/projects?target_id={{targetId}}&limit={{min}}``.

    Uses ``limit >= SNYK_REST_PROJECTS_PAGE_MIN_LIMIT`` (Snyk returns 400 if lower).
    Returns True if any project remains for that target.
    """
    base = rest_base.rstrip("/")
    url = f"{base}/rest/orgs/{org_id}/projects"
    r = session.get(
        url,
        params={
            "version": version,
            "limit": SNYK_REST_PROJECTS_PAGE_MIN_LIMIT,
            "target_id": [target_id],
        },
    )
    r.raise_for_status()
    payload = r.json()
    data = payload.get("data") or []
    return len(data) > 0


def delete_target_rest(
    session: requests.Session,
    rest_base: str,
    org_id: str,
    target_id: str,
    version: str,
) -> tuple[bool, str]:
    """``DELETE /rest/orgs/{{org_id}}/targets/{{targetId}}?version=...`` → expect 204."""
    base = rest_base.rstrip("/")
    url = f"{base}/rest/orgs/{org_id}/targets/{target_id}"
    r = session.delete(url, params={"version": version})
    if r.status_code == 204:
        return True, ""
    return False, r.text or r.reason


def project_matches_any_cluster_image(project: dict, cluster_images: set[str]) -> bool:
    proj_keys = snyk_project_image_keys(project)
    if not proj_keys:
        return False
    for c in cluster_images:
        if cluster_image_matches_snyk(c, proj_keys):
            return True
    return False


def cleanup_stale_deployed_projects(
    rest_session: requests.Session,
    v1_session: requests.Session,
    rest_base: str,
    v1_base: str,
    org_id: str,
    rest_version: str,
    cluster_images: set[str],
    tag_key: str,
    tag_value: str,
    *,
    dry_run: bool,
    require_tag: bool = True,
) -> int:
    """
    Remove container projects that **no longer match any** image string in ``cluster_images``
    (pod ``spec.image`` and ``status.image_id`` digests — i.e. what is actually running).

    When ``require_tag`` is True (default), the project list uses the REST ``tags`` query
    filter (``key:value``) so the server returns only matching projects; the
    ``is_likely_container_project`` check is skipped (tag scope is enough; avoids dropping
    deb/apk-typed linux base images). When ``require_tag=False``, type filtering applies.
    Set ``require_tag=False`` to list all projects and match on image identity only (no tag gate).

    After each **successful** v1 project delete, resolves the owning REST target from
    the **pre-delete** project body: ``relationships.target.data.id``. When all stale
    projects for that target are removed without error, calls
    ``GET /rest/orgs/{{orgId}}/projects?target_id={{id}}&limit=10``; if the page has
    no projects, calls ``DELETE /rest/orgs/{{orgId}}/targets/{{targetId}}``. Fully
    automatic (no manual steps).

    Returns the number of failed delete or follow-up operations (0 when ``dry_run``).
    """
    if require_tag and (not tag_key.strip() or not tag_value.strip()):
        print("Cleanup skipped: empty SNYK_IMPORT_TAG_KEY or SNYK_IMPORT_TAG_VALUE.", flush=True)
        return 0

    tag_token: str | None = None
    if require_tag:
        tag_token = f"{tag_key.strip()}:{tag_value.strip()}"
        print(
            f"\nCleanup: listing projects with REST tags={tag_token!r} and expand=target "
            f"({'dry-run; no deletes' if dry_run else 'stale projects will be deleted'})...",
            flush=True,
        )
    else:
        print(
            f"\nCleanup: scanning container projects (image match only; no tag filter — "
            f"{'dry-run; no deletes' if dry_run else 'stale projects will be deleted'})...",
            flush=True,
        )

    stale: list[tuple[str, dict]] = []
    try:
        for proj in iter_snyk_projects(
            rest_session,
            rest_base,
            org_id,
            rest_version,
            tags=[tag_token] if require_tag and tag_token else None,
            expand=["target"],
        ):
            # When require_tag=True, REST tags= scopes to script-managed projects;
            # skip project_type filtering (deb/apk linux base layers are still containers).
            if not require_tag and not is_likely_container_project(proj):
                continue
            if project_matches_any_cluster_image(proj, cluster_images):
                continue
            pid = proj.get("id")
            if not isinstance(pid, str) or not pid:
                continue
            stale.append((pid, proj))
    except requests.HTTPError as e:
        detail = f" Body: {e.response.text[:500]}" if e.response is not None else ""
        print(f"Cleanup: Snyk REST list failed: {e}.{detail}", file=sys.stderr)
        return 1
    except requests.RequestException as e:
        print(f"Cleanup: Snyk REST unreachable: {e}", file=sys.stderr)
        return 1

    if not stale:
        print(
            "Cleanup: no stale projects (all container projects in scope match the cluster image set).",
            flush=True,
        )
        return 0

    by_target: dict[str | None, list[tuple[str, dict]]] = defaultdict(list)
    for pid, proj in stale:
        tid = resolve_project_target_id(
            rest_session, rest_base, org_id, rest_version, proj
        )
        by_target[tid].append((pid, proj))

    print(f"Cleanup: {len(stale)} project(s) no longer match the cluster image set:", flush=True)
    failures = 0
    for target_id, entries in by_target.items():
        batch_failures = 0
        for pid, proj in entries:
            attrs = proj.get("attributes") or {}
            name = attrs.get("name") or pid
            if dry_run:
                tid_label = target_id or "(no target)"
                print(
                    f"  [dry-run] would DELETE project {pid} ({name!r}) "
                    f"[target {tid_label}]",
                    flush=True,
                )
                continue
            ok, err = delete_project_v1(v1_session, v1_base, org_id, pid)
            if ok:
                print(f"  deleted project {pid} ({name!r})", flush=True)
            else:
                print(f"  delete failed for {pid} ({name!r}): {err[:500]}", file=sys.stderr)
                batch_failures += 1
                failures += 1

        if dry_run:
            if target_id:
                print(
                    f"  [dry-run] would DELETE target {target_id} via REST if no projects remain",
                    flush=True,
                )
            continue

        # Orphan target removal: target_id comes from each project's relationships.target.data.id
        # (captured before v1 DELETE). Re-check with REST list; delete target only if count is zero.
        if target_id and batch_failures == 0:
            try:
                if target_has_remaining_projects(
                    rest_session, rest_base, org_id, rest_version, target_id
                ):
                    print(
                        f"  target {target_id} still has other project(s); not removing target",
                        flush=True,
                    )
                    continue
            except requests.HTTPError as e:
                detail = f" Body: {e.response.text[:500]}" if e.response is not None else ""
                print(
                    f"  could not list projects for target {target_id}: {e}{detail}",
                    file=sys.stderr,
                )
                failures += 1
                continue
            except requests.RequestException as e:
                print(f"  could not list projects for target {target_id}: {e}", file=sys.stderr)
                failures += 1
                continue
            tok, terr = delete_target_rest(
                rest_session, rest_base, org_id, target_id, rest_version
            )
            if tok:
                print(f"  deleted target {target_id} (no remaining projects)", flush=True)
            else:
                print(f"  delete target failed for {target_id}: {terr[:500]}", file=sys.stderr)
                failures += 1
        elif not target_id and batch_failures == 0:
            print(
                "  warning: could not resolve REST target id for this group; "
                "skipping DELETE /targets (orphan target may remain).",
                flush=True,
            )

    return failures


def tag_projects_from_import_job(
    session: requests.Session,
    v1_base: str,
    org_id: str,
    job_payload: dict,
    tags: list[tuple[str, str]],
    context: str,
) -> int:
    """
    Apply tags to every project id found in a completed import job.
    Returns the number of failed tag operations.
    """
    if not tags:
        return 0
    pids = project_ids_from_import_job(job_payload)
    if not pids:
        print(
            f"  warning: could not find project ids in import job to apply tags ({context})",
            file=sys.stderr,
        )
        return 0
    failures = 0
    for pid in pids:
        ok, err = add_project_tags(session, v1_base, org_id, pid, tags)
        if ok:
            label = ", ".join(f"{k}={v}" for k, v in tags)
            print(f"  tagged {context} project {pid} ({label})", flush=True)
        else:
            print(
                f"  tag failed for project {pid} ({context}): {err[:500]}",
                file=sys.stderr,
            )
            failures += 1
    return failures


def poll_import_job(session: requests.Session, job_url: str, interval_sec: float = 5.0) -> dict:
    while True:
        r = session.get(job_url)
        r.raise_for_status()
        data = r.json()
        if data.get("status") != "pending":
            return data
        time.sleep(interval_sec)


# ---------------------------------------------------------------------------
# File-based image override
# ---------------------------------------------------------------------------

def resolve_images_file_path(root: Path, arg: str) -> Path:
    raw = Path(arg).expanduser()
    candidates = [raw.resolve()] if raw.is_absolute() else [
        (root / raw).resolve(), (Path.cwd() / raw).resolve()
    ]
    for p in candidates:
        if not p.is_file():
            continue
        for base in (root.resolve(), Path.cwd().resolve()):
            try:
                p.relative_to(base)
                return p
            except ValueError:
                continue
    raise RuntimeError(f"Images file not found under project or cwd. Got: {arg!r}")


def load_images_file(path: Path) -> set[str]:
    if not path.is_file():
        raise RuntimeError(f"Images file not found: {path}")
    images = {
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    }
    if not images:
        raise RuntimeError(f"No image references in {path}")
    return images


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    _root = Path(__file__).resolve().parent
    load_dotenv(_root / ".env")
    load_dotenv()

    parser = argparse.ArgumentParser(
        description="Reconcile AKS running images with Snyk container projects."
    )
    parser.add_argument(
        "--images-file",
        metavar="PATH",
        help="Read image refs from a file (one per line) instead of querying Azure.",
    )
    parser.add_argument(
        "--wait-import",
        action="store_true",
        help="Poll each import job until completion (slower; useful for debugging).",
    )
    parser.add_argument(
        "--include-kube-system",
        action="store_true",
        help=(
            "Include images from pods in the kube-system namespace "
            "(default: exclude; reduces addon/MCR noise)."
        ),
    )
    parser.add_argument(
        "--all-pod-phases",
        action="store_true",
        help=(
            "Include images from pods in any phase (Succeeded, Failed, Pending, etc.). "
            "Default: only Running pods, so completed Job/CronJob pods do not pollute the image set."
        ),
    )
    parser.add_argument(
        "--exclude-init-containers",
        action="store_true",
        help=(
            "Do not collect images from initContainers (only main + ephemeral containers). "
            "Useful when workloads use busybox solely as an init helper."
        ),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help=(
            "Log stale tagged projects that would be deleted after import; "
            "do not call the delete API."
        ),
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable DEBUG logging (per-project keys during cleanup image matching).",
    )
    args = parser.parse_args()

    _configure_reconcile_logging(
        args.debug or _env_truthy("SNYK_DEBUG", default=False)
    )

    include_kube_system = args.include_kube_system or _env_truthy(
        "INCLUDE_KUBE_SYSTEM", default=False
    )
    include_all_phases = args.all_pod_phases or _env_truthy(
        "INCLUDE_ALL_POD_PHASES", default=False
    )
    only_running_pods = not include_all_phases
    exclude_init_containers = args.exclude_init_containers or _env_truthy(
        "EXCLUDE_INIT_CONTAINERS", default=False
    )

    token = os.environ.get("SNYK_TOKEN", "").strip()
    org_id = os.environ.get("SNYK_ORG_ID", "").strip()
    routing = load_integration_routing()
    rest_base = os.environ.get("SNYK_REST_BASE", "https://api.snyk.io").rstrip("/")
    v1_base = os.environ.get("SNYK_V1_BASE", "https://snyk.io").rstrip("/")
    rest_version = os.environ.get("SNYK_REST_VERSION", DEFAULT_REST_VERSION)

    if not token or not org_id or routing is None:
        print("Set SNYK_TOKEN, SNYK_ORG_ID, and SNYK_INTEGRATION_ID.", file=sys.stderr)
        return 1

    tag_imported = _env_truthy("SNYK_TAG_IMPORTED_PROJECTS", default=True)
    tag_key = (_env_optional("SNYK_IMPORT_TAG_KEY") or DEFAULT_IMPORT_TAG_KEY).strip()
    tag_value = (_env_optional("SNYK_IMPORT_TAG_VALUE") or DEFAULT_IMPORT_TAG_VALUE).strip()
    tag_pairs: list[tuple[str, str]] = (
        [(tag_key, tag_value)] if tag_imported and tag_key and tag_value else []
    )
    cleanup_require_tag = _env_truthy("SNYK_CLEANUP_REQUIRE_TAG", default=True)

    # --- Collect images ---
    if args.images_file:
        img_path = resolve_images_file_path(_root, args.images_file)
        print(f"Loading images from {img_path}...", flush=True)
        cluster_images = load_images_file(img_path)
        print(f"Found {len(cluster_images)} unique image references in file.", flush=True)
    else:
        sub_env = os.environ.get("AZURE_SUBSCRIPTION_ID", "").strip()
        if not sub_env:
            print("Set AZURE_SUBSCRIPTION_ID (comma-separated for multiple).", file=sys.stderr)
            return 1
        subscription_ids = [s.strip() for s in sub_env.split(",") if s.strip()]
        resource_group = _env_optional("AZURE_RESOURCE_GROUP")
        cluster_images = collect_all_images(
            subscription_ids,
            resource_group,
            include_kube_system=include_kube_system,
            only_running_pods=only_running_pods,
            exclude_init_containers=exclude_init_containers,
        )
        print(f"\nTotal: {len(cluster_images)} unique image references across all clusters.", flush=True)

    cluster_refs_raw: set[str] = set(cluster_images)
    n_before_dedupe = len(cluster_refs_raw)
    cluster_images = dedupe_cluster_images_by_content(cluster_refs_raw)
    if len(cluster_images) < n_before_dedupe:
        print(
            f"Deduplicated {n_before_dedupe} strings to {len(cluster_images)} "
            "import target(s) (same digest from spec + status counts once).",
            flush=True,
        )

    if not cluster_images:
        print("No images found — nothing to reconcile.")
        return 0

    rest_session = requests.Session()
    rest_session.headers.update({
        "Authorization": f"token {token}",
        "Accept": "application/vnd.api+json",
        "Content-Type": "application/vnd.api+json",
    })
    v1_session = requests.Session()
    v1_session.headers.update({
        "Authorization": f"token {token}",
        "Content-Type": "application/json; charset=utf-8",
    })

    # --- Import (every run: re-trigger Snyk import for each deployed image) ---
    to_import = sorted(cluster_images)
    print(
        f"\nImporting {len(to_import)} cluster image(s) "
        "(reimport every run; integration id chosen per registry).",
        flush=True,
    )
    for m in to_import:
        print(f"  - {m}")

    failures = 0
    if tag_pairs:
        print(
            f"\nAfter each import completes, projects get tag "
            f"{tag_key}={tag_value} "
            f"(override with SNYK_IMPORT_TAG_*; disable with SNYK_TAG_IMPORTED_PROJECTS=0).",
            flush=True,
        )

    for img in to_import:
        iid = integration_id_for_image(img, routing)
        ok, detail = import_image_v1(v1_session, v1_base, org_id, iid, img)
        if not ok:
            print(f"Import failed: {img} -> {detail}", file=sys.stderr)
            failures += 1
            continue
        print(f"Import started: {img} -> {detail}")
        poll_for_job = bool(detail) and (args.wait_import or bool(tag_pairs))
        if poll_for_job and detail:
            try:
                final = poll_import_job(v1_session, detail)
            except Exception as e:
                print(f"  import job poll failed ({img}): {e}", file=sys.stderr)
                failures += 1
                continue
            if args.wait_import:
                print(f"  job status: {final.get('status')} {final.get('error', '')}")
            if tag_pairs:
                failures += tag_projects_from_import_job(
                    v1_session, v1_base, org_id, final, tag_pairs, context=img
                )

    failures += cleanup_stale_deployed_projects(
        rest_session,
        v1_session,
        rest_base,
        v1_base,
        org_id,
        rest_version,
        cluster_refs_raw,
        tag_key,
        tag_value,
        dry_run=args.dry_run,
        require_tag=cleanup_require_tag,
    )

    return 1 if failures else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as e:
        print(str(e), file=sys.stderr)
        raise SystemExit(1) from None