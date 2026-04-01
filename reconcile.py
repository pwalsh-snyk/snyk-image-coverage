#!/usr/bin/env python3
"""
Reconcile container images running in AKS with Snyk projects.

Flow:
  1. Authenticate to Azure via DefaultAzureCredential (picks up `az login` session,
     environment variables, managed identity, etc. — no kubectl required).
  2. Discover all AKS clusters in the configured subscription (optionally scoped to
     a resource group) and fetch per-cluster kubeconfigs via the Azure API.
  3. Query running pod images from each cluster using the Kubernetes Python client.
  4. Paginate Snyk REST projects and build a set of known image refs.
  5. For images not matched, POST to the Snyk v1 import API using the integration
     that matches the image registry.

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
    SNYK_REST_BASE         Snyk REST API base (default: https://api.snyk.io)
    SNYK_V1_BASE           Snyk v1 API base (default: https://snyk.io)
    SNYK_REST_VERSION      REST API version (default: 2024-10-15)

  Optional tagging (after each successful import job completes):
    SNYK_TAG_IMPORTED_PROJECTS  If unset or 1/true/yes: apply Snyk project tags (default on).
                                Set to 0/false/no to skip.
    SNYK_IMPORT_TAG_KEY       Tag key (default: image)
    SNYK_IMPORT_TAG_VALUE     Tag value (default: deployed)

Usage:
  1. az login  (or set AZURE_CLIENT_ID / AZURE_CLIENT_SECRET / AZURE_TENANT_ID for SP auth)
  2. cp .env.example .env  # fill in SNYK_TOKEN, SNYK_ORG_ID, SNYK_INTEGRATION_ID,
                           # AZURE_SUBSCRIPTION_ID
  3. pip install -r requirements.txt
  4. python reconcile.py

Override cluster discovery with a static image list:
  python reconcile.py --images-file images.txt

Cron (hourly):
  0 * * * * cd /path/to/snyk-image-coverage && .venv/bin/python reconcile.py >> /var/log/snyk-reconcile.log 2>&1
"""

from __future__ import annotations

import argparse
import base64
import os
import re
import sys
import time
import yaml
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import requests
from dotenv import load_dotenv
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
V1_IMPORT_PATH = "/api/v1/org/{org_id}/integrations/{integration_id}/import"
V1_PROJECT_TAGS_PATH = "/api/v1/org/{org_id}/project/{project_id}/tags"
DEFAULT_IMPORT_TAG_KEY = "image"
DEFAULT_IMPORT_TAG_VALUE = "deployed"


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


def collect_cluster_images(core_v1: k8s_client.CoreV1Api) -> set[str]:
    """Return the set of unique image references from all running pods."""
    images: set[str] = set()
    try:
        pods = core_v1.list_pod_for_all_namespaces(watch=False)
    except ApiException as e:
        raise RuntimeError(f"Kubernetes list pods failed: {e}") from e
    except (MaxRetryError, ProtocolError, ConnectionError, OSError) as e:
        raise RuntimeError(f"Could not reach the cluster API server: {e}") from e

    for pod in pods.items:
        spec = pod.spec
        if not spec:
            continue
        for container in (spec.containers or []) + (spec.init_containers or []) + (spec.ephemeral_containers or []):
            if container.image:
                images.add(container.image.strip())
    return images


def collect_all_images(
    subscription_ids: list[str],
    resource_group: str | None = None,
) -> set[str]:
    """
    Discover all AKS clusters across the given subscriptions and collect
    running image references from each one.
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
            try:
                core_v1 = make_k8s_core_v1(sub, rg, name)
                images = collect_cluster_images(core_v1)
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


def strip_digest(ref: str) -> str:
    if "@sha256:" in ref:
        return ref.split("@sha256:", 1)[0].strip()
    return ref.strip()


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


# ---------------------------------------------------------------------------
# Snyk helpers
# ---------------------------------------------------------------------------

def snyk_project_image_keys(project: dict) -> set[str]:
    keys: set[str] = set()
    attrs = project.get("attributes") or {}
    name = attrs.get("name")
    if isinstance(name, str) and name:
        keys.add(normalize_image_ref(name))
        keys.add(normalize_image_ref(strip_digest(name)))
    for key in ("imageId", "image_id", "targetReference", "target_reference"):
        val = attrs.get(key)
        if isinstance(val, str) and val:
            keys.add(normalize_image_ref(val))
            keys.add(normalize_image_ref(strip_digest(val)))
    return keys


def iter_snyk_projects(
    session: requests.Session,
    rest_base: str,
    org_id: str,
    version: str,
) -> Iterable[dict]:
    base = rest_base.rstrip("/")
    url = f"{base}/rest/orgs/{org_id}/projects"
    params: dict | None = {"version": version, "limit": 100}

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
        if isinstance(pt, str) and "container" in pt.lower():
            return True
        if pt in ("dockerfile", "helm", "kubernetes"):
            return True
        if pt in ("apk", "deb"):
            return False
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
    args = parser.parse_args()

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
        cluster_images = collect_all_images(subscription_ids, resource_group)
        print(f"\nTotal: {len(cluster_images)} unique image references across all clusters.", flush=True)

    if not cluster_images:
        print("No images found — nothing to reconcile.")
        return 0

    # --- Fetch Snyk projects ---
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

    print("\nFetching Snyk projects...", flush=True)
    known: set[str] = set()
    project_count = 0
    try:
        for proj in iter_snyk_projects(rest_session, rest_base, org_id, rest_version):
            project_count += 1
            if not is_likely_container_project(proj):
                continue
            known.update(snyk_project_image_keys(proj))
    except requests.HTTPError as e:
        detail = f" Body: {e.response.text[:500]}" if e.response is not None else ""
        print(f"Snyk REST API request failed: {e}.{detail}", file=sys.stderr)
        return 1
    except requests.RequestException as e:
        print(f"Snyk REST API unreachable: {e}", file=sys.stderr)
        return 1

    print(f"Scanned {project_count} Snyk projects; {len(known)} normalized image keys for matching.")

    # --- Reconcile ---
    missing: list[str] = []
    for img in sorted(cluster_images):
        n = normalize_image_ref(img)
        n_base = normalize_image_ref(strip_digest(img))
        if n in known or n_base in known:
            continue
        if n.startswith("docker.io/"):
            short = n[len("docker.io/"):]
            if short in known or normalize_image_ref(strip_digest(short)) in known:
                continue
        missing.append(img)

    if not missing:
        print("All cluster images appear to have a matching Snyk project.")
        return 0

    print(f"\n{len(missing)} images not matched; importing:")
    for m in missing:
        print(f"  - {m}")
    if tag_pairs:
        print(
            f"\nAfter each import completes, projects get tag "
            f"{tag_key}={tag_value} "
            f"(override with SNYK_IMPORT_TAG_*; disable with SNYK_TAG_IMPORTED_PROJECTS=0).",
            flush=True,
        )

    failures = 0
    for img in missing:
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

    return 1 if failures else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as e:
        print(str(e), file=sys.stderr)
        raise SystemExit(1) from None