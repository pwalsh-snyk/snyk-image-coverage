#!/usr/bin/env python3
"""
Reconcile container images running in Kubernetes (e.g. AKS) with Snyk projects.

Flow:
  1. List images from all pods (workloads + init containers), deduplicated.
  2. Paginate Snyk REST projects for the org and build a set of known image refs.
  3. For images not matched, POST to the v1 import API using the integration that matches the
     image registry (see SNYK_INTEGRATION_ID and optional SNYK_INTEGRATION_ID_* in .env.example).

Matching is heuristic: normalized `registry/repo:tag` strings compared to project names and
target references. Images referenced only by digest (`image@sha256:...`) may not match Snyk
project names that use tags — tune or extend matching for your environment.

Usage (local laptop against AKS — no CI required):
  1. Point kubectl at your cluster (same context the script uses):
       az aks get-credentials --resource-group <rg> --name <cluster> --overwrite-existing
     Optional: export KUBECONFIG=... if you use a non-default kubeconfig file.
  2. Sanity check: kubectl get pods -A
  3. python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt
  4. cp .env.example .env and set SNYK_TOKEN, SNYK_ORG_ID, SNYK_INTEGRATION_ID
     (org ID and integration ID: Snyk UI → Organization settings / Integrations)
  5. Run: python reconcile.py (.env beside this script is loaded automatically)

Usage (minimal):
  pip install -r requirements.txt
  cp .env.example .env  # fill in values
  python reconcile.py

Cron (hourly example):
  0 * * * * cd /path/to/snyk-image-coverage && /path/to/venv/bin/python reconcile.py >> /var/log/snyk-reconcile.log 2>&1
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import requests
from dotenv import load_dotenv
from urllib3.exceptions import MaxRetryError, ProtocolError

try:
    from kubernetes import client, config
    from kubernetes.client.rest import ApiException
except ImportError:
    print("Install dependencies: pip install -r requirements.txt", file=sys.stderr)
    raise

# Snyk REST projects version (pagination + attributes)
DEFAULT_REST_VERSION = "2024-10-15"
V1_IMPORT_PATH = "/api/v1/org/{org_id}/integrations/{integration_id}/import"

@dataclass(frozen=True)
class IntegrationRouting:
    """Map image refs to Snyk registry integration IDs; unset fields fall back to default."""

    default: str
    acr: str | None = None
    gcp: str | None = None
    mcr: str | None = None
    docker_hub: str | None = None
    ecr: str | None = None


def _env_optional(key: str) -> str | None:
    v = os.environ.get(key, "").strip()
    return v or None


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


_K8S_UNREACHABLE = (
    "Cannot reach the Kubernetes API server (connection failed or reset). "
    "Use the same machine/network where `kubectl get pods -A` works: check VPN, "
    "authorized IP ranges on AKS, private cluster access, and KUBECONFIG. "
    "Or export image refs to a file and pass --images-file PATH."
)


def load_k8s() -> client.CoreV1Api:
    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config()
    return client.CoreV1Api()


def collect_cluster_images(core_v1: client.CoreV1Api) -> set[str]:
    images: set[str] = set()
    try:
        pods = core_v1.list_pod_for_all_namespaces(watch=False)
    except ApiException as e:
        raise RuntimeError(f"Kubernetes list pods failed: {e}") from e
    except (MaxRetryError, ProtocolError, ConnectionError, OSError) as e:
        raise RuntimeError(_K8S_UNREACHABLE) from e

    for pod in pods.items:
        spec = pod.spec
        if not spec:
            continue
        for container in spec.containers or []:
            if container.image:
                images.add(container.image.strip())
        for container in spec.init_containers or []:
            if container.image:
                images.add(container.image.strip())
        for container in spec.ephemeral_containers or []:
            if container.image:
                images.add(container.image.strip())
    return images


def normalize_image_ref(ref: str) -> str:
    """Lowercase and collapse spacing for comparison."""
    s = ref.strip().lower()
    s = re.sub(r"\s+", "", s)
    return s


def strip_digest(ref: str) -> str:
    """`repo:tag@sha256:...` -> `repo:tag`; `repo@sha256:...` unchanged except trim."""
    if "@sha256:" in ref:
        return ref.split("@sha256:", 1)[0].strip()
    return ref.strip()


def strip_registry_hostname(ref: str) -> str:
    """Remove registry hostname prefix for Snyk import API.

    The hostname is implied by the integration — passing the full reference
    (e.g. pwalshobaks2025.azurecr.io/microservices-demo/frontend:v0.10.5)
    causes 'Unauthorized access or resource does not exist'. Only the
    repository path and tag should be sent as target.name.

    Examples:
      pwalshobaks2025.azurecr.io/microservices-demo/frontend:v0.10.5
        -> microservices-demo/frontend:v0.10.5
      us-central1-docker.pkg.dev/google-samples/microservices-demo/frontend:v0.10.5
        -> google-samples/microservices-demo/frontend:v0.10.5
      mcr.microsoft.com/oss/kubernetes/coredns:v1.12.1
        -> oss/kubernetes/coredns:v1.12.1
      redis:alpine  (no hostname — returned unchanged)
        -> redis:alpine
    """
    parts = ref.split("/", 1)
    if len(parts) > 1 and ("." in parts[0] or ":" in parts[0]):
        return parts[1]
    return ref


def snyk_project_image_keys(project: dict) -> set[str]:
    """Extract comparable keys from a REST project resource."""
    keys: set[str] = set()
    attrs = project.get("attributes") or {}
    name = attrs.get("name")
    if isinstance(name, str) and name:
        keys.add(normalize_image_ref(name))
        keys.add(normalize_image_ref(strip_digest(name)))
    # Some container projects expose target in relationships/meta depending on version
    for key in ("imageId", "image_id", "targetReference", "target_reference"):
        val = attrs.get(key)
        if isinstance(val, str) and val:
            keys.add(normalize_image_ref(val))
            keys.add(normalize_image_ref(strip_digest(val)))
    return keys


def resolve_images_file_path(root: Path, arg: str) -> Path:
    """Resolve CLI path to an existing file under project root or cwd (path traversal safe)."""
    raw = Path(arg).expanduser()
    candidates: list[Path] = []
    if raw.is_absolute():
        candidates.append(raw.resolve())
    else:
        candidates.append((root / raw).resolve())
        candidates.append((Path.cwd() / raw).resolve())
    root_r, cwd_r = root.resolve(), Path.cwd().resolve()
    for p in candidates:
        if not p.is_file():
            continue
        for base in (root_r, cwd_r):
            try:
                p.relative_to(base)
                return p
            except ValueError:
                continue
    raise RuntimeError(
        f"Images file must exist under the project directory ({root_r}) or "
        f"the current working directory ({cwd_r}). Got: {arg!r}"
    )


def load_images_file(path: Path) -> set[str]:
    """One image reference per line; empty lines and # comments skipped."""
    if not path.is_file():
        raise RuntimeError(f"Images file not found: {path}")
    images: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        images.add(line)
    if not images:
        raise RuntimeError(f"No image references in {path}")
    return images


def iter_snyk_projects(
    session: requests.Session,
    rest_base: str,
    org_id: str,
    version: str,
) -> Iterable[dict]:
    base = rest_base.rstrip("/")
    url = f"{base}/rest/orgs/{org_id}/projects"
    params: dict[str, str | int] | None = {"version": version, "limit": 100}

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
        if next_href.startswith("http"):
            url = next_href
        else:
            url = f"{base}{next_href}" if next_href.startswith("/") else f"{base}/{next_href}"
        params = None


def is_likely_container_project(project: dict) -> bool:
    """Filter to container-ish projects when type is present."""
    ptype = project.get("type")
    if ptype == "project":
        meta = project.get("meta") or {}
        # REST often uses meta.project_type or attributes.type
        pt = meta.get("project_type") or (project.get("attributes") or {}).get("type")
        if pt is None:
            return True  # include unknowns; matching still uses image strings
        if isinstance(pt, str) and "container" in pt.lower():
            return True
        if pt in ("dockerfile", "helm", "kubernetes"):
            return True
        if pt == "apk" or pt == "deb":  # linux packages — skip
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
    # Strip the registry hostname — Snyk's import API expects only the repository
    # path (e.g. "microservices-demo/frontend:v0.10.5"), not the full reference
    # including the registry hostname. The hostname is already encoded in the
    # integration, and including it causes "Unauthorized access or resource does
    # not exist" even when credentials are correct.
    target_name = strip_registry_hostname(image_ref)
    body = {"target": {"name": target_name}}
    r = session.post(url, json=body)
    if r.status_code == 201:
        loc = r.headers.get("Location")
        if loc and loc.startswith("/"):
            loc = f"{v1_base.rstrip('/')}{loc}"
        return True, loc
    return False, r.text


def poll_import_job(session: requests.Session, job_url: str, interval_sec: float = 5.0) -> dict:
    """Poll v1 import job until not pending (best effort)."""
    while True:
        r = session.get(job_url)
        r.raise_for_status()
        data = r.json()
        status = data.get("status")
        if status != "pending":
            return data
        time.sleep(interval_sec)


def main() -> int:
    _root = Path(__file__).resolve().parent
    load_dotenv(_root / ".env")
    load_dotenv()  # optional: cwd .env overrides for local experiments
    parser = argparse.ArgumentParser(description="Reconcile K8s images with Snyk container projects.")
    parser.add_argument(
        "--images-file",
        metavar="PATH",
        help="Read image refs from this file (one per line) instead of querying the cluster.",
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

    rest_session = requests.Session()
    rest_session.headers.update(
        {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.api+json",
            "Content-Type": "application/vnd.api+json",
        }
    )
    v1_session = requests.Session()
    v1_session.headers.update(
        {
            "Authorization": f"token {token}",
            "Content-Type": "application/json; charset=utf-8",
        }
    )

    if args.images_file:
        img_path = resolve_images_file_path(_root, args.images_file)
        print(f"Loading images from {img_path}...", flush=True)
        cluster_images = load_images_file(img_path)
        print(f"Found {len(cluster_images)} unique image references in file.", flush=True)
    else:
        print("Collecting images from cluster...", flush=True)
        core = load_k8s()
        cluster_images = collect_cluster_images(core)
        print(f"Found {len(cluster_images)} unique image references in running pods.", flush=True)

    print("Fetching Snyk projects...", flush=True)
    known: set[str] = set()
    project_count = 0
    try:
        for proj in iter_snyk_projects(rest_session, rest_base, org_id, rest_version):
            project_count += 1
            if not is_likely_container_project(proj):
                continue
            known.update(snyk_project_image_keys(proj))
    except requests.HTTPError as e:
        detail = ""
        if e.response is not None and e.response.text:
            detail = f" Body: {e.response.text[:500]}"
        print(f"Snyk REST API request failed: {e}.{detail}", file=sys.stderr)
        return 1
    except requests.RequestException as e:
        print(f"Snyk REST API unreachable: {e}", file=sys.stderr)
        return 1

    print(f"Scanned {project_count} Snyk projects; {len(known)} normalized image keys for matching.")

    missing: list[str] = []
    for img in sorted(cluster_images):
        n = normalize_image_ref(img)
        n_base = normalize_image_ref(strip_digest(img))
        if n in known or n_base in known:
            continue
        # Heuristic: also try without default docker.io/library prefix
        if n.startswith("docker.io/"):
            short = n[len("docker.io/") :]
            if short in known or normalize_image_ref(strip_digest(short)) in known:
                continue
        missing.append(img)

    if not missing:
        print("All cluster images appear to have a matching Snyk project (heuristic).")
        return 0

    print(f"{len(missing)} images not matched; importing:")
    for m in missing:
        print(f"  - {m}")

    failures = 0
    for img in missing:
        iid = integration_id_for_image(img, routing)
        ok, detail = import_image_v1(v1_session, v1_base, org_id, iid, img)
        if ok:
            print(f"Import started: {img} -> {detail}")
            if args.wait_import and detail:
                try:
                    final = poll_import_job(v1_session, detail)
                    print(f"  job status: {final.get('status')} {final.get('error', '')}")
                except Exception as e:
                    print(f"  poll failed: {e}", file=sys.stderr)
                    failures += 1
        else:
            print(f"Import failed: {img} -> {detail}", file=sys.stderr)
            failures += 1

    return 1 if failures else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as e:
        print(str(e), file=sys.stderr)
        raise SystemExit(1) from None