# snyk-image-coverage

Reconcile **container images running in Kubernetes** (for example on AKS) with **Snyk container projects** in your organization. The script lists images from all pods, compares them to projects returned by the Snyk REST API, and **imports** unmatched images through your org’s **container registry integration** (ACR, Docker Hub, etc.).

Matching is **heuristic**: normalized `registry/repo:tag` strings are compared to project names and related attributes. Images referenced only by digest (`image@sha256:...`) may not align with Snyk project names that use tags—extend or tune matching if needed for your environment.

## Prerequisites

- Python 3.10+ (tested workflow uses a virtual environment)
- `kubectl` access to the target cluster (or in-cluster credentials when run as a pod)
- A Snyk org with a **container registry integration** and API token

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
```

Edit `.env` with your values (see [Configuration](#configuration)).

### Kubernetes context (local / laptop)

Point `kubectl` at your cluster, for example:

```bash
az aks get-credentials --resource-group <resource-group> --name <cluster> --overwrite-existing
```

Optional: `export KUBECONFIG=/path/to/kubeconfig` for a non-default config.

Sanity check:

```bash
kubectl get pods -A
```

## Configuration

| Variable | Required | Description |
|----------|----------|-------------|
| `SNYK_TOKEN` | Yes | Snyk API token |
| `SNYK_ORG_ID` | Yes | Organization ID (Snyk UI → Organization settings) |
| `SNYK_INTEGRATION_ID` | Yes | Container registry integration ID (Integrations) |
| `SNYK_REST_BASE` | No | REST API base (default `https://api.snyk.io`) |
| `SNYK_V1_BASE` | No | v1 API base for import (default `https://snyk.io`) |
| `SNYK_REST_VERSION` | No | REST version header value (default `2024-10-15`) |

`python-dotenv` loads `.env` from the project directory (next to `reconcile.py`); a `.env` in the current working directory can override values for local experiments.

## Usage

Run reconciliation (lists cluster images, fetches Snyk projects, then imports any image that did not match):

```bash
python reconcile.py
```

If the machine running the script **cannot** reach the Kubernetes API (for example some CI sandboxes or wrong network), export images where `kubectl` works, then run against that file (path must be under this repo or your current working directory):

```bash
python reconcile.py --images-file cluster-images.txt
```

See `cluster-images.example.txt` for a template and a `kubectl`/`jq` one-liner to build the file.

Poll each import job until it finishes (slower; useful for debugging):

```bash
python reconcile.py --wait-import
```

Exit code `0` means success or nothing to do; non-zero indicates missing configuration or import failures.

### Troubleshooting

- **`Cannot reach the Kubernetes API server`** — The process needs the same network path as a working `kubectl get pods -A`. For AKS: connect VPN if required, add your IP under **Networking → API server authorized IP ranges**, or use a **private cluster** access path (`kubectl` via command invoke / jump box). Cursor’s integrated agent terminal often **cannot** reach a private or IP-restricted API server even when your laptop can.
- **Snyk import errors** — The **container registry integration** in Snyk must match where images are hosted (for example the same ACR as `yourregistry.azurecr.io/...` in pod specs). Images pulled only from Docker Hub or `gcr.io` need an integration that can resolve those refs, not only an empty ACR.
- **`CERTIFICATE_VERIFY_FAILED` to `api.snyk.io`** — Common with a fresh Python install on macOS. Point OpenSSL at Mozilla’s bundle, for example: `export SSL_CERT_FILE=$(python -c "import certifi; print(certifi.where())")` (after `pip install certifi`), or use the official Python installer’s “Install Certificates” step.

## Local end-to-end test (AKS + Snyk)

Use this on the same machine where `kubectl` can reach the API server (VPN or public endpoint, depending on how AKS is set up).

**1. Confirm workloads and images**

```bash
kubectl config current-context
kubectl get pods -A -o wide
```

Unique image references from all containers (regular + init; mirrors what the script collects for standard pods):

```bash
kubectl get pods -A -o json | jq -r '
  .items[]
  | (.spec.containers // []) + (.spec.initContainers // []) + (.spec.ephemeralContainers // [])
  | .[]
  | .image
  | select(. != null)
' | sort -u
```

If you do not have `jq`, use `kubectl describe` / the `IMAGE` column from `kubectl get pods -A -o wide` as a spot check.

**2. Configure Snyk**

Fill `.env` with `SNYK_TOKEN`, `SNYK_ORG_ID`, and `SNYK_INTEGRATION_ID` for the registry integration that can resolve the images you run (for example ACR).

**3. Run**

```bash
cd /path/to/snyk-image-coverage
source .venv/bin/activate
python reconcile.py
```

Optional: `python reconcile.py --wait-import`. Confirm imports and new projects in the Snyk UI.

## Scheduling

Example hourly cron (adjust paths):

```cron
0 * * * * cd /path/to/snyk-image-coverage && /path/to/.venv/bin/python reconcile.py >> /var/log/snyk-reconcile.log 2>&1
```

For a **CronJob** inside the cluster, use a pod service account with RBAC to list pods cluster-wide; do not rely on `KUBECONFIG`—the client uses in-cluster config when available.

## Dependencies

- [kubernetes](https://github.com/kubernetes-client/python) — cluster API
- [requests](https://requests.readthedocs.io/) — Snyk HTTP APIs
- [python-dotenv](https://github.com/theskumar/python-dotenv) — load `.env`

## Security notes

- Keep `.env` out of version control (it is listed in `.gitignore`).
- Treat `SNYK_TOKEN` as a secret; use least-privilege tokens where possible.
