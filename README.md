# snyk-image-coverage

## Purpose

This script helps you **close the gap between what is actually running in your cluster and what Snyk already tracks**. It discovers **container images deployed on your AKS workloads** (every distinct image reference from running pods), compares them to your Snyk org’s **container projects**, and for anything **not yet represented in Snyk** it calls Snyk’s **import API**. Each import queues Snyk to pull and scan that image via the **registry integration** you configured (ACR, MCR, ECR, Docker Hub, etc.). The goal is **coverage**: workloads on the cluster get corresponding container projects in Snyk without manually importing image by image.

## Matching cluster images to Snyk

When you import a container image, Snyk’s model is **digest-centric**: the scan is tied to the immutable layer identity you get from the registry (the same digest Kubernetes resolves when it pulls the image). The REST API exposes that in places like project **attributes** (e.g. `imageId` / `image_id`, target reference fields) and via **Container image** endpoints (`/rest/orgs/{org_id}/container_images`, …), which are keyed by Snyk’s own image identifiers.

**Yes — matching on that identity (ultimately the digest) is the right long-term approach** and avoids fragile “same tag string” comparisons.

This script’s implementation is still **mostly string-heuristic** on the **Projects** list: it normalizes full image strings and compares them to project names plus a handful of attribute values copied into a single `known` set (including `imageId` where the API returns it). It does **not** yet:

- Treat **`sha256:…` as a first-class join key** on both sides (for example, if the workload string is `registry/app@sha256:abc…` but Snyk’s stored fields surface only digest-shaped values, the script does not reliably declare a match unless those strings happen to coincide after normalization).

- Pull **resolved** image identities from pod **status** (e.g. `containerStatuses[].imageID`), only the **spec** `image` strings. So pods that specify `image: myrepo/app:1.2` while the node is running digest `sha256:…` may not contribute a digest on the cluster side for the script to compare — even though Snyk may only “look like” digest + repo in the UI/API.

So mismatches remain possible (digest-only spec, tag-only spec, multi-arch digest variance, or API field shapes that do not land in the attributes this script reads). **Tighter matching** would mean extending `reconcile.py`: collect runtime image IDs (and/or canonical digests) from the cluster, normalize digests from Snyk project/container-image responses, and reconcile on **digest equality** (with a tag/name fallback if you still want it).

## How it works

1. **Azure** — Uses [DefaultAzureCredential](https://learn.microsoft.com/en-us/python/api/azure-identity/azure.identity.defaultazurecredential) (`az login`, service principal, managed identity, etc.) against the subscription(s) in `AZURE_SUBSCRIPTION_ID`, optionally limited by `AZURE_RESOURCE_GROUP`.
2. **Discover clusters** — Lists AKS managed clusters in those subscriptions via the Azure Resource Manager API.
3. **Cluster API access** — For each cluster, obtains a short-lived **kubeconfig** from Azure (`list_cluster_user_credentials`); no kubeconfig files or cluster admin kubeconfig on disk are required.
4. **List running images** — Uses the Kubernetes Python client to **list pods in all namespaces** and collects images from regular containers, init containers, and ephemeral containers.
5. **Snyk inventory** — Paginates your org’s projects from the **Snyk REST API** and derives normalized keys from project names and container-related attributes.
6. **Reconcile** — Any cluster image that does not match the known set is treated as missing; the script **POSTs** to Snyk’s **v1 import** endpoint with the appropriate **integration ID** (from `SNYK_INTEGRATION_ID` or per-registry overrides like `SNYK_INTEGRATION_ID_ACR`). The request strips the registry hostname from the image ref where Snyk expects only the repository path for that integration.
7. **Tag imported projects (default)** — For each import, the script **polls the import job** until it finishes, reads the created **project id(s)** from the job payload, and **POSTs** Snyk **project tags** (v1 API: `.../project/{projectId}/tags`). By default it applies **`image` = `deployed`** so you can filter reports on *deployed* workload images. Disable or override with `SNYK_TAG_IMPORTED_PROJECTS` and `SNYK_IMPORT_TAG_KEY` / `SNYK_IMPORT_TAG_VALUE` (see configuration).

If you cannot or do not want to talk to Azure for a given run, you can pass **`--images-file`** with one image reference per line; the same reconcile and import steps run against that static list.

## Prerequisites

- Python 3.10+
- Azure access to the subscription(s) that host AKS: `az login` (or environment variables / managed identity for service principals and automation)
- **Azure RBAC** that can list managed clusters and fetch user credentials (for example **Azure Kubernetes Service Cluster User Role** on the cluster or subscription)
- A Snyk org with **registry integration(s)** and a **Snyk API token**

**Integration IDs are per org.** After changing `SNYK_ORG_ID`, set `SNYK_INTEGRATION_ID` (and any `SNYK_INTEGRATION_ID_*` overrides) to integrations that exist in that org. You can list v1 integration keys with:

`GET https://api.snyk.io/v1/org/<SNYK_ORG_ID>/integrations` (Bearer-style: `Authorization: token <SNYK_TOKEN>`).

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

Edit `.env` in the repo root with your values (see [Configuration](#configuration)). Once it contains secrets, do not commit or push `.env`—keep those changes local only.

### Azure sign-in

```bash
az login
az account set --subscription <subscription-id>   # optional if you have many subscriptions
```

The script reads `AZURE_SUBSCRIPTION_ID` from `.env` (comma-separated for multiple subscriptions).

## Configuration

| Variable | Required | Description |
|----------|----------|-------------|
| `SNYK_TOKEN` | Yes | Snyk API token |
| `SNYK_ORG_ID` | Yes | Organization ID (Snyk UI → Organization settings) |
| `SNYK_INTEGRATION_ID` | Yes | Default container registry integration ID (often ACR) |
| `AZURE_SUBSCRIPTION_ID` | Yes* | Subscription UUID(s) to scan; comma-separated for multiple |
| `AZURE_RESOURCE_GROUP` | No | If set, only clusters in this resource |
| `SNYK_INTEGRATION_ID_ACR` | No | `*.azurecr.io` |
| `SNYK_INTEGRATION_ID_GCP` | No | Artifact Registry / GCR |
| `SNYK_INTEGRATION_ID_ECR` | No | ECR |
| `SNYK_INTEGRATION_ID_MCR` | No | `mcr.microsoft.com` |
| `SNYK_INTEGRATION_ID_DOCKER_HUB` | No | Docker Hub / implicit `library/...` |
| `SNYK_REST_BASE` | No | Default `https://api.snyk.io` |
| `SNYK_V1_BASE` | No | v1 import + project-tags host; default `https://snyk.io` (imports may redirect to `app.snyk.io`) |
| `SNYK_REST_VERSION` | No | Default `2024-10-15` |
| `SNYK_TAG_IMPORTED_PROJECTS` | No | If `1`/`true`/unset: tag new projects after import (default). Set `0`/`false`/`no` to skip. |
| `SNYK_IMPORT_TAG_KEY` | No | Project tag **key** (default `image`) |
| `SNYK_IMPORT_TAG_VALUE` | No | Project tag **value** (default `deployed`) |

\*Not required when using `--images-file` only (no cluster discovery).

`python-dotenv` loads `.env` next to `reconcile.py`, then optional overrides from a `.env` in the current working directory.

## Usage

```bash
python reconcile.py
```

**Static image list** (skips Azure discovery; path must resolve under this repo or your current working directory):

```bash
python reconcile.py --images-file cluster-images.txt
```

See `cluster-images.example.txt` for the line-oriented file format.

**Wait for each import job** (slower; debugging):

```bash
python reconcile.py --wait-import
```

Exit code `0` means success or nothing to do; non-zero indicates missing configuration, unreachable Azure/Kubernetes/Snyk, or import failures.

### Troubleshooting

- **Cluster listing or kubeconfig errors** — Confirm subscription ID and RBAC. ARM resource IDs from Azure may use mixed casing (`/resourceGroups/` vs `/resourcegroups/`); the script normalizes that when resolving the resource group.
- **`org source not found` on import** — `SNYK_INTEGRATION_ID` does not belong to `SNYK_ORG_ID`, or the integration type cannot serve that registry. Fix the org/integration pairing or add `SNYK_INTEGRATION_ID_MCR` (and similar) for multi-registry clusters.
- **Addon images (`mcr.microsoft.com/...`)** — Use an integration that can pull from MCR, or skip system images via a filtered `--images-file` workflow.
- **Snyk REST shows 0 projects** — Normal for an empty org; first run imports everything that does not match.
- **`CERTIFICATE_VERIFY_FAILED` to `api.snyk.io`** — Common on some macOS Python installs. Try `export SSL_CERT_FILE=$(python -c "import certifi; print(certifi.where())")` after `pip install certifi`.
- **Tagging: “could not find project ids in import job”** — Snyk may return a different job JSON shape than this script parses, or the job failed before projects were created. Use `python reconcile.py --wait-import` once and inspect the job response; open an issue with a redacted sample if it persists.

## Scheduling

Example hourly cron:

```cron
0 * * * * cd /path/to/snyk-image-coverage && /path/to/.venv/bin/python reconcile.py >> /var/log/snyk-reconcile.log 2>&1
```

For automation, prefer a **service principal** or **managed identity** and set the Azure environment variables consumed by `DefaultAzureCredential`, instead of interactive `az login`.

## Dependencies

- [azure-identity](https://github.com/Azure/azure-sdk-for-python/tree/main/sdk/identity/azure-identity) — Azure authentication
- [azure-mgmt-containerservice](https://github.com/Azure/azure-sdk-for-python/tree/main/sdk/containerservice/azure-mgmt-containerservice) — list clusters and user kubeconfig
- [PyYAML](https://pyyaml.org/) — parse kubeconfig from Azure
- [kubernetes](https://github.com/kubernetes-client/python) — list pods and container images
- [requests](https://requests.readthedocs.io/) — Snyk HTTP APIs
- [python-dotenv](https://github.com/theskumar/python-dotenv) — load `.env`

## Security notes

- Keep `.env` out of version control (it is listed in `.gitignore`).
- Treat `SNYK_TOKEN` and Azure credentials as secrets; use least-privilege tokens and RBAC.
