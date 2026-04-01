# snyk-image-coverage

Reconcile **container images running on AKS** with **Snyk container projects** in your organization. The script authenticates with Azure, discovers clusters (optionally scoped to a resource group), lists images from all pods, compares them to projects returned by the Snyk REST API, and **imports** unmatched images through the right **container registry integration** (ACR, ECR, MCR, Docker Hub, etc., depending on what you configure).

You do **not** need local `kubectl` or a kubeconfig file: credentials come from the Azure Resource Manager API (`list_cluster_user_credentials`) using [DefaultAzureCredential](https://learn.microsoft.com/en-us/python/api/azure-identity/azure.identity.defaultazurecredential).

Matching is **heuristic**: normalized `registry/repo:tag` strings are compared to project names and related attributes. Images referenced only by digest (`image@sha256:...`) may not align with Snyk project names that use tags—extend or tune matching if needed for your environment.

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
cp .env.example .env
```

Edit `.env` with your values (see [Configuration](#configuration)).

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
| `SNYK_V1_BASE` | No | v1 import host; default `https://snyk.io` (imports may redirect to `app.snyk.io`) |
| `SNYK_REST_VERSION` | No | Default `2024-10-15` |

\*Not required when using `--images-file` only (no cluster discovery).

`python-dotenv` loads `.env` next to `reconcile.py`, then optional overrides from a `.env` in the current working directory.

## Usage

```bash
python reconcile.py
```

**Static image list** (no Azure calls; path must resolve under this repo or your current working directory):

```bash
python reconcile.py --images-file cluster-images.txt
```

See `cluster-images.example.txt` for a template and a `kubectl`/`jq` one-liner to build the file from a cluster you can reach.

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
