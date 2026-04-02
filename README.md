# snyk-deployed-image-coverage

Automatically reconcile container images running in your AKS clusters with Snyk container projects. Import images that are deployed but not yet scanned, tag them so you can find them later, and clean up Snyk projects for images that are no longer running — all without kubectl or a local kubeconfig.

---

## Why this exists

When customers talk about container scanning with Snyk, the ask is almost always the same: *scan what's actually deployed, not everything in the registry.* Snyk has no native way to determine which scanned images are actively running on your clusters. This script closes that gap.

On each run it:

1. Discovers all AKS clusters in your Azure subscription(s) using the Azure SDK (no kubectl required).
2. Collects every image reference from running pods — both the `spec` tag string and the resolved `sha256` digest from `status.containerStatuses[].image_id`.
3. Pages through your Snyk org's projects and builds a set of known image refs and digests.
4. Imports any cluster image that doesn't already have a Snyk project, routing to the right registry integration by hostname.
5. Tags newly imported projects `image=deployed` (configurable) so you can filter in the Snyk UI.
6. Deletes Snyk projects tagged `image=deployed` whose image is no longer running, then removes the orphaned Snyk target if no projects remain.

---

## Prerequisites

- Python 3.10+
- An Azure subscription with at least one AKS cluster
- `az login` (or a service principal via env vars — see [Auth](#auth))
- Your identity needs **Azure Kubernetes Service Cluster User Role** on each cluster
- A Snyk org with at least one container registry integration configured

---

## Setup

**1. Clone and create a virtual environment**

```bash
git clone https://github.com/pwalsh-snyk/snyk-image-coverage
cd snyk-image-coverage

python3 -m venv .venv
```

A virtual environment keeps this project's dependencies isolated from the rest of your system Python — nothing else on your machine gets affected.

**2. Install dependencies**

```bash
.venv/bin/pip install -r requirements.txt
```

**3. Configure your environment**

```bash
cp .env.example .env
# open .env and fill in your values
```

**4. Authenticate to Azure**

```bash
az login
```

---

## Running the script

Always use the Python interpreter from the virtual environment:

```bash
.venv/bin/python reconcile.py
```

Using `.venv/bin/python` instead of just `python` ensures you're running against the installed dependencies, not your system Python. On Windows, the path is `.venv\Scripts\python`.

The `2>&1` you may see in examples (e.g. in a cron job) redirects error output into the same stream as normal output, so both end up in the same log file. You don't need it when running interactively in a terminal.

### .env

```dotenv
# Required
SNYK_TOKEN=your-snyk-api-token
SNYK_ORG_ID=your-snyk-org-uuid
SNYK_INTEGRATION_ID=your-default-integration-uuid   # ACR recommended as default
AZURE_SUBSCRIPTION_ID=your-azure-subscription-id    # comma-separated for multiple

# Optional: route different registries to separate Snyk integrations
SNYK_INTEGRATION_ID_ACR=        # Azure Container Registry
SNYK_INTEGRATION_ID_GCP=        # Google Artifact Registry / GCR
SNYK_INTEGRATION_ID_ECR=        # AWS ECR
SNYK_INTEGRATION_ID_MCR=        # Microsoft Container Registry
SNYK_INTEGRATION_ID_DOCKER_HUB= # Docker Hub

# Optional: scope discovery
AZURE_RESOURCE_GROUP=           # limit to one resource group

# Optional: tagging (defaults shown)
SNYK_IMPORT_TAG_KEY=image
SNYK_IMPORT_TAG_VALUE=deployed
SNYK_TAG_IMPORTED_PROJECTS=1    # set to 0 to skip tagging

# Optional: cleanup
SNYK_CLEANUP_REQUIRE_TAG=1      # set to 0 to match all container projects, not just tagged ones
```

---

## Usage

```bash
# Standard run: discover clusters, import missing images, clean up stale projects
python reconcile.py

# Preview deletions without calling the Snyk delete API
python reconcile.py --dry-run

# Include cluster addon images from kube-system (excluded by default)
python reconcile.py --include-kube-system

# Include images from completed/failed Job pods (not recommended — pulls in stale images)
python reconcile.py --all-pod-phases

# Skip init container images (useful when workloads use busybox only as an init helper)
python reconcile.py --exclude-init-containers

# Test against a static list of image refs instead of querying Azure
python reconcile.py --images-file images.txt

# Show debug output: first project attributes, per-project key extraction
python reconcile.py --debug

# Wait for each import job to finish before moving on (slower; useful for debugging)
python reconcile.py --wait-import
```

---

## Auth

The script uses `DefaultAzureCredential`, which tries credential sources in this order:

1. `az login` — recommended for local development
2. Environment variables (`AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_TENANT_ID`) — for service principals in CI
3. Managed identity — for running on Azure VMs or AKS itself

No kubeconfig or kubectl installation needed. The script fetches per-cluster credentials directly from the Azure API.

---

## How image matching works

Each cluster image goes through two representations:

- **Spec ref** — what's in `pod.spec.containers[].image`, e.g. `myregistry.azurecr.io/app:v1.2.3`
- **Digest ref** — what's in `pod.status.containerStatuses[].image_id`, e.g. `myregistry.azurecr.io/app@sha256:abc123...`

Both are normalized (lowercase, whitespace stripped, `docker-pullable://` prefix removed) before comparison against Snyk project names. If a `sha256` digest appears in either side of the comparison, it's used directly — so a tag bump that points to the same underlying image won't trigger a re-import.

When a spec ref and a digest ref refer to the same content (matched via repo path + digest), they're deduplicated to a single import target.

---

## Cleanup behavior

After imports, the script looks for Snyk projects tagged `image=deployed` (or whatever `SNYK_IMPORT_TAG_*` is set to) that don't match any currently running image. Those projects are deleted. If deleting a project leaves the owning Snyk target with zero remaining projects, the target is deleted too — so the Snyk UI stays clean without manual intervention.

Set `SNYK_CLEANUP_REQUIRE_TAG=0` to instead scan all container projects in the org regardless of tag. Use with care in shared orgs.

---

## Running on a schedule

```cron
0 * * * * cd /path/to/snyk-image-coverage && .venv/bin/python reconcile.py >> /var/log/snyk-reconcile.log 2>&1
```

For production use, a service principal with scoped permissions is recommended over `az login`.

---

## Requirements

```
kubernetes>=29.0.0
requests>=2.31.0
python-dotenv>=1.0.0
azure-identity>=1.15.0
azure-mgmt-containerservice>=28.0.0
pyyaml>=6.0
```
