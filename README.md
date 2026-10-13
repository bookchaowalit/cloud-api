# cloud-api

Moved out of solo-empire `services/cloud-api` on 2026-10-11 with its history (subtree split).
**Standalone:** the sanitized provider adapters (`cloud_usage`, `paas_action`, `paas_execute`,
`paas_inventory`, `render_preflight` and their helpers, including `secret_resolver`, `decision_store`,
`task_store`) are vendored in `adapters/` (copied from solo-empire `infra/scripts/{platform,utils}`), and the
registries they read live in `registry/` (`cloud-providers.yaml`, `paas-action-policy.json`,
`free-resource-index.json`). No other checkout is needed.
Optional: `SOLO_ACCOUNTS_ROOT` (a `bookchaowalit/platform-accounts-api` checkout) enables the account-metadata section;
a git-ignored `.env` at the repository root is loaded without overriding the shell.
Tests: `python3 -m unittest discover -s tests -p '*test*.py'`.

---

# Solo Empire Cloud API

`cloud-api` is the independently runnable backend for the Cloud/PaaS
extraction pilot. It exposes the existing sanitized usage and inventory
projections through a versioned `cloud.v1` contract; it does not read provider
credentials in the browser and it never returns provider payloads.

The legacy `infra/dashboard` facade was removed from solo-empire on 2026-10-11; `owner-web`
(`bookchaowalit/life-dashboard-web`) is the web surface.

## Run

From this repository root:

```bash
python3 server.py
```

The default listener is `http://127.0.0.1:3440`. Configure `CLOUD_API_HOST`,
`CLOUD_API_PORT`, and `CLOUD_API_CORS_ORIGINS` as needed. A non-loopback bind
fails closed unless `CLOUD_API_TOKEN` is set; use TLS and an authenticated
reverse proxy before exposing it beyond the local machine.

Read-only routes default to offline/credential-only mode. Add `?live=true`
only when an explicit provider read is wanted:

```text
GET /health
GET /api/v1/cloud/usage?live=false
GET /api/v1/paas/inventory?live=false
GET /api/v1/paas/actions
GET /api/v1/paas/render/discovery?live=false
GET /api/v1/paas/render/action-preflight?...  # read-only preflight
POST /api/v1/paas/commands                     # local-owner boundary
```

The command route is intentionally not a general browser mutation API. It
requires a loopback peer, an allowed local `Origin`,
`X-Solo-PaaS-Command: 1`, JSON content, and (when configured) the bearer
token. `paas_execute.dispatch` remains the authority for proposal binding,
approval freshness, confirmation, provider preflight, atomic claim, and
ambiguous-result handling.

See the machine-readable [Cloud API v1 envelope contract](contracts/cloud.v1.json)
for the shared `contract` and `route` fields returned by each projection.

Run the deterministic backend tests with:

```bash
python3 -m unittest discover -s tests -p '*test*.py'
```
