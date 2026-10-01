# Cloud Security

Vectra Cloud Security imports findings from each cloud provider's own security service, converts them to one Vectra finding format, and shows them next to Web, Network and SAST findings. It aggregates findings; it doesn't scan cloud accounts itself. A finding appears only if the provider reported it.

| Provider | Security service | Status |
|---|---|---|
| AWS | AWS Security Hub (`GetFindings`, ASFF) | Available |
| Google Cloud | Security Command Center API v2 | Available |
| Azure | Microsoft Defender for Cloud | Planned |
| Vercel, Netlify | None (no native findings API) | Planned (configuration checks) |

## Architecture

```
Browser ──(Firebase ID token)──▶ FastAPI /cloud/*
                                   │  cloud/access.py   uid → user → membership → org → role
                                   │  api/cloud.py      validation, RBAC, tenant-scoped paths
                                   ▼
                      cloud/sync.py (background task, one per integration)
                                   │
                  cloud/registry.py ─▶ providers/aws.py ─▶ AWS Security Hub
                                   └─▶ providers/gcp.py ─▶ Security Command Center
                                   │
                      normalizers/{aws,gcp}.py → NormalizedFinding / NormalizedAsset
                                   ▼
                      cloud/store.py → Firestore (Admin SDK only)
```

Provider-specific code lives only in `backend/cloud/providers/` and `backend/cloud/normalizers/`. Everything else works with the normalized models in `backend/cloud/models.py`.

Frontend:
- **Pages:** `frontend/app/app/cloud-security/`
  - `page.tsx`: overview
  - `integrations/`, `findings/`, `findings/[findingId]/`, `assets/`
- **Components:** `frontend/components/cloud/`
- **API client:** `frontend/lib/api-cloud.ts`

## Firestore model

Everything is stored under the organization. Browsers can't read or write any of it (see `firestore.rules`); all access goes through the backend API.

| Collection | Contents |
|---|---|
| `organizations/{orgId}/cloud_integrations/{id}` | provider, display name, auth method, **non-secret** config, account, status, last validation, sync status, last-sync statistics, counters |
| `organizations/{orgId}/cloud_secrets/{id}` | AES-256-GCM encrypted credentials only |
| `organizations/{orgId}/cloud_findings/{fingerprint}` | normalized finding, first/last seen, status history, capped raw provider data |
| `organizations/{orgId}/cloud_assets/{assetId}` | resources referenced by findings, open/total finding counts |
| `organizations/{orgId}/cloud_syncs/{syncId}` | sync jobs: status, statistics, failed scopes, errors |

Cloud events are written to the organization audit log (`organizations/{orgId}/auditLogs`, `category: "cloud"`).

**Indexes:** queries use either no filter or a single equality filter on `integrationId`, both covered by Firestore's automatic single-field indexes. The platform-admin view uses an unfiltered collection-group read of `cloud_integrations`. No composite indexes are required.

## Authentication and credential storage

The browser never keeps provider credentials. They are sent once, on connect or rotate. The backend validates them, encrypts them and never returns them.

- **Encryption:** AES-256-GCM with `VECTRA_SECRETS_KEY`.
  - The organization id and integration id are bound in as associated data, so an encrypted blob copied onto another integration or organization won't decrypt.
  - No secret manager existed in this deployment. To move to Google Secret Manager, replace `seal` / `open_sealed` in `backend/cloud/secrets.py`.
- **AWS, IAM role (recommended):** Vectra's own AWS identity calls `sts:AssumeRole` on the customer's role.
  - Each organization has its own `ExternalId`, computed from the deployment key and the org id. Another organization can't predict it, which stops one customer from using a role that trusts Vectra on behalf of another (the confused-deputy problem).
  - Needs `VECTRA_AWS_PRINCIPAL_ARN`, plus credentials for that principal from the standard AWS credential chain.
- **AWS, access key:** long-term `AKIA…` key of a read-only IAM user. Temporary `ASIA…` keys are rejected because they expire.
- **GCP, service-account key:** only the fields needed for signing are stored.
  - The key's `token_uri` must be `https://oauth2.googleapis.com/token`, and its universe must be `googleapis.com`.
  - Otherwise a crafted key could make the backend send a signed token request to any URL (SSRF).

Nothing is logged in plaintext: credentials, authorization headers, provider error text and raw responses are all kept out of logs. User-facing errors are fixed messages written by Vectra.

## Required provider permissions

**AWS** (policy attached to the role or user):
```json
{ "Version": "2012-10-17", "Statement": [{ "Effect": "Allow",
  "Action": ["securityhub:GetFindings", "securityhub:DescribeHub"], "Resource": "*" }] }
```
Role trust policy:
```json
{ "Effect": "Allow", "Principal": { "AWS": "<VECTRA_AWS_PRINCIPAL_ARN>" },
  "Action": "sts:AssumeRole", "Condition": { "StringEquals": { "sts:ExternalId": "<shown in Vectra>" } } }
```
Security Hub must be enabled in each configured Region. If cross-Region aggregation is on, configuring the aggregation Region alone is enough.

**Google Cloud:**
- Enable `securitycenter.googleapis.com` and activate Security Command Center for the scope.
- Grant the service account `roles/securitycenter.findingsViewer` on the project, folder or organization.

## Environment variables

| Variable | Required | Purpose |
|---|---|---|
| `VECTRA_SECRETS_KEY` | Yes | 32 random bytes, base64. Encrypts stored credentials and computes each org's AWS ExternalId. **Rotating it makes stored credentials unreadable**; integrations must then be reconnected. |
| `VECTRA_AWS_PRINCIPAL_ARN` | For IAM-role connections | Vectra's AWS principal, shown in the trust policy |
| AWS credential chain (instance/task role, or `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`) | For IAM-role connections | Credentials Vectra uses to call `sts:AssumeRole` |
| `CLOUD_SYNC_MAX_FINDINGS` | No (default 25000) | Maximum findings fetched per sync |

See `backend/.env.example`.

## Roles and permissions

These are enforced on the server in `backend/cloud/access.py`; `frontend/lib/rbac.ts` mirrors them only to decide what the UI shows.

| Permission | Viewer | Editor | Org admin |
|---|:-:|:-:|:-:|
| `VIEW_CLOUD_SECURITY`, `VIEW_CLOUD_FINDINGS` | ✓ | ✓ | ✓ |
| `SYNC_CLOUD_FINDINGS` | | ✓ | ✓ |
| `MANAGE_CLOUD_INTEGRATIONS`, `DELETE_CLOUD_INTEGRATION` | | | ✓ |

- **Disabled organizations:** can still view history, but can't sync or manage integrations.
- **Platform admins:** see integration health across all organizations at `GET /admin/cloud/integrations`. Credentials are never included.
- **Org roles and platform roles are separate:** a platform role grants no access inside an organization's cloud data.

## API

All endpoints need a Firebase ID token. The organization always comes from the token, never from the request.

| Method | Path | Permission |
|---|---|---|
| GET | `/cloud/providers` | view |
| GET | `/cloud/providers/{aws\|gcp}/setup` | manage |
| GET | `/cloud/integrations` | view |
| POST | `/cloud/integrations` | manage (validates live; stores nothing on failure) |
| GET | `/cloud/integrations/{id}` | view |
| PATCH | `/cloud/integrations/{id}` | manage (rename / reconfigure / rotate credentials; re-validates) |
| POST | `/cloud/integrations/{id}/validate` | manage |
| POST | `/cloud/integrations/{id}/sync` | sync (returns `202 {syncId}`; `409` if already running) |
| GET | `/cloud/integrations/{id}/syncs` | view |
| GET | `/cloud/syncs/{syncId}` | view |
| DELETE | `/cloud/integrations/{id}?deleteFindings=` | delete |
| GET | `/cloud/findings` | view (filters, sort, pagination, facets) |
| GET | `/cloud/findings/{fingerprint}` | view |
| GET | `/cloud/assets` | view |
| GET | `/cloud/summary` | view |
| GET | `/cloud/report-data?integrationId=&includeResolved=` | view |

Request bodies reject unknown fields, so extra properties can't be slipped into stored documents (mass assignment). Ids are format-checked, and an id from another organization returns `404`.

## Normalization

**Severity:**

| AWS `Severity.Label` | GCP `severity` | Vectra |
|---|---|---|
| CRITICAL | CRITICAL | critical |
| HIGH | HIGH | high |
| MEDIUM | MEDIUM | medium |
| LOW | LOW | low |
| INFORMATIONAL | SEVERITY_UNSPECIFIED / absent | info |

- **AWS with no Label:** `Severity.Normalized` is mapped using AWS's documented ranges: 0 info, 1–39 low, 40–69 medium, 70–89 high, 90–100 critical.
- **Original value:** always kept in `providerSeverity`, so an unrated finding is shown as unrated rather than given a made-up severity.

**Status:** this is the lifecycle the provider reports. The team's own workflow (assignee, in progress, accepted risk) stays in Vulnerability Management's existing `finding_tracking`.

| Vectra | AWS | GCP |
|---|---|---|
| open | `Workflow.Status` NEW / NOTIFIED | `state` ACTIVE |
| resolved | `Workflow.Status` RESOLVED, or `RecordState` ARCHIVED | `state` INACTIVE |
| suppressed | `Workflow.Status` SUPPRESSED | `mute` MUTED |

**CVE:**
- IDs are taken only from provider vulnerability data and must match `CVE-YYYY-NNNN…`.
- CVSS: AWS takes the highest v3/v4 score first. GCP uses `cvssv3.baseScore`, which comes without a vector string.
- Affected packages and fixed versions are kept.
- Findings without a CVE work normally.

**Links:** only `http(s)` URLs from provider payloads are kept.

## Sync behaviour

1. `POST …/sync` claims the integration in a transaction; only one sync can be queued or running per integration. It then starts a background task.
2. The provider fetches **every page**:
   - **AWS:** `GetFindings` paginator, 100 per page, each configured Region fetched independently, `RecordState=ACTIVE`.
   - **GCP:** `findings.list`, 1000 per page, `state="ACTIVE"`.
3. **Duplicates:** the finding id is the fingerprint `sha256(provider | integration | provider finding id)`. Re-syncs update the existing document instead of creating a new one; duplicates returned by AWS cross-Region aggregation are dropped.
4. **Writes:** batched upserts (400 writes per batch). The first-seen time and status history are preserved.
5. **Resolution:** a stored open finding the provider no longer returns is marked `resolved` ("no longer reported"), but only if its scope synced completely. Nothing is resolved after a partial or truncated sync. Findings are never deleted by a sync.
6. **Results:** counters, `lastSyncStatus` (`completed` / `partial` / `failed`) and statistics are written, plus an audit log entry.

**Retries and timeouts:**
- **AWS:** botocore adaptive retries, 6 attempts, 10 s connect / 30 s read timeouts.
- **GCP:** exponential backoff with jitter on 429/5xx and network errors, at most 5 attempts, honouring `Retry-After` (capped at 30 s), 10 s / 60 s timeouts.
- Neither retries forever.

**Scan quota:** cloud syncs do **not** use the organization scan allowance. The quota covers scanner runs (Web, Network, SAST); a sync imports results the customer's own cloud service already produced.

**Restarts:** running syncs are tracked in the backend process, the same single-instance design as existing scans. A sync interrupted by a restart is marked `failed` (`INTERRUPTED`) the next time its status is read, and can be retried.

## Integrations with other modules

- **Vulnerability Management:** open cloud findings appear with module `CLOUD`, grouped by cloud account or project. Assignment, status, comments and SLA reuse the existing tracking, keyed by fingerprint.
- **Dashboard:** a Cloud Security card shows real open counts by severity, or "No cloud providers connected".
- **Reports:** Reports → Cloud Security, for one integration or all of them.
  - PDF on the shared `ReportDoc` layout: executive summary, provider summary, severity distribution, affected assets, findings, CVEs, detailed findings, remediation, references and timeline.
  - Excel export with the same content.
- **Admin:** Admin → Cloud Security shows integration health across organizations.

## Troubleshooting

| Error code | Meaning / action |
|---|---|
| `NOT_CONFIGURED` | `VECTRA_SECRETS_KEY` missing or invalid, or no Vectra AWS principal for role connections |
| `INVALID_CREDENTIALS` | Key deleted, disabled or wrong; reconnect or rotate credentials |
| `ACCESS_DENIED` | Missing permissions (see above), or AWS trust policy / ExternalId mismatch |
| `SERVICE_NOT_ENABLED` | Security Hub not enabled in that Region / SCC API not enabled or not activated |
| `INVALID_CONFIGURATION` | Wrong Region, role ARN, project/folder/organization id or location |
| `THROTTLED` | Provider rate limit after retries; sync again later |
| `TIMEOUT` | Provider unreachable after retries |
| `PARTIAL_FAILURE` | Some Regions/scopes failed; the others were imported, and no findings were resolved for the failed scopes |
| `TRUNCATED` | More than `CLOUD_SYNC_MAX_FINDINGS`; resolution skipped |
| `INTERRUPTED` | Backend restarted during a sync; retry |

## Adding a provider

1. Subclass `CloudProvider` in `backend/cloud/providers/<name>.py`: declare `auth_methods` and `capabilities`, and implement `parse_config`, `validate_connection`, `fetch_findings` and optionally `setup_info`.
2. Add a normalizer in `backend/cloud/normalizers/<name>.py` that returns `NormalizedFinding` / `NormalizedAsset`, with deterministic fingerprints.
3. Register it in `backend/cloud/registry.py`, removing its entry from `_FUTURE`.
4. Add a connect dialog in `frontend/components/cloud/connect-dialogs.tsx`.
5. Add connector tests that stub the SDK or HTTP boundary, as `backend/tests/test_cloud_connectors.py` does.

Don't register a provider until it returns real data. Only real connectors ship in the registry; test fakes live only under `backend/tests/`.

## Tests

From `backend/`. Run each suite in its own process, because each one points the Firebase client at its own emulator project.

```bash
.venv/bin/python -m unittest tests.test_cloud_connectors -v          # no emulator needed
java -jar ~/.cache/firebase/emulators/cloud-firestore-emulator-*.jar --host 127.0.0.1 --port 8571 &
FIRESTORE_EMULATOR_HOST=127.0.0.1:8571 .venv/bin/python -m unittest tests.test_cloud_api -v
FIRESTORE_EMULATOR_HOST=127.0.0.1:8571 .venv/bin/python -m unittest tests.test_org_quota -v
```

Firestore rules: see `scripts/firestore-rules-test/README.md`.
