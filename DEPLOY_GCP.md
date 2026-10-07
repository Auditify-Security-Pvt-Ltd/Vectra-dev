# Vectra on Google Cloud

| | |
|---|---|
| Google Cloud project | `vectra-cdb39` (number `318304562218`) |
| Region | `asia-south1` (Mumbai) |
| Frontend | https://vectra-frontend-318304562218.asia-south1.run.app — Cloud Run `vectra-frontend` |
| Backend/API | https://vectra-backend-318304562218.asia-south1.run.app — Cloud Run `vectra-backend` |
| Artifact Registry | `asia-south1-docker.pkg.dev/vectra-cdb39/vectra` (`backend`, `frontend`) |
| Auth + database | Firebase Auth + Firestore in the **separate** Firebase project `vactra` (unchanged) |
| Backend state | Cloud Storage bucket `gs://vectra-cdb39-backend-state` mounted at `/mnt/state` (scan schedules) |
| Custom domain | none |
| Deployment method | local `docker build` → Artifact Registry → `gcloud run deploy` (`scripts/deploy_gcp.sh`) |

## Architecture

```
Browser ──HTTPS──▶ vectra-frontend (Next.js, scale-to-zero, 1 vCPU / 512 MiB)
                      │  /api/backend/*  (server-side rewrite)
                      ▼
                   vectra-backend (FastAPI + scan worker + nmap/nuclei/wpscan/subfinder/httpx)
                      │  1 vCPU / 2 GiB, min=max=1 instance, CPU always allocated
                      ├──▶ Firebase Auth / Firestore (project vactra, via admin SA key)
                      ├──▶ Secret Manager (vectra-* secrets)
                      └──▶ gs://vectra-cdb39-backend-state (schedules)
```

The backend is pinned to **exactly one instance** because the scan queue is
in-process memory; scaling it out would split scan state. CPU is always
allocated so background scans keep running between requests.

### Cloud Run limitation: nmap
Cloud Run cannot grant `NET_RAW`/`NET_ADMIN`. The backend image is built with
`NMAP_SETCAP=false` and runs with `NMAP_UNPRIVILEGED=true`, so nmap uses TCP
connect scans and **skips OS detection (`-O`) and MAC/vendor detection**. Ports,
services and versions still work. Full nmap fidelity needs a VM (see `DOCKER.md`).

## Configuration

Service accounts (least privilege, no Owner/Editor):
- `vectra-backend@vectra-cdb39.iam.gserviceaccount.com` — `secretmanager.secretAccessor`
  (IAM condition: only secrets named `vectra-*`), `storage.objectUser` on the state bucket.
- `vectra-frontend@vectra-cdb39.iam.gserviceaccount.com` — no roles.

Secrets (Secret Manager → backend env):

| Env var | Secret |
|---|---|
| `FIREBASE_SERVICE_ACCOUNT_JSON` | `vectra-firebase-service-account-json` |
| `VECTRA_SECRETS_KEY` | `vectra-vectra-secrets-key` |
| `NVD_API_KEY` | `vectra-nvd-api-key` |
| `GITHUB_CLIENT_SECRET` | `vectra-github-client-secret` |

Plain backend env vars: `FIREBASE_PROJECT_ID`, `FRONTEND_URL`, `BACKEND_URL`,
`CORS_ORIGINS` (frontend origin only), `NMAP_UNPRIVILEGED`, `SCHEDULES_DIR`,
`CVE_MODE`, `GITHUB_CLIENT_ID`, `SMTP_PORT`, `SMTP_FROM`, scan tuning
(`MAX_*`, `*_TIMEOUT_SECS`, `STALE_SCAN_SECS`), `CLOUD_SYNC_MAX_FINDINGS`.

Frontend build args (public, baked into the bundle): `NEXT_PUBLIC_FIREBASE_*`,
`NEXT_PUBLIC_API_URL=` (empty → same-origin proxy), `BACKEND_ORIGIN` (backend URL).

Not configured (empty in `.env`): GitLab OAuth, SMTP host/user/pass (team
invitation emails will not send until added).

### Adding / rotating a secret
```bash
printf '%s' "$VALUE" | gcloud secrets versions add vectra-<name> --data-file=- --project vectra-cdb39
gcloud run services update vectra-backend --region asia-south1 --project vectra-cdb39 \
  --update-secrets ENV_NAME=vectra-<name>:latest
```
New secrets must be named `vectra-*` for the backend to be able to read them.

## Useful commands
```bash
scripts/deploy_gcp.sh                         # rebuild + deploy both
scripts/deploy_gcp.sh backend                 # one service
gcloud run services logs read vectra-backend --region asia-south1 --project vectra-cdb39 --limit 100
gcloud run services describe vectra-backend --region asia-south1 --project vectra-cdb39
curl https://vectra-backend-318304562218.asia-south1.run.app/health
```

## Rollback
```bash
gcloud run revisions list --service vectra-backend --region asia-south1 --project vectra-cdb39
gcloud run services update-traffic vectra-backend --region asia-south1 --project vectra-cdb39 \
  --to-revisions <REVISION>=100
```
Same for `vectra-frontend`. Images are kept per tag (`<git-sha>-<timestamp>`) in
Artifact Registry, so any previous image can also be redeployed with `--image`.

Initial revisions: `vectra-backend-00001-xw4`, `vectra-backend-00002-px2` (current),
`vectra-frontend-00001-nwh` (current).

## Outstanding items
- Add `vectra-frontend-318304562218.asia-south1.run.app` to Firebase Auth →
  Authorized domains in project `vactra` (needed for any popup/redirect sign-in or
  email action links; email/password login already works).
- GitHub OAuth app callback URL must be updated to the backend URL above for SAST
  repo connection to work in production.
- `AUTH_STRICT` is off: several frontend calls (`lib/api*.ts`) are still sent
  without a Firebase ID token, so turning it on would break them. Org-data and
  admin endpoints already require a verified token.
- `/docs` (Swagger) and `/debug/*` are publicly reachable on the backend.
