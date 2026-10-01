# Running Vectra with Docker

This guide containerizes Vectra as **two images** and runs them together with
Docker Compose. Firebase Authentication and Firestore stay as **external managed
services** — nothing about them is containerized.

```
INTERNET
   │
   ▼
frontend container  ── Next.js (port 3000)
   │  proxies /api/backend/* (server-side) →
   ▼
backend container   ── FastAPI + embedded scan worker + scanners (port 8000)
   │                     nmap · nuclei · wpscan · subfinder · httpx · SAST
   ▼
Firebase Auth + Firestore   (external, managed by Google — NOT in Docker)
```

**Why two containers and not three?** Vectra's scan worker is not a separate
service — it runs as in-process async tasks inside the backend
(`backend/utils/scan_queue.py`) that shell out to the scanner binaries. The API
that queues a scan and the worker that runs it share in-memory state and must be
the same process. Splitting the scanner into its own container would require a
distributed queue (Redis/PubSub) and a worker rewrite. So the scanner tools are
installed **into the backend image** and run as its subprocesses.

---

## First time (step by step)

### 1. Install Docker
Docker Engine plus the **Compose v2 plugin** are required.

- **Kali / Debian / Ubuntu:**
  ```bash
  sudo apt update && sudo apt install -y docker.io docker-compose-v2
  ```
- Let your user run Docker without `sudo` (log out/in afterward):
  ```bash
  sudo usermod -aG docker "$USER"
  ```
  Verify: `docker compose version` should print a version.

> If `docker compose` (with a space) is unavailable but you have the old
> `docker-compose` (with a hyphen), use that spelling instead in every command
> below.

### 2. Configure environment variables
```bash
cp .env.example .env
```
Open `.env` and fill in the values. Minimum to boot and log in:
- the six `NEXT_PUBLIC_FIREBASE_*` values (Firebase Console → Project Settings → Web app),
- `FIREBASE_SERVICE_ACCOUNT_JSON` (backend Admin key — see below),
- `VECTRA_SECRETS_KEY` (generate with the command in the file).

**Firebase Admin key (backend):** download the service-account JSON from
Firebase Console → Project Settings → Service Accounts → *Generate new private
key*. Put it into `.env` as a single line, base64-encoded so it survives the
`.env` format:
```bash
echo "FIREBASE_SERVICE_ACCOUNT_JSON=$(base64 -w0 firebase-service-account.json)" >> .env
```
(The backend accepts raw JSON too, but base64 avoids line-break problems.)

### 3. Build the containers
```bash
docker compose build
```
First build is slow (downloads scanner tools, compiles the wpscan gem). The
`NEXT_PUBLIC_*` values from `.env` are baked into the frontend during this step —
**if you change them later, you must rebuild the frontend.**

### 4. Start everything
```bash
docker compose up -d
```
`-d` runs in the background. Open **http://localhost:3000**.

### 5. View logs
```bash
docker compose logs -f            # all services, follow
docker compose logs -f backend    # just the backend / scanners
```

### 6. Stop
```bash
docker compose down               # stop & remove containers (keeps the data volume)
docker compose down -v            # also delete the backend-data volume
```

### 7. Rebuild after code changes
```bash
docker compose up -d --build      # rebuild changed images and restart
```

---

## Command reference

| Command | What it does |
|---|---|
| `docker compose build` | Build both images from the Dockerfiles. |
| `docker compose up -d` | Start containers in the background. |
| `docker compose up -d --build` | Rebuild then start (use after code changes). |
| `docker compose ps` | Show running containers and health. |
| `docker compose logs -f [svc]` | Stream logs (optionally one service). |
| `docker compose exec backend sh` | Open a shell inside the backend container. |
| `docker compose restart backend` | Restart just the backend. |
| `docker compose down` | Stop and remove containers (data volume kept). |
| `docker compose down -v` | Stop and also delete the `backend-data` volume. |

Check scanner tools inside the backend:
```bash
docker compose exec backend sh -lc 'nmap --version | head -1; nuclei -version; wpscan --version | head -3; subfinder -version; httpx-toolkit -version'
```

---

## Environment variables — summary

| Variable | Where | When | Secret | Notes |
|---|---|---|---|---|
| `NEXT_PUBLIC_FIREBASE_*` (×6) | frontend | build | no | Web SDK config; baked into the browser bundle. |
| `NEXT_PUBLIC_API_URL` | frontend | build | no | Leave empty → same-origin `/api/backend` proxy. |
| `BACKEND_ORIGIN` | frontend | **build** | no | Baked into the rewrite (Next evaluates `rewrites()` at build). Compose sets it to `http://backend:8000`. Changing it requires rebuilding the frontend. |
| `FIREBASE_SERVICE_ACCOUNT_JSON` | backend | run | **YES** | Admin key (raw or base64). Never a `NEXT_PUBLIC_*`. |
| `FIREBASE_CREDENTIALS` | backend | run | path | Alternative: path to a mounted key file. |
| `VECTRA_SECRETS_KEY` | backend | run | **YES** | Required; encrypts stored cloud credentials. |
| `VECTRA_AWS_PRINCIPAL_ARN` | backend | run | no | Optional; enables AWS IAM-role connections. |
| `NVD_API_KEY` | backend | run | **YES** | Optional; raises NVD rate limits. |
| `GITHUB/GITLAB_CLIENT_ID/SECRET` | backend | run | secret=**YES** | SAST repo OAuth. |
| `FRONTEND_URL` / `BACKEND_URL` | backend | run | no | Used to build OAuth redirect URIs. |
| `SMTP_*` | backend | run | pass=**YES** | Team invitation emails. |
| `MAX_*`, `*_TIMEOUT_SECS`, `STALE_SCAN_SECS` | backend | run | no | Scan queue tuning. |

**Never expose backend secrets through `NEXT_PUBLIC_*`** — anything with that
prefix is shipped to the browser.

---

## Ports & networking
- **3000** — frontend, published to the host (the only port users need).
- **8000** — backend, published locally so SAST OAuth callbacks and `/health`
  work. In production the backend can stay private and be reached only through
  the frontend proxy.
- Container-to-container: the frontend reaches the backend at `http://backend:8000`
  (Docker service name), **never `localhost`**. The browser only ever talks to
  the frontend origin; `/api/backend/*` is rewritten server-side to the backend.

---

## Persistent data (containers are disposable)

| Data | Location | Strategy |
|---|---|---|
| Scan schedules | `backend/data/network_schedules.json` | **Persistent** — mounted to the `backend-data` volume. |
| CVE reference data | `backend/data/cves` | Baked into the image (read-only). |
| SAST uploads / clones | `tempfile.mkdtemp()` | **Temporary** — deleted after each scan. |
| Scan results, findings, quotas, org/RBAC | Firestore | External — survives everything. |
| Logs | stdout/stderr | Collected by Docker / Cloud Logging. |

The `backend-data` volume is the only local state that must survive container
recreation. Everything of record lives in Firestore.

---

## Scanner privileges (least privilege)
- The backend runs as a **non-root** user (`appuser`).
- `nmap` is granted **file capabilities** `cap_net_raw,cap_net_admin+eip` in the
  image, so host discovery (`-sn`) and OS detection (`-O`) work without running
  the whole process as root.
- Compose grants the container `NET_RAW` + `NET_ADMIN` (nothing more).
  `NET_RAW` is a Docker default; `NET_ADMIN` is what `-O` additionally needs.
- **No** `privileged: true`, **no** Docker-socket mount, **no** host-filesystem
  mount, **no** host networking.
- **Important:** because the nmap binary carries `cap_net_admin` in its permitted
  set, the container **must** be granted `NET_ADMIN` (and `NET_RAW`) or the kernel
  refuses to exec nmap at all (`Operation not permitted`) — it does not merely
  degrade. Compose grants both, so this only bites if you run the backend image
  with a stripped capability set (e.g. plain `docker run`, or Cloud Run). There,
  network scanning won't work; the rest of the app (web/SAST/cloud) still does.

---

## Google Cloud deployment readiness

| Component | Recommended target | Why |
|---|---|---|
| **frontend** | **Cloud Run** | Stateless HTTP, scales to zero, standalone Next server. |
| **backend + scanner** | **Compute Engine (VM) or GKE** | Needs `NET_RAW`/`NET_ADMIN` for nmap, long-running scans (up to 30 min), and in-memory scan state that must not be split across autoscaled instances. Cloud Run drops raw-socket caps and is request-scoped — a poor fit for the scanner. |

If you must run the backend on Cloud Run, accept that nmap OS detection/ping
sweeps degrade (no raw sockets) and run a **single instance** (`--min-instances=1
--max-instances=1 --no-cpu-throttling`) so the in-memory queue stays coherent.

**Backend on a Compute Engine VM (recommended):**
- Attach a service account with only the roles it needs (Firestore access; plus
  Security Hub / SCC read roles if using Cloud Security). Then you can drop
  `FIREBASE_SERVICE_ACCOUNT_JSON` and rely on Application Default Credentials.
- Store secrets in **Secret Manager**, inject as env vars.
- Persist `backend/data` on the VM disk or a mounted PD.
- Suggested sizing: **2 vCPU / 4 GB RAM** baseline; raise for heavier concurrent
  scans (`MAX_NETWORK_WORKERS`).

**Frontend on Cloud Run:**
- Build with the `NEXT_PUBLIC_*` args, set `BACKEND_ORIGIN` to the backend's
  internal URL, size ~**1 vCPU / 512 MB–1 GB**.

**Google Cloud APIs / services likely needed:** Firestore, Secret Manager,
Artifact Registry (images), Cloud Logging, plus Compute Engine or GKE. Cloud
Security integration additionally uses the AWS/GCP provider APIs you connect.

Do not deploy automatically — build, push to Artifact Registry, then deploy.

---

## Troubleshooting
- **Blank page / `auth/invalid-api-key`** → `NEXT_PUBLIC_FIREBASE_*` were missing
  at build time. Fix `.env` and `docker compose build frontend` again.
- **Backend logs `Firebase Admin is not configured`** → `FIREBASE_SERVICE_ACCOUNT_JSON`
  is empty/invalid, or its `project_id` differs from `NEXT_PUBLIC_FIREBASE_PROJECT_ID`.
- **nmap finds hosts but no OS info** → the `NET_RAW`/`NET_ADMIN` capabilities
  aren't being granted (some hosts/CI strip them).
- **SAST OAuth redirect fails** → `BACKEND_URL` must be a URL the browser can
  reach (e.g. `http://localhost:8000` locally).
