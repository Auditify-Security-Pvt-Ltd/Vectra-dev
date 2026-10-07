# syntax=docker/dockerfile:1

# ─────────────────────────────────────────────────────────────────────────────
# Vectra backend + embedded scan worker.
#
# The scan worker is NOT a separate service: utils/scan_queue.py runs scans as
# in-process asyncio tasks that shell out to the scanner binaries. So the scanner
# toolchain (nmap, nuclei, wpscan, subfinder, httpx) is installed INTO this image
# and runs as subprocesses of the FastAPI process.
#
# Runs as a non-root user. nmap is given file capabilities (cap_net_raw +
# cap_net_admin) so host discovery (-sn) and OS detection (-O) work without root;
# the container must be granted NET_RAW + NET_ADMIN (see docker-compose.yml).
# ─────────────────────────────────────────────────────────────────────────────
FROM python:3.13-slim-bookworm

# Pinned scanner versions (verified release assets).
ARG NUCLEI_VERSION=3.8.0
ARG SUBFINDER_VERSION=2.16.0
ARG HTTPX_VERSION=1.6.10
# Set to false for hosts that cannot grant NET_RAW/NET_ADMIN (e.g. Cloud Run):
# a capability-tagged nmap binary refuses to exec there. Pair with
# NMAP_UNPRIVILEGED=true at runtime.
ARG NMAP_SETCAP=true

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    HOME=/home/appuser

# ── System packages + scanner toolchain ─────────────────────────────────────
# nmap        — network host discovery / port / service / OS scanning
# ruby + gem  — runtime for wpscan (a Ruby gem)
# tini        — PID 1 init: forwards SIGTERM and reaps orphaned scanner processes
# libcap2-bin — provides setcap for granting nmap raw-socket capabilities
# build-essential/ruby-dev/libcurl — only needed to build the wpscan gem; purged after
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        ca-certificates curl unzip nmap tini \
        ruby ruby-dev \
        libcap2-bin; \
    # --- wpscan (build deps installed, then purged in the same layer) ---
    apt-get install -y --no-install-recommends build-essential libcurl4-openssl-dev zlib1g-dev; \
    gem install --no-document wpscan; \
    apt-get purge -y --auto-remove build-essential ruby-dev libcurl4-openssl-dev zlib1g-dev; \
    # --- ProjectDiscovery binaries (nuclei / subfinder / httpx-toolkit) ---
    cd /tmp; \
    curl -fsSL -o nuclei.zip    "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip"; \
    curl -fsSL -o subfinder.zip "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_linux_amd64.zip"; \
    curl -fsSL -o httpx.zip     "https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VERSION}/httpx_${HTTPX_VERSION}_linux_amd64.zip"; \
    unzip -o nuclei.zip    nuclei    -d /usr/local/bin; \
    unzip -o subfinder.zip subfinder -d /usr/local/bin; \
    unzip -o httpx.zip     httpx     -d /usr/local/bin; \
    # scanners/httpx_scanner.py prefers the name "httpx-toolkit"
    mv /usr/local/bin/httpx /usr/local/bin/httpx-toolkit; \
    chmod +x /usr/local/bin/nuclei /usr/local/bin/subfinder /usr/local/bin/httpx-toolkit; \
    rm -f /tmp/*.zip; \
    # --- least-privilege nmap: raw-socket caps on the binary, not the process ---
    if [ "$NMAP_SETCAP" = "true" ]; then setcap cap_net_raw,cap_net_admin+eip "$(command -v nmap)"; fi; \
    rm -rf /var/lib/apt/lists/*

# ── Non-root application user ────────────────────────────────────────────────
RUN useradd --create-home --home-dir /home/appuser --shell /usr/sbin/nologin appuser

WORKDIR /app

# ── Python dependencies (layer cached until requirements.txt changes) ────────
COPY requirements.txt ./
RUN pip install --upgrade pip && pip install -r requirements.txt

# ── Application code ─────────────────────────────────────────────────────────
COPY . .

# backend/data holds locally-persisted scheduler state (network_schedules.json).
# Make it writable by the app user; mount a volume here to survive restarts.
RUN mkdir -p /app/data && chown -R appuser:appuser /app/data /home/appuser

USER appuser
EXPOSE 8000

# Readiness = FastAPI answering /health (mounted at root by api/scans.py).
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health',timeout=4).status==200 else 1)"

# tini as PID 1 → clean SIGTERM propagation + zombie reaping for scanner children.
# uvicorn's graceful-shutdown window lets in-flight requests finish; the async
# scan tasks are cancelled on loop shutdown, which kills their child processes.
ENTRYPOINT ["tini", "--"]
# PORT is injected by Cloud Run; defaults to 8000 elsewhere.
CMD ["sh", "-c", "exec uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000} --timeout-graceful-shutdown 30"]
