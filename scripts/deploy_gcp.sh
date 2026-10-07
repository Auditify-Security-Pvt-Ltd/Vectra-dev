#!/usr/bin/env bash
# Build, push and deploy Vectra to Cloud Run. See DEPLOY_GCP.md.
#
#   scripts/deploy_gcp.sh            # backend + frontend
#   scripts/deploy_gcp.sh backend    # one service only
#   scripts/deploy_gcp.sh frontend
#
# Reads NEXT_PUBLIC_FIREBASE_* from ./.env (public, browser-visible values).
# Server-side secrets live in Secret Manager and are NOT read here; env vars and
# secret bindings already set on the services are preserved by `gcloud run deploy`.
set -euo pipefail
cd "$(dirname "$0")/.."

PROJECT=vectra-cdb39
REGION=asia-south1
REGISTRY="$REGION-docker.pkg.dev/$PROJECT/vectra"
BACKEND_URL="https://vectra-backend-318304562218.$REGION.run.app"
TAG="$(git rev-parse --short HEAD)-$(date +%Y%m%d%H%M)"
TARGET="${1:-all}"

gcloud auth configure-docker "$REGION-docker.pkg.dev" --quiet >/dev/null

if [[ "$TARGET" == all || "$TARGET" == backend ]]; then
  # Cloud Run cannot grant NET_RAW/NET_ADMIN, so nmap runs without file caps.
  docker build --build-arg NMAP_SETCAP=false -t "$REGISTRY/backend:$TAG" -t "$REGISTRY/backend:latest" backend
  docker push -q "$REGISTRY/backend:$TAG"; docker push -q "$REGISTRY/backend:latest"
  gcloud run deploy vectra-backend --project "$PROJECT" --region "$REGION" \
    --image "$REGISTRY/backend:$TAG"
fi

if [[ "$TARGET" == all || "$TARGET" == frontend ]]; then
  set -a; . ./.env; set +a
  docker build -t "$REGISTRY/frontend:$TAG" -t "$REGISTRY/frontend:latest" \
    --build-arg NEXT_PUBLIC_FIREBASE_API_KEY \
    --build-arg NEXT_PUBLIC_FIREBASE_AUTH_DOMAIN \
    --build-arg NEXT_PUBLIC_FIREBASE_PROJECT_ID \
    --build-arg NEXT_PUBLIC_FIREBASE_STORAGE_BUCKET \
    --build-arg NEXT_PUBLIC_FIREBASE_MESSAGING_SENDER_ID \
    --build-arg NEXT_PUBLIC_FIREBASE_APP_ID \
    --build-arg NEXT_PUBLIC_API_URL= \
    --build-arg BACKEND_ORIGIN="$BACKEND_URL" \
    frontend
  docker push -q "$REGISTRY/frontend:$TAG"; docker push -q "$REGISTRY/frontend:latest"
  gcloud run deploy vectra-frontend --project "$PROJECT" --region "$REGION" \
    --image "$REGISTRY/frontend:$TAG"
fi

echo "Deployed tag $TAG"
