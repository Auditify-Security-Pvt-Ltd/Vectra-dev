# syntax=docker/dockerfile:1

# ─────────────────────────────────────────────────────────────────────────────
# Vectra frontend — Next.js 16 (App Router), pnpm, standalone output.
#
# NEXT_PUBLIC_* values are BAKED INTO THE CLIENT BUNDLE at `next build` time, so
# they MUST be provided as build args (not just runtime env). Firebase init is
# eager on the client; without these the app fails to render (auth/invalid-api-key).
# ─────────────────────────────────────────────────────────────────────────────

# ---- Stage 1: dependencies -------------------------------------------------
FROM node:22-bookworm-slim AS deps
WORKDIR /app
# Enable the pinned pnpm from package manager metadata (repo uses pnpm).
RUN corepack enable && corepack prepare pnpm@10 --activate
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN --mount=type=cache,target=/root/.local/share/pnpm/store \
    pnpm install --frozen-lockfile

# ---- Stage 2: build --------------------------------------------------------
FROM node:22-bookworm-slim AS builder
WORKDIR /app
RUN corepack enable && corepack prepare pnpm@10 --activate

# Public (browser-visible) build-time config. Safe to embed — these are NOT
# secrets; Firebase Web config is designed to be shipped to the browser.
ARG NEXT_PUBLIC_FIREBASE_API_KEY
ARG NEXT_PUBLIC_FIREBASE_AUTH_DOMAIN
ARG NEXT_PUBLIC_FIREBASE_PROJECT_ID
ARG NEXT_PUBLIC_FIREBASE_STORAGE_BUCKET
ARG NEXT_PUBLIC_FIREBASE_MESSAGING_SENDER_ID
ARG NEXT_PUBLIC_FIREBASE_APP_ID
# Optional: leave UNSET to use the same-origin /api/backend proxy (recommended).
ARG NEXT_PUBLIC_API_URL
# Next.js evaluates rewrites() at BUILD time, so the proxy destination is baked
# into routes-manifest.json here — it must be a build arg, not just runtime env.
ARG BACKEND_ORIGIN=http://backend:8000
ENV BACKEND_ORIGIN=$BACKEND_ORIGIN
ENV NEXT_PUBLIC_FIREBASE_API_KEY=$NEXT_PUBLIC_FIREBASE_API_KEY \
    NEXT_PUBLIC_FIREBASE_AUTH_DOMAIN=$NEXT_PUBLIC_FIREBASE_AUTH_DOMAIN \
    NEXT_PUBLIC_FIREBASE_PROJECT_ID=$NEXT_PUBLIC_FIREBASE_PROJECT_ID \
    NEXT_PUBLIC_FIREBASE_STORAGE_BUCKET=$NEXT_PUBLIC_FIREBASE_STORAGE_BUCKET \
    NEXT_PUBLIC_FIREBASE_MESSAGING_SENDER_ID=$NEXT_PUBLIC_FIREBASE_MESSAGING_SENDER_ID \
    NEXT_PUBLIC_FIREBASE_APP_ID=$NEXT_PUBLIC_FIREBASE_APP_ID \
    NEXT_PUBLIC_API_URL=$NEXT_PUBLIC_API_URL \
    NEXT_TELEMETRY_DISABLED=1

COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN pnpm build

# ---- Stage 3: runtime ------------------------------------------------------
FROM node:22-bookworm-slim AS runner
WORKDIR /app
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=3000 \
    HOSTNAME=0.0.0.0

# Run as the unprivileged 'node' user shipped in the base image.
# Standalone output: server.js + minimal node_modules, plus static + public assets.
COPY --from=builder --chown=node:node /app/.next/standalone ./
COPY --from=builder --chown=node:node /app/.next/static ./.next/static
COPY --from=builder --chown=node:node /app/public ./public

USER node
EXPOSE 3000

# Container-level healthcheck: the app is ready when the HTTP server answers.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:3000/').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

# BACKEND_ORIGIN (server-side only) is read by next.config.mjs rewrites at runtime.
CMD ["node", "server.js"]
