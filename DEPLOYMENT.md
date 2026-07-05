# SecureShare — Deployment Guide

This guide covers running SecureShare locally for development, and deploying it to production (Vercel for frontend + backend, MongoDB Atlas, Cloudinary, and a ClamAV container on Render). See [ENVIRONMENT_VARIABLES.md](ENVIRONMENT_VARIABLES.md) for a full reference of every variable mentioned below, and [SECURITY_TESTING.md](SECURITY_TESTING.md) for post-deploy verification steps.

---

## 1. Local Development

### Prerequisites
- Node.js 18+ and npm
- A MongoDB instance (local `mongod`, Docker, or a free [MongoDB Atlas](https://www.mongodb.com/atlas) cluster)
- A [Cloudinary](https://cloudinary.com) account (free tier is sufficient)
- Docker (optional, for MongoDB/ClamAV containers)
- ClamAV (optional — the app degrades gracefully without it, see [§3](#3-clamav-docker))

### Frontend

```bash
cd frontend
npm install
cp .env.example .env.local   # then edit NEXT_PUBLIC_API if needed
npm run dev
# → http://localhost:3000
```

### Backend

```bash
cd backend
npm install
cp .env.example .env         # fill in MONGO_URI, JWT_SECRET, Cloudinary creds, etc.
node generateKeys.js         # generates backend/{public,private}.pem (legacy v1 RSA keypair)
npm run dev
# → http://localhost:5000 (nodemon, auto-restarts on .js changes)
```

> **Note**: nodemon's default watched extensions are `js,mjs,cjs,json` — it does **not** restart on `.env` changes. If you edit `.env` while the dev server is running, restart it manually, or add an `nodemonConfig` block to `backend/package.json` with `"ext": "js,json,env"`.

### MongoDB

**Option A — MongoDB Atlas (recommended, matches production)**
1. Create a free cluster at [mongodb.com/atlas](https://www.mongodb.com/atlas).
2. Under **Network Access**, add your current IP (or `0.0.0.0/0` for unrestricted local dev only — never in production).
3. Under **Database Access**, create a user with read/write access.
4. Copy the connection string into `MONGO_URI` in `backend/.env`.

**Option B — Local via Docker**
```bash
docker run -d --name secureshare-mongo -p 27017:27017 mongo:7
```
Then set `MONGO_URI=mongodb://localhost:27017/secureshare`.

### Cloudinary

1. Sign up at [cloudinary.com](https://cloudinary.com) (free tier).
2. From the dashboard, copy **Cloud Name**, **API Key**, and **API Secret** into `backend/.env`.

### Docker (full local stack, backend + MongoDB)

```bash
cd SecureShare
docker compose up --build
```

This starts the backend (`http://localhost:5000`) and MongoDB (`localhost:27017`) using `docker-compose.yml`. The frontend isn't included in this compose file — run it separately with `npm run dev` in `frontend/`, pointed at `NEXT_PUBLIC_API=http://localhost:5000/api`.

```bash
docker compose down          # stop
docker compose down -v       # stop and wipe the mongo_data volume
```

This project deploys to managed cloud services only (Vercel/Render/MongoDB Atlas/Redis Cloud/Cloudinary/ClamAV-on-Render) — see [§2](#2-production-deployment) below. There is no production Docker Compose/Nginx stack; `docker-compose.yml` above is a local-dev convenience only. Redis is optional even locally — the backend runs fine without `REDIS_URL` set, falling back to in-memory rate limiting and in-process background jobs (see [README.md's Phase 13 section](README.md#%EF%B8%8F-phase-13-production-hardening--cloud-platform-operations)).

### ClamAV (local)

See [§3 — ClamAV Docker](#3-clamav-docker) below; the same container setup works identically for local development — just point `CLAMAV_HOST=127.0.0.1` and `CLAMAV_PORT=3310` at it. Without it running, malware scanning still functions (magic bytes, hashing, VirusTotal, risk classification all work), just with `clamav.status: "unavailable"` on every scan.

---

## 2. Production Deployment

### Frontend — Vercel

1. Push the repository to GitHub.
2. In the [Vercel dashboard](https://vercel.com), **Add New → Project → Import** your repo.
3. Set the project's **Root Directory** to `frontend`.
4. Under **Settings → Environment Variables**, add:
   - `NEXT_PUBLIC_API` = your deployed backend URL + `/api` (e.g. `https://secureshare-backend.vercel.app/api`)
5. Deploy. Every push to the connected branch triggers a redeploy.

> Changing `NEXT_PUBLIC_API` after the first deploy requires a **new deployment** (redeploy or push a commit) — Next.js inlines `NEXT_PUBLIC_*` vars at build time, so the running app won't pick up an env var change without a rebuild.

### Backend — Vercel

The repo includes `backend/api/index.js`, a Vercel serverless entrypoint wrapping the Express app.

1. In Vercel, **Add New → Project → Import** the same repo again, with **Root Directory** set to `backend`.
2. Under **Settings → Environment Variables**, add every required variable from [ENVIRONMENT_VARIABLES.md](ENVIRONMENT_VARIABLES.md) (`MONGO_URI`, `JWT_SECRET`, Cloudinary credentials, RSA keypair, and optionally `CLAMAV_HOST`/`PORT`/`VIRUSTOTAL_API_KEY`).
3. Deploy, then note the resulting URL — this is what the frontend's `NEXT_PUBLIC_API` should point to.

**Alternative**: any Node host that can run `npm start` (Render, Railway, Fly.io, a VPS) works equally well for the backend — Vercel's serverless model is convenient but not required. A long-running host is actually a better fit for the ClamAV TCP connection used by Phase 4 scanning, since serverless cold-starts add latency to every scan's `clamd` handshake.

### Database — MongoDB Atlas

Use the same Atlas cluster described in [§1](#mongodb). For production:
- Restrict **Network Access** to your backend host's actual egress IP(s) rather than `0.0.0.0/0`.
- Use a dedicated database user (not the Atlas account owner) scoped to just the `secureshare` database.
- Enable Atlas's built-in backup if you're on a tier that supports it.

### Storage — Cloudinary

No additional production configuration beyond the credentials already in `backend/.env` — Cloudinary's free/paid tiers work identically from the app's perspective. For higher volume, consider enabling Cloudinary's automatic stale-asset cleanup and monitoring your plan's storage/bandwidth quota, since every uploaded file (as ciphertext) counts against it.

### Threat Scanner — Render (Docker)

ClamAV (`clamd`) is a long-running daemon, not a fit for serverless — deploy it as a small persistent Docker service on [Render](https://render.com) (or any host that runs arbitrary Docker containers: Fly.io, Railway, a VPS, etc.).

1. In Render, **New → Web Service** (or **Private Service**, if you don't need a public URL — `clamd` should generally *not* be publicly reachable).
2. Choose **Deploy an existing image from a registry**, and use `clamav/clamav:stable` (the official ClamAV image) — or point Render at a Dockerfile if you want to pin a specific version.
3. Expose port `3310` (clamd's default).
4. Once deployed, set the backend's `CLAMAV_HOST`/`CLAMAV_PORT` environment variables (on Vercel or wherever the backend runs) to this service's internal address and port.

See [§3](#3-clamav-docker) below for the exact Docker commands, and [§4](#4-render-deployment) for Render-specific configuration details.

---

## 3. ClamAV Docker

SecureShare's backend talks to ClamAV over `clamd`'s `INSTREAM` TCP protocol (`backend/services/clamavScanner.js`) — no ClamAV client library is bundled in the app; any reachable `clamd` works.

### Pull the image

```bash
docker pull clamav/clamav:stable
```

### Run the container

```bash
docker run -d \
  --name secureshare-clamav \
  -p 3310:3310 \
  clamav/clamav:stable
```

The official image downloads virus definitions (`freshclam`) on first start, which can take a few minutes — `clamd` isn't ready to accept connections until that completes.

### Check logs (wait for "clamd started" / definitions loaded)

```bash
docker logs -f secureshare-clamav
```

Look for a line indicating `clamd` is listening on port 3310 and that the virus database loaded successfully before pointing the backend at it.

### Confirm it's running

```bash
docker ps --filter name=secureshare-clamav
```

### Point the backend at it

```env
CLAMAV_HOST=127.0.0.1   # or the container's hostname/IP if not on the same host
CLAMAV_PORT=3310
```

Restart the backend after setting these. If `clamd` is unreachable for any reason, scans don't fail — `clamav.status` reports `"unavailable"` and the rest of the Phase 4 pipeline (magic bytes, hashing, VirusTotal, risk classification) continues normally. See [SECURITY_TESTING.md §4.3](SECURITY_TESTING.md#43-clamav-clean-file) to verify it's genuinely connected (not silently degrading).

### Docker Compose (optional, local dev)

To run ClamAV alongside the existing `docker-compose.yml` stack, add:

```yaml
  clamav:
    image: clamav/clamav:stable
    ports:
      - "3310:3310"
```

under `services:`, then set `CLAMAV_HOST=clamav` (the Compose service name) in `backend/.env` when running the backend inside the same Compose network — or `CLAMAV_HOST=127.0.0.1` if the backend runs on the host directly against the mapped port.

---

## 4. Render Deployment

Render-specific notes for the ClamAV container from §3:

### Deploy the Docker container
- **New → Private Service** (recommended — `clamd` has no auth of its own, so it shouldn't be exposed to the public internet; a Private Service is only reachable from other services in the same Render project).
- Image: `clamav/clamav:stable`.
- Set the service's internal port to `3310`.

### Set environment variables
`clamav/clamav`'s default image needs no additional environment variables to run with its default configuration. If you customize `clamd.conf` (e.g. to tune `StreamMaxLength` for larger files), mount it via a Render disk or bake a custom image.

### Health checks
Render's health check for a TCP-only service like `clamd` should be a simple TCP port check on `3310` rather than an HTTP path (clamd doesn't speak HTTP). Configure this under the service's **Health & Alerts** settings.

### Networking
Render Private Services are reachable from other services in the same project via their internal hostname (e.g. `secureshare-clamav.internal` or similar, shown in the Render dashboard once created) — use that as `CLAMAV_HOST` in the backend's environment variables, with `CLAMAV_PORT=3310`. If the backend is deployed elsewhere (e.g. Vercel, outside Render's private network), you'll need a **Public** Render service instead, with network-level access restrictions (Render's IP allowlisting or a firewall) since `clamd` itself has no authentication.

---

## 5. VirusTotal

VirusTotal integration (`backend/services/virusTotalLookup.js`) is entirely optional — a second opinion alongside ClamAV, looked up by file hash rather than uploading the file itself.

### How to obtain an API key

1. Create a free account at [virustotal.com/gui/join-us](https://www.virustotal.com/gui/join-us).
2. Go to your profile → **API Key**.
3. Copy the key shown there (VT API v3).

The free tier has request-rate limits (as of writing, roughly 4 requests/minute, 500/day) — sufficient for moderate upload volume, but consider a paid tier for high-traffic deployments.

### How to configure

Set in `backend/.env` (or your hosting provider's environment variable settings):

```env
VIRUSTOTAL_API_KEY=your_key_here
```

No other configuration is needed — restart the backend and new uploads will automatically be checked.

### How graceful fallback works

If `VIRUSTOTAL_API_KEY` is unset, `lookupHashOnVirusTotal()` returns immediately with `{ status: "skipped" }` — no network call is made, no error is raised, and the rest of the scan pipeline (magic bytes, hashing, ClamAV, risk classification) proceeds unaffected. If the key *is* set but the API call fails (network error, rate limit, unexpected response), the lookup returns `{ status: "error" }` rather than throwing — a transient VirusTotal outage never blocks an upload or crashes the scan endpoint. See [SECURITY_TESTING.md §4.7](SECURITY_TESTING.md#47-virustotal-lookup) to verify this behavior.

---

## 6. Cloud Security Posture Management (Phase 11)

CSPM/ASM scanning runs automatically (a daily `node-cron` job at 04:00, plus a one-off scan ~10s after every server startup) — no configuration is required to get baseline coverage of SecureShare's own deployment.

### Optional configuration

Set in `backend/.env` if you want certificate monitoring against your real production domain(s):

```env
# Base URL the attack-surface scanner self-probes - defaults to http://localhost:${PORT}
APP_BASE_URL=https://your-backend-domain.example.com

# Comma-separated HTTPS domains to monitor for certificate expiry/weak TLS, beyond WEBAUTHN_ORIGIN
CLOUD_MONITORED_DOMAINS=your-frontend-domain.example.com,your-backend-domain.example.com
```

### Triggering a scan from your deploy pipeline

There is no reliable way for a long-running Node process to detect "a deploy just happened" to itself, so config-change/deployment triggers (PART 10 of the Phase 11 spec) are satisfied via the manual scan endpoint instead of inferred automatically:

```bash
curl -X POST https://your-backend-domain.example.com/api/cloud/scan \
  -H "Authorization: Bearer <admin_jwt>"
```

Call this as the last step of your CI/CD pipeline (after the new instance is serving traffic) to pick up any configuration changes immediately rather than waiting for the next daily scan.

---

## 7. DevSecOps / Software Supply Chain Security (Phase 12)

Repository, dependency, secret, SAST, container, and IaC scanning run automatically (a daily `node-cron` job at 05:00, plus a one-off scan ~15s after every server startup) - no configuration is required to get baseline coverage of this repository's own supply-chain posture.

### Optional configuration

Set in `backend/.env` only if you want live GitHub Actions pipeline status (otherwise the scanner correctly reports "no CI/CD configuration detected" if `.github/workflows` doesn't exist, or "detected but status unknown" if it does):

```env
# A GitHub personal access token with `actions:read` scope on the target repo.
GITHUB_TOKEN=

# owner/repo, e.g. Shanidhya01/SecureShare
GITHUB_REPO=
```

### Triggering a scan manually

```bash
curl -X POST https://your-backend-domain.example.com/api/devsecops/scan \
  -H "Authorization: Bearer <admin_jwt>"
```

Like the Cloud Security scan, there is no reliable way for this process to detect "a deploy just happened" to itself - call this endpoint as a step in your CI/CD pipeline (or rely on the daily scheduled scan) rather than expecting automatic detection.

### Notes on scan scope

- The dependency scanner's "outdated version" check makes a live call to `registry.npmjs.org` per dependency - this can be slow on a large `node_modules` tree. Pass `?live=false` to `POST /api/devsecops/scan` (or rely on the startup scan, which always skips it) to scan offline only.
- The secret/SAST scanners never read `.env`/`.env.production` - only tracked source/config files. Real secrets are never persisted, even in masked form.
- Container/IaC scanning is static analysis of `Dockerfile`/`docker-compose.yml` only - no image is built, pulled, or run.

---

## 8. Redis Cloud (Phase 13 — background jobs, caching, rate limiting)

Redis is entirely optional — the backend runs normally without it, falling back to in-memory rate limiting and in-process job execution (see [README.md's Phase 13 section](README.md#%EF%B8%8F-phase-13-production-hardening--cloud-platform-operations)) — but [Redis Cloud](https://redis.io/cloud/) is the recommended managed Redis for this deployment target (Vercel + Render have no persistent local disk/process to run Redis on themselves).

1. Create a free/paid database at [Redis Cloud](https://redis.io/cloud/).
2. Copy the connection string (including credentials) into `REDIS_URL` in the Render backend service's environment variables — format: `redis://default:<password>@<host>:<port>`.
3. Redeploy the backend. `GET /api/platform/health` (admin JWT required) should show the `redis` component as `UP`.

If `REDIS_URL` is unset or the connection fails at any point, the backend logs it and falls back to in-memory rate limiting and in-process job execution — no redeploy is required to recover once Redis becomes reachable again (the shared client auto-reconnects).

## 9. Platform Operations, Monitoring & Scaling (Phase 13)

This deployment target has no VPS/host to run Nginx or Docker Compose orchestration on — Vercel and Render each handle their own reverse proxying, TLS termination, and process supervision. Phase 13's Platform Operations layer (`/api/platform/*`, `/platform` dashboard) monitors the managed dependencies instead of local host resources.

### Required environment variables (backend, on Render)
See [ENVIRONMENT_VARIABLES.md](ENVIRONMENT_VARIABLES.md) for the full list. Phase 13 additions:
- `REDIS_URL` (optional) — Redis Cloud connection string, see [§8](#8-redis-cloud-phase-13--background-jobs-caching-rate-limiting).
- `FRONTEND_URL` (optional but recommended) — the deployed Vercel URL (e.g. `https://secureshare.vercel.app`), used by the health engine's "Frontend API" check. Falls back to `WEBAUTHN_ORIGIN` if unset.
- `LOG_LEVEL` (optional) — winston log verbosity (`error`/`warn`/`info`/`debug`), defaults to `info`.

### Health check endpoints
- `GET /api/health` — unauthenticated, minimal liveness probe (`{status: "ok"}`) — point Render's own health check at this.
- `GET /api/platform/health` (admin JWT) — full Cloud Health Engine breakdown: MongoDB Atlas, Redis Cloud, Cloudinary, ClamAV, background queue, backend API, frontend API, and scheduler status, each `Healthy`/`Warning`/`Critical`, plus a weighted overall score.
- `GET /api/platform/dashboard` (admin JWT) — health + metrics + alerts + queue + recent jobs in one call, backing the `/platform` page.

### Monitoring
- `GET /api/platform/metrics` and `/metrics/history` — API latency/error-rate, upload/download timing, per-scan-type duration (threat/malware/DLP/compliance/SOAR/cloud/DevSecOps/report generation), authentication success/failure rate, and background queue length.
- `GET /api/platform/alerts` — currently active alerts (MongoDB/Redis/Cloudinary/ClamAV offline, queue failure, high error rate, slow API, background job failure, health score drop).
- Structured JSON logs (winston, `backend/utils/logger.js`) are written to stdout — visible directly in Render's log viewer, or pipe them into any external log aggregator; every line carries `requestId`/`correlationId` for tracing a single request end-to-end.
- See [MONITORING.md](MONITORING.md) for the full monitoring reference.

### Scaling recommendations
- **Backend (Render)**: stateless aside from its MongoDB Atlas/Redis Cloud/Cloudinary connections — safe to scale horizontally via Render's autoscaling or multiple instances behind Render's own load balancer, as long as every instance shares the same `MONGO_URI`/`REDIS_URL`/Cloudinary credentials. The in-process job-queue fallback only makes sense for a single instance — run with Redis configured (BullMQ) once you scale beyond one backend instance, so scheduled/background jobs aren't duplicated per instance.
- **Frontend (Vercel)**: scales automatically — no action needed.
- **MongoDB Atlas**: upgrade the cluster tier (or enable auto-scaling storage) as data volume grows; see [§1](#mongodb) for Network Access hardening.
- **Redis Cloud**: upgrade plan tier if `queue_failure`/`redis_offline` alerts fire under load; monitor Redis Cloud's own dashboard for memory/eviction pressure.
- **ClamAV (Render)**: a single instance is normally sufficient (it's stateless per-scan) — if scan volume grows, run a second Render service and round-robin `CLAMAV_HOST` at the application layer, or front it with Render's internal load balancing if available on your plan.

### Troubleshooting
- **`GET /api/platform/health` shows `redis: DOWN`**: check `REDIS_URL` in Render's environment variables and Redis Cloud's own dashboard for outages; the app continues to function without it (see [§8](#8-redis-cloud-phase-13--background-jobs-caching-rate-limiting)).
- **`clamav: DOWN`**: verify the ClamAV Render service is running and `CLAMAV_HOST`/`CLAMAV_PORT` point at its correct internal address (see [§4](#4-render-deployment)); the official image can take several minutes to become ready after a cold start while `freshclam` downloads virus definitions.
- **`frontend_api: UNKNOWN`**: set `FRONTEND_URL` in the backend's Render environment variables to the deployed Vercel URL.
- **`mongodb: DOWN`**: check MongoDB Atlas Network Access allows Render's egress IPs (or is set to allow all, for simplicity) and that `MONGO_URI` is current.

---

## Post-Deployment Checklist

- [ ] Frontend loads and `NEXT_PUBLIC_API` correctly points at the deployed backend
- [ ] Register + login works end-to-end (confirms `MONGO_URI`/`JWT_SECRET` are correct)
- [ ] Upload + download round-trips correctly (confirms Cloudinary credentials)
- [ ] `GET /api/health` returns `{ status: "ok" }`
- [ ] `clamav.status` is `"clean"` (not `"unavailable"`) on a test upload, if ClamAV was deployed
- [ ] `GET /api/cloud/dashboard` (with an admin JWT) returns a populated overall score after the startup scan runs
- [ ] `virusTotal.status` is not `"error"` on a test upload, if a VirusTotal key was configured
- [ ] `GET /api/devsecops/dashboard` (with an admin JWT) returns a populated overall score after the startup scan runs
- [ ] MongoDB Atlas Network Access is restricted to known IPs (not left at `0.0.0.0/0`) for production
- [ ] `JWT_SECRET` and the RSA keypair are unique to this deployment, not copied from a dev `.env`
- [ ] `GET /api/platform/dashboard` (with an admin JWT) returns a populated health score and no unresolved `DOWN` components
- [ ] If Redis is configured, `GET /api/platform/health` shows the `redis` component as `UP` (not `DOWN` or stuck on fallback)
- [ ] A manual backup (`POST /api/platform/backup` with `{"type":"full"}`) succeeds and validates (`POST /api/platform/backup/validate`)
- [ ] `FRONTEND_URL` is set on the Render backend service, and `GET /api/platform/health` shows `frontend_api: UP` rather than `UNKNOWN`

See [SECURITY_TESTING.md](SECURITY_TESTING.md) for the full test suite to run after any deployment.
