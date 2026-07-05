# SecureShare — Monitoring Guide (Phase 13)

This document covers the Platform Operations monitoring layer added in Phase 13: the Cloud Health
Engine, metrics, alerts, background queue, and the managed cloud dependencies it watches (MongoDB
Atlas, Redis Cloud, Cloudinary, ClamAV on Render). This deployment has no VPS/host to monitor CPU,
disk, or memory on — every check here targets a managed dependency or an application-level metric.
See [DEPLOYMENT.md](DEPLOYMENT.md) for how each dependency is provisioned, and [API.md](API.md) for
the full `/api/platform/*` endpoint reference.

---

## Platform Health

`backend/services/platform/healthChecker.js` checks eight components every 5 minutes (via the
scheduler) and on-demand (`GET /api/platform/health?fresh=true`):

| Component | What it checks | Degrades to |
|---|---|---|
| `mongodb` | `mongoose.connection.db.admin().ping()` against MongoDB Atlas | `DOWN` if unreachable or `readyState !== 1` |
| `redis` | `PING` against Redis Cloud | `UNKNOWN` if `REDIS_URL` unset, `DOWN` if configured but unreachable |
| `clamav` | `zPING` over the same clamd INSTREAM TCP protocol Phase 4 uses, against the ClamAV Render service | `DOWN` if unreachable |
| `cloudinary` | `cloudinary.api.ping()` | `UNKNOWN` if not configured, `DOWN` if the API call fails |
| `queue` | BullMQ job counts (or in-process fallback counts) — `DEGRADED` above 20 failed jobs | `UNKNOWN` on error |
| `backend_api` | Self-check (process uptime) — always `UP` if this code is running | n/a |
| `frontend_api` | `fetch(FRONTEND_URL)` against the deployed Vercel frontend | `UNKNOWN` if `FRONTEND_URL` unset, `DOWN`/`DEGRADED` on failure/non-2xx |
| `scheduler` | Whether any registered `PlatformScheduledJob`'s most recent run failed | `DEGRADED`/`DOWN` based on failure ratio |

Each component contributes to a weighted **overall health score** (0-100) and status
(`HEALTHY` ≥90, `WARNING` ≥60, `CRITICAL` <60), persisted to `PlatformHealthSnapshot` for trend
charting on `/platform`. A status change emits a `PLATFORM_HEALTH_CHANGED` SIEM event.

**Endpoints**: `GET /api/platform/health`, `GET /api/platform/health/history?hours=`.

---

## Metrics

`backend/services/platform/metricsCollector.js` collects, in-memory (persisted to
`PlatformMetricSnapshot` on each scheduled scan):

- **API**: request count, average/p95/p99 latency, error count/rate (recorded per-request by `backend/middleware/metrics.middleware.js`).
- **Upload/Download timing**: average and p95 duration.
- **Scan durations**: per scan type (`threatScan`, `malwareScan`, `dlpScan`, `complianceScan`, `soarExecution`, `cloudScan`, `devSecOpsScan`, `reportGeneration`) — populated whenever Phase 13's own queue (`services/platform/queue.js`) or scheduler (`server.js`) invokes that scan's orchestrator. **Known limitation**: threat/malware/DLP scans that run inline during upload (not via the queue) aren't timed today — only re-scans routed through the background queue are; timing the inline upload path would require instrumenting Phase 4/5's upload controller, out of scope for this pass.
- **Authentication success/failure rate**: reuses Phase 9's existing `login`/`login_failed` SIEM events (no changes to the auth controller).
- **Scan activity counts**: 24h counts of Threat/DLP/SOAR/Compliance/Cloud/DevSecOps activity, read from their existing collections.
- **Queue length**: current background queue depth.

**Endpoints**: `GET /api/platform/metrics`, `GET /api/platform/metrics/history?hours=`.

---

## Alerts

`backend/services/platform/alertEngine.js` evaluates 9 rules against the latest health/metrics
every 5 minutes:

| Rule | Trigger | Severity |
|---|---|---|
| `MONGODB_OFFLINE` | `mongodb` component `DOWN` | CRITICAL |
| `REDIS_OFFLINE` | `redis` component `DOWN` | MEDIUM |
| `CLOUDINARY_FAILURE` | `cloudinary` component `DOWN` | HIGH |
| `CLAMAV_OFFLINE` | `clamav` component `DOWN` | MEDIUM |
| `QUEUE_FAILURE` | queue component `DEGRADED` (>20 failed jobs) | HIGH |
| `HIGH_ERROR_RATE` | API error rate >10% | HIGH |
| `SLOW_API` | p95 API latency >2000ms | MEDIUM |
| `BACKGROUND_JOB_FAILURE` | ≥3 background jobs failed in the last hour | MEDIUM |
| `HEALTH_SCORE_DROP` | overall health score <60 | HIGH |

Each trigger creates/resolves a `PlatformAlert` and emits the matching SIEM event (category
`PLATFORM`, deliberately distinct from `AUTOMATION` so SOAR can still act on it — see
[SECURITY.md](SECURITY.md#production-hardening--cloud-platform-operations-phase-13)).

**Endpoints**: `GET /api/platform/alerts` (`?active=false` for full history).

---

## Background Queue (BullMQ)

`backend/services/platform/queue.js` manages 8 named queues (`threat-scan`, `malware-scan`,
`cloud-scan`, `compliance-scan`, `devsecops-scan`, `report-generation`, `notification`, `email`),
backed by BullMQ + Redis Cloud when `REDIS_URL` is configured and reachable, or run inline
in-process otherwise — every job's status/duration/retry count/logs are tracked identically in
`PlatformJob` either way.

- Failed jobs retry up to `maxRetries` (default 3) with exponential backoff, when BullMQ is active.
- A `BACKGROUND_JOB_FAILED` SIEM event fires on every failure (any mode).

**Endpoints**: `GET /api/platform/jobs` (`?queue=`, `?status=`), `POST /api/platform/jobs/run` (body: `{ queue, payload }`).

---

## Redis (Redis Cloud)

`backend/middleware/redisClient.js` is the single shared `ioredis` client, used by rate limiting,
the queue, and health checks. `isRedisAvailable()` is checked independently by each consumer, so a
Redis outage degrades each feature to its own fallback rather than cascading:

- Rate limiting → in-memory store (unchanged limits, per-process only).
- Queue → jobs run inline instead of via BullMQ.
- Health check → `redis` component reports `DOWN`, contributing to a `REDIS_OFFLINE` alert.

No manual intervention is needed to recover — the client auto-reconnects and every consumer
re-checks `isRedisAvailable()` on its next operation.

---

## Cloudinary

Health-checked via `cloudinary.api.ping()`. A `DOWN` result fires `CLOUDINARY_FAILURE` (HIGH
severity, since file upload/download depends on it). No caching or CDN-level monitoring is
implemented beyond this reachability check — Cloudinary's own dashboard should be used for
storage/bandwidth quota monitoring (see [DEPLOYMENT.md §2](DEPLOYMENT.md#storage--cloudinary)).

---

## ClamAV (Render)

Health-checked via a raw `zPING` over the same clamd INSTREAM TCP protocol
`backend/services/clamavScanner.js` uses for actual scans, against the Render-hosted ClamAV
service (`CLAMAV_HOST`/`CLAMAV_PORT`). A `DOWN` result fires `CLAMAV_OFFLINE` (MEDIUM severity,
since the rest of the malware-detection pipeline — magic bytes, hashing, VirusTotal, risk scoring
— still functions without it). See [DEPLOYMENT.md §3-4](DEPLOYMENT.md#3-clamav-docker) for
provisioning.

---

## Platform Reports

Five report types (`health`, `availability`, `performance`, `queue`, `infrastructure`), each
exportable as PDF/CSV/JSON via `GET /api/platform/export/{pdf,csv,json}?reportType=` or
`POST /api/platform/reports`. Every generation fires a `PLATFORM_REPORT_GENERATED` SIEM event.
