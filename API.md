# SecureShare — API Reference

This file is a route-group-level map of every `/api/*` endpoint namespace across all 13 phases,
plus full endpoint detail for the newest modules (`/api/devsecops`, Phase 12; `/api/platform`,
Phase 13). For full endpoint tables of earlier phases, see
[README.md's API Endpoints section](README.md#-api-endpoints); this file is the quick-reference
index across all of them.

All routes are mounted under `/api` in `backend/server.js`. Unless noted otherwise, authenticated
routes require `Authorization: Bearer <jwt>`; admin-only routes additionally require the caller's
account to have `isAdmin: true` or `role` in `["administrator", "org_owner"]`.

## Route Groups

| Base Path | Phase | Auth | Purpose |
|---|---|---|---|
| `/api/auth` | 1 | Public (login/register) | Registration, login, token issuance |
| `/api/files` | 1–5 | User | Upload/download, encryption metadata, malware/DLP scan results |
| `/api/users` | 1 | User | Account profile |
| `/api/devices` | 3 | User | Trusted device management |
| `/api/sessions` | 3 | User | Active session listing/revocation |
| `/api/security` | 3, 6 | User | Security Center activity feed |
| `/api/threats` | 4 | User | Malware/threat scan results |
| `/api/dlp` | 5 | User | DLP scan results and policy |
| `/api/siem` | 6 | User/Admin | SIEM events, incidents, correlation |
| `/api/threat-intel` | 7 | User/Admin | IOC lookups, MITRE mapping, YARA rules |
| `/api/soar` | 8 | Admin | Automation rules, playbooks, executions |
| `/api/mfa` | 9 | User | TOTP MFA enrollment/verification |
| `/api/passkeys`, `/api/auth/passkey` | 9 | User | WebAuthn passkey registration/login |
| `/api/iam` | 9, 9.5 | User/Admin | Security policy, roles, login history, identity stats |
| `/api/compliance` | 10 | Admin | Frameworks, controls, assessments, policies, reports |
| `/api/cloud` | 11 | Admin | CSPM/ASM assets, findings, certificates, score, reports |
| `/api/devsecops` | 12 | Admin | Repository, dependency/secret/SAST/container/IaC findings, SBOM, reports |
| `/api/platform` | 13 | Admin | Platform health, metrics, alerts, background jobs, scheduler, backups, reports |

## `/api/devsecops` (Phase 12 — DevSecOps & Software Supply Chain Security)

All routes require `auth, requireAdmin` (`backend/routes/devsecops.routes.js`).

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/dashboard` | Overall + 5 component scores (repository/dependency/secret/container/pipeline), repository card, finding counts by severity/category, SBOM summary, pipeline runs, recent SIEM scans, 90-day trend, recommendations |
| `GET` | `/repositories` | List tracked repositories (in practice, one self-scanned row for this repo) |
| `POST` | `/repositories` | Re-scan this repo's git remote/branch/commit/author via read-only `git` commands |
| `GET` | `/dependencies` | Open dependency findings (`?severity=`, `?status=`) |
| `GET` | `/secrets` | Open secret findings (masked previews only, never full matched values) |
| `GET` | `/sast` | Open static-analysis findings |
| `GET` | `/container` | Open container/Dockerfile findings |
| `POST` | `/container` | Run just the container scan |
| `GET` | `/iac` | Open Infrastructure-as-Code findings (docker-compose.yml today) |
| `GET` | `/sbom` | List generated SBOM document metadata (component count, format, filename) |
| `POST` | `/sbom` | Generate a new SBOM — body: `{ format: "CycloneDX"\|"SPDX", serialization: "JSON"\|"XML" }` |
| `GET` | `/reports` | List generated report records |
| `POST` | `/scan` | Run the full scan: repository → dependency → secret → SAST → container → IaC → pipeline → artifact signing → risk score. Query `?live=false` skips the live npm-registry outdated-version check |
| `GET` | `/export/json` \| `/export/csv` \| `/export/pdf` | Export a report. Query `?reportType=executive\|sbom\|dependency\|secret\|container\|pipeline` selects the variant (defaults to `executive`) |

### Example: running a scan and reading the dashboard

```bash
# Run a full scan (admin JWT required)
curl -X POST https://your-backend/api/devsecops/scan \
  -H "Authorization: Bearer <admin_jwt>"

# Read the dashboard
curl https://your-backend/api/devsecops/dashboard \
  -H "Authorization: Bearer <admin_jwt>"

# Export the executive report as PDF
curl "https://your-backend/api/devsecops/export/pdf?reportType=executive" \
  -H "Authorization: Bearer <admin_jwt>" -o devsecops-report.pdf
```

### DevSecOpsFinding shape

```json
{
  "_id": "…",
  "category": "DEPENDENCY | SECRET | SAST | CONTAINER | IAC | PIPELINE",
  "ruleId": "dependency-advisory:crypto",
  "title": "Deprecated package shadows a Node.js builtin module",
  "severity": "INFO | LOW | MEDIUM | HIGH | CRITICAL",
  "status": "open | acknowledged | resolved",
  "file": "backend/Dockerfile",
  "line": 12,
  "package": "crypto",
  "recommendation": "…",
  "reference": "https://…",
  "detectedAt": "2026-07-04T00:00:00.000Z"
}
```

See [README.md's Phase 12 section](README.md#%EF%B8%8F-phase-12-enterprise-devsecops--software-supply-chain-security) for the full architecture writeup, and [ARCHITECTURE.md](ARCHITECTURE.md) for the scan-pipeline diagram.

## `/api/platform` (Phase 13 — Production Hardening & Cloud Platform Operations)

All routes require `auth, requireAdmin` (`backend/routes/platform.routes.js`). Health checks target managed cloud dependencies only (MongoDB Atlas, Redis Cloud, Cloudinary, ClamAV on Render, the Vercel frontend) - there is no local CPU/disk/memory endpoint, since this deployment has no host VM to monitor those on.

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/dashboard` | Latest health snapshot, current metrics, active alerts, queue status, scheduled jobs, recent background jobs, recent backups |
| `GET` | `/health` | Latest persisted health snapshot (`?fresh=true` forces a new check) |
| `GET` | `/health/history` | Health snapshot history (`?hours=`, default 24) |
| `GET` | `/metrics` | Current API/scan-duration/auth/scan-activity metrics |
| `GET` | `/metrics/history` | Persisted metric snapshots (`?hours=`, default 24) |
| `GET` | `/alerts` | Active alerts (`?active=false` for full history, `?limit=`) |
| `GET` | `/jobs` | Recent background jobs (`?queue=`, `?status=`) plus queue status |
| `POST` | `/jobs/run` | Enqueue a background job onto BullMQ (or run inline via the Redis-down fallback) — body: `{ queue, payload }` |
| `GET` | `/scheduler` | List all scheduled jobs (cron expression, last/next run, status, failure count) — bonus, beyond the core spec |
| `POST` | `/scheduler/run-now` \| `/scheduler/pause` \| `/scheduler/resume` | Scheduler control — body: `{ key }` — bonus, beyond the core spec |
| `POST` | `/backup` | Run a backup — body: `{ type: "database"\|"configuration"\|"metadata"\|"audit"\|"full" }` — bonus, beyond the core spec |
| `GET` | `/backup` | List backup records — bonus, beyond the core spec |
| `POST` | `/backup/validate` | Re-checksum a backup archive — body: `{ backupId }` — bonus, beyond the core spec |
| `GET` | `/reports` | List supported platform report types |
| `POST` | `/reports` | Generate a report — body: `{ reportType, format }` (`reportType`: health/availability/performance/queue/infrastructure; `format`: json/csv/pdf) |
| `GET` | `/export/pdf` \| `/export/csv` \| `/export/json` | Export a report directly — query `?reportType=` (defaults to `health`) |
| `POST` | `/scan` | Run an on-demand platform health/metrics/alert scan |

### Example: checking platform health and exporting a report

```bash
# Force a fresh health check
curl "https://your-backend/api/platform/health?fresh=true" \
  -H "Authorization: Bearer <admin_jwt>"

# Export the health report as PDF
curl "https://your-backend/api/platform/export/pdf?reportType=health" \
  -H "Authorization: Bearer <admin_jwt>" -o platform-health-report.pdf

# Enqueue an on-demand DevSecOps re-scan
curl -X POST https://your-backend/api/platform/jobs/run \
  -H "Authorization: Bearer <admin_jwt>" -H "Content-Type: application/json" \
  -d '{"queue":"devsecops-scan","payload":{}}'
```

See [README.md's Phase 13 section](README.md#%EF%B8%8F-phase-13-production-hardening--cloud-platform-operations) and [MONITORING.md](MONITORING.md) for the full architecture and monitoring writeup.
