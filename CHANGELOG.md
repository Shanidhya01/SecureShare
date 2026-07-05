# Changelog

All notable changes to SecureShare are documented in this file, grouped by the security phase that introduced them. Dates reflect when each phase's implementation commit landed.

This project does not yet follow strict [Semantic Versioning](https://semver.org/) tags in git, but the phase number is used informally as the major version (e.g. "Phase 4" ≈ `v4.x`).

---

## Phase 14 — Frontend Production QA
**2026-07-05**

A pre-deployment audit of the frontend covering hydration safety and accessibility. `npm run build`, `npm run lint`, and `tsc --noEmit` were already clean going in (no prerender errors); this pass targeted defects that don't surface as build errors - SSR/client hydration mismatches and screen-reader gaps - by reading every page that touches `window`/`localStorage`/`document` and every custom (non-primitive) interactive component.

### Fixed
- **Hydration mismatches** from reading `localStorage`/`window` synchronously during render or via a `useState` lazy initializer (which runs again on the client's first hydration pass, before it can match the server's output):
  - `components/shell/Topbar.tsx` - the signed-in user's name/email in the account menu rendered "Account"/"Signed in" from the server and the real value on hydration, on every page, for every logged-in user. Now defaults to `null` and is populated in a `useEffect`.
  - `context/ThemeContext.tsx` - the theme toggle icon (`Sun`/`Moon`) in `Topbar` could flip between server and client render depending on the visitor's stored/OS theme. Now starts at a fixed `"dark"` default (matching the server) and resolves the real theme client-side after mount; the existing inline no-flash `<script>` in `layout.tsx` still prevents a visible flash of the wrong theme on the page background.
  - `app/cloud-security/reports/page.tsx`, `app/devsecops/reports/page.tsx` - an admin-only page gate (`if (!ready) return null`) computed synchronously from `localStorage` in a lazy initializer, so the page could render fully on the client before hydration reconciled with the server's `null`. Now gates on a `useState(false)` set inside the existing access-check effect.
  - `app/settings/page.tsx` - notification/table-density toggles read persisted preferences synchronously, which could mismatch the `checked` state of the rendered switches. Now initializes to fixed defaults and loads the persisted values in an effect.
  - `components/design/NotificationCenter.tsx` - the unread-count badge's read/archived state had the same synchronous-read pattern (currently latent, since the events list itself loads asynchronously and is empty on first render either way, but fixed for correctness).
- **Accessibility** gaps in hand-rolled (non-design-system) components - the shared `Dialog`/`Button`/`Switch` primitives already handle focus trapping, `Escape`, ARIA roles, and focus-visible rings correctly:
  - `components/UnlockKeyModal.tsx` was a fully hand-rolled overlay with no focus trap, no `Escape` handling, no `role`/`aria-modal`, an unlabeled icon-only close button, and hardcoded dark-only colors (`bg-slate-800`, `text-white`, ...) that ignored the light/dark theme. Rebuilt on the existing `Dialog` primitive (same open/onClose/onSuccess API), which supplies focus trapping, `Escape`-to-close, ARIA wiring, and a labeled close button for free, and switched to theme tokens (`bg-card`, `border-border`, `text-foreground`, ...).
  - Icon-only action buttons that carried only a `title` attribute (not read by most screen readers, and stripped on touch devices) now also carry `aria-label`: rule enable/disable and delete in `app/soar/page.tsx`, playbook export/clone/delete in the same file, run/pause/resume in `app/platform/scheduler/page.tsx`, and the copy-share-link button in `app/upload/page.tsx`.
  - The notification/preference `Switch` toggles in `app/settings/page.tsx` were visually adjacent to their label text but had no programmatic association (`aria-label`/`aria-labelledby`), so a screen reader announced only "switch, on/off" with no name. Each now carries `aria-label={label}`.

### Verified, no changes needed
- Route builds (`/files`, `/identity/devices`, and all 34 routes) were already clean under `next build` - no prerender errors found.
- `DataTable` renders semantic `<table>`/`<th>` markup, wraps in `overflow-x-auto` for narrow viewports, and its sort buttons pair an icon with visible header text (not icon-only).
- All Recharts usage (11 pages) is already wrapped in `ResponsiveContainer`.
- No hardcoded dark-only Tailwind colors remain outside the fixed modal; the rest of the app already uses semantic theme tokens exclusively.
- No unused dependencies in `package.json`; `shadcn` and `tw-animate-css` are consumed via CSS imports rather than JS imports, which a naive import-grep misses.

---

## Phase 13 — Production Hardening & Cloud Platform Operations
**2026-07-05**

A Cloud Health Engine and platform-operations layer targeting this project's actual deployment shape - Vercel (frontend), Render (backend + ClamAV in Docker), MongoDB Atlas, Redis Cloud, and Cloudinary - with no VPS/self-hosted infrastructure: Redis-backed caching/queueing with automatic in-process fallback, a BullMQ background job queue, a health engine over managed dependencies only, structured logging/metrics, an alert engine, and a non-destructive backup manager. No prior phase's code was rewritten; every existing scan orchestrator (Cloud/DevSecOps/Compliance) is reused as-is by the new queue and scheduler. An initial pass within this same phase added VPS-style infrastructure (Nginx, a multi-service Docker Compose stack, local CPU/disk/memory monitoring) that was removed once the actual deployment target was clarified - see "Changed" below.

### Added
- `backend/models/PlatformHealthSnapshot.js`, `PlatformMetricSnapshot.js`, `PlatformJob.js`, `PlatformScheduledJob.js`, `PlatformAlert.js`, `PlatformBackup.js`
- `backend/services/platform/healthChecker.js` - checks MongoDB Atlas, Redis Cloud, ClamAV (Render), Cloudinary, the job queue, this backend's own process, the deployed Vercel frontend, and the scheduler's run history, and computes a weighted overall health score/status (`HEALTHY`/`WARNING`/`CRITICAL`) - deliberately no local CPU/disk/memory check, since this deployment has no host VM
- `backend/services/platform/metricsCollector.js` - in-memory ring buffer of API latency/error-rate/upload/download timings, per-scan-type duration (threat/malware/DLP/compliance/SOAR/cloud/DevSecOps/report-generation), authentication success/failure rate (reusing Phase 9's existing `login`/`login_failed` events), and scan-activity counts, snapshotted periodically for history
- `backend/services/platform/alertEngine.js` - rule-based alerting (`MONGODB_OFFLINE`, `REDIS_OFFLINE`, `CLOUDINARY_FAILURE`, `CLAMAV_OFFLINE`, `QUEUE_FAILURE`, `HIGH_ERROR_RATE`, `SLOW_API`, `BACKGROUND_JOB_FAILURE`, `HEALTH_SCORE_DROP`), each rule emitting a SIEM event that auto-triggers SOAR
- `backend/services/platform/queue.js` - BullMQ-backed background job queue via Redis Cloud (`threat-scan`, `malware-scan`, `cloud-scan`, `compliance-scan`, `devsecops-scan`, `report-generation`, `notification`, `email`) with an in-process fallback when Redis is unavailable; every job's status/duration/retry count/logs are persisted regardless of mode
- `backend/services/platform/scheduler.js` - wraps every `node-cron` schedule (including the pre-existing Phase 10/11/12 daily scans) with last/next run, duration, status, and failure tracking
- `backend/services/platform/backupManager.js` - database/configuration/metadata/audit ZIP backups with SHA-256 checksum validation; no destructive restore is implemented
- `backend/services/platform/platformReportGenerator.js` - Health/Availability/Performance/Queue/Infrastructure reports in CSV/JSON/PDF
- `backend/services/platform/platformOrchestrator.js` (`runPlatformScan`) - the single entry point chaining health + metrics + alerts, mirroring `devSecOpsOrchestrator.js`
- `backend/utils/logger.js`, `backend/middleware/requestContext.middleware.js`, `backend/middleware/metrics.middleware.js`, `backend/middleware/redisClient.js` - structured JSON logging (winston) with request/correlation IDs via `AsyncLocalStorage`, and a shared Redis client that every consumer (rate limiting, queue, health checks) degrades gracefully without
- `backend/controllers/platform.controller.js`, `backend/routes/platform.routes.js` (`/api/platform/*`, admin-only) - dashboard, health, metrics, alerts, jobs, scheduler, backup, report, and export (`/export/pdf|csv|json`) endpoints
- A new `platformOpsEvaluator` in `services/compliance/controlEvaluators.js`, seeded as one control under ISO 27001, SOC 2, NIST CSF, and PCI DSS, feeding platform availability/health-score/backup-recency into those frameworks' availability and operational-resilience controls
- 11 new SIEM event types (`platform_health_changed`, `mongodb_offline`, `redis_offline`, `clamav_offline`, `cloudinary_failure`, `queue_failure`, `high_api_latency`, `background_job_failed`, `backup_completed`, `backup_failed`, `platform_report_generated`) and a new `PLATFORM` category, added additively to `SecurityEvent.js` - deliberately distinct from the `AUTOMATION` category so these events can still trigger SOAR playbooks
- `/platform` dashboard (Platform Health/MongoDB/Redis/Cloudinary/ClamAV cards, average response time, background queue, alerts, availability, plus 8 Recharts visualizations) plus `/scheduler`, `/backups`, and `/reports` subpages, with a new "Platform" nav entry
- A health/metrics/alert scan every 5 minutes and a nightly full backup at 02:00, both registered through the new scheduler
- `backend/tests/platform.test.js` - unit tests for the SIEM catalog additions, alert rule coverage/category isolation, the queue's declared queue names, scan-duration/auth/upload-download metrics, and the report builders
- `MONITORING.md` - the full monitoring reference (health, metrics, alerts, queue, Redis, Cloudinary, ClamAV)

### Changed
- `backend/server.js` - mounts `/api/platform`, initializes the shared Redis client and BullMQ queues (non-fatal if unset/unreachable), registers every recurring scan (Phase 10/11/12's daily scans plus the new Phase 13 ones) through the scheduler instead of calling `cron.schedule` directly, times each scheduled scan via `recordScanDuration`, adds request-context and metrics middleware globally, and reads `PORT` from the environment instead of a hardcoded `5000`
- `.env.example` - new Phase 13 section (`REDIS_URL`, `FRONTEND_URL`, `LOG_LEVEL`)
- `DEPLOYMENT.md` - added Redis Cloud provisioning and a Platform Operations/Monitoring/Scaling section specific to Vercel + Render + Atlas + Redis Cloud + Cloudinary; removed an initial VPS-oriented Docker Compose + Nginx production-stack section once the deployment target was clarified
- Reverted, as out of scope for this deployment target: `docker-compose.yml` (back to its original local-dev-only `backend`+`mongo` shape), `frontend/next.config.ts` (removed `output: "standalone"`); deleted `nginx/` and `frontend/Dockerfile` entirely (no reverse proxy or containerized frontend in this deployment)

---

## Phase 12 — Enterprise DevSecOps & Software Supply Chain Security
**2026-07-04**

A self-scanning software-supply-chain layer over SecureShare's own repository, dependencies, source code, container, and CI/CD config - there is no real multi-repo/CVE-feed/CI system to integrate with, so every finding is produced by introspecting this project's own real files. No prior phase's code was rewritten.

### Added
- `backend/models/Repository.js`, `DevSecOpsFinding.js`, `SBOMDocument.js`, `PipelineRun.js`, `ArtifactSignature.js`, `DevSecOpsScoreSnapshot.js` - the self-scanned repository record, a unified finding store for dependency/secret/SAST/container/IaC/pipeline findings, generated SBOM documents, pipeline observations, artifact tamper-evidence records, and per-scan-run score snapshots
- `backend/services/devsecops/repositoryScanner.js` - reads this repo's own git remote/branch/commit/author via read-only `git` commands
- `backend/services/devsecops/dependencyScanner.js` - scans both real `package.json` manifests for known-deprecated packages (flags the `crypto` npm shim), typosquats (Levenshtein distance), copyleft licenses, and (optionally, live) outdated versions
- `backend/services/devsecops/secretScanner.js` - regex + Shannon-entropy secret detection (AWS/Azure/GCP/GitHub/GitLab/Slack/Stripe/OpenAI/JWT/PEM/DB-connection-string patterns) over this repo's own source
- `backend/services/devsecops/sastScanner.js` - pattern-based static analysis (SQLi, command injection, eval, open redirect, path traversal, weak hashes, unsigned-expiry JWTs, SSRF, unbounded uploads) - caught a real missing-`expiresIn` JWT in `services/iam/sessionIssuer.js`
- `backend/services/devsecops/containerScanner.js` - static analysis of `backend/Dockerfile` (real findings: runs as root, ships a dev-server `CMD`, no `HEALTHCHECK`, non-reproducible install)
- `backend/services/devsecops/iacScanner.js` - analyzes `docker-compose.yml` (real findings: Mongo's port publicly exposed, missing restart/resource-limit policies)
- `backend/services/devsecops/sbomGenerator.js` - real CycloneDX 1.5 / SPDX 2.3 SBOM generation (JSON + XML) directly from both `package-lock.json` files
- `backend/services/devsecops/pipelineMonitor.js` - detects `.github/workflows`/GitLab CI/Jenkins/Azure Pipelines config (none present today - logged as a real finding, not faked); optional live GitHub Actions API check via `GITHUB_TOKEN`/`GITHUB_REPO`
- `backend/services/devsecops/artifactSecurity.js` - reuses `utils/fileHashes.js` to hash + HMAC-sign `package-lock.json` files as stand-in build artifacts, with tamper detection via re-hash comparison
- `backend/services/devsecops/riskEngine.js` - Repository/Dependency/Secret/Container/Pipeline component scores plus a weighted overall DevSecOps score
- `backend/services/devsecops/devSecOpsOrchestrator.js` (`runDevSecOpsScan`) - the single entry point chaining every scanner above
- `backend/services/devsecops/devSecOpsReportGenerator.js` - CSV/JSON/PDF export builders, parameterized into Executive/SBOM/Dependency/Secret/Container/Pipeline report variants
- `backend/controllers/devsecops.controller.js`, `backend/routes/devsecops.routes.js` (`/api/devsecops/*`, admin-only) - dashboard, repositories, category-scoped findings, SBOM, reports, scan, and export endpoints
- A new `devSecOpsEvaluator` in `services/compliance/controlEvaluators.js`, seeded as one control under ISO 27001, SOC 2, NIST CSF, PCI DSS, CIS Controls, and OWASP ASVS
- A new "Supply Chain Incident Response" playbook and `DEPENDENCY_VULNERABILITY_CRITICAL`/`SECRET_FOUND_CRITICAL`/`CONTAINER_VULNERABILITY_CRITICAL`/`PIPELINE_BLOCKED`/`HIGH_RISK_REPOSITORY` automation triggers (`services/soar/seedPlaybooks.js`), plus three new SOAR actions: `blockDeployment` (advisory - no live CD system to enforce it), `rerunDevSecOpsScan`, `generateDevSecOpsReport`
- 11 new SIEM event types (`dependency_vulnerability`, `secret_found`, `sbom_generated`, `sast_finding`, `container_vulnerability`, `pipeline_failed`, `pipeline_blocked`, `high_risk_repository`, `iac_misconfiguration`, etc.) and a new `DEVSECOPS` category, added additively to `SecurityEvent.js`/`Incident.js`
- `/devsecops` dashboard plus `/findings`, `/sbom`, and `/reports` pages, with a new "DevSecOps" nav entry (and a Phase 11 gap fix - `/cloud-security` was never added to the Topbar/Security Center links; both it and `/devsecops` are added now)
- A daily `node-cron` scan (05:00) and a startup scan in `server.js`
- `backend/tests/devsecops.test.js` - unit tests for every scanner's rule functions, SBOM component/PURL generation, artifact tamper detection, the risk engine's weighting, and the new SOAR/SIEM trigger mappings

---

## Phase 11 — Cloud Security Posture Management & Attack Surface Management
**2026-07-04**

A continuous CSPM/ASM layer that discovers and scores SecureShare's own deployment posture (there is no multi-cloud footprint to enumerate) and feeds findings into the existing SIEM, SOAR, and Compliance pipelines. No prior phase's code was rewritten.

### Added
- `backend/models/Asset.js`, `CloudFinding.js`, `Certificate.js`, `SecurityScoreSnapshot.js` - the discovered asset inventory, a unified finding store for configuration/exposure/certificate/threat-intel findings, monitored TLS certificates, and per-scan-run score snapshots
- `backend/services/cloud/assetDiscovery.js` - discovers servers, the database, API route groups (via static parsing of `backend/routes/*.routes.js`), the frontend domain, file storage, ClamAV, and Docker/Compose assets
- `backend/services/cloud/configScanner.js` - ~20 pure configuration/hardening rules (HTTPS/HSTS/CSP/X-Frame-Options/Permissions-Policy/helmet, CORS, directory listing, rate limiting, compression, debug mode, cookies, JWT secret strength, exposed Swagger/admin APIs, upload size limits)
- `backend/services/cloud/certificateMonitor.js` - TLS certificate expiry/weak-TLS monitoring via Node's built-in `tls` module, with deduped 30/15/7-day and expired alerts
- `backend/services/cloud/attackSurfaceScanner.js` - self-probes SecureShare's own base URL for well-known exposure paths (robots.txt, security.txt, .well-known, api-docs, admin, metrics, debug, .env, .git/config)
- `backend/services/cloud/threatIntelCorrelation.js` - reuses `services/threatIntel/iocLookupService.js` to correlate discovered domains against known-malicious IOC data
- `backend/services/cloud/scoreEngine.js` - Asset/Configuration/Exposure/Certificate/Identity/Compliance component scores plus a weighted overall score, persisted per run
- `backend/services/cloud/cloudScanOrchestrator.js` (`runCloudScan`) - the single entry point chaining discovery → config scan → certs → attack surface → threat intel → score engine
- `backend/services/cloud/cloudReportGenerator.js` - CSV/JSON/PDF export builders mirroring `services/compliance/reportGenerator.js`
- `backend/controllers/cloud.controller.js`, `backend/routes/cloud.routes.js` (`/api/cloud/*`, admin-only) - dashboard, assets, findings, certificates, score, history, scan, and export endpoints
- A new `cloudSecurityEvaluator` in `services/compliance/controlEvaluators.js`, seeded as one control under ISO 27001, SOC 2, GDPR, PCI DSS, NIST CSF, and OWASP ASVS - open CRITICAL/HIGH cloud findings now lower those frameworks' scores
- A new "Cloud Exposure Response" playbook and `PUBLIC_EXPOSURE_CRITICAL`/`CERTIFICATE_EXPIRED`/`CLOUD_SCORE_DROP` automation triggers (`services/soar/seedPlaybooks.js`), plus two new SOAR actions: `rerunCloudScan`, `generateCloudReport`
- 12 new SIEM event types (`asset_discovered`, `configuration_scan`, `public_exposure`, `certificate_expired`, `security_score_updated`, etc.) and a new `CLOUD` category, added additively to `SecurityEvent.js`/`Incident.js`
- `/cloud-security` dashboard plus `/assets`, `/findings`, `/certificates`, `/reports`, and per-asset `/assets/:id` detail pages, with a new "Cloud Security" nav entry
- A daily `node-cron` scan (04:00) and a startup scan in `server.js`, plus a fire-and-forget rescan after compliance policy updates
- `backend/tests/cloud.test.js` - unit tests for the config scanner rules, certificate expiry/tier math, the score engine's weighting, and the new SOAR/SIEM trigger mappings

---

## Phase 10 — Enterprise Compliance & Governance
**2026-07-04**

An additive governance layer that continuously evaluates SecureShare against 8 security/privacy frameworks by reading evidence straight from the existing SIEM, SOAR, Threat Intelligence, IAM, DLP, and Zero Trust subsystems - no prior phase's detection/crypto/policy code was modified.

### Added
- `backend/models/ComplianceFramework.js`, `ComplianceControl.js`, `ComplianceAssessment.js`, `ComplianceEvidence.js`, `CompliancePolicy.js`, `ComplianceReport.js` - the framework/control catalog, per-run assessment history, linked evidence, versioned governance policies, and report audit records
- `backend/services/compliance/controlEvaluators.js` - 11 pure, DB-free evaluators (encryption, MFA, threat detection, malware protection, DLP, zero trust, audit logging, session management, incident response, threat intel, SOAR automation), mirroring `services/soar/ruleMatcher.js`'s pure-function testability
- `backend/services/compliance/evidenceCollector.js` - builds the shared evidence context from `File`, `User`, `SecurityEvent`, `Incident`, `AutomationRule`/`AutomationExecution`, and `SecurityPolicy`, and persists `ComplianceEvidence` linking each source to a control
- `backend/services/compliance/complianceEngine.js` (`runAssessment`) - orchestrates a full or per-framework assessment run, computes framework/overall scores, and emits `compliance_scan`/`control_passed`/`control_failed` SIEM events - which automatically re-enter the existing SOAR engine, so a critical control failure or score drop beneath the 70 threshold can trigger the new `COMPLIANCE_SCORE_DROP` automation rule with zero extra plumbing
- `backend/services/compliance/seedFrameworks.js` - idempotent seed of ISO 27001, SOC 2, GDPR, HIPAA, PCI DSS, NIST CSF, CIS Controls, and OWASP ASVS, each with a representative subset (6-9) of real, well-known controls mapped to an evaluator
- `backend/services/compliance/reportGenerator.js` - CSV/JSON report builders (manual string building, matching `soar.controller.js`'s existing export convention) plus a PDF builder using the new `pdfkit` dependency
- `backend/services/compliance/policyEvaluator.js` - versioned `CompliancePolicy` read/write helpers (file retention, max upload size, blocked file types, restricted countries, DLP enforcement) plus a pure `evaluatePolicyViolations()` checker
- `backend/services/soar/actions/generateComplianceReport.js` - new SOAR action, runs a fresh assessment and records a `ComplianceReport`, registered in `actions/index.js`
- New `COMPLIANCE` category and 7 SIEM event types (`compliance_scan`, `control_passed`, `control_failed`, `policy_updated`, `compliance_policy_violation`, `report_generated`, `evidence_collected`) in `eventCatalog.js`/`SecurityEvent.js`/`Incident.js`; new `COMPLIANCE_SCORE_DROP` trigger in `AutomationRule.js` + `ruleMatcher.js`
- Compliance REST API (`/api/compliance/frameworks`, `/controls`, `/assessments`, `/scan`, `/evidence`, `/policies`, `/reports`, `/dashboard`) - admin-only end to end, matching SOAR's rule/playbook config gating rather than a per-user page
- A daily `node-cron` job (03:00) re-running the full assessment, attributed to the first admin account found
- Compliance & Governance dashboard: `frontend/app/compliance/page.tsx` - score, framework status, control coverage, open findings, recent assessments, an evidence browser, policy status, and recommendations, plus "Compliance" added to the main navigation
- `backend/tests/compliance.test.js` - 23 unit/integration tests covering all 11 evaluators, the policy violation checker, and the new `compliance_scan`/`control_failed` → `COMPLIANCE_SCORE_DROP` ruleMatcher mappings

### Changed
- Nothing in prior phases was rewritten; all Phase 10 additions read existing collections rather than duplicating their storage (e.g. MFA/session/password/country settings are read live from the existing `SecurityPolicy`, not copied into `CompliancePolicy`)
- New dependency: `pdfkit` (backend)

### Added (continuation, same date)
- 6 additional pure evaluators in `controlEvaluators.js` - password policy, identity governance, device trust, adaptive authentication, digital signatures, and file integrity (17 total). Every evaluator now also returns `severity` (derived from its verdict) and `evidence` (a readable summary of `details`) via a shared `withEvaluatorMeta()` wrapper, without changing any existing evaluator's core logic
- `backend/services/compliance/riskScoring.js` - pure `computeRiskScore()` (severity-weighted 0-100 risk score), `riskDistribution()`, and `buildComplianceTrend()`, wired into `complianceEngine.js`'s `runAssessment()` output and a new `getComplianceTrend()` export (reads existing `ComplianceAssessment` history - no new trend-storage collection needed)
- New `COMPLIANCE_FAILED`/`COMPLIANCE_PASSED` (overall-run-level, distinct from the existing per-control `CONTROL_FAILED`/`CONTROL_PASSED`) and `FRAMEWORK_UPDATED` SIEM events
- `backend/services/soar/actions/assignComplianceOwner.js` and `rerunComplianceAssessment.js` - two new SOAR actions powering a seeded "Compliance Failure Response" playbook (raise incident → notify admin → assign owner → re-run assessment) on the existing `COMPLIANCE_SCORE_DROP` trigger, plus three lightweight "recheck compliance" automation rules attached to the existing `THREAT_FOUND`/`DLP_BLOCK`/`MITRE_CRITICAL` triggers for continuous compliance after malware detections, DLP violations, and SIEM-critical alerts - no `ruleMatcher.js` changes needed since those triggers already existed
- Policy management: `validatePolicyValue()`, `getPolicyHistory()`, `rollbackPolicy()`, `setPolicyApproval()`, `setPolicyVersionEnabled()` in `policyEvaluator.js`; `CompliancePolicy` gained an additive `approvalStatus`/`approvedBy`/`approvedAt` review trail
- API additions on `/api/compliance`: `GET /framework/:id` + `PATCH /frameworks/:id`, `GET /control/:id`, `GET /findings`, `POST /run` (scan alias), `POST /report` (report alias), `POST /policies` (create), `PATCH /policies/:id` (enable/disable/approve a specific version), `GET /policies/:name/history`, `POST /policies/:name/rollback/:version`, and dedicated `GET /export/pdf|csv|json` routes alongside the existing `?format=` query style
- Reports (CSV/JSON/PDF) now include risk score, risk distribution, and a 90-day trend/"Trend Analysis" section, not just framework/control scores
- Compliance dashboard gained a Risk Score stat card, a Compliance Trend/Assessment History area chart, a Risk Distribution pie chart, and a Governance Activity (policy violations / audit events, 30d) bar chart - all via Recharts, matching the existing chart styling
- "Compliance Center" links added to the Topbar account menu, the Dashboard (admin-only quick action + stat card), and the Security Center page header (admin-only)
- `idempotent top-up functions - `ensureAdditionalControls()` in `seedFrameworks.js` and `ensureAdditionalComplianceAutomation()` in `seedPlaybooks.js` - so a database that already seeded Phase 10 (or Phase 8) before this continuation still picks up the new controls/playbook/rules on next start, without re-seeding or duplicating anything
- 16 additional tests in `backend/tests/compliance.test.js` (39 total in that file): the 6 new evaluators, the severity/evidence wrapper, risk scoring, policy value validation, and report-builder shape

---

## Phase 9.5 — Enterprise Authentication & Adaptive Access
**2026-07-04**

Sharpens Phase 9's adaptive-auth foundation - a four-tier (LOW/MEDIUM/HIGH/CRITICAL) risk engine with VPN/Tor/impossible-travel signals - and fixes two policies that phase defined but never enforced (device restrictions, session timeout). No Phase 9 file was rewritten; every change here extends the same modules.

### Added
- `backend/services/iam/networkIntel.js` (`checkNetworkIntel`) - local-only, honestly-scoped VPN/Tor heuristic detection (Phase 7 IOC tags + a small illustrative Tor directory-node list); no external IP-intelligence API is called during login
- `detectImpossibleTravel()` in `backend/services/iam/loginRiskEngine.js` - pure country-level, time-window impossible-travel check (a documented simplification; no lat/long geo-database exists in this codebase)
- `evaluateDevicePolicy()`, `evaluatePasswordPolicy()`, `evaluateSessionTimeout()` in `backend/services/iam/policyEngine.js` - pure evaluators for the two Phase 9 policy fields that previously had no enforcement, plus a new password policy
- `SecurityPolicy.allowedDeviceIds`, `minPasswordLength`, `requirePasswordComplexity` fields, plus a 15-second in-memory cache on `getPolicy()` (needed now that `auth.middleware.js` calls it on every authenticated request)
- New `impossible_travel` SIEM event (severity CRITICAL) and two new SOAR triggers - `IMPOSSIBLE_TRAVEL` (unconditional) and `CRITICAL_RISK_LOGIN` (conditional on `step_up_auth`'s `riskLevel` metadata) - firing a newly seeded "Critical Risk Response" playbook (`requireMfaStepUp` → `raiseIncident` → `notifyUser`)
- Dedicated Trusted Devices dashboard: `frontend/app/identity/devices/page.tsx`
- `GET /api/iam/stats` + an Analytics section on `/identity` - Risk Levels, MFA Usage, Countries, Devices, and Failed Logins charts
- 20 additional tests in `backend/tests/iam.test.js` (44 total in that file): the four-tier risk model, VPN/Tor/impossible-travel signals, the three new policy evaluators, the two new SOAR trigger mappings, and an end-to-end integration test chaining risk scoring → event shape → SOAR trigger → playbook execution

### Changed
- `backend/services/iam/loginRiskEngine.js`'s `scoreLogin()` reweighted for six signals and four risk tiers (thresholds: Critical ≥80, High ≥55, Medium ≥25) - `iam.test.js`'s risk-scoring assertions updated to match
- `backend/controllers/auth.controller.js`'s `login()` now also gathers VPN/Tor/impossible-travel signals, enforces the (now-hard) device-restriction policy before any device/session bookkeeping, and forces step-up on `Critical` risk in addition to `High`
- `backend/controllers/auth.controller.js`'s `register()` now enforces the configurable password policy
- `backend/middleware/auth.middleware.js` now enforces `sessionTimeoutMinutes` on every authenticated request (previously defined in the schema but never checked)
- `backend/services/iam/sessionIssuer.js`'s `login` SIEM event now carries `riskLevel`/`riskScore`/`authMethod` in its metadata, powering the new analytics endpoint
- `backend/services/siem/eventCatalog.js`: the `login` type's `siemType` relabeled `LOGIN_SUCCESS` (spec-aligned naming); `LOGIN` kept in `SecurityEvent`'s enum only for historical-document validity
- `backend/models/AutomationRule.js`'s `trigger` enum gained `IMPOSSIBLE_TRAVEL`/`CRITICAL_RISK_LOGIN`; `backend/services/soar/ruleMatcher.js`'s `eventTriggerFor()` gained the corresponding mappings
- `frontend/app/identity/page.tsx` gained an Analytics section, a link to `/identity/devices`, and Policy form fields for the three new policy settings

---

## Phase 9 — Identity & Access Management (IAM) + Multi-Factor Authentication
**2026-07-04**

TOTP MFA, WebAuthn passkeys, a fuller RBAC role model, configurable security policies, and risk-based adaptive authentication - layered additively onto the existing JWT/password login flow. Existing authentication is unchanged for every account that hasn't opted into these features.

### Added
- `backend/services/iam/totp.js`, `recoveryCodes.js` - TOTP generation/verification (`otplib`) and bcrypt-hashed, single-use recovery codes
- `backend/controllers/mfa.controller.js` + `routes/mfa.routes.js` (`/api/mfa`) - two-step enrollment (`setup`/`verify`), `disable`, `recovery/regenerate`, `status`, and `verify-login` (the second step of an MFA-gated login)
- `backend/models/Passkey.js`, `WebAuthnChallenge.js`, `backend/controllers/passkey.controller.js` + `routes/passkey.routes.js` (`/api/passkeys`, `/api/auth/passkey`) - full WebAuthn register/login/remove flow via `@simplewebauthn/server` (backend) and `@simplewebauthn/browser` (frontend)
- `backend/models/SecurityPolicy.js`, `backend/services/iam/policyEngine.js` - a global, admin-configurable policy (require MFA, password expiry, session timeout, max sessions, allowed countries, block untrusted devices) with pure, unit-tested evaluators
- `backend/services/iam/loginRiskEngine.js` (`scoreLogin`) - pure adaptive-auth scoring from new-device/IOC-matched-IP/country-change signals
- `backend/services/iam/sessionIssuer.js` (`issueSessionAndToken`) - the single function (extracted from the original inline `login()`) that creates a Session, updates Device state, signs the JWT, and logs SIEM events for every login path (password, MFA-verified, passkey)
- `backend/services/iam/loginFailureTracker.js` - logs `login_failed` with a rolling 15-minute count, finally giving Phase 8's dormant `MULTIPLE_FAILED_LOGINS` trigger a real source
- `backend/services/soar/actions/requireMfaStepUp.js` - new SOAR action; a seeded "Account Lockdown Response" playbook (`requireMfaStepUp` → `notifyUser`) now fires on repeated failed logins
- `backend/middleware/requireRole.js` - finer-grained RBAC gate (applied only to new Phase 9 endpoints)
- IAM REST API (`/api/iam/policy`, `/roles`, `/users`, `/users/:id/role`, `/login-history`)
- Identity dashboard (`frontend/app/identity/page.tsx`) - MFA enrollment/QR/recovery codes, Passkeys, Trusted Devices, Sessions, Roles (admin), Policies (admin), Login History
- Login page (`frontend/app/login/page.tsx`) gained an MFA code-entry step and a "Sign in with a passkey" option, both additive to the existing password form
- `backend/tests/iam.test.js` - 24 unit tests: TOTP round-trip, recovery code lifecycle, adaptive-auth scoring, policy evaluators, and the new `login_failed` → `MULTIPLE_FAILED_LOGINS` SOAR trigger mapping

### Changed
- `backend/models/User.js` gained `role` (5-value enum, default `user`), `mfa` (enabled/secret/pendingSecret/recoveryCodeHashes/enabledAt), `passwordChangedAt` (defaults to account creation), `forceMfaOnNextLogin` - all additive with safe defaults
- `backend/models/Device.js` gained `mfaTrustedUntil` for MFA trusted-device support
- `backend/controllers/auth.controller.js`'s `login()` now runs adaptive-auth scoring, security-policy checks, and MFA gating before finalizing a session via the new `issueSessionAndToken()` - the device/session/JWT-issuing logic itself is unchanged, just relocated
- `backend/middleware/requireAdmin.js` now accepts either the original `isAdmin` boolean or `role` being `administrator`/`org_owner` - every existing Phase 8 admin account keeps working unchanged
- `backend/services/soar/ruleMatcher.js`'s `eventTriggerFor()` gained a conditional mapping (`login_failed` with `metadata.recentFailureCount >= 3` → `MULTIPLE_FAILED_LOGINS`), the same pattern already used for `MITRE_CRITICAL`
- `backend/services/siem/eventCatalog.js`/`SecurityEvent.js` extended (additive) with `login_failed`, `mfa_success`, `mfa_failed`, `passkey_login`, `device_trusted`, `policy_block`, `step_up_auth`, and a new `IAM` category (also added to `Incident.category`)
- Added "Identity & Access" to the main navigation (`frontend/components/shell/navItems.ts`)
- New dependencies: `otplib`, `qrcode`, `@simplewebauthn/server` (backend); `@simplewebauthn/browser` (frontend)

---

## Phase 8 — Security Orchestration, Automation & Response (SOAR)
**2026-07-04**

Automatically responds to security events using configurable automation rules and reusable playbooks - closing the loop between Phase 6's unified event feed and actual remediation, without adding new detection logic or modifying any existing detection/crypto/policy code.

### Added
- `backend/models/AutomationRule.js` - trigger + conditions + ordered actions (inline or via a shared playbook), priority, enabled flag
- `backend/models/Playbook.js` - named, reusable ordered list of response action steps
- `backend/models/AutomationExecution.js` - full audit record of every rule firing: actions executed, status, duration, result, linked incident
- `backend/models/Notification.js` - in-app notification record used by the notifyUser/notifyAdmin actions
- `backend/services/soar/ruleMatcher.js` - pure, DB-free `matchRules`/`evaluateCondition`/`eventTriggerFor`, unit tested like `correlationEngine.js`'s `evaluateRules`
- `backend/services/soar/playbookRunner.js` (`runPlaybook`) - executes ordered steps against an injectable action-handler registry, supporting `continueOnFailure` and completed/partial/failed status
- `backend/services/soar/actions/` - 13 response action handlers (quarantineFile, deleteFile, blockDownload, revokeSession, logoutUser, disableDevice, markFileHighRisk, raiseIncident, notifyUser, notifyAdmin, sendEmail, generateSiemEvent, generateAuditLog), registered in `actions/index.js` mirroring the `dlp/detectors/index.js` pattern
- `backend/services/soar/soarEngine.js` (`runSoarEngine`) - the orchestrator, called from a single interception point (`siemLogger.js`, right after correlation) with a recursion guard against automation-generated events
- `backend/services/soar/seedPlaybooks.js` - seeds 5 example playbooks (Malware Response, Credential Leak Response, DLP Response, Suspicious Device Response, Known Malicious IOC Response) and their triggering rules once at server startup
- `backend/middleware/requireAdmin.js` - the first admin-gating middleware in this codebase
- SOAR REST API (`/api/soar/rules`, `/playbooks` [+clone/import/export], `/action-types`, `/executions`, `/stats`, `/export`)
- SOAR dashboard (`frontend/app/soar/page.tsx`) - rule/playbook management, Recent/Failed Executions, Automation Success Rate/Action Distribution/Top Rules/Top Playbooks/Automation Frequency charts, CSV/JSON export
- `frontend/lib/auth.ts` - client-side JWT payload decode for the `isAdmin` UI convenience claim (never trusted for actual authorization)
- `backend/tests/soarEngine.test.js` - unit tests for rule matching, playbook execution ordering/failure handling, and the automation recursion guard

### Changed
- `backend/models/User.js` gained `isAdmin` (default `false`) - the first role field in this codebase, additive and safe for every existing account
- `backend/controllers/auth.controller.js`'s login now includes `isAdmin` in the signed JWT (a UI convenience claim only; the backend always re-checks the User document)
- `backend/models/Incident.js` gained `automationStatus`, `executedPlaybooks[]`, `actionTimeline[]`, `responseDurationMs` - additive fields populated by the SOAR engine after `correlationEngine.js`'s existing incident logic runs, untouched
- `backend/services/siem/eventCatalog.js`'s `TYPE_META`/`CATEGORIES` extended (additive) with `playbook_started/completed/failed`, `automation_triggered/skipped`, `session_revoked_automatically`, `file_quarantined_automatically`, `user_notified`, and a new `AUTOMATION` category
- `backend/services/siem/siemLogger.js` now calls `runSoarEngine()` (fire-and-forget) after correlation, re-fetching the persisted event first so `correlationId` is current
- **Bug fix**: `backend/models/SecurityEvent.js`'s `type`/`siemType` enums were missing every Phase 7 (Threat Intelligence) value - those events were silently failing Mongoose validation since Phase 7 shipped. Fixed alongside the Phase 8 additions; both Phase 7's and Phase 8's event types are now present in both enums
- Added "SOAR" to the main navigation (`frontend/components/shell/navItems.ts`)

---

## Phase 7 — Threat Intelligence & IOC Intelligence
**2026-07-04**

Cross-references every upload against Indicators of Compromise (IOCs), MITRE ATT&CK techniques, and YARA-style detection rules, sitting as an enrichment layer between malware/DLP scanning and SIEM event emission - without modifying any existing detection, cryptography, or Zero Trust logic.

### Added
- `backend/models/IOC.js` - the local IOC database (IP/domain/URL/SHA256/SHA1/MD5/email/filename/certificate-fingerprint), each record carrying confidence, severity, source, tags, and references
- `backend/models/YaraRule.js`, `backend/models/ThreatIntelScan.js` - stored detection rules and per-file enrichment results
- `backend/services/threatIntel/providers/` - six provider modules (VirusTotal, AbuseIPDB, AlienVault OTX, URLHaus, OpenPhish, CIRCL), each gracefully skipping (never throwing) when its API key is unset, registered in a `PROVIDERS` array mirroring `dlp/detectors/index.js`'s pattern
- `backend/services/threatIntel/iocLookupService.js` - merges local IOC hits with provider results into one normalized confidence/severity verdict
- `backend/services/threatIntel/mitreMapping.js` - a curated MITRE ATT&CK technique subset with keyword-based mapping
- `backend/services/threatIntel/yaraEngine.js` - a documented, simplified YARA-like rule matcher (`strings:`/`condition:` subset) plus `ensureSeedRules()`, called once at server startup
- `backend/services/threatIntel/extractors.js` - dependency-free URL/domain/email/IPv4 extraction from explicitly-submitted plaintext
- `backend/services/threatIntel/threatIntelEngine.js` (`runThreatIntelScan`) - the orchestrator tying hash lookups, YARA matching, and MITRE mapping into one result
- `backend/services/threatIntel/threatIntelIntegration.js` (`runThreatIntelScanAsync`) - fire-and-forget hook called from `file.controller.js` right after upload, operating on already-computed file hashes (never re-reading plaintext, respecting the zero-knowledge boundary)
- Threat Intelligence REST API (`/api/threat-intel/scan-text`, `/scans`, `/stats`, `/search`, `/iocs`, `/mitre`, `/yara-rules`, `/export`)
- Threat Intelligence dashboard (`frontend/app/threat-intelligence/page.tsx`) - IOC summary stat cards, global IOC/MITRE/YARA search, Top IOC Types and Confidence Distribution charts, a Threat Timeline, MITRE technique badges, YARA match list, Threat Feed table, and CSV/JSON export
- `backend/tests/threatIntel.test.js` - unit tests for indicator extraction, MITRE mapping, YARA rule parsing/condition evaluation, and every provider's graceful-skip behavior

### Changed
- `backend/services/siem/eventCatalog.js`'s `TYPE_META` extended (additive only) with `ioc_match`, `ioc_lookup`, `threat_intel_match`, `mitre_mapping`, `yara_match`, `provider_error`
- `backend/models/File.js` extended with optional `threatIntelScanId`/`threatScore`/`threatConfidence`/`iocMatchCount` fields, all defaulting to values that leave pre-Phase-7 files unaffected
- `backend/controllers/file.controller.js`'s upload handler now fires `runThreatIntelScanAsync()` after linking the malware/DLP scans - fire-and-forget, never blocks or fails the upload response
- `frontend/app/threats/page.tsx` gained a link card to the new Threat Intelligence dashboard with a live MITRE technique count
- Added "Threat Intelligence" to the main navigation (`frontend/components/shell/navItems.ts`)

---

## Phase 6 — Centralized SIEM Platform
**2026-07-03**

Unified event visibility across every prior phase - one taxonomy, one severity scale, automatic correlation into incidents, and a Security Operations Center dashboard - without modifying any existing detection, cryptography, Zero Trust, malware scanning, or DLP logic.

### Added
- `backend/services/siem/eventCatalog.js` - single-source-of-truth mapping from every `SecurityEvent.type` (legacy and new) to a canonical `siemType`, default `severity` (`INFO`/`LOW`/`MEDIUM`/`HIGH`/`CRITICAL`), and `category`
- `backend/services/siem/siemLogger.js` (`logSecurityEvent`) - the one function that now writes every `SecurityEvent` document; every controller that previously called `SecurityEvent.create(...)` directly now calls this instead, with identical arguments
- `backend/services/siem/correlationEngine.js` - a small, pure, unit-tested rule engine (`evaluateRules`) plus a DB-aware wrapper (`correlateEvent`) that groups related events into `Incident` documents: malware quarantined → later download denied; 3+ DLP violations within an hour; a new device followed by a denied access attempt
- `Incident` model (`backend/models/Incident.js`) - correlated event groups with severity, category, status, and the full list of grouped `SecurityEvent` ids
- New event emission points that previously went unlogged: `LOGIN`, `REGISTER`, `SESSION_CREATED`, `UPLOAD`, `DOWNLOAD_ALLOWED`, `THREAT_FOUND` (elevated risk that didn't trigger quarantine)
- `POST /api/siem/events/signature` - a narrowly-scoped, whitelisted endpoint (`verified`/`invalid` only) letting the frontend report client-side ECDSA signature verification outcomes, closing the previous gap where the server never learned whether a download's signature check passed
- SIEM REST API (`/api/siem/dashboard`, `/events`, `/incidents`, `/incidents/:id`, `/search`, `/export`, `/stats`, `/catalog`) - all authenticated and scoped to the caller's own account, matching every other dashboard in the app
- Security Operations Center dashboard (`frontend/app/soc/page.tsx`) - a tabbed layout (Overview, Events, Incidents, Timeline, Analytics) with 8 stat cards, a Recent Activity/Recent Incidents panel, an animated live event feed, 9 Recharts panels (Security Activity, Threat Trend, Severity Distribution, Category Distribution, Incident Timeline, Incidents by Status, Risk Trend, DLP Findings, Zero Trust Events), a critical alerts panel, filtering (date/severity/category/device/country/file/incident), full-text search, and CSV/JSON export
- Incident Viewer (`frontend/components/soc/IncidentViewer.tsx`) - a slide-over detail panel for a single incident (title, severity, status, category, chronological timeline, referenced files, and expandable per-event evidence), backed by `GET /api/siem/incidents/:id`
- `backend/tests/correlationEngine.test.js` - unit tests for the correlation engine's pure rule evaluation, using the same `node --test` pattern as the existing DLP tests

### Changed
- `SecurityEvent` model extended with optional `siemType`, `severity`, `category`, `correlationId`, and `metadata` fields, plus two new indexes (`{owner, severity, createdAt}`, `{owner, correlationId}`)
- `SecurityEvent.type` enum extended with new lowercase values (`login`, `register`, `session_created`, `upload`, `download_allowed`, `threat_found`, `signature_verified`, `signature_invalid`, `policy_violation`) alongside the original 8 - purely additive
- `frontend/app/file/[id]/page.tsx`'s existing `verifySignature()` now reports its outcome to `POST /api/siem/events/signature` after verifying - no change to the ECDSA verification logic itself
- Added "Security Operations" to the main navigation (`frontend/components/shell/navItems.ts`)

### Compatibility
- Every field on the original `SecurityEvent` schema, and its original 8-value `type` enum, is unchanged - `GET /api/security/events` and the Audit Logs page (`/audit`) work exactly as before
- All new `SecurityEvent` fields are optional; events logged before this phase simply lack them and appear as "uncategorized" in SIEM views
- No detection, cryptography, Zero Trust, malware scanning, or DLP logic was modified - only the logging call at each existing site changed (same arguments, different function), and a few new logging calls were added at points that previously went unlogged
- The SIEM is scoped per-user (`owner: req.user.id`), identical to every other dashboard in the app - no new admin/RBAC concept was introduced

---

## Phase 4 — Malware Scanning & Threat Detection
**2026-07-02**

Introduced a full pre-encryption malware scanning and threat classification pipeline, reconciling content-safety scanning with the zero-knowledge architecture via a narrowly-scoped, documented exception.

### Added
- `POST /api/threats/scan` — transient, pre-encryption plaintext scan endpoint (the one deliberate exception to "server never sees plaintext"; buffer is never persisted or logged)
- Magic-byte file-type detection (`backend/utils/magicBytes.js`), independent of claimed filename/MIME type — catches disguised executables
- MIME-mismatch detection between claimed and actual file type
- SHA-256, SHA-1, and MD5 hash generation for every scanned file (`backend/utils/fileHashes.js`)
- ClamAV integration via a hand-rolled `clamd` INSTREAM TCP client (`backend/services/clamavScanner.js`) — no external npm dependency, graceful `"unavailable"` degradation if `clamd` isn't reachable
- Optional VirusTotal API v3 hash lookup (`backend/services/virusTotalLookup.js`) — skipped cleanly if `VIRUSTOTAL_API_KEY` is unset
- Configurable risk engine (`backend/services/riskEngine.js`) classifying every scan as Low/Medium/High/Critical based on malware detection, dangerous extensions, macros, encrypted archives, and MIME mismatches — including a dedicated rule for disguised-executable detection
- Automatic quarantine of High/Critical-risk uploads — enforced unconditionally at download time, independent of any other passing check
- `ThreatScan` model capturing full scan results (hashes, detected types, engine verdicts, risk level, quarantine status)
- `File` model extended with `scanId`, `scanStatus`, `riskLevel`, `quarantined`
- Threat Center dashboard (`frontend/app/threats/page.tsx`) — scan history, quarantined files, malware detections, threat statistics, manual quarantine release
- REST APIs for scan history, quarantine management, and aggregate threat statistics (`/api/threats/*`)
- Audit log entries (`File.logs[]`) extended with `scanStatus`/`riskLevel` snapshots

### Changed
- `uploadFile` (v2/E2E path) now requires a valid, unconsumed `scanId` referencing a completed scan
- `downloadFile` checks quarantine status before anything else — before the Zero Trust policy engine, before signature verification, before decryption

### Compatibility
- Every file uploaded before this phase defaults to `scanStatus: "not_scanned"`, `quarantined: false` — fully unaffected and still downloadable
- Legacy (`encryptionVersion: 1`) uploads scan inline during their existing server-side flow, since they already receive plaintext server-side

---

## Phase 3 — Zero Trust Access Control
**2026-07-02**

Added an access-control layer that evaluates every download request against device, network, timing, and identity signals — independent of whether the file's encryption/signing checks pass.

### Added
- Client-side device fingerprinting (`frontend/lib/security/fingerprint.ts`) — SHA-256 hash of user agent, platform, language, timezone, screen resolution, and a canvas rendering signature; only the resulting hash is ever transmitted
- `Device` model — devices are recorded and trusted automatically on successful password-authenticated login (trust bootstrap)
- `Session` model — JWTs now embed a revocable session id (`sid`); sessions can be individually revoked from the Security Center, checked on every authenticated request
- Configurable per-file access policy engine (`backend/services/policyEngine.js`, pure function) supporting: allowed countries, allowed IPs, allowed devices, business-hours windows (including overnight ranges), max distinct devices, and an approval requirement
- Best-effort country resolution from CDN/proxy geo-IP headers (`backend/utils/geoLookup.js`) — fails closed to `"Unknown"` when unavailable
- `SecurityEvent` model — unified activity feed for new devices, device removals, session revocations, and blocked downloads
- Security Center dashboard (`frontend/app/security/page.tsx`) — trusted devices, active sessions, blocked access attempts, recent security events
- REST APIs for device management, session management, and security events (`/api/devices`, `/api/sessions`, `/api/security/events`)
- Audit log entries (`File.logs[]`) extended with `deviceId`, `browser`, `operatingSystem`, `country`, `decision`, `denialReason`

### Changed
- `backend/middleware/auth.middleware.js` now checks session revocation on every request (tokens without a `sid` claim — issued before this phase — skip the check, treated as untracked legacy sessions)
- Login now records/refreshes a `Device` entry and creates a `Session` document

### Compatibility
- `File.policy` defaults to an all-empty subdocument — evaluates to unconditional `allow`, so every pre-Phase-3 file and every new file without a configured policy is unaffected
- Tokens issued before this phase (no `sid` claim) continue to work without being logged out

---

## Phase 2 — Digital Signatures & Integrity Verification
**2026-07-02**

Added cryptographic authenticity and integrity guarantees on top of Phase 1's confidentiality — a recipient can now verify who produced a file and that it hasn't been altered, before decrypting it.

### Added
- Per-user ECDSA P-256 signing keypair, generated client-side and kept entirely separate from the RSA-OAEP encryption keypair
- New crypto modules: `frontend/lib/crypto/ecdsa.ts` (keypair generation, import/export), `hash.ts` (standalone SHA-256), `signature.ts` (`signEncryptedFile`/`verifyEncryptedFileSignature`)
- Signing private key encrypted with the same PBKDF2-derived-from-login-password mechanism as the RSA private key, stored only in IndexedDB
- `User.signingPublicKey` field and `PATCH/GET /api/users/signingkey` endpoints
- `File` model extended with `signature`, `fileHash`, `hashAlgorithm`, `signatureAlgorithm`, `signedAt`
- Client-side signature verification before decryption on every download — a failed check blocks the download entirely with a tampering warning
- UI feedback: signing progress during upload, verification progress and pass/fail/unsigned states during download

### Compatibility
- Signing is fully additive and optional per file — files without a `signature` (legacy, or uploaded before this phase) are treated as "unsigned," not an error, and download unblocked

---

## Phase 1 — Zero-Knowledge End-to-End Encryption
**2026-07-02**

Migrated SecureShare from server-side encryption to true client-side, zero-knowledge end-to-end encryption — the server no longer has any code path capable of reading uploaded file content.

### Added
- Client-side AES-256-GCM file encryption (Web Crypto API) — a fresh key and random 96-bit IV generated per file, entirely in the browser
- Per-user RSA-OAEP-SHA256 keypair (3072-bit by default), generated client-side; public key uploaded to the server, private key encrypted with a PBKDF2-derived key from the login password and stored only in IndexedDB
- Two zero-knowledge sharing modes: raw AES key in the share link's URL fragment (never transmitted), or password-derived key wrapping (PBKDF2-SHA256, password never sent to the server)
- New crypto module structure under `frontend/lib/crypto/` (`aes.ts`, `rsa.ts`, `pbkdf2.ts`, `base64.ts`, `fileEncryption.ts`, `keyStorage.ts`, `cryptoHelpers.ts` barrel)
- `encryptionVersion` field on `File` distinguishing legacy server-side encryption (`1`) from the new client-side E2E flow (`2`)
- New download page (`frontend/app/file/[id]/page.tsx`) performing client-side decryption

### Changed
- `uploadFile`/`downloadFile` split into version-specific paths — new uploads perform zero server-side cryptography (pure ciphertext passthrough to/from Cloudinary)

### Compatibility
- Pre-Phase-1 files (`encryptionVersion: 1`, the default) continue to use the original server-side AES-256-CBC + global RSA-2048 keypair flow unchanged, relocated to `backend/utils/legacy/`

---

## Pre-Phase-1 (baseline)

The original SecureShare: server-side AES encryption, RSA key wrapping with a single global keypair, JWT authentication, password-protected/expiring/one-time-download links, Cloudinary storage, and per-file download audit logs. See the early commit history (`5fda074`, `b532e88`, and earlier) for this baseline implementation.
