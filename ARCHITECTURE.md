# SecureShare — Architecture Notes

This file supplements [README.md](README.md)'s per-phase architecture diagrams with a short, standalone reference for the newest subsystem. See README's [System Architecture](README.md#-system-architecture) section for the overall request-flow diagrams across Phases 1-10.

## Phase 5.1: Confidence-Based DLP Engine

Extends Phase 5's regex-only DLP detectors with a scoring layer that reduces false positives (a Rapido ride receipt's "Ride ID" being auto-blocked as a credit card) without touching the existing detector registry, policy config shape, or API contracts.

```
                     detector.detect(text)              (unchanged, all 19 detectors)
                              │
                     detector.detectWithConfidence(text)  (opt-in, currently: credit_card)
                              │
                              ▼
                    ┌──────────────────────┐
                    │ confidenceEngine.js  │
                    └──────────┬───────────┘
                               │
        ┌──────────────────────┼──────────────────────┐
        ▼                      ▼                      ▼
  Regex match (+40)      Luhn validation (+40)   Context analysis (+20 / override)
                                                  ┌─────────────┬─────────────┐
                                                  ▼             ▼
                                          card keywords   non-card ID keywords
                                          (Visa, CVV,      (Ride ID, Invoice No,
                                           Cardholder...)   Booking ID...) → force
                                                            confidence toward 0
                               │
                               ▼
                     Confidence Score (0-100)
                               │
                               ▼
              LOW (0-40) / MEDIUM (41-70) / HIGH (71-100)
                               │
                               ▼
                decisionForConfidenceLevel(level)
             Allow+Log / Allow+Warn / Block+Log+SIEM
                               │
                               ▼
              finding.decisionHint  ──▶  dlpPolicyConfig.resolveDecision()
       (per-instance decision takes priority over the blanket per-detector
        policy, e.g. credit_card's normal hard-block override)
                               │
                               ▼
                    runDLPScan() aggregates every
                    finding into a uniform riskReport
                    { pattern, confidence, confidenceLevel,
                      reasons, matchedText, context, decision }
                               │
                               ▼
        DLPScan document  ──▶  DLP Center UI  +  SIEM event metadata
```

**Backward compatibility**: `detect()` on every detector (including `credit_card`) is untouched and still returns a plain `string[]` - existing callers/tests (`backend/tests/dlp.test.js`) are unaffected. `detectWithConfidence()` is an additional, optional export; `dlpEngine.js` prefers it when present and falls back to `detect()` otherwise, so adding confidence scoring to another detector later is opt-in, not a breaking change.

**New detectors**: `iban` and `swift_bic` were added to close the Part 9 test matrix (IBAN/SWIFT must be "Detected"). `swift_bic` requires a nearby "SWIFT"/"BIC" keyword before it fires at all, since the bare 8/11-character alphanumeric shape is otherwise indistinguishable from ordinary uppercase text - the same context-analysis idea as the credit card scorer, applied as a hard gate instead of a score adjustment.

For the full weighting/threshold tables and code entry points, see [README.md's Confidence-Based DLP Engine section](README.md#confidence-based-dlp-engine) and [CHANGELOG.md](CHANGELOG.md).

## Phase 11: Cloud Security Posture Management & Attack Surface Management

SecureShare is a single-tenant, self-hosted application with no multi-cloud account to enumerate. Phase 11's "cloud" scanning is therefore self-referential: it discovers and scores SecureShare's own Express/Next.js deployment, not external cloud resources.

```
                        ┌─────────────────────────────┐
                        │   cloudScanOrchestrator.js  │
                        │        runCloudScan()       │
                        └──────────────┬──────────────┘
                                       │
        ┌──────────────┬──────────────┼──────────────┬──────────────┐
        ▼              ▼              ▼              ▼              ▼
 assetDiscovery  configScanner  certificateMonitor  attackSurface  threatIntel
   .js               .js              .js           Scanner.js   Correlation.js
        │              │              │              │              │
        ▼              ▼              ▼              ▼              ▼
      Asset       CloudFinding    Certificate    CloudFinding   CloudFinding
                  (CONFIGURATION)                (EXPOSURE)     (THREAT_INTEL)
        │              │              │              │              │
        └──────────────┴──────────────┴──────────────┴──────────────┘
                                       │
                                       ▼
                              scoreEngine.js
                        (Asset/Config/Exposure/Cert/
                         Identity/Compliance scores)
                                       │
                                       ▼
                          SecurityScoreSnapshot
                                       │
                                       ▼
                    logSecurityEvent() ──▶ SIEM correlation ──▶ SOAR engine
                                       │                            │
                                       ▼                            ▼
                     cloudSecurityEvaluator                "Cloud Exposure Response"
                     (lowers ISO27001/SOC2/GDPR/            playbook (raise incident,
                      PCI DSS/NIST CSF/OWASP scores)         notify admin, rerun scan,
                                                              generate report)
```

**Trigger points**: daily `node-cron` (04:00), a startup scan (~10s after Mongo connects), a fire-and-forget rescan after any Compliance policy update, and `POST /api/cloud/scan` for manual/CI-CD-triggered runs.

**Self-scan boundary**: `attackSurfaceScanner.js` and `certificateMonitor.js` only ever target SecureShare's own configured base URL/domains (`APP_BASE_URL`, `CLOUD_MONITORED_DOMAINS`, `WEBAUTHN_ORIGIN`) - there is no code path that accepts an arbitrary target, by design.

**Data model**: `Asset` (inventory) → `CloudFinding` (category: CONFIGURATION | EXPOSURE | CERTIFICATE | THREAT_INTEL, optionally linked to an `Asset`) → `SecurityScoreSnapshot` (one per scan run, backing the dashboard's trend chart) - the same "current state + append-only history" shape Phase 10's `ComplianceControl`/`ComplianceAssessment` already established.

For the full endpoint list, SIEM event catalog, and SOAR trigger wiring, see [README.md's Phase 11 section](README.md#%EF%B8%8F-phase-11-cloud-security-posture-management--attack-surface-management) and [CHANGELOG.md](CHANGELOG.md).

## Phase 12: Enterprise DevSecOps & Software Supply Chain Security

Same self-referential principle one layer down the stack: there is no real multi-repo GitHub org, CVE feed, or CI system to integrate with, so Phase 12 scans SecureShare's own git repository, dependency manifests, source tree, Dockerfile, and docker-compose.yml.

```
                        ┌──────────────────────────────┐
                        │  devSecOpsOrchestrator.js    │
                        │     runDevSecOpsScan()       │
                        └───────────────┬──────────────┘
                                        │
   ┌────────────┬────────────┬─────────┼─────────┬────────────┬────────────┐
   ▼            ▼            ▼         ▼         ▼            ▼            ▼
repository  dependency    secret      sast    container      iac      pipeline +
 Scanner     Scanner     Scanner    Scanner    Scanner     Scanner   artifactSecurity
   │            │            │         │         │            │            │
   ▼            ▼            ▼         ▼         ▼            ▼            ▼
Repository  DevSecOpsFinding (category: DEPENDENCY|SECRET|SAST|CONTAINER|IAC)  PipelineRun
                                                                            ArtifactSignature
   │            │            │         │         │            │            │
   └────────────┴────────────┴─────────┴─────────┴────────────┴────────────┘
                                        │
                                        ▼
                                riskEngine.js
                       (Repository/Dependency/Secret/
                          Container/Pipeline scores)
                                        │
                                        ▼
                          DevSecOpsScoreSnapshot
                                        │
                                        ▼
                    logSecurityEvent() ──▶ SIEM correlation ──▶ SOAR engine
                                        │                            │
                                        ▼                            ▼
                       devSecOpsEvaluator              "Supply Chain Incident Response"
                    (lowers ISO27001/SOC2/NIST/          playbook (raise incident, notify
                     PCI DSS/CIS/OWASP scores)           admin, advisory deployment block,
                                                          rerun scan, generate report)
```

**Trigger points**: daily `node-cron` (05:00, offset from Compliance's 03:00 and Cloud's 04:00), a startup scan (~15s after Mongo connects, skipping the live npm-registry check), and `POST /api/devsecops/scan` for manual/CI-CD-triggered runs.

**Self-scan boundary**: every scanner reads this repo's own files (`git` commands, `package.json`/`package-lock.json`, source tree, `Dockerfile`, `docker-compose.yml`) - none accepts an external target, and none calls a real CVE/NVD database or container registry. `secretScanner.js`/`sastScanner.js` additionally exclude their own `backend/services/devsecops/` implementation from the scan, since their rule definitions' descriptive text/patterns would otherwise trivially self-match.

**Data model**: `Repository` (one self-scanned row) + `DevSecOpsFinding` (category: DEPENDENCY | SECRET | SAST | CONTAINER | IAC | PIPELINE) + `SBOMDocument`/`PipelineRun`/`ArtifactSignature` → `DevSecOpsScoreSnapshot` (one per scan run, backing the dashboard's trend chart) - the same "current state + append-only history" shape Phase 10/11 already established.

For the full endpoint list, SIEM event catalog, and SOAR trigger wiring, see [README.md's Phase 12 section](README.md#%EF%B8%8F-phase-12-enterprise-devsecops--software-supply-chain-security), [API.md](API.md), and [CHANGELOG.md](CHANGELOG.md).

## Phase 13: Production Hardening & Cloud Platform Operations

An operations layer over the platform's managed cloud dependencies, wired through the same existing SIEM/SOAR/Compliance plumbing every prior phase uses - no new orchestration engine, and no VPS/host-level monitoring since this deployment target (Vercel + Render + MongoDB Atlas + Redis Cloud + Cloudinary) has no VM to introspect.

```
                    ┌────────────────────────────────┐
                    │   platformOrchestrator.js       │
                    │      runPlatformScan()          │
                    └────────────────┬─────────────────┘
                                     │
              ┌──────────────────────┼──────────────────────┐
              ▼                      ▼                      ▼
       healthChecker.js      metricsCollector.js      alertEngine.js
  (MongoDB Atlas/Redis Cloud/  (API latency/error-rate,  (rule array over
   Cloudinary/ClamAV-Render/    scan durations, auth       health + metrics)
   queue/backend+frontend/      success rate, scan-
   scheduler)                    activity counts)
              │                      │                      │
              ▼                      ▼                      ▼
   PlatformHealthSnapshot   PlatformMetricSnapshot     PlatformAlert
              │                      │                      │
              └──────────────────────┴──────────────────────┘
                                     │
                                     ▼
                     logSecurityEvent() ──▶ SIEM correlation ──▶ SOAR engine
                                     │                            │
                                     ▼                            ▼
                        platformOpsEvaluator            admin notification /
                     (lowers ISO27001/SOC2/NIST/          incident playbooks
                        PCI DSS availability scores)

        ┌─────────────────────┐        ┌──────────────────────┐
        │   scheduler.js       │        │   queue.js (BullMQ +   │
        │ (last/next run,       │        │   Redis Cloud)          │
        │  status, failures,    │        │  threat/malware/cloud/  │
        │  tracked in            │        │  compliance/devsecops/  │
        │  PlatformScheduledJob) │        │  report/notification/   │
        └─────────────────────┘        │  email queues, or        │
                                        │  in-process fallback      │
                                        │  when Redis Cloud is down │
                                        └──────────────────────┘
                                     │
                                     ▼
                            PlatformJob (status/duration/
                             retryCount/logs either way)
```

**Trigger points**: a platform health/metrics/alert scan every 5 minutes and a nightly full backup at 02:00, both registered through `scheduler.js` alongside the pre-existing Phase 10/11/12 daily scans (which are now also registered through it, unchanged in timing), plus `POST /api/platform/scan` for on-demand runs.

**Graceful degradation is structural, not incidental**: `middleware/redisClient.js`'s `isRedisAvailable()` is checked by rate limiting, the queue, and the health checker independently - each has its own fallback path (in-memory rate-limit store, in-process job execution, a `DOWN` health component) rather than one central "Redis mode" flag, so a Redis Cloud outage degrades functionality gracefully instead of cascading into a full outage.

**No reverse proxy or container orchestration layer**: Vercel and Render each handle their own TLS termination, reverse proxying, and process supervision for this deployment target - Phase 13 adds no Nginx configuration or Docker Compose stack. `backend/Dockerfile` remains available for teams who prefer Render's Docker deploy option, but is not required (Render's native Node buildpack works identically).

**Data model**: `PlatformHealthSnapshot`/`PlatformMetricSnapshot` (one per scan run, backing the dashboard's trend charts - the same "current state + append-only history" shape Phase 10/11/12 already established), `PlatformJob` (one per background job execution), `PlatformScheduledJob` (one per registered cron job), `PlatformAlert` (active/resolved alert instances), `PlatformBackup` (one per backup archive, with checksum + validation state).

For the full endpoint list, SIEM event catalog, and SOAR trigger wiring, see [README.md's Phase 13 section](README.md#%EF%B8%8F-phase-13-production-hardening--cloud-platform-operations), [API.md](API.md), [MONITORING.md](MONITORING.md), and [CHANGELOG.md](CHANGELOG.md).

---

## Phase 15: Frontend RBAC & Role-Aware UI

```
                JWT (role, isAdmin, org_owner claims)
                              │
                              ▼
                  frontend/hooks/useRole.ts
              { ready, role, isAdmin, isOrgOwner }
                              │
              ┌───────────────┼────────────────┐
              ▼               ▼                ▼
        <AdminOnly>/    <RequireRole>      SidebarNav /
        <RoleGuard>     (full-page guard,   Topbar / QuickSearch
        (hide a piece    redirect to         (filter nav items,
         of a shared      /login or /403)     shortcuts, and
         page)                                search categories)
```

Every admin-gated backend router (`cloud.routes.js`, `compliance.routes.js`, `devsecops.routes.js`, `platform.routes.js` - all `router.use(auth, requireAdmin)`; `iam.routes.js` and `soar.routes.js` - `requireAdmin`/`requireRole` per-route) already enforced access server-side since Phase 8/9. This phase makes the frontend match that boundary exactly, so a non-admin never sees a link, button, or search result that leads to a 403.

**Two guard shapes, chosen by whether the backend gates the whole router or just some routes on it**: pages fully behind `router.use(auth, requireAdmin)` (Compliance, Cloud Security, DevSecOps, Platform + sub-pages) are wrapped once at the page level in `<RequireRole role="admin">`. Pages that mix open and admin-only routes (Identity: policy GET is open, PUT is admin-only, role PATCH is `org_owner`-only; SOAR: rule/playbook reads are open, mutations are admin-only) instead wrap just the admin-only JSX in `<AdminOnly>`, leaving the rest of the page visible to every authenticated user.

**No duplicated role logic**: earlier iterations of these pages independently called `getIsAdminFromToken(localStorage.getItem("token"))` into local component state; all of that was consolidated onto the single `useRole()` hook so there is exactly one place that decodes the JWT for UI purposes.

See [README.md's Phase 15 section](README.md#%EF%B8%8F-phase-15-frontend-rbac--role-aware-ui) for the full component/file breakdown.
