# SecureShare — Architecture Notes

This file supplements [README.md](README.md)'s per-phase architecture diagrams with a short, standalone reference for the newest subsystem. See README's [System Architecture](README.md#-system-architecture) section for the overall request-flow diagrams across Phases 1-10.

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
