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
