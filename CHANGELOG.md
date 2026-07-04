# Changelog

All notable changes to SecureShare are documented in this file, grouped by the security phase that introduced them. Dates reflect when each phase's implementation commit landed.

This project does not yet follow strict [Semantic Versioning](https://semver.org/) tags in git, but the phase number is used informally as the major version (e.g. "Phase 4" ≈ `v4.x`).

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
