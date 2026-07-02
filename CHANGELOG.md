# Changelog

All notable changes to SecureShare are documented in this file, grouped by the security phase that introduced them. Dates reflect when each phase's implementation commit landed.

This project does not yet follow strict [Semantic Versioning](https://semver.org/) tags in git, but the phase number is used informally as the major version (e.g. "Phase 4" ≈ `v4.x`).

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
