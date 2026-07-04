# SecureShare — Security Overview

This document consolidates SecureShare's security model across all six implemented phases. For implementation detail and rationale behind each design decision, see the corresponding section of [README.md](README.md#-security-architecture-roadmap). For how to verify these guarantees hold, see [SECURITY_TESTING.md](SECURITY_TESTING.md).

---

## Security Features

### Zero-Knowledge Encryption (Phase 1)

Every file is encrypted **in the browser**, before any network request, using a freshly generated AES-256-GCM key. That key is wrapped (never sent raw) with the uploader's own RSA-OAEP public key for owner re-access, and made available to recipients either via a URL fragment (never transmitted to the server) or a password-derived key. The server only ever stores and serves ciphertext and wrapped keys — it has no code path capable of decrypting an `encryptionVersion: 2` file.

### Digital Signatures (Phase 2)

Every upload is signed client-side with the uploader's ECDSA P-256 private key, over a SHA-256 hash of the *encrypted* file. Downloaders verify this signature against the uploader's public signing key **before** attempting decryption — a mismatch (tampered ciphertext, forged signature, or wrong signer) blocks the download outright, never reaching the decryption step.

### Zero Trust Access Control (Phase 3)

No request is trusted by default, regardless of network origin or prior authentication. Every download is evaluated against the specific file's configured policy (country, IP, device, time-of-day, device-count cap, approval requirement) on every attempt — possessing a valid link and even the correct decryption key is necessary but not sufficient if a policy is configured. Sessions are individually revocable and checked on every authenticated request, independent of JWT expiry.

### Malware Detection (Phase 4)

Every new upload is scanned for malicious content — magic-byte type verification, cryptographic hashing, ClamAV signature scanning, optional VirusTotal hash lookup, and heuristic checks (dangerous extensions, macro-enabled documents, encrypted archives) — before it's stored. Files scoring High or Critical risk are automatically quarantined, which unconditionally blocks all future downloads regardless of any other passing check.

### Threat Classification

Every scan produces a single `riskLevel` (`Low` / `Medium` / `High` / `Critical`) from a pure, configurable rule engine (`backend/services/riskEngine.js`) combining all Phase 4 signals. See the **Risk Classification** table in [SECURITY_TESTING.md §4.8](SECURITY_TESTING.md#48-risk-classification) for the authoritative signal→level mapping, kept in one place to avoid drift between docs.

### Data Loss Prevention (Phase 5)

Every new upload of a supported text-based file is scanned for embedded secrets and PII — emails, phone numbers, Luhn-validated credit card numbers, Aadhaar/PAN/passport numbers, cloud/source-control/AI-service API keys and tokens, JWTs, PEM private keys, certificates, hardcoded passwords, and `.env`-style secrets — before it's encrypted. A configurable policy (`backend/services/dlp/dlpPolicyConfig.js`) resolves findings into one of four decisions: **Allow**, **Warn**, **Require Approval**, or **Block**. Blocked uploads are refused outright; nothing is encrypted or stored. Detected values are never persisted in full — only masked previews are kept, so the DLP scan history itself never becomes a secondary leak of the secrets it found. Binary/unsupported files are skipped gracefully rather than scanned.

### Security Information & Event Management (Phase 6)

Every event emitted by Phases 1-5 above — logins, uploads, downloads, quarantines, DLP verdicts, device/session changes, policy denials, and client-reported signature verification outcomes — is normalized into one taxonomy (`siemType`), assigned a severity (`INFO`/`LOW`/`MEDIUM`/`HIGH`/`CRITICAL`) and category, and written through a single logging service (`backend/services/siem/siemLogger.js`). A rule-based correlation engine (`backend/services/siem/correlationEngine.js`) groups related events into `Incident` records (e.g. a quarantined file later denied for download), surfaced in a unified Security Operations Center dashboard (`/soc`) with severity-ranked alerts, incident tracking, filtering, full-text search, and export.

**What the correlation engine does not do**: it is detection-only and purely observational. It never blocks, delays, alters, or auto-remediates a request — an `Incident` is a grouped, labeled view over events that already happened, not an enforcement mechanism. No cryptography, Zero Trust policy evaluation, malware scanning, or DLP detection logic was modified to build this phase; the SIEM only consumes their existing outputs.

### Threat Intelligence & IOC Intelligence (Phase 7)

Every uploaded file's hash is cross-referenced against a local IOC (Indicator of Compromise) database and, if configured, external reputation providers (VirusTotal, AbuseIPDB, AlienVault OTX, URLHaus, OpenPhish, CIRCL) — all optional and independently disableable, with enrichment always degrading to "no external data" rather than blocking or failing an upload. Matches are further mapped to MITRE ATT&CK techniques (a curated subset, not the full corpus) and checked against stored YARA-style detection rules (`backend/services/threatIntel/yaraEngine.js` — a documented, simplified `strings:`/`condition:` matcher, not a native `libyara` binding, to avoid a compiled-binary dependency). Results are surfaced on the `/threat-intelligence` dashboard and fed into the same SIEM taxonomy as every other phase (`IOC_MATCH`, `THREAT_INTEL_MATCH`, `MITRE_MAPPING`, `YARA_MATCH`, `PROVIDER_ERROR`).

**Zero-knowledge boundary respected**: by the time enrichment runs (after upload completes), the server no longer holds the file's plaintext — automatic enrichment only ever operates on the SHA-256/SHA-1/MD5 hashes already computed during the Phase 4 pre-encryption scan. The one place raw text is intentionally examined for embedded URLs/domains/emails/IPs is `POST /api/threat-intel/scan-text`, a deliberate, explicit, auth-only endpoint mirroring the same "documented scoped exception" pattern Phase 4/5 already use for pre-encryption scanning — it is never invoked against DLP's masked findings, which intentionally never contain raw matched values.

**What Phase 7 does not do**: like the SIEM correlation engine, it is detection/enrichment-only — a critical IOC/YARA/MITRE match never blocks an upload or a download by itself (that remains Phase 3's Zero Trust policy engine and Phase 4/5's quarantine/block decisions). No existing model, route, or controller behavior was changed; every integration point is additive.

### Security Orchestration, Automation & Response (Phase 8)

Configurable Automation Rules watch the unified SecurityEvent stream Phase 6 already produces; when a rule's trigger and conditions match, its Playbook's ordered response actions run automatically (quarantine a file, revoke a session, disable a device, notify the owner/an administrator, raise an incident). Every execution — including every individual action's success/failure — is recorded as an `AutomationExecution` document, and the correlated `Incident` (if any) is updated with the automation's status and action timeline.

**Admin gating is new in this phase**: `User.isAdmin` (default `false`) is the first role concept in this codebase. Creating, editing, or deleting rules and playbooks requires an admin account, enforced server-side by `backend/middleware/requireAdmin.js`, which re-checks the User document on every request rather than trusting the JWT's `isAdmin` claim. Normal users can view automation history but only for their own files.

**No real email delivery**: `notifyUser`/`notifyAdmin`/`sendEmail` create in-app `Notification` records, not SMTP-delivered email — there is no mail transport in this codebase. This is documented plainly in the action handlers themselves rather than presented as email delivery.

**Recursion safety**: SOAR's own actions emit SecurityEvents (notifications, playbook status, audit-log entries), all tagged `category: "AUTOMATION"`. The engine's entry point explicitly ignores events in that category before doing any rule matching, so automation can never trigger itself in a loop.

**What Phase 8 does not do**: it does not add new detection capability — every trigger is sourced from an event a prior phase already produces. A playbook step failing never blocks or fails the original request that triggered it (e.g. a failed quarantine action doesn't undo an upload); failures are recorded for visibility on the `/soar` dashboard, not silently swallowed. No existing model, route, or controller behavior was changed — every integration point (the `isAdmin` field, the JWT claim, the `Incident` schema additions, the `logSecurityEvent` hook) is additive.

### Identity & Access Management + Multi-Factor Authentication (Phase 9)

Login gains TOTP MFA (`otplib`), WebAuthn passkeys (`@simplewebauthn/server`/`browser`), a five-level role model, a configurable global security policy, and risk-based step-up — all layered on top of the email+password flow every prior phase already relies on. **This is the one requirement that overrides all others in this phase: existing JWT authentication and plain password login must keep working unchanged for every account that hasn't opted into MFA/passkeys.** It does.

**Two-step MFA enrollment, never a half-enabled state**: `POST /api/mfa/setup` generates a secret and stores it as `User.mfa.pendingSecret` — inert until `POST /api/mfa/verify` proves possession with a real code, at which point (and only then) it's promoted to `User.mfa.secret` and `enabled: true`. An abandoned enrollment leaves the account exactly as it was.

**MFA-gated login is a two-request exchange, not a session-in-waiting**: when MFA is required, `POST /api/auth/login` returns `202 {mfaRequired: true, mfaToken}` — never a real session token. `mfaToken` is a JWT signed with `purpose: "mfa"` and a 5-minute expiry; `POST /api/mfa/verify-login` is the only endpoint that accepts it, and only after checking that exact claim, so it can't be replayed as (or mistaken for) a real session credential.

**Recovery codes are bcrypt-hashed, single-use, shown once**: `User.mfa.recoveryCodeHashes` never stores plaintext; `services/iam/recoveryCodes.js`'s `consumeRecoveryCode()` removes a matched hash from the array so it can never be reused.

**RBAC is additive over Phase 8's admin flag, not a replacement**: `backend/middleware/requireAdmin.js` now accepts *either* `User.isAdmin` *or* `role` being `administrator`/`org_owner` — every account granted admin access under Phase 8's original mechanism keeps working exactly as before. Role changes themselves require `org_owner` (`requireRole.js`), since granting `administrator` is itself a privilege-escalation-sensitive action.

**Security policy enforcement is deliberately mostly soft**: `services/iam/policyEngine.js`'s evaluators return flags (`passwordExpired`, `mfaSetupRequired`) rather than denying login, because this application has no self-service password-reset or account-unlock flow — a hard block here would be a permanent, unrecoverable lockout, not a security improvement. The single hard block is the country restriction (`evaluateCountryPolicy`), since "log in again from an allowed location" is an actually-recoverable failure mode, unlike the others.

**Adaptive authentication never blocks, only escalates or nudges**: `services/iam/loginRiskEngine.js`'s `scoreLogin()` is a pure function over three signals (new device, IP matching a local Phase 7 IOC record, country change) — network calls are deliberately excluded from the login path to keep it fast and to avoid Phase 7's optional external providers becoming a login-latency or availability dependency. A `High` score forces a step-up challenge if the account has MFA/a passkey; otherwise it only logs and recommends, since forcing enrollment mid-login isn't possible.

**Closing a real gap while adding SOAR integration**: prior to this phase, a failed login attempt was never logged anywhere — Phase 8 shipped with a `MULTIPLE_FAILED_LOGINS` automation trigger that could never fire because nothing produced the event it needed. `services/iam/loginFailureTracker.js` now logs `login_failed` with a rolling failure count on every bad password or MFA code, giving that trigger — and the newly seeded "Account Lockdown Response" playbook — a real source. Successful logins are entirely unaffected by this addition.

**What Phase 9 does not do**: it does not replace or weaken the existing JWT-based session model — MFA, passkeys, and policies all end at the same `issueSessionAndToken()` that plain password login always used. It does not implement real email delivery (see Phase 8's note above — `sendEmail`-style semantics remain in-app only). It does not force MFA on any account that hasn't explicitly enrolled or been targeted by an admin-configured policy/automation action.

### Enterprise Authentication & Adaptive Access (Phase 9.5)

Sharpens Phase 9's risk engine and, importantly, fixes two policies that phase defined but never actually enforced — `blockUntrustedDevices` and `sessionTimeoutMinutes` were schema fields with no code path checking them until this phase.

**Risk scoring is honest about its own limitations**: `services/iam/loginRiskEngine.js`'s four-tier score now includes VPN/Tor and impossible-travel signals, but `services/iam/networkIntel.js` explicitly documents that VPN/Tor detection is local-only (no external IP-intelligence subscription exists in this codebase) and that its illustrative Tor-node list is not exhaustive — real coverage requires an admin importing a maintained exit-node list into the Phase 7 `IOC` collection. Similarly, "impossible travel" is a country-level time-window heuristic, not a geodesic distance/speed calculation, because this codebase has no lat/long geo-database. Both limitations are stated in the code, not glossed over.

**Device restriction is a hard block, deliberately**: unlike password expiry or MFA-enrollment (Phase 9's soft blocks, chosen because this app has no account-recovery flow), `evaluateDevicePolicy()` denies outright. The reasoning is the same "is the recovery trivial?" test Phase 9 already applied to country restrictions — logging in from a device the account has already used, or getting added to an admin's allow-list, is always available to the genuine owner.

**Session timeout is enforced on every request, not just at login**: `backend/middleware/auth.middleware.js` now checks `evaluateSessionTimeout()` against the session's `lastActiveAt` before refreshing it, so an idle session is actually revoked rather than the policy field being silently decorative. A short in-memory cache on `SecurityPolicy.getPolicy()` (15 seconds) keeps this from adding a database round-trip to every authenticated request.

**No new detection capability, only better-informed automation**: the two new SOAR triggers (`IMPOSSIBLE_TRAVEL`, `CRITICAL_RISK_LOGIN`) route through the exact same `soarEngine.js`/`playbookRunner.js` Phase 8 built — this phase adds signals and a seeded playbook, not new orchestration machinery.

**What Phase 9.5 does not do**: it does not add a commercial-grade IP intelligence or geolocation integration (documented as a deployment-time extension point, not a built-in guarantee). It does not retroactively enforce the new password policy against existing accounts. It does not change what a JWT looks like, how sessions are revoked, or any Phase 1-9 detection/crypto logic.

### Enterprise Compliance & Governance (Phase 10)

A read-only governance layer over Phases 1-9.5 - it evaluates and reports on the state of existing controls, it does not itself enforce anything new. No detection, crypto, or auth code path was modified to build it.

**Evidence lifecycle**: every `runAssessment()` call builds one shared context from live queries (`File`, `User`, `SecurityEvent`, `Incident`, `AutomationRule`/`AutomationExecution`, `SecurityPolicy`), runs each control's evaluator against it, and persists both a `ComplianceAssessment` (score/status/recommendations) and a `ComplianceEvidence` document linking the control to the data that justified the verdict. Evidence is retained indefinitely and can be marked `approved` by an admin (`POST /api/compliance/evidence/:id/approve`) as a lightweight review trail - approval is advisory, it does not change the assessment's score.

**Control catalog is representative, not exhaustive**: `services/compliance/seedFrameworks.js` seeds real, correctly-mapped controls (ISO 27001, SOC 2, GDPR, HIPAA, PCI DSS, NIST CSF, CIS Controls, OWASP ASVS) but intentionally does not attempt each framework's full published control set. This is stated here so the compliance score is understood as "how well SecureShare's actual capabilities satisfy a curated sample of each framework's requirements," not a certified audit result.

**Policy versioning, never mutation**: `CompliancePolicy` documents are never updated in place - every change to `FILE_RETENTION_DAYS`, `MAX_UPLOAD_SIZE_MB`, `BLOCKED_FILE_TYPES`, `RESTRICTED_COUNTRIES`, or `DLP_ENFORCEMENT` inserts a new document with an incremented `version`, so the full history of what the policy was at any point in time is preserved for audit purposes.

**Deliberately does not duplicate SecurityPolicy**: MFA requirement, session timeout, password length, and allowed-countries settings already exist on Phase 9's `SecurityPolicy` singleton. Phase 10 reads them live via `evidenceCollector.js` rather than copying them into a second, potentially-divergent policy store.

**SOAR integration reuses existing plumbing, not new triggers on the hot path**: `compliance_scan`/`control_failed` events go through the same `logSecurityEvent()` → SOAR-engine re-entry every other phase's events already use. The new `COMPLIANCE_SCORE_DROP` trigger and `generateComplianceReport` action are additive entries in the existing trigger enum and action registry - no change to `soarEngine.js`'s orchestration logic itself.

**Admin-only, not per-user**: unlike `/identity` (a user's own account view), `/compliance` and every `/api/compliance/*` route require `requireAdmin` - this is org-wide governance data (aggregate scores, all users' MFA adoption, all files' encryption ratio), not something scoped to a single account.

**What Phase 10 does not do**: it does not block uploads, logins, or downloads based on policy violations - `policyEvaluator.js`'s `evaluatePolicyViolations()` is evidence-only today, feeding scores and recommendations rather than gating Phase 3/4/5's existing enforcement paths (a documented follow-up, not an oversight - wiring a new hard block into the upload path was out of scope for an additive governance layer). It does not certify actual compliance with any framework; it is a continuous internal self-assessment tool.

**Continuation - risk scoring is additive weighting, not a new judgment**: `services/compliance/riskScoring.js`'s `computeRiskScore()` only re-weights the same PASS/FAIL/PARTIAL verdicts and control severities the engine already produces; it introduces no new evaluation logic. A control's static `severity` (set at seed time) and its per-run `status` are the only inputs.

**Continuation - policy approval is advisory, like evidence approval**: `CompliancePolicy.approvalStatus` (Phase 10 continuation) does not gate whether a policy version is "current" - `getCurrentPolicyValues()` still resolves to the highest-versioned *enabled* document regardless of approval state. Approval is a review/audit trail, not an activation gate, exactly like `ComplianceEvidence.approved`.

**Continuation - rollback never deletes history**: `rollbackPolicy()` creates a brand-new version copying an older one's value; no `CompliancePolicy` document is ever mutated or removed, preserving the same append-only audit guarantee the original versioning design established.

**Continuation - automation reuses existing triggers, not new hooks into core paths**: the "recheck compliance" rules attached to `THREAT_FOUND`/`DLP_BLOCK`/`MITRE_CRITICAL` are ordinary additional `AutomationRule` documents against triggers those phases already emit - no change to `soarEngine.js`, `ruleMatcher.js`'s trigger-detection logic, or the malware/DLP/threat-intel code that raises those events in the first place.

---

## Supported Algorithms

| Purpose | Algorithm | Notes |
|---|---|---|
| File content encryption | **AES-256-GCM** | Generated fresh per file, 96-bit random IV, browser-only (Web Crypto API). The GCM authentication tag doubles as a tamper-evidence check on decrypt. |
| Key wrapping (owner access) | **RSA-OAEP-SHA256** | Per-user keypair, 3072-bit modulus by default (2048-bit minimum supported). Wraps the AES key so the owner can always re-access their own uploads. |
| Key wrapping (password-protected sharing) | **PBKDF2-SHA256** → AES-GCM | 210,000 iterations by default; derives a wrapping key from the share password, itself never transmitted to the server. |
| Digital signatures | **ECDSA P-256** | Per-user signing keypair, distinct from the RSA encryption keypair. Signs `SHA-256(ciphertext)` via the Web Crypto API's combined sign-and-hash primitive. |
| Hashing (signatures, integrity, threat intel) | **SHA-256** | Primary hash throughout — file integrity hashes, VirusTotal lookups, device/session identifiers. |
| Hashing (Phase 4, interoperability only) | SHA-1, MD5 | Computed alongside SHA-256 for compatibility with legacy threat-intel tooling that keys on them. **Never** used as the basis for any security decision — informational only. |
| Password storage | **bcrypt** | User account passwords (login credentials), 10 salt rounds. Distinct from — and unrelated to — the PBKDF2 key derivation used for share-link passwords above. |
| Session/auth tokens | **JWT** (HMAC via `JWT_SECRET`) | Carries a revocable session id (`sid`) as of Phase 3; sessions are independently checked against a `Session` collection on every request. |

---

## Security Model

**Trust boundary**: the server (and anyone who compromises it — including database backups, Cloudinary storage, or a malicious insider) is assumed to potentially see everything it's sent, but is *never* trusted with plaintext file content, raw AES keys, or any private key (RSA or ECDSA). The one narrow, deliberate exception is described in [Threat Model](#threat-model) below.

**Client trust**: the browser performing encryption/decryption/signing is trusted for the duration of that operation — SecureShare cannot protect against a compromised endpoint (malware on the user's own machine, a malicious browser extension, etc.). This is inherent to any client-side-crypto system and is called out explicitly rather than implied.

**Zero-knowledge, with two documented exceptions**: Phase 4's malware scanning and Phase 5's DLP scanning both fundamentally cannot operate on ciphertext (encrypted bytes carry no detectable signature or extractable text, regardless of the underlying content). SecureShare resolves this by having the browser send plaintext to `POST /api/threats/scan` and `POST /api/dlp/scan` — and only those two endpoints — before any encryption happens. Each buffer exists in server memory for the duration of a single request, is never written to disk or logged, and only the resulting *verdict* is persisted (hashes/risk level/threat names for Phase 4; masked finding previews/severity/decision for Phase 5 — never the raw matched secret values). This is a conscious, minimal trade-off, not an oversight — see [README.md's Phase 4](README.md#-phase-4-malware-scanning--threat-detection) and [Phase 5](README.md#️-phase-5-data-loss-prevention-dlp) sections for the full reasoning and the alternatives that were considered.

**Defense in depth**: security-critical checks are enforced server-side even when a client-side UI gate exists for UX purposes. For example, the upload page refuses to proceed past a Critical/High-risk scan client-side (fail-fast UX), but the actual security boundary — the download-time quarantine block — holds unconditionally even if that client gate is bypassed entirely (e.g. a direct API call).

---

## Threat Model

### In scope (SecureShare is designed to resist)
- A fully compromised server, including database access, that never held plaintext, raw keys, or the transient Phase 4 scan buffer.
- A network observer (passive or active MITM, absent TLS-stripping) between browser and server — sees only ciphertext, wrapped keys, and hashes.
- A malicious or careless third party gaining read access to Cloudinary storage — sees only ciphertext.
- Tampering with stored ciphertext or its metadata (Phase 2 signatures catch this before decryption).
- Access attempts from unauthorized devices/networks/times against a policy-protected file (Phase 3).
- Distribution of known-malware or disguised-executable files (Phase 4), to the extent ClamAV/VirusTotal/heuristic signals can detect them.
- Accidental upload of files containing embedded secrets or PII in supported text formats (Phase 5), to the extent the configured detectors can recognize them.
- Lack of visibility into related, multi-step suspicious activity (e.g. a quarantined file later targeted for download) — Phase 6's correlation engine surfaces this as a single incident instead of disconnected log rows.

### Out of scope (known, accepted limitations)
- A compromised client device/browser at the moment of encryption, decryption, or signing — the endpoint holding key material in memory during that operation is inherently trusted for that operation.
- Loss of the share link/password with no other recovery path — by design, the server cannot recover a lost key on the user's behalf (that would defeat zero-knowledge).
- Device-bound private keys: RSA/ECDSA private keys live only in the browser's IndexedDB; clearing browser storage or switching devices without the original share link/password permanently loses owner-side access to previously uploaded files.
- The transient plaintext exposure window during Phase 4/5 scanning (see above) — accepted as the minimum necessary trade-off to offer real malware/DLP detection at all.
- Server-reported public keys (RSA encryption keys, ECDSA signing keys) are currently trusted at face value — see [Limitations](#limitations) below regarding key pinning.
- Heuristic/signature-based detection limits: ClamAV and VirusTotal only catch *known* malware signatures and *known-suspicious* patterns — zero-day or sufficiently obfuscated malicious content can evade both.
- Pattern-based DLP detection limits: regex/heuristic detectors will miss secrets in binary formats, obfuscated/encoded values, or PII formats not covered by an existing detector, and will occasionally false-positive on similarly-shaped data (see [Limitations](#limitations)).
- Denial of service: rate limiting (`express-rate-limit`) mitigates casual abuse but SecureShare has no dedicated DDoS protection layer; that's expected to be handled at the hosting/CDN level in production.

---

## Limitations

- **No out-of-band key verification.** A downloader's ECDSA signature check trusts whatever `signingPublicKey` the server currently reports for a file's owner. A fully malicious server could theoretically substitute both the public key *and* re-sign with a key it controls — a strictly harder attack than tampering with ciphertext alone, but not impossible in a total-server-compromise scenario. A future hardening step would let users cross-verify each other's key fingerprints out-of-band (see README's Phase 2 "Known limitation").
- **Geo-IP resolution is a header-based stub**, not a dedicated geo-IP database — `allowedCountries` policy rules rely on `CF-IPCountry`/`X-Vercel-IP-Country`-style headers from an upstream CDN/proxy. Locally, or on a host that doesn't inject one, country resolves to `"Unknown"` and fails closed (any `allowedCountries` restriction is simply never satisfiable). See [DEPLOYMENT.md](DEPLOYMENT.md) if you need a real geo-IP provider integrated.
- **`requireApproval` has no dedicated approval workflow.** It currently means "the recipient must be an authenticated, already-trusted-device user" — there's no in-app request/approve UI for a *new* device or user to be granted access; the owner must pre-authorize by other means.
- **ClamAV/VirusTotal availability is environment-dependent.** Neither is bundled with the app; both are optional dependencies that degrade to "unavailable"/"skipped" rather than blocking uploads. A deployment that never configures either still runs, but with meaningfully reduced malware-detection coverage (magic bytes and heuristics only).
- **No automated test suite yet** for most of the above — [SECURITY_TESTING.md](SECURITY_TESTING.md) documents manual procedures; the DLP engine (`backend/tests/dlp.test.js`, run via `node --test`) is the first automated coverage, converting the remaining pure-function pieces (`riskEngine.js`, `policyEngine.js`) into an automated suite is a natural next step.
- **Legacy (`encryptionVersion: 1`) files remain server-side-decryptable by design**, using a single global RSA-2048 keypair — this predates the zero-knowledge model and exists purely for backward compatibility with files uploaded before Phase 1. New uploads never use this path.
- **DLP detection is heuristic, not exhaustive.** Passport and phone-number patterns in particular are broad and will false-positive on similarly-shaped IDs; Aadhaar validation uses a first-digit heuristic rather than the full Verhoeff checksum. Only text-based files are inspected — secrets embedded in binary formats (compiled binaries, image metadata, etc.) are not detected, and scanned content is capped at 5MB per file.
- **DLP's `require_approval` decision has no synchronous confirmation step in the legacy (`encryptionVersion: 1`) upload flow** — since that path is a single request with no round-trip, such findings are refused rather than held for approval; use the v2 (zero-knowledge) flow, which supports `POST /api/dlp/scans/:id/acknowledge`, if you need to override one.
- **The SIEM correlation engine is rule-based, not ML/anomaly-based.** It only recognizes the specific patterns encoded in `backend/services/siem/correlationEngine.js` (currently three rules); attack patterns outside those rules won't be automatically grouped into an incident, though the underlying events are still logged and visible individually.
- **Signature-verification events are self-reported by the client.** `POST /api/siem/events/signature` records whatever outcome the browser's own ECDSA check produced — a fully compromised client could report a false outcome. This doesn't weaken the actual signature check (which still runs and still blocks a genuinely invalid download client-side); it only means the SIEM's record of that outcome carries the same trust level as any other client-observed telemetry.
- **Events logged before Phase 6 lack `severity`/`category`/`siemType`.** They still appear in the SIEM's event list and the original Audit Logs page, just without those fields populated (shown as "uncategorized" in SOC views).

---

## Responsible Disclosure

If you discover a security vulnerability in SecureShare, please report it privately rather than opening a public issue.

- **Do**: email the maintainer (see repository contact info) with a clear description, reproduction steps, and — if possible — the affected component/file.
- **Do**: give a reasonable window to investigate and address the issue before any public disclosure.
- **Don't**: test against production data you don't own, or any deployment you haven't been explicitly authorized to test.
- **Don't** open a public GitHub issue with exploit details before a fix is available.

There is currently no formal bug bounty program. Reports are still welcomed and will be credited (with permission) once resolved.
