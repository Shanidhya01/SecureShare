# SecureShare — Security Overview

This document consolidates SecureShare's security model across all four implemented phases. For implementation detail and rationale behind each design decision, see the corresponding section of [README.md](README.md#-security-architecture-roadmap). For how to verify these guarantees hold, see [SECURITY_TESTING.md](SECURITY_TESTING.md).

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

**Zero-knowledge, with one documented exception**: Phase 4's malware scanning fundamentally cannot operate on ciphertext (encrypted bytes carry no detectable signature, regardless of the underlying content). SecureShare resolves this by having the browser send plaintext to `POST /api/threats/scan` — and only that endpoint — before any encryption happens. That buffer exists in server memory for the duration of a single request, is never written to disk or logged, and only the resulting *verdict* (hashes, risk level, detected threat names) is persisted. This is a conscious, minimal trade-off, not an oversight — see [README.md's Phase 4 section](README.md#-phase-4-malware-scanning--threat-detection) for the full reasoning and the alternatives that were considered.

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

### Out of scope (known, accepted limitations)
- A compromised client device/browser at the moment of encryption, decryption, or signing — the endpoint holding key material in memory during that operation is inherently trusted for that operation.
- Loss of the share link/password with no other recovery path — by design, the server cannot recover a lost key on the user's behalf (that would defeat zero-knowledge).
- Device-bound private keys: RSA/ECDSA private keys live only in the browser's IndexedDB; clearing browser storage or switching devices without the original share link/password permanently loses owner-side access to previously uploaded files.
- The transient plaintext exposure window during Phase 4 scanning (see above) — accepted as the minimum necessary trade-off to offer real malware detection at all.
- Server-reported public keys (RSA encryption keys, ECDSA signing keys) are currently trusted at face value — see [Limitations](#limitations) below regarding key pinning.
- Heuristic/signature-based detection limits: ClamAV and VirusTotal only catch *known* malware signatures and *known-suspicious* patterns — zero-day or sufficiently obfuscated malicious content can evade both.
- Denial of service: rate limiting (`express-rate-limit`) mitigates casual abuse but SecureShare has no dedicated DDoS protection layer; that's expected to be handled at the hosting/CDN level in production.

---

## Limitations

- **No out-of-band key verification.** A downloader's ECDSA signature check trusts whatever `signingPublicKey` the server currently reports for a file's owner. A fully malicious server could theoretically substitute both the public key *and* re-sign with a key it controls — a strictly harder attack than tampering with ciphertext alone, but not impossible in a total-server-compromise scenario. A future hardening step would let users cross-verify each other's key fingerprints out-of-band (see README's Phase 2 "Known limitation").
- **Geo-IP resolution is a header-based stub**, not a dedicated geo-IP database — `allowedCountries` policy rules rely on `CF-IPCountry`/`X-Vercel-IP-Country`-style headers from an upstream CDN/proxy. Locally, or on a host that doesn't inject one, country resolves to `"Unknown"` and fails closed (any `allowedCountries` restriction is simply never satisfiable). See [DEPLOYMENT.md](DEPLOYMENT.md) if you need a real geo-IP provider integrated.
- **`requireApproval` has no dedicated approval workflow.** It currently means "the recipient must be an authenticated, already-trusted-device user" — there's no in-app request/approve UI for a *new* device or user to be granted access; the owner must pre-authorize by other means.
- **ClamAV/VirusTotal availability is environment-dependent.** Neither is bundled with the app; both are optional dependencies that degrade to "unavailable"/"skipped" rather than blocking uploads. A deployment that never configures either still runs, but with meaningfully reduced malware-detection coverage (magic bytes and heuristics only).
- **No automated test suite yet** for any of the above — [SECURITY_TESTING.md](SECURITY_TESTING.md) documents manual procedures; converting the pure-function pieces (`riskEngine.js`, `policyEngine.js`) into an automated suite is a natural next step.
- **Legacy (`encryptionVersion: 1`) files remain server-side-decryptable by design**, using a single global RSA-2048 keypair — this predates the zero-knowledge model and exists purely for backward compatibility with files uploaded before Phase 1. New uploads never use this path.

---

## Responsible Disclosure

If you discover a security vulnerability in SecureShare, please report it privately rather than opening a public issue.

- **Do**: email the maintainer (see repository contact info) with a clear description, reproduction steps, and — if possible — the affected component/file.
- **Do**: give a reasonable window to investigate and address the issue before any public disclosure.
- **Don't**: test against production data you don't own, or any deployment you haven't been explicitly authorized to test.
- **Don't** open a public GitHub issue with exploit details before a fix is available.

There is currently no formal bug bounty program. Reports are still welcomed and will be credited (with permission) once resolved.
