# SecureShare 🔒

A production-ready, full-stack secure file sharing application that prioritizes **privacy, security, and simplicity**. Upload files with end-to-end encryption, create time-limited or one-time download links, and maintain comprehensive audit logs—all with an intuitive user interface.

## 🎯 Overview

SecureShare enables users to securely share files without exposing sensitive data. Files are encrypted **in the browser** before they ever leave your device, using true end-to-end, zero-knowledge encryption (AES-256-GCM + RSA-OAEP key wrapping via the Web Crypto API) — the server only ever stores ciphertext and wrapped keys, and can never read your files. Links can be password-protected, and can be set to expire or become unavailable after a certain number of downloads. Recipients receive a secure link with detailed access logs.

> Files uploaded before this migration used server-side encryption (`encryptionVersion: 1`) and remain downloadable unchanged for backward compatibility — see [Zero-Knowledge Encryption Architecture](#-zero-knowledge-encryption-architecture) below.

---

## ✨ Key Features

### Security
- **True Client-Side End-to-End Encryption**: files are encrypted in the browser with AES-256-GCM before upload; the AES key is wrapped with RSA-OAEP-SHA256 (per-user keypair, 3072-bit). The server never sees plaintext files or raw keys — a genuine zero-knowledge architecture.
- **Password Protection**: Optional password protection; for E2E files the password derives the unwrapping key entirely client-side (PBKDF2-SHA256) and is never sent to the server
- **Digital Signatures** (Phase 2): every upload is signed with a per-user ECDSA P-256 key; downloads verify the signature before decrypting, blocking tampered files outright
- **Zero Trust Access Policies** (Phase 3): optional per-file country/IP/device allowlists, business-hours windows, device caps, and approval requirements, plus device fingerprinting and revocable sessions
- **Malware Scanning & Quarantine** (Phase 4): every new upload is scanned pre-encryption (magic bytes, ClamAV, VirusTotal, MIME-mismatch/macro/archive heuristics) and automatically quarantined if flagged High/Critical risk
- **Audit Logging**: Track all file downloads with IP, device, browser, country, policy decision, and scan result
- **Automatic Expiration**: Files automatically delete after expiry time
- **JWT Authentication**: Secure token-based user authentication with revocable sessions
- **Rate Limiting**: API rate limiting to prevent abuse (25 requests per 15 minutes)

### File Management
- **One-Time Download Links**: Set files to be downloadable only once
- **Limited Download Links**: Configure maximum download count (1-100 downloads)
- **Customizable Expiry**: Set file expiration from 1 hour to 30 days
- **Cloud Storage Integration**: Files stored securely on Cloudinary
- **File Revocation**: Revoke access to shared files at any time

### User Experience
- **Intuitive Dashboard**: View all uploaded files with stats and actions
- **Quick Share**: Copy share links with one click
- **Real-time Feedback**: Toast notifications for all actions (upload, download, errors)
- **Responsive Design**: Mobile-friendly UI built with Tailwind CSS
- **Modern Icons**: Beautiful UI components with Lucide Icons
- **File History**: View download logs and access statistics

### Backend Operations
- **Automatic Cleanup**: Cron job removes expired files daily
- **JWT Token Management**: Secure session management
- **MongoDB Integration**: Scalable document-based database
- **Rate Limiting**: Protect API from abuse with configurable limits

---

## 🏗️ Tech Stack

### Frontend
- **Framework**: Next.js 16.1.1 (App Router)
- **Styling**: Tailwind CSS 4
- **HTTP Client**: Axios 1.13.2
- **UI Components**: Lucide React 0.562.0
- **Notifications**: react-hot-toast 2.6.0
- **Language**: TypeScript 5
- **Linting**: ESLint 9

### Backend
- **Runtime**: Node.js (LTS)
- **Framework**: Express 5.2.1
- **Database**: MongoDB 9.1.1 (Mongoose ODM)
- **Authentication**: JWT (jsonwebtoken 9.0.3)
- **File Handling**: Multer 2.0.2
- **Encryption**: Node.js crypto module
- **Password Hashing**: bcryptjs 3.0.3
- **Rate Limiting**: express-rate-limit 8.2.1
- **Scheduled Tasks**: node-cron 4.2.1
- **Cloud Storage**: Cloudinary
- **Development**: Nodemon 3.1.11

### DevOps & Infrastructure
- **Containerization**: Docker & Docker Compose
- **Database**: MongoDB (containerized)
- **Cloud Storage**: Cloudinary CDN

---

## 📂 Project Structure

```
SecureShare/
├── frontend/                      # Next.js client application
│   ├── app/
│   │   ├── page.tsx              # Home page
│   │   ├── layout.tsx            # Root layout
│   │   ├── login/                # Login page
│   │   ├── register/             # Registration page
│   │   ├── upload/               # File upload page
│   │   ├── dashboard/            # User dashboard
│   │   ├── security/             # Phase 3: Security Center (devices, sessions, events)
│   │   ├── threats/              # Phase 4: Threat Center (scans, quarantine, malware detections)
│   │   └── file/[id]/            # File detail & download
│   ├── components/               # Reusable React components
│   │   ├── Navbar.tsx
│   │   ├── FileCard.tsx
│   │   ├── UnlockKeyModal.tsx    # Set-up/unlock prompt for the local RSA key
│   │   └── ToasterClient.tsx
│   ├── context/
│   │   └── CryptoKeyContext.tsx  # Holds the unwrapped RSA + ECDSA private keys in memory for the session
│   ├── lib/                      # Utilities & API client
│   │   ├── api.js
│   │   ├── ipTracking.ts
│   │   ├── security/
│   │   │   └── fingerprint.ts     # Phase 3: privacy-minimal device fingerprint hash (getDeviceId)
│   │   └── crypto/                # Zero-knowledge crypto module (Web Crypto API only, no crypto-js)
│   │       ├── cryptoHelpers.ts   # Public entry point - re-exports everything below
│   │       ├── base64.ts          # base64 / base64url encode-decode helpers
│   │       ├── aes.ts             # AES-256-GCM key generation + raw import/export
│   │       ├── fileEncryption.ts  # encryptFile() / decryptFile() - the only place plaintext exists
│   │       ├── rsa.ts             # RSA-OAEP-SHA256 keypair + wrapAESKey()/unwrapAESKey()
│   │       ├── pbkdf2.ts          # PBKDF2-SHA256 password-derived key wrapping
│   │       ├── keyStorage.ts      # Encrypt/decrypt + IndexedDB persistence of private keys
│   │       ├── ecdsa.ts           # Phase 2: ECDSA P-256 signing keypair generation + import/export
│   │       ├── hash.ts            # Phase 2: SHA-256 hashing
│   │       └── signature.ts       # Phase 2: signEncryptedFile() / verifyEncryptedFileSignature()
│   ├── styles/                   # Global styles
│   └── package.json
│
├── backend/                       # Express API server
│   ├── api/
│   │   └── index.js              # Vercel API routes (optional)
│   ├── controllers/              # Business logic
│   │   ├── auth.controller.js
│   │   ├── user.controller.js
│   │   ├── device.controller.js   # Phase 3: trusted device list/removal
│   │   ├── session.controller.js  # Phase 3: active session list/revocation
│   │   ├── security.controller.js # Phase 3: unified security-event feed
│   │   ├── threat.controller.js   # Phase 4: pre-encryption scan, scan history, quarantine
│   │   └── file.controller.js
│   ├── models/                   # Mongoose schemas
│   │   ├── User.js
│   │   ├── Device.js              # Phase 3
│   │   ├── Session.js             # Phase 3
│   │   ├── SecurityEvent.js       # Phase 3 (extended in Phase 4 with file_quarantined)
│   │   ├── ThreatScan.js          # Phase 4
│   │   └── File.js
│   ├── routes/                   # API endpoints
│   │   ├── auth.routes.js
│   │   ├── user.routes.js
│   │   ├── device.routes.js       # Phase 3
│   │   ├── session.routes.js      # Phase 3
│   │   ├── security.routes.js     # Phase 3
│   │   ├── threat.routes.js       # Phase 4
│   │   └── file.routes.js
│   ├── middleware/               # Custom middleware
│   │   ├── auth.middleware.js     # Phase 3: also checks session revocation
│   │   └── rateLimit.js
│   ├── services/                 # Pure/orchestration logic, no Express coupling
│   │   ├── policyEngine.js        # Phase 3: Zero Trust download policy evaluation
│   │   ├── riskEngine.js          # Phase 4: classifyRisk() / shouldQuarantine()
│   │   ├── threatScanService.js   # Phase 4: orchestrates the full scan pipeline
│   │   ├── clamavScanner.js       # Phase 4: clamd INSTREAM protocol client
│   │   └── virusTotalLookup.js    # Phase 4: optional VirusTotal hash lookup
│   ├── utils/                    # Helper functions
│   │   ├── cloudinary.js
│   │   ├── deviceContext.js       # Phase 3: dependency-free User-Agent parsing
│   │   ├── geoLookup.js           # Phase 3: best-effort country resolution from proxy headers
│   │   ├── magicBytes.js          # Phase 4: file-type detection by signature bytes
│   │   ├── fileHashes.js          # Phase 4: SHA-256/SHA-1/MD5 hashing
│   │   └── legacy/                # encryptionVersion 1 only — server-side AES-CBC (unused by new uploads)
│   │       ├── encrypt.js
│   │       └── decrpyt.js
│   ├── cron/
│   │   └── cleanup.js            # Scheduled file cleanup
│   ├── keys/                     # RSA key pair (generated)
│   │   ├── public.pem
│   │   └── private.pem
│   ├── server.js                 # Express app entry point
│   ├── package.json
│   └── Dockerfile
│
├── docker-compose.yml            # Development environment setup
├── LICENSE                        # MIT License
└── README.md                      # This file
```

---

## 🔐 Zero-Knowledge Encryption Architecture

SecureShare uses **true client-side end-to-end encryption**. All cryptography happens in the browser via the native [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) (`frontend/lib/crypto/`, no `crypto-js` or other JS crypto library) — the server only ever handles ciphertext and already-wrapped keys, and has no way to decrypt uploaded files.

### Threat model
- **In scope**: the server (and anyone who compromises it, including database backups or the Cloudinary bucket) should never be able to recover plaintext file contents or any user's RSA private key. A network observer between browser and server should see only ciphertext and wrapped keys.
- **Out of scope**: a compromised *browser/device* at encrypt or decrypt time (the endpoint that holds the AES key in memory), and loss of the share link/password with no other recovery path (see the device-bound trade-off below).

### Key model
- **Per-file AES-256-GCM key**: a brand-new, unique key + random 96-bit IV (`crypto.getRandomValues`) is generated for every file, entirely in the browser (`generateAESKey`, `encryptFile` in `frontend/lib/crypto/aes.ts` / `fileEncryption.ts`).
- **Per-user RSA-OAEP-SHA256 keypair (owner access, 2048-bit minimum, 3072-bit by default)**: each account gets its own keypair, generated client-side (`generateRSAKeyPair` in `rsa.ts`). The public key is uploaded to the server (`User.publicKey`); the private key is encrypted with a key derived from the user's login password via PBKDF2-SHA256 (`encryptPrivateKey`/`decryptPrivateKey` in `keyStorage.ts`) and stored **only in the browser's IndexedDB** — it never touches the server, and is never put in `localStorage`. This lets the file owner always re-decrypt their own files from the dashboard, using their own key.
- **Sharing**: for the recipient (who may not have an account), the same AES key is made available in one of two zero-knowledge ways:
  - **No password**: the raw AES key travels in the share link's URL *fragment* (`/file/:id#k=...`) — fragments are never transmitted to the server by the browser, so the key never appears in any network request.
  - **With a password**: the AES key is wrapped with a key derived from the share password via PBKDF2-SHA256 + a random salt (`wrapAESKeyWithPassword` in `pbkdf2.ts`). The wrapped key + salt are stored server-side, but the password itself is never sent to the server — the recipient's browser re-derives the key locally, and an AES-GCM authentication-tag failure is the "wrong password" signal (the server performs no password validation for these files).

### Architecture diagram

```
Upload (browser)                              Download (browser)
─────────────────                              ──────────────────
File                                            Encrypted blob + IV ◄── GET /files/download/:id
  │ generateAESKey()                            Wrapped key(s)     ◄── GET /files/file/:id/meta
  ▼
encryptFile() ── AES-256-GCM, random IV                │
  │                                              unwrapAESKey() / unwrapAESKeyWithPassword()
  ▼                                              (RSA-OAEP private key from IndexedDB, or
wrapAESKey() ── RSA-OAEP (owner)                  password-derived PBKDF2 key, or raw
wrapAESKeyWithPassword() (optional)               fragment key - never sent to the server)
  │                                                       │
  ▼                                                       ▼
POST /files/upload                              decryptFile() ── AES-256-GCM
  (ciphertext + wrapped key(s) + IV + metadata            │
   -- NEVER plaintext, NEVER a raw AES key)                ▼
  │                                              Blob ── triggered browser download
  ▼
Cloudinary (ciphertext only)                    Server never decrypts, never sees plaintext.
```

### Upload flow (client-side)
1. Browser generates a fresh AES-256-GCM key and encrypts the file locally (`encryptFile`) — plaintext never leaves the device.
2. The AES key is wrapped with the uploader's own RSA-OAEP public key (`wrapAESKey`), and either embedded in the share link fragment or wrapped with a password-derived key (`wrapAESKeyWithPassword`).
3. **(Phase 2)** The uploader's ECDSA P-256 private signing key signs the encrypted file (`signEncryptedFile`) — see below.
4. Only the ciphertext, the wrapped key(s), the signature/hash metadata, the IV, and other metadata are uploaded — the server stores the encrypted blob on Cloudinary as-is, with no server-side cryptography.

### Download flow (client-side)
1. Browser fetches file metadata (IV, wrapped key(s), signature) from `GET /files/file/:id/meta` and the encrypted bytes from `GET /files/download/:id`.
2. **(Phase 2)** If the file has a signature, the browser verifies it against the uploader's public signing key *before* touching the AES key or attempting decryption — see below. A failed verification aborts the download entirely.
3. The AES key is unwrapped locally — via the fragment key, the share password (`unwrapAESKeyWithPassword`), or the owner's own private key (`unwrapAESKey`, unlocked from IndexedDB with the login password).
4. The file is decrypted locally with AES-GCM (`decryptFile`) and handed to the browser as a downloadable Blob. AES-GCM's built-in authentication tag doubles as an integrity check — a wrong key, wrong password, or tampered ciphertext all surface as a decryption failure, mapped to a specific in-app error (wrong password / integrity verification failed / missing key / expired / revoked / network failure).

### Backward compatibility
Files uploaded before this migration (`File.encryptionVersion: 1`, the default) keep working exactly as before: server-side AES-256-CBC decryption with a single global RSA-2048 keypair (`backend/utils/legacy/`, `backend/keys/*.pem`). New uploads always use `encryptionVersion: 2` (client-side E2E) — the legacy path exists purely for old links. Digital signatures (Phase 2, below) are an *additive* layer on top of `encryptionVersion: 2` and are entirely optional per file — v2 files uploaded before Phase 2 shipped simply have no `signature`, and the download flow treats that as "unsigned," not an error.

### Trade-off: device-bound private keys
Because the RSA private key lives only in the browser's IndexedDB (never on the server), clearing browser storage or switching devices means losing owner-side access to previously uploaded files unless the original share link/password is still known. This is the deliberate cost of true zero-knowledge storage — the server holding a recovery copy of your private key would defeat the purpose. The same trade-off applies identically to the ECDSA signing key introduced in Phase 2.

---

## ✍️ Phase 2: Digital Signatures & Integrity Verification

Phase 1 (above) guarantees **confidentiality** — the server can't read your files. Phase 2 adds **authenticity and integrity**: a recipient can cryptographically prove that a downloaded file was (a) produced by the claimed uploader and (b) not altered in any way since it was signed — *before* spending any effort decrypting it. This closes a gap Phase 1 alone doesn't cover: AES-GCM's authentication tag proves the ciphertext wasn't corrupted *relative to whichever key you're using to decrypt*, but says nothing about who encrypted it in the first place, or whether a malicious actor with write access to storage could have substituted a different ciphertext + matching key material. A digital signature, tied to a specific user's long-lived signing identity, closes that gap.

### Trust model
- **Identity = signing keypair, not the account itself.** A user's authenticity, from a downloader's perspective, rests entirely on possession of the ECDSA private key that matches the `signingPublicKey` the server reports for that account. The server is trusted to correctly associate a `signingPublicKey` with the right `User` document (i.e., to not lie about whose key is whose) but is **not** trusted with the private key itself, and cannot forge a valid signature.
- **What a passing verification proves**: the encrypted file bytes are byte-for-byte identical to what was signed, and the signer held the private key matching the public key the server reports for the file's owner at query time.
- **What it does NOT prove**: that the plaintext content is what the recipient expects (only decryption + inspection tells you that), or that the account itself wasn't compromised at signing time (if an attacker steals a user's *password*, they could unlock that user's signing key too — signing protects against tampering *in transit/at rest*, not against a fully compromised account).
- **Server compromise**: even a fully malicious server cannot produce a valid signature for a file it tampers with, since it never has the private signing key. It *could* swap out `ownerSigningPublicKey` in the `/meta` response to point at a key it does control — but then the signature would need to have been produced with that same attacker-controlled key, which only helps an attacker who controls the *entire* round trip (metadata AND ciphertext AND signature), a strictly harder attack than tampering with ciphertext alone. This is a known limitation of any system where the verification key is fetched from the same server being defended against; a future hardening step (see below) would be pinning/out-of-band key verification.

### Key model (Phase 2 addition)
- **Per-user ECDSA P-256 signing keypair**, entirely separate from the RSA-OAEP encryption keypair (`generateSigningKeyPair` in `frontend/lib/crypto/ecdsa.ts`) — encryption and signing keys are never shared, since mixing their use case weakens both.
- Generated client-side, at the same moment as the RSA keypair (registration, or lazily backfilled on next unlock for accounts created before Phase 2 shipped).
- The public signing key is uploaded to the server (`User.signingPublicKey`, `PATCH /api/users/signingkey`).
- The private signing key is encrypted with the **same password-derived-key mechanism** already used for the RSA private key (PBKDF2-SHA256 → AES-GCM, `encryptPrivateKey`/`decryptPrivateKeyBytes` in `keyStorage.ts`) and stored **only in the browser's IndexedDB**, alongside the RSA key material, in the same per-user record.

### Verification workflow
1. **Sign (upload)**: after AES-GCM-encrypting the file, the browser computes `SHA-256(ciphertext)` and signs the ciphertext with `crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, signingPrivateKey, ciphertext)`. (The Web Crypto API's ECDSA sign/verify always hashes its input per the `hash` parameter — there's no separate "sign this already-computed digest" primitive — so signing the ciphertext with `hash: "SHA-256"` *is* signing SHA-256(ciphertext); a manually-computed `fileHash` is stored alongside purely as human-readable/audit metadata, and is never itself trusted as the basis for verification.)
2. **Upload**: `signature`, `fileHash`, `hashAlgorithm` ("SHA-256"), `signatureAlgorithm` ("ECDSA-P256-SHA256"), and `signedAt` are sent to the server alongside the existing ciphertext/wrapped-key/IV fields and stored on the `File` document.
3. **Fetch (download)**: the browser retrieves `signature` + the uploader's `ownerSigningPublicKey` from `GET /files/file/:id/meta`, and the ciphertext from `GET /files/download/:id`.
4. **Verify BEFORE decrypt**: `verifyEncryptedFileSignature` (in `signature.ts`) calls `crypto.subtle.verify(...)` over the downloaded ciphertext. This happens strictly before the AES key is ever unwrapped or used — a failed check means the file is never decrypted, full stop.
5. **Outcome**:
   - ✅ **Verified** — signature valid, proceed to decrypt normally. UI shows "Signature verified — this file is authentic and unmodified."
   - ⚠️ **Tampering detected** — signature present but invalid. Download is **blocked entirely**; UI shows a red tampering warning and the decrypt flow aborts (`TAMPERED` error).
   - ℹ️ **Unsigned** — no signature on this file (legacy `encryptionVersion: 1`, or a Phase-1-only `encryptionVersion: 2` upload). Decryption proceeds as before Phase 2 existed; UI shows a neutral "unsigned, integrity not cryptographically verified" notice rather than blocking, preserving full backward compatibility.

### New crypto modules
- **`frontend/lib/crypto/ecdsa.ts`** — ECDSA P-256 keypair generation, public/private key import-export, `decryptSigningPrivateKey`.
- **`frontend/lib/crypto/hash.ts`** — standalone SHA-256 hashing (`sha256`, `sha256Base64`).
- **`frontend/lib/crypto/signature.ts`** — the high-level `signEncryptedFile`/`verifyEncryptedFileSignature` pair that upload/download pages call directly, combining the two modules above.

### UI feedback
The upload page shows a "Signing file (ECDSA P-256)..." progress step during signing and a "Digitally signed" badge on success (or an "uploaded without a signature" notice if the local signing key isn't set up yet). The download page shows a "Verifying digital signature..." step before decryption begins, followed by one of: a green "Signature verified" badge, a red blocking tampering warning, or a neutral "unsigned file" notice.

### Known limitation & future hardening
As noted in the trust model, the signing public key used for verification is fetched from the same server whose compromise this feature partly defends against. A fully hardened design would let users independently verify each other's signing public keys out-of-band (e.g., a key fingerprint displayed on each user's profile that recipients can cross-check via a side channel) — this is a natural next step, not yet implemented.

---

## 🛡️ Phase 3: Zero Trust Access Control

Phase 1 secures *what* is stored (confidentiality) and Phase 2 secures *who produced it* (authenticity/integrity). Phase 3 adds a third, independent layer: **access control that never assumes a request is legitimate just because it arrived** — every download is evaluated against the requester's device, network, timing, and (optionally) identity, regardless of whether the file's encryption/signing checks pass. This is what "Zero Trust" means here: no implicit trust from network location, a valid-looking link, or a prior successful login — every access attempt is evaluated on its own merits, every time.

### Zero Trust model
- **Never trust, always verify**: possessing a share link (and even the correct decryption key) is necessary but not sufficient to download a policy-protected file — the request must also satisfy every rule configured on that file (see below).
- **Device trust is bootstrapped, not assumed**: a device becomes "trusted" for a user only after successfully authenticating with that user's password from it (see [Device fingerprinting](#device-fingerprinting) below) — trust is earned per-device, not inherited from the account.
- **Sessions are independently revocable**: authentication (a valid JWT) and session validity (that JWT's session hasn't been revoked) are checked separately on every request — logging in doesn't grant indefinite trust; a session can be cut off from the Security Center at any time, from any device, without changing the password.
- **Policy evaluation is additive, never assumed**: this whole layer is opt-in per file. A file with no policy configured is unaffected — it behaves exactly as it did in Phase 1/2. Zero Trust here means "verify every request against whatever rules exist," not "add friction by default."

### Device fingerprinting
Every login computes a **stable, privacy-minimal device identifier** in the browser (`frontend/lib/security/fingerprint.ts`) by hashing a fixed set of attributes with SHA-256:
- `navigator.userAgent`, `navigator.platform`, `navigator.language`
- `Intl.DateTimeFormat().resolvedOptions().timeZone`
- screen resolution + color depth
- a canvas rendering fingerprint (drawing fixed text/shapes to an offscreen `<canvas>` and hashing the resulting pixel data — a common browser/GPU/font-rendering signal that's stable per device but reveals nothing about the user)

**Only the resulting hash is ever sent to the server** — none of the raw attribute values are transmitted or stored, which is what keeps this "unnecessary personal data"-free: the server learns "this is the same device as last time," never the underlying fingerprint data itself (most of which — like the User-Agent string — it would see in every request's headers regardless).

A device that successfully authenticates (correct password) is recorded and trusted automatically (`Device` model, `backend/controllers/auth.controller.js`'s `login`) — this is the trust bootstrap: no separate approval workflow is required, since a correct password is already the credential proving "this is the account owner." A first-time device also emits a `new_device` security event.

### Session management
Login now embeds a random session id (`sid`) in the JWT and records a matching `Session` document (browser, OS, IP, country, device, timestamps). `backend/middleware/auth.middleware.js` checks, on every authenticated request, that the token's session hasn't been revoked — a session revoked from the Security Center is rejected on its very next request, without needing the token itself to expire or the password to change. Tokens issued before this existed carry no `sid` claim and are treated as untracked "legacy sessions" that skip the revocation check, so upgrading doesn't log anyone out.

### Access policy engine
`backend/services/policyEngine.js` is a **pure function** — no DB or network access — that evaluates a resolved request context against a file's optional `policy` subdocument and returns `{ decision: "allow" }` or `{ decision: "deny", reason }`. Being pure makes it trivial to unit test (every branch is a one-line assertion) and safe to reuse from any future call site.

Every check is independently opt-in (`backend/models/File.js`'s `policy` field):

| Field | Effect |
|---|---|
| `allowedCountries` | Only these ISO country codes (resolved from geo-IP headers, see below) may download |
| `allowedIPs` | Only these exact IP addresses may download |
| `allowedDevices` | Only these device fingerprint hashes may download |
| `businessHours` | Restrict downloads to a UTC hour range (supports overnight windows, e.g. 22:00-06:00) |
| `maxDevices` | Cap the number of *distinct* devices that may ever download this file |
| `requireApproval` | Require an authenticated requester on a trusted device (blocks anonymous/link-only access entirely) |

A file with **no policy fields set evaluates to `allow` unconditionally** — this is what preserves every file that existed before Phase 3, and every new file that doesn't opt into any restriction.

`GET/PATCH /api/files/file/:id/policy` (owner-only) let the uploader view/edit a file's policy after upload; the upload page also exposes an optional, collapsed-by-default "Advanced Security Policy" section for setting one at upload time.

**Country resolution** is a best-effort read of common CDN/proxy geo-IP headers (`CF-IPCountry`, `X-Vercel-IP-Country`, ...) — this app does not call any external geo-IP API or ship a MaxMind-style database (`backend/utils/geoLookup.js`). Locally, or on a host that doesn't inject one of those headers, country resolves to `"Unknown"`, and any `allowedCountries` restriction simply can't be satisfied (fails closed). Swap in a real geo-IP provider there for production deployments that need it.

### Extended audit logs
Every download attempt — allowed *or denied* — appends an entry to `File.logs[]`, now including `deviceId`, `browser`, `operatingSystem`, `country`, `decision` (`"allow"`/`"deny"`), and `denialReason` alongside the existing `ip`/`userEmail`/`time`. This means the same per-file audit trail the dashboard already showed (`/file/:id/logs`) now doubles as a full Zero Trust decision log for that file, with no separate query needed.

### Security Center
`frontend/app/security/page.tsx` (linked from the navbar) gives users one place to review and act on all of the above:
- **Trusted Devices** — every device that has ever logged in, with last-seen time/IP and a remove action (removing a device also revokes any sessions created from it)
- **Active Sessions** — every non-revoked session, with browser/OS/IP/country/login time, and a per-session revoke action (works even on the current session — revoking it logs that browser out on its next request)
- **Blocked Access Attempts** — every `download_denied` policy decision against the user's own files, with the specific reason
- **Recent Security Events** — new-device logins, device removals, and session revocations, in one activity feed

### Backward compatibility
Every Phase 3 addition is additive to the existing schema and strictly opt-in at evaluation time: `File.policy` defaults to an all-empty subdocument (`hasActivePolicy()` returns `false`, `evaluateDownloadPolicy()` returns `allow`), so every file created before Phase 3 - and every new file that doesn't configure a policy - downloads exactly as it did in Phase 1/2. Sessions predating the `sid` JWT claim skip the revocation check entirely rather than being rejected.

### Authentication
- **Registration**: Email & password → bcryptjs hashing (salt rounds: 10)
- **Login**: Credentials validated → JWT token generated, embedding a session id (`sid`) tied to a revocable `Session` record → device fingerprint (if provided) recorded/refreshed as a trusted device
- **Protected Routes**: All file operations require a valid JWT token whose session (if tracked) hasn't been revoked

### Access Control
- **One-Time Links**: After 1 download, link becomes inactive
- **Limited Downloads**: Configurable max downloads (1-100)
- **Time-Based Expiry**: Files auto-delete after specified duration
- **Password Protection**: Additional layer of security
- **Link Revocation**: Owner can revoke access anytime
- **Zero Trust Access Policy** (Phase 3, optional per file): country/IP/device allowlists, business-hours windows, max-device caps, and approval requirements — see above

---

## 🦠 Phase 4: Malware Scanning & Threat Detection

Phases 1-3 protect confidentiality, authenticity, and access — but none of them ask "is this file's *content* actually safe?" Phase 4 adds that layer: every new upload is scanned for malware and suspicious characteristics before it's ever stored, with automatic quarantine for anything dangerous.

### The zero-knowledge conflict, and how it's resolved

SecureShare's server never sees plaintext file bytes (Phase 1) — but malware scanning (magic-byte inspection, ClamAV, VirusTotal, MIME-mismatch detection) is fundamentally meaningless against ciphertext: encrypted data is high-entropy noise that doesn't match any signature and whose hash won't match any known-malware hash, regardless of what the underlying plaintext actually is. There is no way to reconcile "the server never sees plaintext" with "the server can meaningfully scan file content" — one of those has to give, even slightly.

SecureShare resolves this with a **deliberate, narrowly-scoped exception**: `POST /api/threats/scan` is the *one* endpoint where the browser sends plaintext file bytes to the server, and it does so **before** any client-side encryption happens, purely to be scanned. The buffer:
- exists only in memory for the duration of that single request (Multer's in-memory storage, never written to disk),
- is never logged, and
- goes out of scope (eligible for garbage collection) the moment the request handler returns.

Only the *scan verdict* (hashes, risk level, detected threat names, MIME info) is persisted, as a `ThreatScan` document — never the file content itself. The browser only proceeds to actually encrypt-and-upload the file (Phase 1's flow, unchanged) after this scan completes and clears; the resulting encrypted upload is still fully zero-knowledge from that point on. This is the same trade-off most real products that need both E2E encryption and malware scanning make - see [Threat model](#threat-model) in the Phase 1 section for the analogous reasoning about transient plaintext exposure windows.

The legacy `encryptionVersion: 1` upload path scans inline instead, with no separate request needed - it already receives plaintext server-side as part of its (non-zero-knowledge) design, so there's no additional exposure to reason about there.

### Scan pipeline

For every scanned file, `backend/services/threatScanService.js` runs, in parallel where possible:

1. **Magic-byte type detection** (`backend/utils/magicBytes.js`) — inspects the file's actual signature bytes (dependency-free, no external library) to determine its real type, independent of whatever filename/extension/MIME type the upload claims. Catches PDFs, images, archives, and — critically — executables (Windows PE `MZ`, Linux ELF).
2. **MIME-mismatch detection** — flags when the claimed type (from the browser) and the detected type (from magic bytes) disagree on something concrete (a generic/empty claimed type isn't itself suspicious, so it's never flagged).
3. **Hashing** (`backend/utils/fileHashes.js`) — SHA-256, SHA-1, and MD5 of the plaintext. SHA-256 is the one used for VirusTotal lookups and treated as the primary identity hash; MD5/SHA-1 are included only for interoperability with tooling that still keys on them.
4. **ClamAV scan** (`backend/services/clamavScanner.js`) — talks directly to a `clamd` daemon over its `INSTREAM` TCP protocol (no external npm wrapper), streaming the buffer in chunks. If `clamd` isn't reachable (not installed/running — the common case in a plain dev environment), the scan degrades gracefully to `status: "unavailable"` rather than failing the whole pipeline. Configure via `CLAMAV_HOST`/`CLAMAV_PORT` (default `127.0.0.1:3310`).
5. **VirusTotal lookup** (`backend/services/virusTotalLookup.js`, optional) — looks up the file's SHA-256 against VirusTotal's existing database (VT API v3) — it does *not* upload the file itself, keeping the "never transmit more plaintext-derived data than necessary" principle intact. Entirely skipped if `VIRUSTOTAL_API_KEY` isn't set.
6. **Extension/archive heuristics** — checks the claimed extension against a configurable dangerous-extension list (`.exe`, `.scr`, `.vbs`, `.ps1`, ...) and a macro-enabled Office extension list (`.docm`, `.xlsm`, ...), and inspects ZIP local file headers directly for the encryption bit (flags password-protected/encrypted archives, a common malware-delivery technique for evading content scanners).

### Risk engine

`backend/services/riskEngine.js` is a **pure, configurable function** (`classifyRisk`) that combines every signal above into one of four levels:

| Level | Triggered by |
|---|---|
| **Critical** | Confirmed malware (ClamAV or VirusTotal), OR a disguised executable (magic bytes say "binary," claimed type says otherwise — the mismatch *is* the attack), OR a dangerous extension combined with macros/encryption/mismatch |
| **High** | A dangerous extension or executable content on its own, macros combined with a MIME mismatch, or a VirusTotal "suspicious" (but below the confirmed-malicious threshold) verdict |
| **Medium** | Macros alone, an encrypted/password-protected archive, or a MIME mismatch alone |
| **Low** | None of the above |

`shouldQuarantine(riskLevel)` returns `true` for High and Critical - the dangerous-extensions list, macro-extensions list, and detected-executable-MIME-types list all live in one exported `RISK_CONFIG` object, so the rule set can be tuned (or a signal added) without touching any call site.

### Quarantine

A file whose scan resolves to High/Critical risk is marked `quarantined: true` on both its `ThreatScan` and (once the actual encrypted upload completes) its `File` document. `downloadFile` in `file.controller.js` checks this **before** anything else — before the Zero Trust policy engine, before any decryption — and unconditionally refuses to serve a single byte, logging the attempt and emitting a `file_quarantined` security event. There is no policy override that can un-block a quarantined file except the owner explicitly releasing it from the Threat Center (`POST /api/threats/quarantine/:id/release`) - a deliberate manual step for handling false positives, since ClamAV/magic-byte heuristics aren't infallible.

The upload itself is **not** hard-blocked server-side by a quarantine verdict (the API still accepts it, so it has something to quarantine and display) - the upload page's own UI refuses to proceed past a Critical/High scan result client-side, as a fail-fast UX measure, but the real security boundary is the download-time block, which holds even if that client-side gate is bypassed.

### Threat Center

`frontend/app/threats/page.tsx` (linked from the navbar) gives users:
- **Scan History** — every scan they've triggered, with filename, size, SHA-256, ClamAV/VirusTotal verdicts, and risk level
- **Quarantined Files** — files blocked from download, with a "Release" action for manual override
- **Malware Detections** — scans where ClamAV or VirusTotal actually confirmed a threat, with the detected names
- **Threat Statistics** — total scans, quarantine count, risk-level breakdown, malware-detection count

### Extended audit logs

`File.logs[]` entries (already extended in Phase 3 with device/policy context) now also snapshot `scanStatus` and `riskLevel` at download time, and a quarantine block produces its own `decision: "deny"` log entry with `denialReason: "File is quarantined due to a threat scan detection"` — consistent with how policy denials are already logged.

### Backward compatibility

`File.scanStatus` defaults to `"not_scanned"` and `quarantined` defaults to `false` — every file uploaded before Phase 4 is completely unaffected and remains downloadable exactly as before. New `encryptionVersion: 2` uploads are required to reference a completed scan (`scanId`, obtained from `POST /api/threats/scan`) going forward, so the protection is mandatory for anything created from here on, without touching anything that already exists.

---

## 🚀 Getting Started

### Prerequisites
- Node.js 16+ and npm/yarn
- MongoDB 4.4+ (local or Atlas)
- Cloudinary account (free tier available)
- Docker & Docker Compose (for containerized setup)

### Installation

#### Option 1: Local Development (Recommended for Development)

**1. Clone the repository**
```bash
git clone https://github.com/yourusername/SecureShare.git
cd SecureShare
```

**2. Backend Setup**
```bash
cd backend
npm install
```

**3. Create RSA Keys** (if not already present)
```bash
node generateKeys.js
```

**4. Configure Backend Environment** (`backend/.env`)
```env
PORT=5000
MONGO_URI=mongodb://localhost:27017/secureshare
JWT_SECRET=your_super_secret_jwt_key_change_this_in_production
CLOUDINARY_CLOUD_NAME=your_cloudinary_name
CLOUDINARY_API_KEY=your_api_key
CLOUDINARY_API_SECRET=your_api_secret
RSA_PUBLIC_KEY_BASE64=your_base64_encoded_public_key
RSA_PRIVATE_KEY_BASE64=your_base64_encoded_private_key
```

**5. Start Backend**
```bash
npm run dev
# API runs on http://localhost:5000
```

**6. Frontend Setup** (in a new terminal)
```bash
cd frontend
npm install
```

**7. Configure Frontend Environment** (`frontend/.env.local`)
```env
NEXT_PUBLIC_API=http://localhost:5000/api
```

**8. Start Frontend**
```bash
npm run dev
# App runs on http://localhost:3000
```

#### Option 2: Docker Compose (Recommended for Production-like Setup)

```bash
cd SecureShare
docker-compose up --build
```

This starts:
- Backend API on `http://localhost:5000`
- Frontend on `http://localhost:3000`
- MongoDB on `localhost:27017`

To stop:
```bash
docker-compose down
```

---

## 📋 Environment Variables

### Backend (`backend/.env`)

| Variable | Description | Example |
|----------|-------------|---------|
| `PORT` | Server port | `5000` |
| `MONGO_URI` | MongoDB connection string | `mongodb://localhost:27017/secureshare` |
| `JWT_SECRET` | Secret key for JWT signing | `your_secret_key_here` |
| `CLOUDINARY_CLOUD_NAME` | Cloudinary cloud name | `your_cloud_name` |
| `CLOUDINARY_API_KEY` | Cloudinary API key | `123456789` |
| `CLOUDINARY_API_SECRET` | Cloudinary API secret | `your_api_secret` |
| `RSA_PUBLIC_KEY_BASE64` | Base64 RSA public key | (auto-generated) |
| `RSA_PRIVATE_KEY_BASE64` | Base64 RSA private key | (auto-generated) |
| `NODE_ENV` | Environment mode | `development` or `production` |
| `CLAMAV_HOST` | Hostname of a running `clamd` daemon (Phase 4). Optional - scans degrade to `"unavailable"` if unset/unreachable | `127.0.0.1` |
| `CLAMAV_PORT` | Port `clamd` is listening on (Phase 4) | `3310` |
| `VIRUSTOTAL_API_KEY` | VirusTotal API v3 key (Phase 4). Optional - hash lookups are skipped entirely if unset | (none by default) |

### Frontend (`frontend/.env.local`)

| Variable | Description | Example |
|----------|-------------|---------|
| `NEXT_PUBLIC_API` | API base URL (must include `/api`) | `http://localhost:5000/api` |

---

## 🔌 API Endpoints

### Authentication Routes (`/api/auth`)

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---|
| `POST` | `/register` | Register new user | No |
| `POST` | `/login` | Login user | No |
| `POST` | `/logout` | Logout (token invalidation) | Yes |

**Register Request:**
```json
{
  "name": "John Doe",
  "email": "john@example.com",
  "password": "securePassword123"
}
```

**Login Request:**
```json
{
  "email": "john@example.com",
  "password": "securePassword123"
}
```

**Response:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIs...",
  "user": {
    "id": "64d4a1b2c3d4e5f6g7h8i9j0",
    "name": "John Doe",
    "email": "john@example.com"
  }
}
```

### File Routes (`/api/files`)

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---|
| `POST` | `/upload` | Upload file (client-side pre-encrypted for `encryptionVersion=2`; requires a `scanId` from `POST /api/threats/scan`, Phase 4) | Yes |
| `GET` | `/my-files` | Get user's uploaded files | Yes |
| `GET` | `/file/:id/meta` | Get encryption metadata (IV, wrapped keys, filename) without file bytes | No |
| `GET` | `/download/:fileId` | Download file bytes (decrypted server-side for v1, raw ciphertext for v2) | No |
| `DELETE` | `/:fileId` | Delete/revoke file | Yes |
| `GET` | `/logs/:fileId` | Get download audit logs | Yes |
| `GET` | `/file/:id/policy` | Get a file's Zero Trust access policy (Phase 3, owner-only) | Yes |
| `PATCH` | `/file/:id/policy` | Set/update a file's Zero Trust access policy (Phase 3, owner-only) | Yes |

### User Routes (`/api/users`)

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---|
| `PATCH` | `/publickey` | Set/update your RSA-OAEP public key (base64 SPKI) | Yes |
| `GET` | `/publickey` | Get your own stored public key | Yes |
| `PATCH` | `/signingkey` | Set/update your ECDSA P-256 signing public key (base64 SPKI, Phase 2) | Yes |
| `GET` | `/signingkey` | Get your own stored signing public key | Yes |

### Device Routes (`/api/devices`, Phase 3)

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---|
| `GET` | `/` | List your trusted devices | Yes |
| `DELETE` | `/:deviceId` | Remove a trusted device (also revokes its sessions) | Yes |

### Session Routes (`/api/sessions`, Phase 3)

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---|
| `GET` | `/` | List your active (non-revoked) sessions | Yes |
| `DELETE` | `/:sessionId` | Revoke a session | Yes |

### Security Routes (`/api/security`, Phase 3)

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---|
| `GET` | `/events` | Recent security events (new devices, revocations, blocked downloads, quarantines) | Yes |

### Threat Routes (`/api/threats`, Phase 4)

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---|
| `POST` | `/scan` | Scan a plaintext file for malware/threats before encryption - the one endpoint that receives plaintext (see [Phase 4](#-phase-4-malware-scanning--threat-detection)); returns a `scanId` to reference from `POST /api/files/upload` | Yes |
| `GET` | `/scans` | Your scan history, newest first | Yes |
| `GET` | `/quarantined` | Files of yours currently quarantined | Yes |
| `GET` | `/stats` | Aggregate threat statistics (total scans, risk breakdown, malware detections) | Yes |
| `POST` | `/quarantine/:id/release` | Manually release a file from quarantine (owner override, e.g. for a false positive) | Yes |

**Upload Request:**
```json
{
  "file": <binary>,
  "password": "optional_password",
  "maxDownloads": 5,
  "expiryHours": 48
}
```

**Upload Response:**
```json
{
  "fileId": "64d4a1b2c3d4e5f6g7h8i9j0"
}
```

**File Details Response:**
```json
{
  "_id": "64d4a1b2c3d4e5f6g7h8i9j0",
  "filename": "document.pdf",
  "owner": "64d4a1b2c3d4e5f6g7h8i8k0",
  "maxDownloads": 5,
  "downloadCount": 2,
  "expiresAt": "2026-05-09T15:30:00Z",
  "passwordHash": "hashed_password",
  "revoked": false,
  "createdAt": "2026-05-07T15:30:00Z",
  "logs": [
    {
      "ip": "192.168.1.1",
      "userEmail": "recipient@example.com",
      "time": "2026-05-07T16:00:00Z"
    }
  ]
}
```

---

## 🧪 Testing the Application

### Test User Flow
1. **Register**: Navigate to `/register` and create account
2. **Login**: Login with your credentials
3. **Upload**: Go to `/upload`, select file, set expiry & max downloads
4. **Share**: Copy the share link from dashboard
5. **Download**: Open share link in incognito/new browser
6. **Verify**: Check download logs in dashboard

### Test Cases
- [ ] Register with valid email and password
- [ ] Login with incorrect credentials (should fail)
- [ ] Upload file and verify encryption
- [ ] Download file with valid link
- [ ] Download file after expiry (should fail)
- [ ] Download file after max downloads reached (should fail)
- [ ] Password-protected file download
- [ ] Revoke file access
- [ ] Check audit logs

---

## 🛠️ Development & Maintenance

### Running Tests (if tests exist)
```bash
cd backend
npm test

cd frontend
npm test
```

### Code Linting
```bash
cd frontend
npm run lint
```

### Building for Production

**Backend:**
```bash
cd backend
npm run build  # (if build script exists)
npm start      # Runs server.js
```

**Frontend:**
```bash
cd frontend
npm run build
npm start      # Starts optimized Next.js server
```

### Database Migrations
For Mongoose migrations:
```bash
npm install mongoose-migrate  # if using migration tool
```

### Monitoring & Logs
- **Backend Logs**: Check terminal or `/var/log/secureshare.log` in production
- **Frontend Errors**: Check browser console (F12)
- **API Health**: `GET /api/health` returns `{ "status": "ok", "uptime": ... }`

---

## 🐳 Docker Deployment

### Build Images Separately
```bash
# Backend
docker build -t secureshare-backend ./backend

# Frontend
docker build -t secureshare-frontend ./frontend

# Run containers
docker run -p 5000:5000 -e MONGO_URI=<uri> secureshare-backend
docker run -p 3000:3000 secureshare-frontend
```

### Production Considerations
- Use environment-specific `.env` files
- Enable HTTPS in production
- Configure CORS for specific domains
- Increase rate limit thresholds based on traffic
- Use managed MongoDB (Atlas) instead of local instance
- Enable Cloudinary automatic cleanup
- Set up regular backups
- Monitor API performance and errors

---

## 📊 Database Schema

### User Collection
```javascript
{
  _id: ObjectId,
  name: String,
  email: String (unique),
  password: String (hashed),
  publicKey: String, // base64 SPKI RSA-OAEP-SHA256 public key, generated client-side (E2E encryption)
  signingPublicKey: String, // base64 SPKI ECDSA P-256 public key, generated client-side (Phase 2 signing)
  createdAt: Timestamp,
  updatedAt: Timestamp
}
```

### File Collection
```javascript
{
  _id: ObjectId,
  filename: String,
  cloudinaryId: String,
  encryptionVersion: Number, // 1 = legacy server-side AES-256-CBC, 2 = client-side E2E AES-256-GCM
  mimeType: String,          // v2 only
  originalFilename: String,  // v2 only
  algorithm: String,         // v2 only, e.g. "AES-256-GCM"

  // v1 (legacy) fields
  encryptedKey: String (Base64),   // AES key RSA-wrapped with the global server keypair
  iv: String (Base64),             // 16-byte CBC IV (v1) or 12-byte GCM IV (v2 — same field, reused)
  passwordHash: String (optional), // bcrypt hash, v1 only

  // Phase 2 fields — optional, present only if the uploader signed the file. Absence means
  // "unsigned" (legacy or pre-Phase-2 upload), not an error.
  signature: String,          // base64 ECDSA signature over the ciphertext
  fileHash: String,           // base64 SHA-256 digest of the ciphertext (informational only)
  hashAlgorithm: String,      // "SHA-256"
  signatureAlgorithm: String, // "ECDSA-P256-SHA256"
  signedAt: Date,

  // v2 (client-side E2E) fields — server never sees the raw AES key
  wrappedOwnerKey: String,         // AES key wrapped with the owner's own RSA-OAEP public key
  wrappedPasswordKey: String,      // AES key wrapped with a PBKDF2(password)-derived key (optional)
  keySalt: String,
  keyIterations: Number,
  passwordKeyIvHint: String,

  owner: ObjectId (ref: User),
  oneTime: Boolean,
  maxDownloads: Number,
  downloadCount: Number,
  revoked: Boolean,
  expiresAt: Date,

  // Phase 4: malware/threat scan result, mirrored from the ThreatScan doc referenced by scanId.
  // Defaults keep every pre-Phase-4 file unaffected: scanStatus "not_scanned", quarantined false.
  scanId: ObjectId (ref: ThreatScan),
  scanStatus: String,   // "not_scanned" | "pending" | "completed" | "failed"
  riskLevel: String,    // "Low" | "Medium" | "High" | "Critical" | null
  quarantined: Boolean, // true blocks all downloads unconditionally, see downloadFile()

  // Phase 3: Zero Trust access policy. All fields optional/empty by default - a file with no
  // policy configured is unaffected (see backend/services/policyEngine.js).
  policy: {
    allowedCountries: [String],  // ISO country codes; empty = unrestricted
    allowedIPs: [String],        // empty = unrestricted
    allowedDevices: [String],    // device fingerprint hashes; empty = unrestricted
    businessHours: {
      enabled: Boolean,
      startHour: Number,  // UTC hour, 0-23
      endHour: Number      // UTC hour, 0-24
    },
    maxDevices: Number,          // 0 = unlimited distinct devices
    requireApproval: Boolean     // require an authenticated, trusted-device recipient
  },

  // Download logs - extended in Phase 3 with device/policy context and in Phase 4 with a scan
  // snapshot, populated for both allowed and denied attempts (decision/denialReason distinguish them).
  logs: [
    {
      ip: String,
      userEmail: String,
      time: Date,
      deviceId: String,
      browser: String,
      operatingSystem: String,
      country: String,
      decision: String,      // "allow" | "deny"
      denialReason: String,  // present only when decision === "deny"
      scanStatus: String,    // Phase 4 snapshot at download time
      riskLevel: String      // Phase 4 snapshot at download time
    }
  ],
  createdAt: Timestamp,
  updatedAt: Timestamp
}
```

### Device Collection (Phase 3)
```javascript
{
  _id: ObjectId,
  owner: ObjectId (ref: User),
  deviceId: String,       // client-generated fingerprint hash (see frontend/lib/security/fingerprint.ts)
  label: String,          // e.g. "Chrome on Windows"
  browser: String,
  operatingSystem: String,
  userAgent: String,
  firstSeenAt: Date,
  lastSeenAt: Date,
  lastIp: String,
  trusted: Boolean,
  revoked: Boolean,
  createdAt: Timestamp,
  updatedAt: Timestamp
}
```

### Session Collection (Phase 3)
```javascript
{
  _id: ObjectId,
  owner: ObjectId (ref: User),
  sessionId: String,   // matches the `sid` claim embedded in that login's JWT
  deviceId: String,
  browser: String,
  operatingSystem: String,
  ip: String,
  country: String,
  createdAt: Date,
  lastActiveAt: Date,
  revoked: Boolean
}
```

### SecurityEvent Collection (Phase 3, extended in Phase 4)
```javascript
{
  _id: ObjectId,
  owner: ObjectId (ref: User),
  type: String,   // "new_device" | "device_removed" | "session_revoked" | "download_denied" | "file_quarantined"
  message: String,
  file: ObjectId (ref: File),   // present for download_denied / file_quarantined events
  filename: String,
  deviceId: String,
  ip: String,
  country: String,
  createdAt: Date
}
```

### ThreatScan Collection (Phase 4)
```javascript
{
  _id: ObjectId,
  owner: ObjectId (ref: User),
  fileId: ObjectId (ref: File),   // null until the scan is consumed by an actual upload
  originalFilename: String,
  fileSizeBytes: Number,

  claimedMimeType: String,        // what the browser claimed (File.type)
  detectedMimeType: String,       // what magic-byte inspection actually found
  mimeMismatch: Boolean,
  extension: String,
  dangerousExtension: Boolean,      // claimed filename ends in a dangerous extension
  dangerousDetectedType: Boolean,   // magic-byte content IS executable, regardless of claimed name
  hasMacros: Boolean,
  isEncryptedArchive: Boolean,
  magicBytesHex: String,          // first bytes of the file, hex-encoded, for display/audit only

  hashes: { sha256: String, sha1: String, md5: String },

  clamav: {
    status: String,        // "clean" | "infected" | "error" | "unavailable"
    engineVersion: String,
    scannedAt: Date,
    threatNames: [String]
  },
  virusTotal: {
    status: String,        // "skipped" | "clean" | "suspicious" | "malicious" | "unknown" | "error"
    maliciousCount: Number,
    suspiciousCount: Number,
    totalEngines: Number,
    threatNames: [String],
    checkedAt: Date
  },

  riskLevel: String,       // "Low" | "Medium" | "High" | "Critical"
  quarantined: Boolean,
  scanStatus: String,      // "pending" | "completed" | "failed"
  consumedByUpload: Boolean, // prevents a single scan result from backing more than one upload

  createdAt: Timestamp,
  updatedAt: Timestamp
}
```

---

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Best Practices
- Write clear, descriptive commit messages
- Keep functions small and focused
- Add comments for complex logic
- Test thoroughly before submitting PR
- Update documentation for new features

---

## 📝 License

This project is licensed under the MIT License. See [LICENSE](LICENSE) file for details.

---

## 🐛 Troubleshooting

### Common Issues

**MongoDB Connection Error**
- Ensure MongoDB is running: `mongod`
- Check `MONGO_URI` in `.env`
- Verify network access if using MongoDB Atlas

**Cloudinary Upload Fails**
- Verify `CLOUDINARY_CLOUD_NAME`, `CLOUDINARY_API_KEY`, and `CLOUDINARY_API_SECRET`
- Check Cloudinary account storage limits
- Ensure file size is within limits (default: 100MB)

**RSA Key Not Found** (legacy `encryptionVersion: 1` files only)
- Run `node generateKeys.js` in backend directory
- Or set `RSA_PUBLIC_KEY_BASE64` and `RSA_PRIVATE_KEY_BASE64` in `.env`
- This global keypair is only used to decrypt files uploaded before the client-side E2E migration — new uploads use per-user browser-generated keypairs instead (see [Zero-Knowledge Encryption Architecture](#-zero-knowledge-encryption-architecture))

**"No local key found for this device" / can't decrypt my own file**
- Your RSA private key lives only in this browser's IndexedDB, by design (see architecture doc) — it's never sent to the server
- If you cleared browser storage or switched devices, you'll need the original share link (with its `#k=...` fragment) or share password to recover the file; owner-side dashboard access to that specific file is otherwise lost

**Rate Limiting Issues**
- Check current rate limit: 25 requests per 15 minutes
- Modify in `backend/middleware/rateLimit.js` if needed

**JWT Token Expired**
- User needs to login again
- Token expiration is typically 24 hours
- Check `JWT_SECRET` configuration

**CORS Errors**
- Verify `NEXT_PUBLIC_API` points to correct backend URL
- Check CORS settings in `backend/server.js`

---

## 📞 Support & Contact

For issues, questions, or suggestions:
- Open an issue on GitHub
- Check existing issues for solutions
- Review [FAQ](#faq) below

### FAQ

**Q: How long are files stored?**
- A: Files expire based on `expiryHours` setting (default 24 hours, max 30 days)

**Q: Can I change file expiry after upload?**
- A: Currently no, but can be implemented. Users can revoke access.

**Q: Is this GDPR compliant?**
- A: The system supports GDPR through deletion of user data. Implement GDPR data export/deletion endpoints for compliance.

**Q: What encryption algorithm is used?**
- A: New uploads (`encryptionVersion: 2`) use client-side AES-256-GCM for file content, wrapped with RSA-OAEP-SHA256 (3072-bit) — see [Zero-Knowledge Encryption Architecture](#-zero-knowledge-encryption-architecture). Files uploaded before this migration (`encryptionVersion: 1`) remain on the legacy AES-256-CBC / RSA-2048 server-side flow.

**Q: Can the SecureShare server read my files?**
- A: No, not for files uploaded after this migration. Encryption and decryption happen entirely in your browser; the server only ever stores ciphertext and RSA/password-wrapped keys.

**Q: How does SecureShare know a file hasn't been tampered with?**
- A: Files uploaded with Phase 2 (digital signatures) are signed client-side with the uploader's ECDSA P-256 private key over a SHA-256 hash of the encrypted file. Downloaders verify that signature against the uploader's public signing key *before* decrypting — see [Phase 2: Digital Signatures & Integrity Verification](#️-phase-2-digital-signatures--integrity-verification). Files without a signature (legacy, or uploaded before Phase 2) are treated as unsigned, not tampered — signing is additive, not required.

**Q: How many users can the system handle?**
- A: Depends on infrastructure. MongoDB Atlas can scale horizontally. Consider load balancing for production.

**Q: What is Zero Trust access control, and is it required?**
- A: It's an optional, per-file layer (Phase 3) that evaluates every download attempt against configurable rules — allowed countries/IPs/devices, business-hours windows, a max-device cap, or a requirement that the recipient be an authenticated, trusted-device user. It's entirely opt-in: a file with no policy configured behaves exactly as before. See [Phase 3: Zero Trust Access Control](#️-phase-3-zero-trust-access-control).

**Q: What data does device fingerprinting collect?**
- A: None that leaves your browser in raw form. A SHA-256 hash of a fixed set of browser attributes (user agent, platform, language, timezone, screen size, and a canvas rendering signature) is computed locally and only that hash is sent to the server — enough to recognize "same device as last time," nothing else.

---

## 🚀 Future Enhancements

Planned features and improvements:
- [ ] Drag-and-drop file upload
- [ ] Bulk file operations
- [ ] Share with multiple recipients
- [ ] Download statistics dashboard
- [ ] Email notifications for uploads
- [ ] Two-factor authentication (2FA)
- [ ] File encryption in transit (TLS)
- [ ] Support for multiple file uploads in one link
- [ ] Advanced search and filtering
- [ ] API keys for programmatic access
- [ ] Webhooks for integrations
- [ ] Mobile app (React Native)
- [x] Zero Trust access control: device fingerprinting, session management, per-file access policies (Phase 3)
- [ ] Real geo-IP provider integration (currently a CDN-header stub, see Phase 3's country resolution)
- [ ] In-app approval workflow for `requireApproval` policy files (currently requires an already-trusted device)
- [x] End-to-end encryption on client side
- [x] Digital signatures / integrity verification (Phase 2 — ECDSA P-256)
- [ ] Social sharing options
- [ ] Multi-device sync for the local RSA/ECDSA private keys (currently device-bound, see architecture doc above)
- [ ] Out-of-band signing-key verification (key fingerprints/pinning), to remove trust in the server for key distribution (see Phase 2's "known limitation")

---

## 📚 Additional Resources

- [Next.js Documentation](https://nextjs.org/docs)
- [Express.js Guide](https://expressjs.com/)
- [MongoDB Manual](https://docs.mongodb.com/manual/)
- [Cloudinary Documentation](https://cloudinary.com/documentation)
- [Node.js Crypto Module](https://nodejs.org/api/crypto.html)
- [JWT.io](https://jwt.io/)

---

**Last Updated**: May 2026
**Version**: 1.0.0
**Status**: Production Ready ✅
```

- Frontend dev server: http://localhost:3000
- Backend API: http://localhost:5000 (endpoints under `/api`)

### 2) Run with Docker Compose
```bash
cd SecureShare
docker compose up --build
```
- API: http://localhost:5000
- MongoDB: mongodb://localhost:27017

## Core API Endpoints
- `POST /api/auth/register` — create account
- `POST /api/auth/login` — sign in (returns JWT)
- `POST /api/files/upload` — upload file (Auth required; multipart/form-data, field `file`)
- `GET /api/files/my-files` — list your files (Auth required)
- `GET /api/files/download/:id` — download link

## Frontend Notes
- Toasts are integrated globally via `Toaster` (top-right). Actions like login, register, upload, link copy, and logout show feedback.
- Set `NEXT_PUBLIC_API` so Axios requests reach your API (example: `http://localhost:5000/api`).

## Scripts

Backend:
- `npm run dev` — start API with Nodemon
- `npm start` — start API with Node

Frontend:
- `npm run dev` — start Next dev server
- `npm run build` — production build
- `npm start` — start production server

## Security & Cleanup
- Rate limiting protects the public API from abuse
- A scheduled cleanup job removes expired items

## License
This project is for educational/demo purposes.
