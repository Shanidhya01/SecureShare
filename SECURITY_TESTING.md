# SecureShare — Security Testing Guide

This document describes manual (and where noted, scriptable) test procedures for verifying every security guarantee introduced across Phases 1-4. Each test states its **Purpose**, **Steps**, **Expected Result**, and **Pass Criteria** so it can be run consistently by anyone on the team, or used as the basis for an automated test suite later.

**Scope**: this guide only exercises functionality already implemented — see [SECURITY.md](SECURITY.md) for the full threat model and [README.md](README.md#-security-architecture-roadmap) for architecture background on each phase.

**Prerequisites**: a running backend (`cd backend && npm run dev`) and frontend (`cd frontend && npm run dev`), a MongoDB connection, Cloudinary credentials, and at least one test user account. ClamAV/VirusTotal tests additionally require those services configured (see [ENVIRONMENT_VARIABLES.md](ENVIRONMENT_VARIABLES.md)) — tests that need them note this explicitly and describe the fallback behavior if they're unavailable.

---

## Phase 1 Tests — Zero-Knowledge Encryption

### 1.1 Upload Encryption

**Purpose**: Confirm the server never stores plaintext file content.

**Steps**:
1. Log in, go to `/upload`, select a small text file with distinctive content (e.g. `"THIS IS A PLAINTEXT MARKER 12345"`).
2. Open browser DevTools → Network tab before clicking upload.
3. Upload the file (no password).
4. Inspect the `POST /api/files/upload` request payload (the `file` field).
5. Separately, download the raw object directly from the Cloudinary dashboard (or via its signed URL) and inspect its bytes.

**Expected Result**: Neither the request payload nor the stored Cloudinary object contains the marker string in plaintext — the bytes are indistinguishable from random data.

**Pass Criteria**: A byte-for-byte or substring search for the marker text fails against both the network payload and the stored object.

### 1.2 Browser-side Encryption

**Purpose**: Confirm encryption actually happens client-side, not via a hidden server round-trip.

**Steps**:
1. In DevTools → Network, throttle or disable network momentarily right after clicking Upload but before the request fires (or use a breakpoint on `fetch`/XHR).
2. Observe that `generateAESKey`, `encryptFile`, and `wrapAESKey` (in `frontend/lib/crypto/`) execute and produce ciphertext *before* any network request is dispatched.
3. Alternatively, add a temporary `console.log` in `encryptFile` (fileEncryption.ts) and confirm it logs before the `api.post("/files/upload", ...)` call.

**Expected Result**: The ciphertext, IV, and wrapped key are fully computed in-browser before the first network request for the upload.

**Pass Criteria**: No plaintext file bytes appear in any network request; encryption functions execute measurably before the upload POST fires.

### 1.3 Cloudinary Stores Ciphertext

**Purpose**: Verify long-term storage never holds plaintext.

**Steps**:
1. Upload a file with recognizable content (e.g. a JPEG with a distinctive visual, or a text file).
2. In the Cloudinary console, locate the corresponding `raw` resource (matches `File.cloudinaryId` in MongoDB).
3. Download it directly from Cloudinary (bypassing SecureShare's API entirely).
4. Attempt to open it as its original type (e.g. open the "JPEG" in an image viewer).

**Expected Result**: The downloaded object fails to open as the original file type — it's ciphertext, not a valid file of any recognizable format.

**Pass Criteria**: The raw Cloudinary object is not a valid instance of the original file format.

### 1.4 Legacy Compatibility

**Purpose**: Confirm `encryptionVersion: 1` (pre-Phase-1) files still work unchanged.

**Steps**:
1. Manually insert a `File` document with `encryptionVersion: 1` (or absent) and a correspondingly-encrypted Cloudinary object, matching the legacy shape (`encryptedKey`, `iv`, no `wrappedOwnerKey`). Easiest: temporarily point a checkout at a pre-Phase-1 commit, perform one real upload there, then switch back.
2. Visit `/file/:id` for that document's id.
3. Confirm the page renders the legacy password-prompt-then-download UI (no client-side decrypt attempted).
4. Also hit `GET /api/files/download/:id` directly and confirm it returns decrypted plaintext bytes (server-side decryption, as designed for v1).

**Expected Result**: The legacy file downloads successfully via both the UI and a direct API call, using the original server-side AES-256-CBC + global RSA keypair flow.

**Pass Criteria**: Legacy file content matches its original plaintext exactly; no errors related to missing v2-only fields.

---

## Phase 2 Tests — Digital Signatures & Integrity Verification

### 2.1 Signature Generation

**Purpose**: Confirm every new upload is signed when a signing key is available.

**Steps**:
1. Register a new account (this generates an ECDSA P-256 signing keypair client-side and uploads the public key).
2. Upload a file.
3. Inspect the `POST /api/files/upload` request body for `signature`, `fileHash`, `hashAlgorithm`, `signatureAlgorithm`, `signedAt` fields.
4. Query the created `File` document in MongoDB and confirm those fields are populated.

**Expected Result**: All five signature-related fields are present and non-empty; `signatureAlgorithm` is `"ECDSA-P256-SHA256"`, `hashAlgorithm` is `"SHA-256"`.

**Pass Criteria**: The `File` document has a non-null `signature` field after upload.

### 2.2 Signature Verification

**Purpose**: Confirm a correctly signed file passes verification and decrypts normally.

**Steps**:
1. Upload a file as a logged-in user (signing enabled).
2. Copy the share link and open it in an incognito window.
3. Trigger the download.
4. Observe the UI's signature status indicator during the download flow.

**Expected Result**: UI shows "Verifying digital signature..." followed by a green "Signature verified — this file is authentic and unmodified" badge, then the file downloads and its content is byte-identical to the original.

**Pass Criteria**: Signature status resolves to "verified"; downloaded file matches the original exactly.

### 2.3 Signature Tampering

**Purpose**: Confirm a mismatched/corrupted signature blocks the download entirely.

**Steps**:
1. Upload a signed file, note its `fileId`.
2. In MongoDB, manually flip a few characters in that document's `signature` field (keep it valid base64, just wrong bytes).
3. Attempt to download the file via its share link.

**Expected Result**: Verification fails; UI shows a red "Tampering detected. This file's signature does not match its content - download blocked" message. No decryption is attempted and no plaintext is ever produced.

**Pass Criteria**: Download is blocked; the error message references tampering, not a generic failure; no file is saved to disk.

### 2.4 Ciphertext Tampering

**Purpose**: Confirm the signature also catches tampering with the *encrypted file bytes* themselves (not just the signature field), since the signature covers the ciphertext.

**Steps**:
1. Upload a signed file.
2. In the Cloudinary console, replace the stored raw object's bytes with different (but still arbitrary) bytes of the same or similar length — or use `cloudinary.uploader.upload_stream` in a scratch script to overwrite the same `public_id`.
3. Attempt to download the file via its share link.

**Expected Result**: Signature verification fails (the recomputed hash of the now-different ciphertext no longer matches what was signed) — same blocking behavior as 2.3.

**Pass Criteria**: Download is blocked with a tampering error, even though the `File.signature` field itself was never touched.

### 2.5 Hash Verification

**Purpose**: Confirm the informational `fileHash` field is computed correctly and is consistent with what's actually signed.

**Steps**:
1. Upload a file and note the `fileHash` value stored on its `File` document (base64 SHA-256 of the ciphertext).
2. Independently fetch the ciphertext bytes (`GET /api/files/download/:id` for a v2 file returns raw ciphertext) and compute `SHA-256` over them locally (e.g. `openssl dgst -sha256 file.enc | xxd -r -p | base64`).

**Expected Result**: The independently computed hash matches the stored `fileHash` exactly.

**Pass Criteria**: Byte-for-byte match between the stored and independently computed SHA-256 digest.

---

## Phase 3 Tests — Zero Trust Access Control

### 3.1 Trusted Devices

**Purpose**: Confirm a device is recorded and marked trusted after a successful login.

**Steps**:
1. Log in from a fresh browser profile (or clear IndexedDB/localStorage first).
2. Visit `/security` (Security Center).
3. Check the "Trusted Devices" section.

**Expected Result**: Exactly one device entry appears, labeled with a browser/OS guess, marked "This device", with a recent "last seen" timestamp.

**Pass Criteria**: A `Device` document exists in MongoDB for this `(owner, deviceId)` pair with `trusted: true`.

### 3.2 Device Fingerprinting

**Purpose**: Confirm the fingerprint is stable across sessions and doesn't leak raw attributes to the server.

**Steps**:
1. Log in, note the `deviceId` recorded (visible in MongoDB's `Device` collection, or by inspecting the `deviceId` sent in the login request body via DevTools).
2. Log out, then log back in from the *same* browser.
3. Compare the `deviceId` value between the two logins.
4. Inspect the login request body in DevTools for any raw fingerprint attributes (canvas data URI, exact user agent string as a distinct field, etc.).

**Expected Result**: The `deviceId` is identical across both logins (stable). The request body contains only the final hash, never the intermediate canvas/timezone/screen values as separate fields.

**Pass Criteria**: Same `deviceId` on both logins; no raw fingerprint components appear in any request body.

### 3.3 Active Sessions

**Purpose**: Confirm each login creates a distinct, visible session.

**Steps**:
1. Log in from two different browsers (or one normal + one incognito window).
2. Visit `/security` from either one.
3. Check the "Active Sessions" table.

**Expected Result**: Two session rows appear, each with its own browser/OS/IP/login time; the session matching the current browser is marked "Current".

**Pass Criteria**: Session count matches the number of active logins; the current session is correctly flagged.

### 3.4 Session Revocation

**Purpose**: Confirm revoking a session immediately blocks that session's token from further use.

**Steps**:
1. Log in from Browser A and Browser B (same account).
2. From Browser A's Security Center, revoke Browser B's session.
3. In Browser B, attempt any authenticated action (e.g. reload `/dashboard`, which calls `GET /api/files/my-files`).

**Expected Result**: Browser B's request is rejected (`403 { error: "Session revoked" }`); the frontend redirects it to `/login`.

**Pass Criteria**: The revoked session's JWT is rejected on its very next authenticated request, without needing to wait for expiry.

### 3.5 Security Events

**Purpose**: Confirm notable security actions are logged to the activity feed.

**Steps**:
1. Perform: a first-time login from a new device, a device removal, and a session revocation.
2. Visit `/security` → "Recent Security Events".

**Expected Result**: Three corresponding entries appear (`new_device`, `device_removed`, `session_revoked`), each with a human-readable message and timestamp.

**Pass Criteria**: Each action produces exactly one matching `SecurityEvent` document, visible in the feed within one page refresh.

### 3.6 Zero Trust Policies (general)

**Purpose**: Confirm a file with a policy configured is evaluated on every download attempt, and a file with no policy is unaffected.

**Steps**:
1. Upload File A with no policy configured. Upload File B with the "Advanced Security Policy" section expanded and at least one rule set (e.g. `maxDevices: 1`).
2. Download File A from two different devices/browsers.
3. Download File B from two different devices/browsers.

**Expected Result**: File A succeeds both times (no policy = always allow). File B succeeds on the first device and is denied on the second (`403 policy_denied`, reason mentioning the device cap).

**Pass Criteria**: File A's downloads are never evaluated against any restriction; File B's second download is denied with a policy-specific reason string.

### 3.7 Device Restriction

**Purpose**: Confirm `allowedDevices` correctly restricts downloads to specific device fingerprints.

**Steps**:
1. Upload a file, then `PATCH /api/files/file/:id/policy` (or via the upload-time UI) setting `allowedDevices` to a single, deliberately wrong fingerprint hash (not the current device's).
2. Attempt to download the file from the current (non-matching) device.

**Expected Result**: Download is denied with reason `"Device not authorized for this file"`.

**Pass Criteria**: Request returns `403 policy_denied`; the log entry for the attempt has `decision: "deny"`.

### 3.8 Country Restriction

**Purpose**: Confirm `allowedCountries` restricts by resolved country.

**Steps**:
1. Set a file's policy to `allowedCountries: ["FR"]` (or any country you're not in).
2. Attempt to download it normally.
3. Note: locally, without a CDN/proxy geo-IP header (`CF-IPCountry`, `X-Vercel-IP-Country`), country resolves to `"Unknown"`.

**Expected Result**: Download is denied — either because your actual country isn't `"FR"`, or (in local dev, no geo header) because `"Unknown"` can never satisfy a non-empty `allowedCountries` list (fails closed, by design).

**Pass Criteria**: Download denied with a country-related reason; behavior matches the documented fail-closed semantics from [SECURITY.md](SECURITY.md).

### 3.9 Business Hour Restriction

**Purpose**: Confirm `businessHours` restricts downloads to a configured UTC window.

**Steps**:
1. Set a file's policy to `businessHours: { enabled: true, startHour: <next hour>, endHour: <next hour + 1> }` (a window that does *not* include the current UTC hour).
2. Attempt to download immediately.
3. Then set the window to include the current UTC hour and retry.

**Expected Result**: First attempt denied (`"Outside allowed access hours"`); second attempt succeeds.

**Pass Criteria**: Denial/allow behavior flips correctly based purely on the current UTC hour vs. the configured window (including correctly handling an overnight window like `22:00-06:00`, tested separately if desired).

---

## Phase 4 Tests — Malware Scanning & Threat Detection

### 4.1 Magic Byte Detection

**Purpose**: Confirm file type is detected from content, not filename/extension.

**Steps**:
1. Rename any `.png` file to `test.txt`.
2. Upload it (this triggers `POST /api/threats/scan` before encryption).
3. Inspect the scan result (Threat Center → Scan History, or the API response) for `detectedMimeType` and `mimeMismatch`.

**Expected Result**: `detectedMimeType` is `"image/png"` (correctly identified from the PNG signature bytes), while `claimedMimeType` reflects whatever the browser inferred from the `.txt` extension (likely `"text/plain"`), and `mimeMismatch: true`.

**Pass Criteria**: Detected type is based on file content, independent of the filename used.

### 4.2 MIME Mismatch

**Purpose**: Confirm a claimed-vs-detected type mismatch is flagged and elevates risk.

**Steps**:
1. Use the renamed file from 4.1 (or any file with a mismatched extension).
2. Check its risk level in the scan result.

**Expected Result**: `mimeMismatch: true` and `riskLevel` is at least `"Medium"` (per the risk engine's rules — see [SECURITY.md](SECURITY.md#supported-algorithms) risk table).

**Pass Criteria**: A mismatch alone (no other risk factors) results in `Medium`, not `Low`.

### 4.3 ClamAV Clean File

**Purpose**: Confirm a benign file scans clean when ClamAV is available.

**Prerequisite**: `clamd` running and reachable at `CLAMAV_HOST`/`CLAMAV_PORT` (see [DEPLOYMENT.md §3](DEPLOYMENT.md#3-clamav-docker)).

**Steps**:
1. Upload any ordinary, non-malicious file (e.g. a plain PDF or PNG).
2. Check the scan result's `clamav.status`.

**Expected Result**: `clamav.status === "clean"`.

**Pass Criteria**: Status is `"clean"`, not `"unavailable"` or `"error"` (confirms `clamd` is actually reachable and functioning, not silently degrading).

### 4.4 EICAR Malware Detection

**Purpose**: Confirm ClamAV genuinely detects malicious content using the industry-standard, harmless EICAR test string.

**Steps**:
1. Create a file containing exactly the EICAR test string (no extra whitespace/newlines):
   ```
   X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
   ```
2. Save it as `eicar.txt` (or `.com`, both are standard).
3. Upload it through the normal upload flow.
4. Inspect the scan result.

**Expected Result**: `clamav.status === "infected"`, with `clamav.threatNames` containing an EICAR-related signature name (e.g. `"Eicar-Signature"` or similar, depending on ClamAV's signature database naming). `riskLevel` is `"Critical"`. The upload page shows a blocking error and refuses to proceed to encryption/upload.

**Pass Criteria**: The EICAR file is detected as infected and the upload is blocked client-side; if the request is replayed server-side directly (bypassing the UI), the resulting `File.quarantined` is `true`.

> The EICAR test file is a standardized, universally-recognized antivirus test signature — it is **not** actual malware and is safe to use for this test. See [eicar.org](https://www.eicar.org/) for background.

### 4.5 Quarantine

**Purpose**: Confirm a High/Critical-risk file is marked quarantined end-to-end.

**Steps**:
1. Upload a file guaranteed to trigger quarantine — e.g. rename an executable-signature file (or any binary starting with `MZ`/`4D 5A`) to a `.pdf` extension, which triggers the "disguised executable" Critical-risk rule regardless of ClamAV availability.
2. Confirm the upload page blocks the upload with a risk-level message.
3. If you bypass the client (e.g. via `curl`/Postman calling `POST /api/files/upload` directly with a valid `scanId` from a quarantined scan), confirm the resulting `File` document still gets created with `quarantined: true`.
4. Check the Threat Center's "Quarantined Files" section.

**Expected Result**: The file appears in "Quarantined Files" with its risk level and (if applicable) detected threat names.

**Pass Criteria**: `File.quarantined === true` and `File.riskLevel` is `"High"` or `"Critical"`.

### 4.6 Malware Download Blocking

**Purpose**: Confirm a quarantined file can never be downloaded, regardless of how the download is attempted.

**Steps**:
1. Using the quarantined file from 4.5, attempt to download it via its share link (`/file/:id`).
2. Attempt a direct `GET /api/files/download/:id` call (e.g. via `curl`), bypassing the frontend entirely.

**Expected Result**: Both attempts fail — the frontend shows a "This file is quarantined" block (no download buttons rendered at all), and the direct API call returns `403 { error: "quarantined", riskLevel }`.

**Pass Criteria**: No plaintext or ciphertext bytes are ever served for a quarantined file, through any access path.

### 4.7 VirusTotal Lookup

**Purpose**: Confirm VirusTotal integration works when configured, and degrades gracefully when not.

**Steps (with API key configured)**:
1. Upload a file whose SHA-256 is known to VirusTotal as malicious — the EICAR file from 4.4 works well here too, since VirusTotal also universally recognizes it.
2. Check the scan result's `virusTotal` object.

**Expected Result**: `virusTotal.status === "malicious"`, with `maliciousCount > 0` and populated `threatNames`.

**Steps (without API key configured)**:
1. Temporarily unset `VIRUSTOTAL_API_KEY` and restart the backend.
2. Upload any file.
3. Check the scan result.

**Expected Result**: `virusTotal.status === "skipped"`, all counts `0`, no error — the rest of the scan pipeline (magic bytes, ClamAV, risk classification) still completes normally.

**Pass Criteria**: VirusTotal absence never blocks or errors the overall scan; presence correctly reflects real API data.

### 4.8 Risk Classification

**Purpose**: Confirm the risk engine's rule table (see [SECURITY.md](SECURITY.md)) produces the documented level for each signal combination.

**Steps**: Upload (or directly test via `backend/services/riskEngine.js`'s `classifyRisk()`) each of the following signal combinations and record the resulting `riskLevel`:

| Signals | Expected Level |
|---|---|
| No risk factors | `Low` |
| MIME mismatch only | `Medium` |
| Macro-enabled extension (`.docm`) only | `Medium` |
| Encrypted/password-protected ZIP archive only | `Medium` |
| Dangerous extension (`.exe`) only | `High` |
| Disguised executable (magic bytes = executable, claimed type ≠ executable) | `Critical` |
| Confirmed malware (ClamAV or VirusTotal) | `Critical` |

**Expected Result**: Each row's actual classification matches the table.

**Pass Criteria**: All seven cases match; any mismatch indicates a regression in `riskEngine.js` and should block a release.

---

## Running these tests as part of CI (future work)

None of the above are currently automated. A reasonable first step would be converting the pure-function tests (2.5, 4.8, and the policy engine cases in 3.6-3.9) into a Jest/Vitest suite targeting `backend/services/riskEngine.js` and `backend/services/policyEngine.js` directly, since both are dependency-free pure functions designed for exactly this. The end-to-end tests (uploads, downloads, UI state) would need a browser automation tool (Playwright/Cypress) and are a larger investment — see the Roadmap in [README.md](README.md).
