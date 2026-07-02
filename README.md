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
- **Audit Logging**: Track all file downloads with IP addresses, email, and timestamps
- **Automatic Expiration**: Files automatically delete after expiry time
- **JWT Authentication**: Secure token-based user authentication
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
│   │   └── file.controller.js
│   ├── models/                   # Mongoose schemas
│   │   ├── User.js
│   │   └── File.js
│   ├── routes/                   # API endpoints
│   │   ├── auth.routes.js
│   │   ├── user.routes.js
│   │   └── file.routes.js
│   ├── middleware/               # Custom middleware
│   │   ├── auth.middleware.js
│   │   └── rateLimit.js
│   ├── utils/                    # Helper functions
│   │   ├── cloudinary.js
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

### Authentication
- **Registration**: Email & password → bcryptjs hashing (salt rounds: 10)
- **Login**: Credentials validated → JWT token generated (expires: 24 hours)
- **Protected Routes**: All file operations require valid JWT token

### Access Control
- **One-Time Links**: After 1 download, link becomes inactive
- **Limited Downloads**: Configurable max downloads (1-100)
- **Time-Based Expiry**: Files auto-delete after specified duration
- **Password Protection**: Additional layer of security
- **Link Revocation**: Owner can revoke access anytime

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
| `POST` | `/upload` | Upload file (client-side pre-encrypted for `encryptionVersion=2`) | Yes |
| `GET` | `/my-files` | Get user's uploaded files | Yes |
| `GET` | `/file/:id/meta` | Get encryption metadata (IV, wrapped keys, filename) without file bytes | No |
| `GET` | `/download/:fileId` | Download file bytes (decrypted server-side for v1, raw ciphertext for v2) | No |
| `DELETE` | `/:fileId` | Delete/revoke file | Yes |
| `GET` | `/logs/:fileId` | Get download audit logs | Yes |

### User Routes (`/api/users`)

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---|
| `PATCH` | `/publickey` | Set/update your RSA-OAEP public key (base64 SPKI) | Yes |
| `GET` | `/publickey` | Get your own stored public key | Yes |
| `PATCH` | `/signingkey` | Set/update your ECDSA P-256 signing public key (base64 SPKI, Phase 2) | Yes |
| `GET` | `/signingkey` | Get your own stored signing public key | Yes |

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
  logs: [
    {
      ip: String,
      userEmail: String,
      time: Date
    }
  ],
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
