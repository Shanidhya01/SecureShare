# SecureShare — Environment Variables Reference

Every environment variable SecureShare reads, split into **Required** (the app won't function correctly without it) and **Optional** (the app degrades gracefully, with documented fallback behavior, if it's missing). Template files are provided at `backend/.env.example` and `frontend/.env.example` — copy them to `.env` (backend) and `.env.local` (frontend) and fill in real values. Never commit `.env` files — both are gitignored.

---

## Backend (`backend/.env`)

### Required

| Variable | Explains |
|---|---|
| `MONGO_URI` | MongoDB connection string (Atlas SRV URI or a local `mongodb://` URI). The app logs a startup error and never connects to the database if this is unset — nothing that touches persistence will work. |
| `JWT_SECRET` | Secret used to sign and verify JWT authentication tokens (`backend/middleware/auth.middleware.js`, `backend/controllers/auth.controller.js`). **Rotating this immediately invalidates every existing token and session** — all logged-in users are forced to log in again. Use a long, random, unique value per environment; never reuse a development secret in production. |
| `CLOUDINARY_CLOUD_NAME` | Cloudinary account identifier for file (ciphertext) storage. |
| `CLOUDINARY_API_KEY` | Cloudinary API key, paired with the secret below. |
| `CLOUDINARY_API_SECRET` | Cloudinary API secret. Together with the two vars above, required for every upload/download — `uploadFile`/`downloadFile` fail immediately if any of the three is missing. |
| `RSA_PUBLIC_KEY` / `RSA_PRIVATE_KEY` (or their `_BASE64` variants) | The global RSA keypair used **only** for `encryptionVersion: 1` (legacy, pre-Phase-1) files — server-side AES-CBC encryption wrapped with this keypair. New uploads (`encryptionVersion: 2`) never touch this; each user has their own per-account, browser-generated RSA-OAEP keypair instead (see [SECURITY.md](SECURITY.md)). Generate with `node backend/generateKeys.js`. Technically "required" only in the sense that the app will error when a legacy file's download is attempted without it — a deployment with zero pre-Phase-1 files could omit this without visible problems, but it's simplest to always set it. |

### Optional

| Variable | Default | What happens if missing |
|---|---|---|
| `PORT` | `5000` (hardcoded in `server.js`, not currently read from this var) | The server listens on `5000` regardless of what this is set to — kept in `.env.example` for documentation/future-proofing, but changing it currently has no effect. |
| `NODE_ENV` | unset | No backend behavior currently branches on this; some frontend code checks `process.env.NODE_ENV` (a separate, Next.js-managed value) for dev-only logging. Conventionally set to `production` in deployed environments. |
| `RSA_PUBLIC_KEY_BASE64` / `RSA_PRIVATE_KEY_BASE64` | none | Alternative to `RSA_PUBLIC_KEY`/`RSA_PRIVATE_KEY` — base64-encode the entire PEM file contents if your hosting provider's environment variable UI doesn't handle multi-line values well. If none of `RSA_PUBLIC_KEY(_BASE64)`/`RSA_PRIVATE_KEY(_BASE64)` are set, the app falls back to reading `backend/keys/public.pem` and `backend/keys/private.pem` from disk. |
| `CLAMAV_HOST` | `127.0.0.1` | If `clamd` isn't reachable at this host/port, every scan's `clamav.status` reports `"unavailable"` rather than failing — the rest of the Phase 4 threat pipeline (magic bytes, hashing, VirusTotal, risk classification) still runs and produces a valid `riskLevel`. See [DEPLOYMENT.md §3](DEPLOYMENT.md#3-clamav-docker). |
| `CLAMAV_PORT` | `3310` | Same fallback as `CLAMAV_HOST` above — an unreachable port behaves identically to an unreachable host. |
| `VIRUSTOTAL_API_KEY` | unset | VirusTotal hash lookups are skipped entirely (`virusTotal.status: "skipped"`) with no error and no network call — the scan still completes using every other signal. See [DEPLOYMENT.md §5](DEPLOYMENT.md#5-virustotal). |

---

## Frontend (`frontend/.env.local`)

### Required

| Variable | Explains |
|---|---|
| `NEXT_PUBLIC_API` | Base URL the frontend's Axios client (`frontend/lib/api.js`) and various `fetch()` calls use to reach the backend — must include the `/api` suffix (e.g. `http://localhost:5000/api`). Every API call fails without this. Because it's a `NEXT_PUBLIC_*` variable, Next.js inlines its value at **build time** — changing it in a deployed environment requires a full rebuild/redeploy, not just an env var update. |

### Optional

None currently. The frontend has no other environment-variable-driven configuration — all other behavior (crypto algorithms, UI text, rate limits) is defined in code, not configured via environment.

---

## Quick-reference: what breaks if each is missing

| Missing variable | User-visible symptom |
|---|---|
| `MONGO_URI` | Every request that touches the database fails; server logs a connection error on startup |
| `JWT_SECRET` | Login/register technically "succeed" but token verification is broken/insecure — **never leave unset** |
| Any Cloudinary var | Uploads fail with a 500 error (`"Cloudinary not configured"`) |
| RSA keypair (all forms unset, no `keys/*.pem` either) | Legacy (`encryptionVersion: 1`) uploads/downloads fail; new (`encryptionVersion: 2`) uploads/downloads are unaffected |
| `CLAMAV_HOST`/`CLAMAV_PORT` (clamd unreachable) | Scans complete but always report `clamav.status: "unavailable"` — no malware signature detection, but magic bytes/hashing/VirusTotal/risk classification still work |
| `VIRUSTOTAL_API_KEY` | Scans complete but always report `virusTotal.status: "skipped"` — no second-opinion hash lookup |
| `NEXT_PUBLIC_API` | Every frontend API call fails (wrong/undefined base URL) |

For deployment-specific instructions on setting these (Vercel dashboard, Render, Docker), see [DEPLOYMENT.md](DEPLOYMENT.md).
