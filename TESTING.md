# SecureShare Testing

## Backend — real test suite, passing

```bash
cd backend
npm test
```

Runs via Node's built-in test runner (`node --test tests/**/*.test.js`, see `backend/package.json`'s `test` script) — no separate test framework dependency. As of this writing: **195 tests, all passing**, across:

- `dlp.test.js` — DLP detectors, masking, policy decisions
- `correlationEngine.test.js` — SIEM/SOC event correlation rules
- `threatIntel.test.js` — IOC extraction, MITRE ATT&CK mapping, YARA rule evaluation, threat-intel provider fallbacks (VirusTotal/AbuseIPDB/OTX/URLHaus/OpenPhish/CIRCL, each verified to skip gracefully when unconfigured rather than throwing)
- `soarEngine.test.js` — trigger mapping, condition evaluation, rule matching, playbook execution (including partial-failure and continue-on-failure semantics)
- `iam.test.js`, `cloud.test.js`, `devsecops.test.js`, `compliance.test.js`, `platform.test.js` — the respective phase's pure business logic

Most of these test **pure functions** (no DB, no network) — e.g. `policyEngine.js`, `riskEngine.js`, `dlpPolicyConfig.js`, `correlationEngine.js` are all deliberately written as pure, dependency-free modules specifically so they're this easy to unit test. When adding new business logic, prefer this same shape (pure function in, verifiable output out) over logic embedded directly in a controller, both for testability and for the ability to reuse it from multiple call sites.

## Frontend — no automated test suite yet

There is currently **no** Jest/Vitest/Playwright/Testing-Library configuration in `frontend/`, and no `test` script in `frontend/package.json`. This is a known, real gap — not an oversight to paper over. Verification of frontend changes today relies on:
- `npm run lint` (ESLint, including React Hooks rules)
- `npm run build` (full TypeScript type-check + Next.js production build + static prerendering of every route)
- Manual verification in the browser

### Setting up a frontend test suite (recommended approach, not yet done)

If/when this is prioritized, [Vitest](https://vitest.dev) + [React Testing Library](https://testing-library.com/react) is the natural fit for this stack (fast, native ESM/TypeScript support, works well with Next.js App Router client components):

```bash
cd frontend
npm install -D vitest @vitejs/plugin-react jsdom @testing-library/react @testing-library/jest-dom @testing-library/user-event
```

Good first targets, in rough priority order:
1. **Pure logic first**: `lib/severity.ts`, `lib/chartHelpers.ts` (`bucketByDay`), `lib/securityScore.ts` — no rendering needed, highest test-to-effort ratio, mirrors the backend's pure-function-first testing philosophy.
2. **Shared components** (`components/design/*`) — a `DataTable` sort/column-picker test, an `EmptyState` render test, a `StatCard` variant test. These are used everywhere, so a regression here has the widest blast radius.
3. **The newest interactive components** — `NotificationCenter` (mark-read/archive/filter logic) and `QuickSearch` (keyboard navigation, recent-searches persistence) are the most stateful pieces added recently and currently have zero coverage.
4. **End-to-end** (Playwright, if pursued): login → upload → download round-trip is the single highest-value E2E path, since it exercises the client-side crypto pipeline that's hardest to verify any other way.

## Manual security testing

See [SECURITY_TESTING.md](SECURITY_TESTING.md) for the existing manual security test plan (encryption round-trips, Zero Trust policy evaluation, malware scan false-positive/negative handling, DLP detector accuracy).

## Running everything before a PR

```bash
# Backend
cd backend && npm test

# Frontend
cd frontend && npm run lint && npm run build
```

Both should be clean before merging. There is no CI workflow wired up yet to enforce this automatically — see the "CI & Build Status" section of the [README](README.md#-ci--build-status) for what a `.github/workflows/ci.yml` running these two steps would look like.
