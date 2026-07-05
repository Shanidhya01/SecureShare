# SecureShare Performance

## Frontend

**Code splitting**: Next.js App Router automatically splits JS per route — no manual `dynamic()`/`React.lazy()` splitting has been necessary given the current page count and component sizes. If a specific page grows a genuinely heavy dependency (e.g. a large PDF viewer or a big data-viz library used on only one page), that would be the point to introduce a manual dynamic import for it.

**Data fetching**: every list/table page fetches its data once on mount (`useEffect` + `Promise.all` for pages that need several endpoints), not on every render, and paginates client-side over an already-small server response via the shared `Pagination` component (`components/design/Pagination.tsx`) at a fixed page size (typically 15). No page currently fetches or renders an unbounded list, which is why no virtualization library (`react-window`, `@tanstack/react-virtual`) is in `package.json` — it would be solving a problem that doesn't exist yet. If a future page needs to render hundreds+ of rows without pagination, that's the trigger to add one.

**Animation cost**: framer-motion is used for hover/entrance effects, not for anything on a hot render path (no animation drives layout during scroll or typing). The app-wide `MotionConfig reducedMotion="user"` wrapper (`app/layout.tsx`) also means users with reduced-motion preferences skip animation work entirely, which is both an accessibility and a (minor) performance win for that subset of users.

**Shared components over duplication**: `components/design/*` and `components/soc/charts.tsx` are reused across ~20 pages rather than each page rolling its own card/table/chart implementation — this keeps the JS bundle growing roughly with actual new functionality rather than with copy-pasted UI code, and keeps re-renders scoped to genuinely stateful pieces (each `StatCard`/`DataTable` instance manages its own local state, not a shared global store causing cross-page re-renders).

**Images**: MFA QR codes and any user-facing images use `next/image` (see `app/identity/page.tsx`'s `unoptimized` QR code — deliberately unoptimized since it's a locally-generated data URL, not a remote asset Next.js's image optimizer would help with).

## What hasn't been done (and why)

- **No frontend bundle-size audit** (`@next/bundle-analyzer` or similar) has been run — there's no known bloat, but it also hasn't been measured. Worth doing before optimizing further, rather than guessing.
- **No React Server Components data-fetching** — every page is `"use client"` and fetches via `axios` from the browser, matching the app's existing auth model (JWT read from `localStorage`, which RSC data-fetching on the server can't access without a larger auth-architecture change). This is a deliberate trade-off, not an oversight — migrating to server-fetched data would require moving auth token storage to cookies first.
- **No memoization sweep** — individual pages use `useMemo`/`useCallback` where a derived value is visibly expensive (chart data bucketing, filtered table rows) but there's been no systematic `React.memo` audit of every component. Given current page/data sizes this hasn't been a measured problem.

## Backend

- **Rate limiting** (`express-rate-limit`) protects the API from abuse-driven load spikes.
- **Redis Cloud caching + BullMQ job queues** (Phase 13, `backend/services/platform/queue.js`) move scan-type work (threat/malware/cloud/compliance/DevSecOps scans, report generation, notifications) off the request/response cycle where Redis is configured, falling back to synchronous in-process execution when it isn't — so performance degrades gracefully rather than breaking in environments without Redis.
- **Metrics collection** (`backend/services/platform/metricsCollector.js`) records real API latency/error-rate/throughput data, surfaced on the `/platform` dashboard — use that dashboard's "API Latency (24h)" and "Request Volume (24h)" charts as the actual source of truth for backend performance in a given deployment, rather than guessing.

## How to measure before optimizing further

1. Run `cd frontend && npm run build` and read the route-size table Next.js prints — flags any route whose First Load JS is unusually large relative to its neighbors.
2. Check the `/platform` dashboard's latency/error-rate charts (Phase 13) in a real deployment for actual backend performance data.
3. Use browser DevTools' Performance/Lighthouse tabs on the heaviest pages (Platform, Identity, SOC — the ones with the most charts) before assuming any specific page needs optimization.
