# SecureShare Component Library

Catalog of the shared, app-level components in `frontend/components/design/` and `frontend/components/shell/` — the building blocks every dashboard page is composed from. For the underlying shadcn/ui primitives (button, dialog, table, tabs, etc.), see `frontend/components/ui/` and the [shadcn/ui docs](https://ui.shadcn.com/docs/components).

## Layout & page structure

**`PageHeader`** (`design/PageHeader.tsx`) — every page's title block: icon chip, gradient title, description, optional `actions` (buttons/links), and an `accent` variant (`primary`/`danger`/`warning`/`success`/`purple`) that colors the icon chip and title gradient. Used at the top of every dashboard page.

**`SectionHeader`-style usage** — there's no separate component for sub-section headers within a page; the convention is a `<h2 className="flex items-center gap-2 text-lg font-bold text-foreground mb-4">` with a Lucide icon, repeated inline per page.

## Data display

**`StatCard`** (`design/StatCard.tsx`) — the KPI/summary tile used at the top of nearly every dashboard: `label`, `value`, `icon`, a `variant` (`primary`/`success`/`warning`/`danger`/`muted`/`purple`) controlling the icon-chip color, and an optional `delta` (trend arrow + text). Typically rendered in a `grid grid-cols-2 md:grid-cols-4` row. Pair with `StatsSkeleton` while loading.

**`DataTable<T>`** (`design/DataTable.tsx`) — the generic table used on ~20 pages (Audit, Compliance, Cloud Security, DevSecOps, SOAR, Identity, Threat Intel, ...). Column definitions support `render`, `sortable`/`sortValue`, `csvValue` (CSV export), and `hideable` (column picker). Built-in empty label, optional sticky header, optional CSV export button. No built-in loading state — pair with `TableSkeleton`.

**`StatusBadge`** (`design/StatusBadge.tsx`) — the canonical small pill badge for any status/severity/decision value. Takes a `tone` (`neutral`/`success`/`warning`/`danger`/`info`); also exports `riskTone`, `severityTone`, `decisionTone` lookup maps so callers don't hand-roll their own risk-level → color mapping.

**`SecurityScoreGauge`** (`design/SecurityScoreGauge.tsx`) — the circular 0-100 score gauge used on Security Center and SOC.

**`EventTimeline` / `ProgressTimeline`** (`design/EventTimeline.tsx`, `design/ProgressTimeline.tsx`) — vertical activity-feed components (icon + title + description + timestamp + optional tone/badge), used for login history, security events, and audit-style feeds.

## Filtering & search

**`FilterBar`** (`design/FilterBar.tsx`) — generic search input + facet `<select>`s + optional date range + reset button, for any page with simple filtering needs (e.g. Audit Logs). Deliberately *not* used by SOC, which has its own `components/soc/FilterBar.tsx` with a fixed filter shape and built-in CSV/JSON export — the two are not interchangeable, see the doc-comment in the generic one.

**`SearchInput`** (`design/SearchInput.tsx`) — the standard search box with leading icon + clear button, used inside `FilterBar` and `QuickSearch`.

**`Pagination`** (`design/Pagination.tsx`) — page/of-total controls paired with every `DataTable` usage.

## Feedback & state

**`EmptyState`** (`design/EmptyState.tsx`) — the canonical "nothing here yet" pattern: icon, title, description, and an optional primary action (link or button). Used for empty tables, zero-data dashboards (Platform, Analytics), and the app's `not-found.tsx`/`error.tsx` boundaries.

**`Skeletons`** (`design/Skeletons.tsx`) — three loading skeletons built on shadcn's `Skeleton`: `StatsSkeleton` (stat-card row), `CardsSkeleton` (card grid), `TableSkeleton` (table rows). This is the app's loading-state story — prefer these over a bare spinner for anything above a few hundred milliseconds.

**`Loader`** (`design/Loader.tsx`) — `Spinner` and `InlineLoader` (spinner + label) for inline/button-level loading, and `ProgressBar` (wraps shadcn `Progress`) for determinate progress (e.g. upload/encryption steps).

**`Alert`** (`design/Alert.tsx`) — inline banner-style alert component for page-level errors/warnings.

**`NotificationCenter`** (`design/NotificationCenter.tsx`) — the Topbar's notification dropdown: all/unread filter, per-item archive, mark-all-read. Read/archived state is tracked client-side in `localStorage` (keyed by event id) since there's no backend read-state endpoint — it consumes the same `/security/events` feed the Topbar already fetches.

## Charts

**`components/soc/charts.tsx`** — the shared chart theme: `ChartCard` (title + bordered card wrapper), and a family of pre-built Recharts components (`SeverityDistributionChart`, `CategoryBarChart`, `EventTrendChart`, `RiskTrendChart`, `IncidentTimelineChart`, etc.) all sharing one tooltip style constant and gradient-fill convention. Despite the folder name, these are reused outside SOC too (e.g. the Audit page's 30-day event-volume trend) — treat this as the app's general chart library, not a SOC-only module.

## Application shell

**`AppShell`** (`shell/AppShell.tsx`) — the root layout switch: renders bare `children` for standalone routes (`/`, `/login`, `/register`, public file-download pages) or the full sidebar+topbar shell for authenticated app pages, with page-transition animation via `lib/motion.ts`'s `pageTransition`.

**`SidebarNav`** (`shell/SidebarNav.tsx`) + **`navItems.ts`** — the primary nav, grouped into visual sections (Overview, Files, Security Operations, Identity & Governance, Platform, Insights, Account) per each item's `group` field. Purely a visual grouping — it doesn't affect routing.

**`Topbar`** (`shell/Topbar.tsx`) — breadcrumb, global search trigger (`Ctrl/Cmd K`), theme toggle, `NotificationCenter`, and account menu. Mobile uses a `Sheet` drawer rendering `SidebarNav`.

**`QuickSearch`** (`shell/QuickSearch.tsx`) — the `Ctrl/Cmd K` command palette. Searches live backend data across Files, Threats, Incidents, Users, Compliance, and Cloud Assets (fetched once per open, filtered client-side). Supports arrow-key/Enter navigation and a "recent searches" list persisted to `localStorage`.

## Convention: when to add a new component vs. reuse

If you're about to write a card grid, a status pill, a loading skeleton, or a filter row from scratch — check this list first. The existing set covers essentially every dashboard pattern in the app; a new page should almost never need a new primitive, only new *data* passed into `PageHeader` + `StatCard` + `DataTable`/charts + `EmptyState`/`Skeletons`.
