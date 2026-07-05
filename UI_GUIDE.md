# SecureShare UI Guide

A practical guide to how the frontend is structured and the conventions a new page or feature should follow. For the token/theme reference see [DESIGN_SYSTEM.md](DESIGN_SYSTEM.md); for the component catalog see [COMPONENT_LIBRARY.md](COMPONENT_LIBRARY.md).

## App shell & navigation

`frontend/components/shell/AppShell.tsx` decides, per route, whether to render the full authenticated shell (sidebar + topbar) or a bare standalone layout (landing page, login, register, public file-download links). Authenticated pages live under the shell automatically — a new page under `frontend/app/` doesn't need to opt in.

The sidebar (`SidebarNav.tsx`) is driven entirely by `frontend/components/shell/navItems.ts` — add a route there (with a `group`) to add it to navigation; no separate registration is needed elsewhere.

## Anatomy of a typical dashboard page

Nearly every feature page (`Dashboard`, `Security Center`, `Threat Center`, `SOC`, `SOAR`, `Identity`, `Compliance`, `Cloud Security`, `DevSecOps`, `Platform`, `Audit`, `Analytics`, ...) follows the same shape:

```tsx
export default function SomePage() {
  // 1. auth-guarded data fetch on mount (token from localStorage, redirect to /login if absent)
  // 2. loading / error / data state

  return (
    <div>
      <PageHeader icon={...} title="..." description="..." accent="primary" actions={...} />

      {error && <ErrorBanner />}

      {loading ? (
        <StatsSkeleton count={4} />
      ) : (
        <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
          <StatCard label="..." value={...} icon={...} variant="primary" />
          {/* 3-5 StatCards summarizing the page's data */}
        </div>
      )}

      {/* charts, via components/soc/charts.tsx's ChartCard + chart components */}

      {/* a DataTable, or an EmptyState if there's nothing to show */}
    </div>
  );
}
```

When building a new page, follow this shape rather than inventing a new layout: `PageHeader` → stat row → charts (if there's time-series or categorical data) → table/list → empty/loading states via the shared components. This is what keeps ~20 pages visually consistent despite being built independently over 13 phases.

## Loading, empty, and error states

- **Loading**: prefer `StatsSkeleton`/`CardsSkeleton`/`TableSkeleton` (`components/design/Skeletons.tsx`) over a bare spinner for any section that takes more than a beat to load. Use `Spinner`/`InlineLoader` (`components/design/Loader.tsx`) only for small inline/button-level waits.
- **Empty**: use `EmptyState` (`components/design/EmptyState.tsx`) for "no data yet" — give it a specific, actionable description and, where there's an obvious next step (e.g. "Upload a file"), an `actionLabel` + `actionHref`/`onAction`.
- **Error**: page-level fetch errors use an inline destructive banner (`bg-destructive/10 border border-destructive/30` — see any page's `{error && (...)}` block) rather than a full-page replacement, so the rest of the page (nav, header) stays usable. Route-level failures use `app/not-found.tsx` (404) and `app/error.tsx` (error boundary), both built on `EmptyState`.

## Forms & inputs

Use the shadcn primitives directly (`Input`, `Select`, `Switch`, `Label`) for one-off form fields; use `FilterBar` (`components/design/FilterBar.tsx`) for the search+facet-filter+date-range pattern that recurs across list pages. Don't hand-roll a new filter toolbar — check whether `FilterBar` (generic) or `components/soc/FilterBar.tsx` (SOC's fixed-shape variant) already covers the need.

## Tables

Use `DataTable<T>` (`components/design/DataTable.tsx`) for anything tabular. It gives you sorting, an optional column-visibility picker, optional CSV export, sticky headers, and a consistent empty state — for free, and consistently styled with every other table in the app. Pair with `Pagination` (`components/design/Pagination.tsx`) for anything beyond a handful of rows; every existing `DataTable` usage paginates server-responses client-side at a fixed page size (typically 15).

## Charts

Use `components/soc/charts.tsx`'s `ChartCard` wrapper and pre-built chart components (`EventTrendChart`, `SeverityDistributionChart`, `CategoryBarChart`, `RiskTrendChart`, etc.) rather than writing raw Recharts JSX per page — this is what keeps tooltip style, color palette, and gradient-fill treatment consistent across every chart in the app. If you need a genuinely new chart shape, follow the same tooltip-style-constant + `ResponsiveContainer` pattern already used there.

## Notifications & feedback

- Use `react-hot-toast` (`toast.success(...)`/`toast.error(...)`) for action feedback (save succeeded, revoke failed, etc.) — already wired up globally via `ToasterClient` in the root layout.
- The Notification Center (`components/design/NotificationCenter.tsx`) is for persistent, dismissable security-event notifications, not one-off action feedback — don't push toast-style messages into it.

## Dark mode

Every component should be built against the CSS variable tokens (`bg-card`, `text-foreground`, `border-border`, etc.) rather than hardcoded colors — this is what makes dark mode "just work" without a parallel `dark:` variant on every class. The one common exception is Recharts' `stroke`/`fill` props, which take literal hex values (Recharts doesn't read CSS custom properties) — those are chosen to read reasonably in both themes rather than swapped per-theme.

## Where to look for real examples

- `frontend/app/audit/page.tsx` — a good, relatively small example of the full pattern (header, stats, one chart, filter bar, table, pagination).
- `frontend/app/platform/page.tsx` — the most chart-heavy page (8 charts), and the reference for the "no data yet" full-page `EmptyState`.
- `frontend/components/shell/Topbar.tsx` — the reference for combining several shadcn primitives (`DropdownMenu`, `Sheet`) with app-level components (`NotificationCenter`).
