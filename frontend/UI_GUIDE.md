# SecureShare Frontend UI Guide

Reference for the shared component layers used across every dashboard page. Two layers:

- `components/ui/` — low-level shadcn/base-ui primitives (buttons, inputs, dialogs, menus). Mostly
  unstyled building blocks; rarely used directly by pages except for `Button`, `Input`, `Select`.
- `components/design/` — domain-agnostic components built on top of `components/ui/`, used directly
  by page code. Prefer these over hand-rolling markup in a page.

Design tokens (colors, radius, dark mode) live in `app/globals.css` as CSS variables exposed via
Tailwind's `@theme inline`. Use the semantic token classes (`bg-card`, `text-muted-foreground`,
`border-border`, `text-destructive`, `bg-success/10`, etc.) rather than raw colors, so components stay
correct in both themes automatically.

## components/design/

### PageHeader
`{ icon: LucideIcon, title: string, description?: string, accent?: "primary"|"danger"|"warning"|"success"|"purple", actions?: ReactNode, className?: string }`
Every page's top banner (icon + title + description + optional right-aligned actions).

### StatCard
`{ label: string, value: ReactNode, icon: LucideIcon, variant?: "primary"|"success"|"warning"|"danger"|"muted"|"purple", delta?: { value: string, direction: "up"|"down", positive?: boolean }, className?: string }`
Summary metric tile used in dashboard grids.

### StatusBadge
`{ label: string, tone?: "neutral"|"success"|"warning"|"danger"|"info", className?: string }`
Small pill for risk/severity/decision labels. Exported tone maps: `riskTone`, `severityTone`, `decisionTone`.

### EmptyState
`{ icon: LucideIcon, title: string, description?: string, actionLabel?: string, onAction?: () => void, actionHref?: string }`
Shown when a list/table has no rows.

### Alert *(new)*
`{ tone?: "info"|"success"|"warning"|"danger", title: string, description?: string, action?: ReactNode, onDismiss?: () => void, className?: string }`
Inline, persistent in-page banner (page-level warnings, form errors). Not for transient notices — use
`react-hot-toast` via `components/ToasterClient.tsx` for those.

### SearchInput *(new)*
`{ value: string, onChange: (value: string) => void, placeholder?: string, className?: string, autoFocus?: boolean }`
Search box with leading icon + clear button. Used by `FilterBar` and `QuickSearch`; use directly for
a standalone search field.

### FilterBar *(new)*
`{ search: string, onSearchChange: (v: string) => void, searchPlaceholder?: string, selects?: FilterBarSelect[], dateRange?: FilterBarDateRange, onReset?: () => void, resetDisabled?: boolean, className?: string }`
Generic search + facet-select + date-range toolbar for any page's filter row. Not for SOC — that page
keeps its own `components/soc/FilterBar.tsx` (incident/device/country fields + CSV/JSON export).

### Loader *(new)*
`Spinner({ className?, size? })`, `InlineLoader({ label?, className? })`, `ProgressBar({ value, label?, className? })`
Spinner and inline loading states; `ProgressBar` wraps the shadcn `Progress` primitive for determinate
progress (scans, uploads).

### Skeletons
Existing skeleton placeholders (`TableSkeleton`, etc.) — pair with `loading` state before real content
is ready, in place of a spinner, wherever the eventual layout is table/card shaped.

### DataTable
```
DataTableColumn<T> = {
  key: string; header: string; align?: "left"|"right"; className?: string;
  render: (row: T) => ReactNode;
  sortable?: boolean; sortValue?: (row: T) => string | number;   // new
  csvValue?: (row: T) => string | number;                        // new
  hideable?: boolean;                                            // new, default true
}
DataTable<T>({
  columns, rows, rowKey, emptyLabel?, stickyHeader?, maxHeight?,
  enableColumnPicker?: boolean;   // new — adds a "Columns" visibility dropdown
  enableExport?: boolean;         // new — adds an "Export CSV" button
  exportFilename?: string;        // new
})
```
Sorting, the column picker, and CSV export all operate on whatever `rows` array is passed in. If a
page paginates client-side before calling `DataTable` (the common pattern — see `app/audit/page.tsx`),
sort and export apply to the *current page* of rows, not the full filtered set. Pass the full
pre-pagination array instead if that's not the desired scope.

Only columns with `csvValue` are included in CSV export (since `render` can return JSX that can't be
safely stringified). Only columns with `sortValue` are sortable, even if `sortable: true` is set.

### Pagination
`{ page: number, totalPages: number, totalItems: number, pageSize: number, onPageChange: (page: number) => void }`

### EventTimeline / ProgressTimeline / SecurityScoreGauge
Existing specialized visualizations — see their source for props.

## components/shell/

### AppShell / Topbar / SidebarNav
App chrome: fixed sidebar (desktop) + mobile sheet, sticky topbar with breadcrumbs, notifications
dropdown, profile menu, theme toggle, and quick-search trigger.

### Theme toggle *(new)*
Topbar now exposes a Sun/Moon button wired to the existing `useTheme()` hook
(`context/ThemeContext.tsx`) — no new theme logic, just a way to reach it without visiting Settings.

### QuickSearch *(new)*
`components/shell/QuickSearch.tsx`, mounted once in `app/layout.tsx`. Opens on Ctrl/Cmd+K or via the
"Search…" button in the Topbar (both dispatch/listen for a `quicksearch:open` window event — no shared
context needed). Searches Files, Threats, Incidents, Users, Compliance evidence, and Cloud assets by
calling each domain's existing list endpoint and filtering client-side, the same way individual pages
already do. Selecting a result navigates to that domain's page (not a specific record's detail view —
not every domain has one).

To add a new searchable domain: add an entry to the `CATEGORIES` array in `QuickSearch.tsx` with a
`fetch` (calling the existing list endpoint) and a `match` (substring test) function.

## Adding a filtered, sortable, exportable table to a page

```tsx
<FilterBar
  search={search}
  onSearchChange={setSearch}
  selects={[{ id: "status", label: "Status", value: statusFilter, onChange: setStatusFilter, options: [...] }]}
  dateRange={{ from, to, onFromChange: setFrom, onToChange: setTo }}
  onReset={filtersActive ? resetFilters : undefined}
/>
<DataTable
  columns={columns}
  rows={pageRows}
  rowKey={(r) => r.id}
  enableColumnPicker
  enableExport
  exportFilename="my-export"
/>
<Pagination page={page} totalPages={totalPages} totalItems={filtered.length} pageSize={PAGE_SIZE} onPageChange={setPage} />
```
