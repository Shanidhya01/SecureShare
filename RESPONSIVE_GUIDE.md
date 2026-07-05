# SecureShare Responsive Guide

## Breakpoints

Standard Tailwind v4 breakpoints, no custom scale: `sm` (640px), `md` (768px), `lg` (1024px), `xl` (1280px). No `2xl` usage currently — dashboards are designed to look good up to a wide desktop monitor without a distinct ultra-wide layout.

## App shell responsiveness

- **Sidebar**: hidden below `md`, fixed 16rem-wide column at `md` and above (`AppShell.tsx`: `hidden md:fixed md:inset-y-0 ... md:w-64`). Below `md`, navigation is reached via the Topbar's mobile menu button, which opens `SidebarNav` inside a `Sheet` drawer.
- **Topbar**: the breadcrumb nav hides below `sm`; the search button collapses from a labeled button (`sm:inline-flex`) to an icon-only button (`sm:hidden`) below `sm`. Account name text hides below `sm`, leaving just the avatar.
- **Main content**: `main` padding steps up at each breakpoint (`px-4 py-6 sm:px-6 lg:px-8`) rather than a single fixed value.

## Page-level conventions

- **Stat card rows**: `grid grid-cols-2 md:grid-cols-4` (or `md:grid-cols-5` for pages with 5 stats) is the standard pattern — 2 columns on mobile, full row from tablet up.
- **Chart grids**: `grid grid-cols-1 lg:grid-cols-2` is standard for paired charts — full-width stacked on mobile/tablet, side-by-side from `lg`.
- **Tables**: `DataTable` wraps in `overflow-x-auto` so wide tables scroll horizontally on narrow viewports rather than breaking layout; there's no separate "card view" fallback for tables on mobile — this is a known simplification, not a bug, appropriate for an admin/enterprise tool typically used on larger screens.
- **Settings page**: uses `sm:grid-cols-2` to pair related fields (Profile's Name/Email, Security's two cards) on tablet+ while stacking on mobile; the tab list scrolls horizontally (`overflow-x-auto`) rather than wrapping, so it stays a single row at any width.

## Known thin spots

An audit of `sm:`/`md:`/`lg:` class density found most feature pages (Dashboard, Security Center, Threat Center, SOAR, Identity, Platform, Analytics, ...) have relatively few explicit responsive-breakpoint classes compared to `cloud-security`/`devsecops`, which are noticeably more thorough. This does **not** mean those pages are visually broken on mobile — most already work reasonably well because:
- `StatCard` grids default to 2 columns, which fits narrow screens without an explicit override.
- `DataTable` handles overflow via horizontal scroll regardless of explicit breakpoint classes.
- Chart grids collapse to `grid-cols-1` by default (the `lg:` prefix is the only breakpoint most of them need).

But it does mean a full responsive QA pass (visually testing every page at mobile/tablet/laptop/desktop widths and tightening spacing/typography scale where needed) has not been done page-by-page — this is real, scoped follow-up work if a pixel-perfect mobile experience across all 20+ pages is a priority, rather than "mostly works because of the shared components' defaults."

## How to do a responsive QA pass on a page

1. Open the page in a browser at 375px (mobile), 768px (tablet), 1024px (laptop), and 1440px+ (desktop) widths.
2. Check: does any text/card overflow its container? Does the stat-card grid look cramped at 2 columns on very narrow phones? Do charts stay legible (axis labels not overlapping) at `lg:grid-cols-2` on a 1024px-wide laptop, or does the chart need to stay full-width until `xl`?
3. Check dialogs/sheets specifically — `Dialog`/`Sheet` content widths (`max-w-lg`, `w-72`, etc.) are set per-usage; confirm they don't overflow on a 375px viewport.
4. Compare against an already-thorough page (`cloud-security`, `devsecops`) for the target level of breakpoint coverage.
