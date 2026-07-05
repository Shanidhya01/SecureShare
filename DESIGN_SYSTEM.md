# SecureShare Design System

This documents the actual design tokens and conventions in use across `frontend/`, not an aspirational spec — every value below is read from the live source.

## Foundation

- **Framework**: Next.js 16 (App Router) + React 19 + TypeScript.
- **Styling**: Tailwind CSS v4, configured via `@theme inline` in `frontend/app/globals.css` (no separate `tailwind.config` color palette — tokens are plain CSS custom properties).
- **Component kit**: [shadcn/ui](https://ui.shadcn.com) primitives in `frontend/components/ui/` (button, card, dialog, dropdown-menu, input, select, sheet, table, tabs, tooltip, avatar, badge, switch, progress, scroll-area, separator, skeleton, label), generated via the shadcn CLI and owned/customized in-repo.
- **App-level components**: `frontend/components/design/` — see [COMPONENT_LIBRARY.md](COMPONENT_LIBRARY.md) for the full catalog.
- **Icons**: [Lucide React](https://lucide.dev).
- **Charts**: [Recharts](https://recharts.org), themed consistently in `frontend/components/soc/charts.tsx`.
- **Animation**: [framer-motion](https://www.framer.com/motion/), variants centralized in `frontend/lib/motion.ts`.

## Color tokens

Defined in `frontend/app/globals.css` as CSS custom properties, redefined separately for light (`:root`) and dark (`.dark`) — the app defaults to dark, with a light variant toggled from Settings → Appearance (`context/ThemeContext.tsx`, persisted to `localStorage`, applied via a no-flash inline script in `app/layout.tsx`).

| Token | Purpose |
|---|---|
| `--background` / `--foreground` | Page background / default text |
| `--card` / `--card-foreground` | Card surfaces |
| `--popover` / `--popover-foreground` | Dropdowns, dialogs, tooltips |
| `--primary` | Brand blue (`#2563eb` in both themes) |
| `--secondary`, `--muted`, `--accent` | Neutral surface variants |
| `--destructive` | Errors, danger states, blocked/denied actions |
| `--success` | Positive states (allowed, healthy, verified) |
| `--warning` | Caution states (degraded, pending, medium risk) |
| `--border` / `--input` | Border and form-control outlines (alpha-based, so they blend correctly over any surface) |
| `--ring` | Focus ring color |
| `--chart-1` … `--chart-5` | The 5-color categorical chart palette |
| `--sidebar*` | A parallel token set for the sidebar surface, so it can diverge slightly from the main background |

Semantic status colors (`success`/`warning`/`destructive`/`info`/`neutral`) are the only palette most feature code should reach for — see `StatusBadge`'s `riskTone`/`severityTone`/`decisionTone` maps in `components/design/StatusBadge.tsx` for the canonical mapping from domain values (e.g. `"Critical"`, `"block"`) to a tone.

## Radius tokens

```
--radius: 0.75rem   (base)
--radius-sm:  calc(var(--radius) * 0.6)
--radius-md:  calc(var(--radius) * 0.8)
--radius-lg:  var(--radius)
--radius-xl:  calc(var(--radius) * 1.4)
--radius-2xl: calc(var(--radius) * 1.8)
--radius-3xl: calc(var(--radius) * 2.2)
--radius-4xl: calc(var(--radius) * 2.6)
```

All derived from one base value — changing `--radius` re-scales every corner in the app proportionally.

## Shadow tokens

```
--shadow-sm / --shadow-md / --shadow-lg
```

Defined separately per theme (subtle, low-opacity in light mode; deeper black-based shadows in dark mode so elevation actually reads against a near-black background). Use the Tailwind v4 arbitrary-property syntax: `shadow-(--shadow-sm)`. Applied today to the Topbar (elevation against scrolled content) and the active Sidebar nav item; not swept across every card — most cards use plain `border` for separation, which is intentional (an enterprise dashboard with a shadow under every card gets visually noisy fast).

## Typography

- Font: Geist Sans (`--font-geist-sans`) / Geist Mono (`--font-geist-mono`), loaded via `next/font/google` in `app/layout.tsx`.
- No separate type-scale token file — sizes are ad hoc Tailwind utilities (`text-xs` for meta/labels, `text-sm` for body, `text-lg`/`text-2xl`/`font-bold` for headings and stat values). `PageHeader` and `StatCard` are the two places that standardize heading/value typography so pages don't reinvent it.

## Motion

- Shared variants in `frontend/lib/motion.ts`: `fadeInUp`, `fadeIn`, `staggerContainer`, `pageTransition`, plus `springTransition`/`scaleTap`/`scaleHover` constants.
- The entire app is wrapped in framer-motion's `<MotionConfig reducedMotion="user">` (`frontend/app/layout.tsx`) — every animated component automatically honors the OS-level `prefers-reduced-motion` setting with zero per-component work. Don't bypass this by calling framer-motion outside of `motion.*` components (raw CSS `transition`/`animation` won't be covered by `MotionConfig`).

## Reduce duplication, don't invent new patterns

Before adding a new card/table/badge/loading-state implementation to a page, check [COMPONENT_LIBRARY.md](COMPONENT_LIBRARY.md) first — nearly every common pattern (stat cards, filter bars, empty/loading states, timelines) already has a shared component used across 10-20+ pages. Two known, deliberate exceptions:
- `components/design/FilterBar.tsx` (generic search/select/date-range toolbar) and `components/soc/FilterBar.tsx` (SOC-specific, fixed filter shape + built-in export buttons) are intentionally separate — see the doc-comment in the generic one.
- SOC's chart set (`components/soc/charts.tsx`) is reused outside `soc/` too (e.g. the Audit page's event-volume trend) — the folder name is historical, not a scope boundary.
