# SecureShare Accessibility

An honest account of what's implemented, not a checklist claiming full WCAG conformance. This should be updated as gaps are closed.

## What's in place today

**Keyboard navigation**
- Global command palette (`Ctrl/Cmd K`, `frontend/components/shell/QuickSearch.tsx`): arrow-key/Enter navigation over both the recent-searches list and live search results, with a visible highlighted-row state that stays in sync between keyboard and mouse hover.
- All interactive shadcn/Radix primitives (`Dialog`, `DropdownMenu`, `Select`, `Tabs`, `Sheet`) get focus trapping, arrow-key menu navigation, and Escape-to-close for free from Radix — this covers the Notification Center, account menu, mobile nav drawer, and every modal/dialog in the app.
- `DataTable` sortable column headers are real `<button>` elements, not clickable `<div>`s — reachable and activatable via keyboard.
- Every focusable control in custom components (`SidebarNav`, `Topbar`, `StatCard`, buttons throughout) uses `focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/60` rather than suppressing the focus ring outright.

**ARIA**
- `aria-current="page"` on the active sidebar nav item.
- `aria-label` on icon-only buttons (search trigger, theme toggle, notification bell — including a live unread count in the label — account menu, mobile menu trigger, per-row actions like "Revoke device", SOAR rule/playbook row actions, scheduler run/pause/resume, upload copy-share-link).
- The account-password modal (`UnlockKeyModal`) is built on the same `Dialog` primitive as the rest of the app rather than a hand-rolled overlay, so it gets focus trapping, `Escape`-to-close, and a labeled close button like every other dialog.
- Preference toggles (`Switch`) in Settings carry `aria-label` matching their adjacent visible label, since the label text isn't a `<label for>` wired to the control.
- `DialogTitle`/`SheetTitle` with `sr-only` labels on dialogs whose visual title is redundant (e.g. Quick Search, mobile nav drawer) — keeps the accessible name present without duplicating visible text.
- Form inputs in `FilterBar` (date range) have associated `sr-only` `<label>`s, not just `placeholder` text.

**Reduced motion**
- The entire app is wrapped in framer-motion's `<MotionConfig reducedMotion="user">` (`frontend/app/layout.tsx`) — every `motion.*` animation (page transitions, card hover-lift, staggered list entrances, dropdown/dialog transitions) automatically respects the OS-level `prefers-reduced-motion` setting. This is a single app-wide fix rather than per-component `useReducedMotion()` checks, so it's easy to verify: toggle "reduce motion" in your OS accessibility settings and confirm animations stop.

**Color contrast & status communication**
- Status is never communicated by color alone: `StatusBadge` always pairs a tone color with a text label (e.g. "Critical", "Blocked", "Healthy"), not just a colored dot.
- Dark theme uses a near-black background (`#020617`) with light text (`#e2e8f0`) and semantic colors tuned per-theme (e.g. `--destructive` is `#dc2626` in light mode but `#ef4444` in dark mode, brightened for the darker background) rather than reusing one fixed hex value across both themes.

**Screen reader support**
- Icon-only elements throughout use `aria-label`; decorative icons that sit next to visible text (e.g. a Lucide icon before a labeled stat) are not separately announced since the adjacent text already provides the accessible name.
- Toasts (`react-hot-toast`) announce dynamically, giving non-visual feedback for async actions (upload success/failure, session revoked, etc.).

## Known gaps

- **No automated accessibility testing** (no `axe-core`/`jest-axe`/Playwright a11y checks in CI) — current coverage is manual/code-review-based, not verified by tooling. See [TESTING.md](TESTING.md).
- **Chart accessibility**: Recharts SVG charts have no explicit `aria-label`/text-alternative summarizing the data (e.g. "Event volume trending up 12% over 30 days") — a screen reader user gets little from the chart itself, though the same data is usually also available in the adjacent `StatCard`s or table.
- **Color contrast has not been run through an automated contrast checker** (e.g. WebAIM) across every token combination — the palette was designed with contrast in mind (light text on near-black dark theme, dark text on near-white light theme) but hasn't been formally verified for every text/background pairing, particularly `--muted-foreground` on `--muted` backgrounds.
- **High-contrast mode**: no dedicated `prefers-contrast: more` handling.
- **Focus management on route change**: page transitions don't explicitly move focus to the new page's heading, relying on default browser behavior (focus stays wherever it was, e.g. on the nav link just clicked) rather than an explicit focus-management strategy for single-page-app style navigation.

## How to verify manually

1. **Keyboard-only pass**: unplug your mouse. Tab through the Topbar (search → theme toggle → notifications → account menu), open Quick Search with `Ctrl/Cmd K` and navigate results with arrow keys, open a `DataTable`'s column picker and sort a column, open and dismiss a dialog with `Escape`.
2. **Reduced motion**: enable "Reduce motion" in your OS (System Settings → Accessibility on macOS, Settings → Ease of Access on Windows), reload the app, and confirm page transitions/hover animations no longer play.
3. **Screen reader spot-check**: with VoiceOver/NVDA running, confirm the notification bell announces its unread count, and that dialog titles are announced on open even when visually hidden.
4. **Dark/light contrast**: toggle the theme from Settings → Appearance and visually check text legibility on both, especially `text-muted-foreground` labels.
