"use client";

import SearchInput from "./SearchInput";
import { cn } from "@/lib/utils";

export type FilterBarSelect = {
  id: string;
  label: string;
  value: string;
  onChange: (value: string) => void;
  options: { value: string; label: string }[];
};

export type FilterBarDateRange = {
  from: string;
  to: string;
  onFromChange: (value: string) => void;
  onToChange: (value: string) => void;
};

const inputClass =
  "px-3 py-2.5 bg-card border border-border rounded-lg text-sm text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/60";

/** Generic, domain-agnostic search + facet-filter toolbar. Not a replacement for
 *  components/soc/FilterBar.tsx, which is SOC-specific (incident/device/country fields + CSV/JSON
 *  export) - use this one for any other page that currently hand-rolls its own filter row. */
export default function FilterBar({
  search,
  onSearchChange,
  searchPlaceholder = "Search...",
  selects = [],
  dateRange,
  onReset,
  resetDisabled,
  className,
}: {
  search: string;
  onSearchChange: (value: string) => void;
  searchPlaceholder?: string;
  selects?: FilterBarSelect[];
  dateRange?: FilterBarDateRange;
  onReset?: () => void;
  resetDisabled?: boolean;
  className?: string;
}) {
  return (
    <div className={cn("mb-6 flex flex-col gap-3 lg:flex-row lg:items-center", className)}>
      <SearchInput value={search} onChange={onSearchChange} placeholder={searchPlaceholder} className="flex-1" />
      {selects.map((s) => (
        <select
          key={s.id}
          aria-label={s.label}
          value={s.value}
          onChange={(e) => s.onChange(e.target.value)}
          className={inputClass}
        >
          {s.options.map((o) => (
            <option key={o.value} value={o.value}>
              {o.label}
            </option>
          ))}
        </select>
      ))}
      {dateRange && (
        <div className="flex items-center gap-2">
          <label className="sr-only" htmlFor="filterbar-from-date">
            From date
          </label>
          <input
            id="filterbar-from-date"
            type="date"
            value={dateRange.from}
            onChange={(e) => dateRange.onFromChange(e.target.value)}
            className={inputClass}
          />
          <span className="text-sm text-muted-foreground">to</span>
          <label className="sr-only" htmlFor="filterbar-to-date">
            To date
          </label>
          <input
            id="filterbar-to-date"
            type="date"
            value={dateRange.to}
            onChange={(e) => dateRange.onToChange(e.target.value)}
            className={inputClass}
          />
        </div>
      )}
      {onReset && (
        <button
          type="button"
          onClick={onReset}
          disabled={resetDisabled}
          className="rounded-lg px-3 py-2.5 text-sm font-medium text-muted-foreground transition-colors hover:bg-white/5 hover:text-foreground disabled:pointer-events-none disabled:opacity-50"
        >
          Clear filters
        </button>
      )}
    </div>
  );
}
