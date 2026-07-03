"use client";

import { Search, Download } from "lucide-react";
import { SEVERITY_LEVELS } from "@/lib/severity";

export type SocFilters = {
  search: string;
  severity: string;
  category: string;
  siemType: string;
  deviceId: string;
  country: string;
  file: string;
  incidentId: string;
  fromDate: string;
  toDate: string;
};

export const emptyFilters: SocFilters = {
  search: "",
  severity: "all",
  category: "all",
  siemType: "all",
  deviceId: "",
  country: "",
  file: "",
  incidentId: "",
  fromDate: "",
  toDate: "",
};

const inputClass =
  "px-3 py-2 bg-card border border-border rounded-lg text-sm text-foreground placeholder-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/60";

/** Shared filter/search/export toolbar for the SOC dashboard - covers Date, Severity, Category
 *  (stand-in for Event Type grouping), Device, Country, and File/Incident (via free-text id
 *  fields), plus full-text search and CSV/JSON export. No "User" filter: the SIEM is scoped to
 *  the logged-in user's own account, matching every other dashboard in the app. */
export default function FilterBar({
  filters,
  onChange,
  categories,
  onExport,
  exportDisabled,
}: {
  filters: SocFilters;
  onChange: (next: SocFilters) => void;
  categories: string[];
  onExport: (format: "csv" | "json") => void;
  exportDisabled?: boolean;
}) {
  const set = (patch: Partial<SocFilters>) => onChange({ ...filters, ...patch });

  return (
    <div className="mb-6 flex flex-col gap-3">
      <div className="flex flex-col lg:flex-row gap-3">
        <div className="relative flex-1">
          <Search size={16} className="absolute left-3 top-2.5 text-muted-foreground" />
          <input
            value={filters.search}
            onChange={(e) => set({ search: e.target.value })}
            placeholder="Search events, incidents, IPs, hashes, files..."
            className={`w-full pl-9 pr-4 py-2 ${inputClass}`}
          />
        </div>
        <select aria-label="Severity" value={filters.severity} onChange={(e) => set({ severity: e.target.value })} className={inputClass}>
          <option value="all">All severities</option>
          {SEVERITY_LEVELS.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
        <select aria-label="Category" value={filters.category} onChange={(e) => set({ category: e.target.value })} className={inputClass}>
          <option value="all">All categories</option>
          {categories.map((c) => (
            <option key={c} value={c}>
              {c}
            </option>
          ))}
        </select>
        <div className="flex items-center gap-2">
          <input type="date" aria-label="From date" value={filters.fromDate} onChange={(e) => set({ fromDate: e.target.value })} className={inputClass} />
          <span className="text-muted-foreground text-sm">to</span>
          <input type="date" aria-label="To date" value={filters.toDate} onChange={(e) => set({ toDate: e.target.value })} className={inputClass} />
        </div>
      </div>
      <div className="flex flex-col lg:flex-row gap-3">
        <input
          value={filters.deviceId}
          onChange={(e) => set({ deviceId: e.target.value })}
          placeholder="Filter by device ID"
          className={`flex-1 ${inputClass}`}
        />
        <input
          value={filters.country}
          onChange={(e) => set({ country: e.target.value })}
          placeholder="Filter by country"
          className={`flex-1 ${inputClass}`}
        />
        <input
          value={filters.file}
          onChange={(e) => set({ file: e.target.value })}
          placeholder="Filter by file ID"
          className={`flex-1 ${inputClass}`}
        />
        <input
          value={filters.incidentId}
          onChange={(e) => set({ incidentId: e.target.value })}
          placeholder="Filter by incident ID"
          className={`flex-1 ${inputClass}`}
        />
        <div className="flex gap-2">
          <button
            type="button"
            disabled={exportDisabled}
            onClick={() => onExport("csv")}
            className="inline-flex items-center gap-2 px-4 py-2 bg-card hover:bg-white/5 text-foreground font-semibold rounded-lg text-sm ring-1 ring-border transition-colors disabled:opacity-50"
          >
            <Download size={16} />
            CSV
          </button>
          <button
            type="button"
            disabled={exportDisabled}
            onClick={() => onExport("json")}
            className="inline-flex items-center gap-2 px-4 py-2 bg-card hover:bg-white/5 text-foreground font-semibold rounded-lg text-sm ring-1 ring-border transition-colors disabled:opacity-50"
          >
            <Download size={16} />
            JSON
          </button>
        </div>
      </div>
    </div>
  );
}
