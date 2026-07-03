"use client";

import { useEffect, useState, useCallback, useMemo } from "react";
import { useRouter } from "next/navigation";
import api from "@/lib/api";
import { ScrollText, AlertCircle, Search, Download } from "lucide-react";
import { apiErrorStatus } from "@/lib/errors";
import PageHeader from "@/components/design/PageHeader";
import EmptyState from "@/components/design/EmptyState";
import DataTable, { type DataTableColumn } from "@/components/design/DataTable";
import Pagination from "@/components/design/Pagination";
import StatusBadge, { type StatusTone } from "@/components/design/StatusBadge";
import { TableSkeleton } from "@/components/design/Skeletons";

type SecurityEventEntry = {
  id: string;
  type: "new_device" | "device_removed" | "session_revoked" | "download_denied";
  message: string;
  filename?: string | null;
  deviceId?: string | null;
  ip?: string | null;
  country?: string | null;
  createdAt: string;
};

const typeLabel: Record<SecurityEventEntry["type"], string> = {
  new_device: "New Device",
  device_removed: "Device Removed",
  session_revoked: "Session Revoked",
  download_denied: "Download Denied",
};

const typeTone: Record<SecurityEventEntry["type"], StatusTone> = {
  new_device: "info",
  device_removed: "warning",
  session_revoked: "warning",
  download_denied: "danger",
};

const PAGE_SIZE = 15;

export default function AuditLogsPage() {
  const router = useRouter();
  const [events, setEvents] = useState<SecurityEventEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState<string>("all");
  const [fromDate, setFromDate] = useState("");
  const [toDate, setToDate] = useState("");
  const [page, setPage] = useState(1);

  const fetchAll = useCallback(
    async (token: string) => {
      try {
        setLoading(true);
        const res = await api.get<SecurityEventEntry[]>("/security/events", { headers: { Authorization: `Bearer ${token}` } });
        setEvents(res.data || []);
      } catch (err: unknown) {
        const status = apiErrorStatus(err);
        if (status === 401 || status === 403) {
          router.push("/login");
          return;
        }
        setError("Failed to load audit logs");
      } finally {
        setLoading(false);
      }
    },
    [router]
  );

  useEffect(() => {
    const token = localStorage.getItem("token");
    if (!token) {
      router.push("/login");
      return;
    }
    fetchAll(token);
  }, [fetchAll, router]);

  const filtered = useMemo(() => {
    const from = fromDate ? new Date(fromDate).getTime() : null;
    // end-of-day for the "to" date so it's inclusive
    const to = toDate ? new Date(toDate).getTime() + 24 * 60 * 60 * 1000 - 1 : null;

    return events.filter((e) => {
      if (typeFilter !== "all" && e.type !== typeFilter) return false;
      const eventTime = new Date(e.createdAt).getTime();
      if (from !== null && eventTime < from) return false;
      if (to !== null && eventTime > to) return false;
      if (!search.trim()) return true;
      const q = search.toLowerCase();
      return (
        e.message.toLowerCase().includes(q) ||
        (e.ip || "").toLowerCase().includes(q) ||
        (e.filename || "").toLowerCase().includes(q) ||
        (e.country || "").toLowerCase().includes(q)
      );
    });
  }, [events, search, typeFilter, fromDate, toDate]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const pageRows = filtered.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

  const handleExportCsv = () => {
    const header = ["Type", "Message", "IP", "Country", "Filename", "Time"];
    const rows = filtered.map((e) => [
      typeLabel[e.type],
      e.message.replace(/"/g, '""'),
      e.ip || "",
      e.country || "",
      e.filename || "",
      new Date(e.createdAt).toISOString(),
    ]);
    const csv = [header, ...rows].map((r) => r.map((v) => `"${v}"`).join(",")).join("\n");
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `secureshare-audit-log-${new Date().toISOString().slice(0, 10)}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const columns: DataTableColumn<SecurityEventEntry>[] = [
    { key: "type", header: "Event", render: (e) => <StatusBadge label={typeLabel[e.type]} tone={typeTone[e.type]} /> },
    { key: "message", header: "Details", render: (e) => <span className="max-w-md truncate inline-block">{e.message}</span> },
    { key: "ip", header: "IP / Country", render: (e) => <span className="font-mono text-xs">{e.ip || "-"} {e.country && e.country !== "Unknown" ? `(${e.country})` : ""}</span> },
    { key: "time", header: "Time", className: "whitespace-nowrap text-xs text-muted-foreground", render: (e) => new Date(e.createdAt).toLocaleString() },
  ];

  const resetFilters = () => {
    setSearch("");
    setTypeFilter("all");
    setFromDate("");
    setToDate("");
    setPage(1);
  };

  const filtersActive = search || typeFilter !== "all" || fromDate || toDate;

  return (
    <div>
      <PageHeader
        icon={ScrollText}
        title="Audit Logs"
        description="A searchable trail of security-relevant events on your account."
        actions={
          <button
            type="button"
            onClick={handleExportCsv}
            disabled={filtered.length === 0}
            className="inline-flex items-center gap-2 px-4 py-2.5 bg-card hover:bg-white/5 text-foreground font-semibold rounded-lg text-sm ring-1 ring-border transition-colors disabled:opacity-50"
          >
            <Download size={16} />
            Export CSV
          </button>
        }
      />

      {error && (
        <div className="mb-6 p-4 bg-destructive/10 border border-destructive/30 rounded-lg flex items-center gap-2">
          <AlertCircle className="text-destructive" size={18} />
          <p className="text-destructive text-sm">{error}</p>
        </div>
      )}

      <div className="mb-6 flex flex-col lg:flex-row gap-3">
        <div className="relative flex-1">
          <Search size={16} className="absolute left-3 top-3 text-muted-foreground" />
          <input
            value={search}
            onChange={(e) => {
              setSearch(e.target.value);
              setPage(1);
            }}
            placeholder="Search by message, IP, filename, or country..."
            className="w-full pl-9 pr-4 py-2.5 bg-card border border-border rounded-lg text-sm text-foreground placeholder-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/60"
          />
        </div>
        <select
          aria-label="Filter by event type"
          value={typeFilter}
          onChange={(e) => {
            setTypeFilter(e.target.value);
            setPage(1);
          }}
          className="px-4 py-2.5 bg-card border border-border rounded-lg text-sm text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/60"
        >
          <option value="all">All event types</option>
          {(Object.keys(typeLabel) as SecurityEventEntry["type"][]).map((t) => (
            <option key={t} value={t}>
              {typeLabel[t]}
            </option>
          ))}
        </select>
        <div className="flex items-center gap-2">
          <label htmlFor="fromDate" className="sr-only">From date</label>
          <input
            id="fromDate"
            type="date"
            value={fromDate}
            onChange={(e) => {
              setFromDate(e.target.value);
              setPage(1);
            }}
            className="px-3 py-2.5 bg-card border border-border rounded-lg text-sm text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/60"
          />
          <span className="text-muted-foreground text-sm">to</span>
          <label htmlFor="toDate" className="sr-only">To date</label>
          <input
            id="toDate"
            type="date"
            value={toDate}
            onChange={(e) => {
              setToDate(e.target.value);
              setPage(1);
            }}
            className="px-3 py-2.5 bg-card border border-border rounded-lg text-sm text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/60"
          />
        </div>
        {filtersActive && (
          <button
            type="button"
            onClick={resetFilters}
            className="px-3 py-2.5 text-sm font-medium text-muted-foreground hover:text-foreground rounded-lg hover:bg-white/5 transition-colors"
          >
            Clear filters
          </button>
        )}
      </div>

      {loading ? (
        <TableSkeleton rows={8} cols={4} />
      ) : filtered.length === 0 ? (
        <EmptyState icon={ScrollText} title="No matching events" description="No security events match your current search or filter." />
      ) : (
        <>
          <DataTable columns={columns} rows={pageRows} rowKey={(e) => e.id} stickyHeader maxHeight="65vh" />
          <Pagination page={page} totalPages={totalPages} totalItems={filtered.length} pageSize={PAGE_SIZE} onPageChange={setPage} />
        </>
      )}
    </div>
  );
}
