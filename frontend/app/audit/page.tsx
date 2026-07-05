"use client";

import { useEffect, useState, useCallback, useMemo } from "react";
import { useRouter } from "next/navigation";
import api from "@/lib/api";
import { ScrollText, AlertCircle } from "lucide-react";
import { apiErrorStatus } from "@/lib/errors";
import PageHeader from "@/components/design/PageHeader";
import EmptyState from "@/components/design/EmptyState";
import DataTable, { type DataTableColumn } from "@/components/design/DataTable";
import Pagination from "@/components/design/Pagination";
import FilterBar from "@/components/design/FilterBar";
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

  const columns: DataTableColumn<SecurityEventEntry>[] = [
    {
      key: "type",
      header: "Event",
      sortable: true,
      sortValue: (e) => typeLabel[e.type],
      csvValue: (e) => typeLabel[e.type],
      render: (e) => <StatusBadge label={typeLabel[e.type]} tone={typeTone[e.type]} />,
    },
    {
      key: "message",
      header: "Details",
      csvValue: (e) => e.message,
      render: (e) => <span className="max-w-md truncate inline-block">{e.message}</span>,
    },
    {
      key: "ip",
      header: "IP / Country",
      csvValue: (e) => `${e.ip || ""} ${e.country && e.country !== "Unknown" ? `(${e.country})` : ""}`.trim(),
      render: (e) => <span className="font-mono text-xs">{e.ip || "-"} {e.country && e.country !== "Unknown" ? `(${e.country})` : ""}</span>,
    },
    {
      key: "time",
      header: "Time",
      className: "whitespace-nowrap text-xs text-muted-foreground",
      sortable: true,
      sortValue: (e) => new Date(e.createdAt).getTime(),
      csvValue: (e) => new Date(e.createdAt).toISOString(),
      render: (e) => new Date(e.createdAt).toLocaleString(),
    },
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
      />

      {error && (
        <div className="mb-6 p-4 bg-destructive/10 border border-destructive/30 rounded-lg flex items-center gap-2">
          <AlertCircle className="text-destructive" size={18} />
          <p className="text-destructive text-sm">{error}</p>
        </div>
      )}

      <FilterBar
        search={search}
        onSearchChange={(value) => {
          setSearch(value);
          setPage(1);
        }}
        searchPlaceholder="Search by message, IP, filename, or country..."
        selects={[
          {
            id: "type",
            label: "Filter by event type",
            value: typeFilter,
            onChange: (value) => {
              setTypeFilter(value);
              setPage(1);
            },
            options: [
              { value: "all", label: "All event types" },
              ...(Object.keys(typeLabel) as SecurityEventEntry["type"][]).map((t) => ({
                value: t,
                label: typeLabel[t],
              })),
            ],
          },
        ]}
        dateRange={{
          from: fromDate,
          to: toDate,
          onFromChange: (value) => {
            setFromDate(value);
            setPage(1);
          },
          onToChange: (value) => {
            setToDate(value);
            setPage(1);
          },
        }}
        onReset={filtersActive ? resetFilters : undefined}
      />

      {loading ? (
        <TableSkeleton rows={8} cols={4} />
      ) : filtered.length === 0 ? (
        <EmptyState icon={ScrollText} title="No matching events" description="No security events match your current search or filter." />
      ) : (
        <>
          <DataTable
            columns={columns}
            rows={pageRows}
            rowKey={(e) => e.id}
            stickyHeader
            maxHeight="65vh"
            enableColumnPicker
            enableExport
            exportFilename={`secureshare-audit-log-${new Date().toISOString().slice(0, 10)}`}
          />
          <Pagination page={page} totalPages={totalPages} totalItems={filtered.length} pageSize={PAGE_SIZE} onPageChange={setPage} />
        </>
      )}
    </div>
  );
}
