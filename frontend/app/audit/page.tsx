"use client";

import { useEffect, useState, useCallback, useMemo } from "react";
import { useRouter } from "next/navigation";
import api from "@/lib/api";
import { ScrollText, AlertCircle, ShieldOff, Laptop2, CalendarClock } from "lucide-react";
import { apiErrorStatus } from "@/lib/errors";
import PageHeader from "@/components/design/PageHeader";
import EmptyState from "@/components/design/EmptyState";
import DataTable, { type DataTableColumn } from "@/components/design/DataTable";
import Pagination from "@/components/design/Pagination";
import FilterBar from "@/components/design/FilterBar";
import StatusBadge from "@/components/design/StatusBadge";
import StatCard from "@/components/design/StatCard";
import { StatsSkeleton, TableSkeleton } from "@/components/design/Skeletons";
import { ChartCard, EventTrendChart } from "@/components/soc/charts";
import { securityEventTypeLabel as typeLabel, securityEventTypeTone as typeTone, type SecurityEventEntry } from "@/lib/securityEvents";

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

  const stats = useMemo(() => {
    const startOfToday = new Date();
    startOfToday.setHours(0, 0, 0, 0);
    const todayCount = events.filter((e) => new Date(e.createdAt).getTime() >= startOfToday.getTime()).length;
    const deniedCount = events.filter((e) => e.type === "download_denied").length;
    const deviceChangeCount = events.filter((e) => e.type === "new_device" || e.type === "device_removed").length;
    return { total: events.length, todayCount, deniedCount, deviceChangeCount };
  }, [events]);

  const trendTimeline = useMemo(() => events.map((e) => ({ createdAt: e.createdAt, severity: "INFO" })), [events]);

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

      {loading ? (
        <div className="mb-6">
          <StatsSkeleton count={4} />
        </div>
      ) : (
        <div className="mb-6 grid grid-cols-2 gap-4 md:grid-cols-4">
          <StatCard label="Total Events" value={stats.total} icon={ScrollText} variant="primary" />
          <StatCard label="Today" value={stats.todayCount} icon={CalendarClock} variant="success" />
          <StatCard label="Device Changes" value={stats.deviceChangeCount} icon={Laptop2} variant="warning" />
          <StatCard label="Download Denials" value={stats.deniedCount} icon={ShieldOff} variant="danger" />
        </div>
      )}

      {!loading && events.length > 0 && (
        <div className="mb-6">
          <ChartCard title="Event Volume (Last 30 Days)">
            <EventTrendChart timeline={trendTimeline} />
          </ChartCard>
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
