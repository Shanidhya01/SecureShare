"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import api from "@/lib/api";
import {
  Radar,
  AlertCircle,
  AlertTriangle,
  ShieldAlert,
  Activity,
  Eye,
  ShieldCheck,
  Gauge,
  Smartphone,
  KeySquare,
  ScanSearch,
} from "lucide-react";
import PageHeader from "@/components/design/PageHeader";
import StatCard from "@/components/design/StatCard";
import EventTimeline, { type EventTimelineItem } from "@/components/design/EventTimeline";
import EmptyState from "@/components/design/EmptyState";
import Pagination from "@/components/design/Pagination";
import DataTable, { type DataTableColumn } from "@/components/design/DataTable";
import StatusBadge from "@/components/design/StatusBadge";
import SecurityScoreGauge from "@/components/design/SecurityScoreGauge";
import { StatsSkeleton, TableSkeleton } from "@/components/design/Skeletons";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { apiErrorStatus } from "@/lib/errors";
import { SEVERITY_TONE, CATEGORY_LABELS, type Severity } from "@/lib/severity";
import {
  ChartCard,
  SeverityDistributionChart,
  CategoryBarChart,
  SecurityActivityChart,
  ThreatTrendChart,
  DLPFindingsChart,
  ZeroTrustEventsChart,
  RiskTrendChart,
  IncidentTimelineChart,
  IncidentsByStatusChart,
  type TimelinePoint,
} from "@/components/soc/charts";
import FilterBar, { emptyFilters, type SocFilters } from "@/components/soc/FilterBar";
import IncidentList, { type Incident } from "@/components/soc/IncidentList";
import IncidentViewer from "@/components/soc/IncidentViewer";

type SiemEvent = {
  id: string;
  type: string;
  siemType: string | null;
  severity: Severity;
  category: string | null;
  message: string;
  filename: string | null;
  fileId: string | null;
  deviceId: string | null;
  ip: string | null;
  country: string | null;
  correlationId: string | null;
  createdAt: string;
};

type Dashboard = {
  counts: { today: number; last7d: number; last30d: number };
  bySeverity: Record<string, number>;
  byCategory: Record<string, number>;
  openIncidents: number;
  criticalEvents: SiemEvent[];
  recentIncidents: Incident[];
};

type Stats = {
  bySeverity: Record<string, number>;
  byCategory: Record<string, number>;
  incidentsByStatus: Record<string, number>;
  timeline: TimelinePoint[];
};

const PAGE_SIZE = 20;

const severityIcon = (severity: Severity) => (["HIGH", "CRITICAL"].includes(severity) ? AlertTriangle : Activity);

function toTimelineItems(events: SiemEvent[]): EventTimelineItem[] {
  return events.map((e) => ({
    key: e.id,
    icon: severityIcon(e.severity),
    title: e.message,
    description: [e.filename, e.ip, e.country].filter(Boolean).join(" | ") || undefined,
    timestamp: e.createdAt,
    tone: SEVERITY_TONE[e.severity],
    badgeLabel: e.siemType || e.type,
  }));
}

export default function SocPage() {
  const router = useRouter();

  const [dashboard, setDashboard] = useState<Dashboard | null>(null);
  const [stats, setStats] = useState<Stats | null>(null);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);
  const [events, setEvents] = useState<SiemEvent[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [filters, setFilters] = useState<SocFilters>(emptyFilters);
  const [searchResults, setSearchResults] = useState<{ events: SiemEvent[]; incidents: Incident[] } | null>(null);

  const [loading, setLoading] = useState(true);
  const [eventsLoading, setEventsLoading] = useState(true);
  const [error, setError] = useState("");

  const token = typeof window !== "undefined" ? localStorage.getItem("token") : null;
  const authHeaders = useMemo(() => ({ Authorization: `Bearer ${token}` }), [token]);

  const fetchOverview = useCallback(async () => {
    try {
      setLoading(true);
      const [dashboardRes, statsRes, incidentsRes] = await Promise.all([
        api.get<Dashboard>("/siem/dashboard", { headers: authHeaders }),
        api.get<Stats>("/siem/stats", { headers: authHeaders }),
        api.get<Incident[]>("/siem/incidents", { headers: authHeaders }),
      ]);
      setDashboard(dashboardRes.data);
      setStats(statsRes.data);
      setIncidents(incidentsRes.data || []);
    } catch (err: unknown) {
      const status = apiErrorStatus(err);
      if (status === 401 || status === 403) return router.push("/login");
      setError("Failed to load SIEM overview");
    } finally {
      setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [router]);

  const fetchEvents = useCallback(async () => {
    try {
      setEventsLoading(true);
      const params: Record<string, string | number> = { page, limit: PAGE_SIZE };
      if (filters.severity !== "all") params.severity = filters.severity;
      if (filters.category !== "all") params.category = filters.category;
      if (filters.deviceId) params.deviceId = filters.deviceId;
      if (filters.country) params.country = filters.country;
      if (filters.file) params.file = filters.file;
      if (filters.incidentId) params.incidentId = filters.incidentId;
      if (filters.fromDate) params.from = filters.fromDate;
      if (filters.toDate) params.to = new Date(new Date(filters.toDate).getTime() + 86400000 - 1).toISOString();

      const res = await api.get<{ total: number; events: SiemEvent[] }>("/siem/events", { headers: authHeaders, params });
      setEvents(res.data.events || []);
      setTotal(res.data.total || 0);
    } catch (err: unknown) {
      const status = apiErrorStatus(err);
      if (status === 401 || status === 403) return router.push("/login");
    } finally {
      setEventsLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [page, filters.severity, filters.category, filters.deviceId, filters.country, filters.file, filters.incidentId, filters.fromDate, filters.toDate, router]);

  useEffect(() => {
    if (!token) {
      router.push("/login");
      return;
    }
    fetchOverview();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (!token) return;
    fetchEvents();
  }, [fetchEvents, token]);

  // Full-text search (requirement 8/10): debounced, hits /siem/search across events, incidents,
  // users' own files/hashes/IPs. Non-empty search replaces the filtered event table with search
  // results; clearing it restores the normal filtered/paginated view.
  useEffect(() => {
    if (!filters.search.trim()) {
      setSearchResults(null);
      return;
    }
    const handle = setTimeout(async () => {
      try {
        const res = await api.get("/siem/search", { headers: authHeaders, params: { q: filters.search.trim() } });
        setSearchResults(res.data);
      } catch {
        setSearchResults({ events: [], incidents: [] });
      }
    }, 350);
    return () => clearTimeout(handle);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filters.search]);

  const handleExport = async (format: "csv" | "json") => {
    const params: Record<string, string> = { format };
    if (filters.severity !== "all") params.severity = filters.severity;
    if (filters.category !== "all") params.category = filters.category;
    if (filters.deviceId) params.deviceId = filters.deviceId;
    if (filters.country) params.country = filters.country;
    if (filters.file) params.file = filters.file;
    if (filters.incidentId) params.incidentId = filters.incidentId;

    const res = await api.get("/siem/export", { headers: authHeaders, params, responseType: "blob" });
    const blob = new Blob([res.data], { type: format === "csv" ? "text/csv" : "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `secureshare-siem-export-${new Date().toISOString().slice(0, 10)}.${format}`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const timelineItems = toTimelineItems(searchResults ? searchResults.events : events);
  const categories = useMemo(() => Object.keys(dashboard?.byCategory || CATEGORY_LABELS), [dashboard]);

  // Lightweight risk score derived purely from the SIEM's own severity mix (no extra fetches) -
  // reuses the same gauge/band/color visuals as the Dashboard/Security Center's securityScore.ts
  // for consistency, without requiring their unrelated device/DLP/threat inputs.
  const riskScore = useMemo(() => {
    if (!stats) return 100;
    const total = Object.values(stats.bySeverity).reduce((a, b) => a + b, 0);
    if (total === 0) return 100;
    const penalty = (stats.bySeverity.CRITICAL || 0) * 20 + (stats.bySeverity.HIGH || 0) * 10 + (stats.bySeverity.MEDIUM || 0) * 4;
    return Math.max(0, Math.min(100, Math.round(100 - (penalty / total) * 10)));
  }, [stats]);

  const eventColumns: DataTableColumn<SiemEvent>[] = [
    { key: "severity", header: "Severity", render: (e) => <StatusBadge label={e.severity} tone={SEVERITY_TONE[e.severity]} /> },
    { key: "type", header: "Event", render: (e) => e.siemType || e.type },
    { key: "message", header: "Details", render: (e) => <span className="max-w-md truncate inline-block">{e.message}</span> },
    { key: "ip", header: "IP / Country", render: (e) => <span className="font-mono text-xs">{e.ip || "-"} {e.country ? `(${e.country})` : ""}</span> },
    { key: "time", header: "Time", className: "whitespace-nowrap text-xs text-muted-foreground", render: (e) => new Date(e.createdAt).toLocaleString() },
  ];

  return (
    <div>
      <PageHeader
        icon={Radar}
        title="Security Operations Center"
        description="A unified, correlated view of every security event across your account - authentication, encryption, signatures, Zero Trust, threats, DLP, uploads, downloads, devices, and sessions."
      />

      {error && (
        <div className="mb-6 p-4 bg-destructive/10 border border-destructive/30 rounded-lg flex items-center gap-2">
          <AlertCircle className="text-destructive" size={18} />
          <p className="text-destructive text-sm">{error}</p>
        </div>
      )}

      <Tabs defaultValue="overview">
        <TabsList variant="line" className="mb-6 border-b border-border w-full justify-start overflow-x-auto">
          <TabsTrigger value="overview" className="gap-1.5"><Gauge size={14} /> Overview</TabsTrigger>
          <TabsTrigger value="events" className="gap-1.5"><Activity size={14} /> Events</TabsTrigger>
          <TabsTrigger value="incidents" className="gap-1.5"><ShieldAlert size={14} /> Incidents</TabsTrigger>
          <TabsTrigger value="timeline" className="gap-1.5"><Radar size={14} /> Timeline</TabsTrigger>
          <TabsTrigger value="analytics" className="gap-1.5"><ScanSearch size={14} /> Analytics</TabsTrigger>
        </TabsList>

        {/* OVERVIEW */}
        <TabsContent value="overview">
          {loading || !dashboard || !stats ? (
            <StatsSkeleton count={8} />
          ) : (
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
              <StatCard label="Security Events" value={dashboard.counts.last30d} icon={Activity} variant="primary" />
              <StatCard
                label="Critical Events"
                value={dashboard.criticalEvents.length}
                icon={AlertTriangle}
                variant={dashboard.criticalEvents.length > 0 ? "danger" : "success"}
              />
              <StatCard
                label="Incidents"
                value={dashboard.openIncidents}
                icon={ShieldAlert}
                variant={dashboard.openIncidents > 0 ? "warning" : "success"}
              />
              <StatCard label="Threats" value={stats.byCategory.THREAT || 0} icon={ScanSearch} variant="warning" />
              <StatCard label="DLP Alerts" value={stats.byCategory.DLP || 0} icon={Eye} variant="warning" />
              <StatCard label="Sessions" value={stats.byCategory.SESSION || 0} icon={KeySquare} variant="muted" />
              <StatCard label="Devices" value={stats.byCategory.DEVICE || 0} icon={Smartphone} variant="muted" />
              <StatCard label="Security Score" value={`${riskScore}/100`} icon={Gauge} variant={riskScore >= 85 ? "success" : riskScore >= 60 ? "warning" : "danger"} />
            </div>
          )}

          {!loading && dashboard && stats && (
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
              <div className="rounded-xl border border-border bg-card p-6 flex flex-col items-center justify-center">
                <div className="flex items-center gap-2 text-sm font-semibold text-foreground mb-3">
                  <Gauge size={16} /> Risk Overview
                </div>
                <SecurityScoreGauge score={riskScore} size={140} />
              </div>
              <div className="rounded-xl border border-border bg-card p-6">
                <div className="flex items-center gap-2 text-sm font-semibold text-foreground mb-3">
                  <ShieldCheck size={16} /> Zero Trust Events
                </div>
                <p className="text-3xl font-bold text-foreground">{stats.byCategory.ZERO_TRUST || 0}</p>
                <p className="text-xs text-muted-foreground mt-1">Policy/device-trust events in the last 30 days</p>
              </div>
              <ChartCard title="Severity Distribution">
                <SeverityDistributionChart bySeverity={stats.bySeverity} />
              </ChartCard>
            </div>
          )}

          {!loading && dashboard && dashboard.criticalEvents.length > 0 && (
            <div className="mb-6 rounded-xl border border-destructive/30 bg-destructive/5 p-6">
              <div className="flex items-center gap-2 text-sm font-semibold text-destructive mb-3">
                <AlertTriangle size={16} /> Critical &amp; High Severity Alerts
              </div>
              <EventTimeline items={toTimelineItems(dashboard.criticalEvents)} />
            </div>
          )}

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
            <div>
              <h2 className="text-lg font-semibold text-foreground mb-3">Recent Activity</h2>
              {eventsLoading ? (
                <TableSkeleton rows={4} cols={4} />
              ) : (
                <div className="rounded-2xl border border-border bg-card p-4">
                  <EventTimeline items={toTimelineItems(events.slice(0, 5))} emptyLabel="No recent activity." />
                </div>
              )}
            </div>
            <div>
              <h2 className="text-lg font-semibold text-foreground mb-3">Recent Incidents</h2>
              {loading ? <TableSkeleton rows={4} cols={5} /> : <IncidentList incidents={dashboard?.recentIncidents || []} onSelect={(i) => setSelectedIncidentId(i.id)} />}
            </div>
          </div>
        </TabsContent>

        {/* EVENTS */}
        <TabsContent value="events">
          <FilterBar filters={filters} onChange={(f) => { setFilters(f); setPage(1); }} categories={categories} onExport={handleExport} exportDisabled={events.length === 0} />

          {searchResults ? (
            <>
              {searchResults.incidents.length > 0 && (
                <div className="mb-6">
                  <h3 className="text-sm font-semibold text-muted-foreground mb-2">Matching Incidents</h3>
                  <IncidentList incidents={searchResults.incidents} onSelect={(i) => setSelectedIncidentId(i.id)} />
                </div>
              )}
              <h3 className="text-sm font-semibold text-muted-foreground mb-2">Matching Events</h3>
              {timelineItems.length === 0 ? (
                <EmptyState icon={Radar} title="No matches" description="No events or incidents match your search." />
              ) : (
                <div className="rounded-2xl border border-border bg-card p-4">
                  <EventTimeline items={timelineItems} />
                </div>
              )}
            </>
          ) : eventsLoading ? (
            <TableSkeleton rows={8} cols={5} />
          ) : events.length === 0 ? (
            <EmptyState icon={Radar} title="No matching events" description="No security events match your current filters." />
          ) : (
            <>
              <DataTable columns={eventColumns} rows={events} rowKey={(e) => e.id} stickyHeader maxHeight="60vh" />
              <Pagination page={page} totalPages={Math.max(1, Math.ceil(total / PAGE_SIZE))} totalItems={total} pageSize={PAGE_SIZE} onPageChange={setPage} />
            </>
          )}
        </TabsContent>

        {/* INCIDENTS */}
        <TabsContent value="incidents">
          <h2 className="text-lg font-semibold text-foreground mb-3">All Incidents</h2>
          {loading ? <TableSkeleton rows={6} cols={5} /> : <IncidentList incidents={incidents} onSelect={(i) => setSelectedIncidentId(i.id)} />}
        </TabsContent>

        {/* TIMELINE */}
        <TabsContent value="timeline">
          <h2 className="text-lg font-semibold text-foreground mb-3">Security Timeline</h2>
          {eventsLoading ? (
            <TableSkeleton rows={8} cols={4} />
          ) : events.length === 0 ? (
            <EmptyState icon={Radar} title="No activity yet" description="No security events recorded yet." />
          ) : (
            <div className="rounded-2xl border border-border bg-card p-6">
              <EventTimeline items={timelineItems} />
            </div>
          )}
        </TabsContent>

        {/* ANALYTICS */}
        <TabsContent value="analytics">
          {!stats ? (
            <StatsSkeleton count={8} />
          ) : (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <ChartCard title="Security Activity (30 days)">
                <SecurityActivityChart timeline={stats.timeline} />
              </ChartCard>
              <ChartCard title="Threat Trend">
                <ThreatTrendChart timeline={stats.timeline} />
              </ChartCard>
              <ChartCard title="Severity Distribution">
                <SeverityDistributionChart bySeverity={stats.bySeverity} />
              </ChartCard>
              <ChartCard title="Category Distribution">
                <CategoryBarChart byCategory={stats.byCategory} />
              </ChartCard>
              <ChartCard title="Incident Timeline">
                <IncidentTimelineChart incidents={incidents} />
              </ChartCard>
              <ChartCard title="Incidents by Status">
                <IncidentsByStatusChart incidentsByStatus={stats.incidentsByStatus} />
              </ChartCard>
              <ChartCard title="Risk Trend">
                <RiskTrendChart timeline={stats.timeline} />
              </ChartCard>
              <ChartCard title="DLP Findings">
                <DLPFindingsChart timeline={stats.timeline} />
              </ChartCard>
              <ChartCard title="Zero Trust Events">
                <ZeroTrustEventsChart timeline={stats.timeline} />
              </ChartCard>
            </div>
          )}
        </TabsContent>
      </Tabs>

      <IncidentViewer incidentId={selectedIncidentId} onClose={() => setSelectedIncidentId(null)} />
    </div>
  );
}
