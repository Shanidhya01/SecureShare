"use client";

import { useEffect, useState, useCallback, useMemo } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import api from "@/lib/api";
import { getIsAdminFromToken } from "@/lib/auth";
import {
  Activity,
  Database,
  MemoryStick,
  Cloud,
  ShieldCheck,
  Server,
  ListChecks,
  AlertTriangle,
  RefreshCw,
  Download,
  KeyRound,
  Gauge,
} from "lucide-react";
import { AreaChart, Area, BarChart, Bar, LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts";
import { motion } from "framer-motion";
import toast from "react-hot-toast";
import PageHeader from "@/components/design/PageHeader";
import StatCard from "@/components/design/StatCard";
import StatusBadge, { type StatusTone } from "@/components/design/StatusBadge";
import DataTable, { type DataTableColumn } from "@/components/design/DataTable";
import EmptyState from "@/components/design/EmptyState";
import { StatsSkeleton, TableSkeleton } from "@/components/design/Skeletons";
import { apiErrorStatus } from "@/lib/errors";
import { staggerContainer } from "@/lib/motion";

type Component = { name: string; status: "UP" | "DEGRADED" | "DOWN" | "UNKNOWN"; latencyMs?: number; message?: string };
type Health = { overallScore: number; overallStatus: "HEALTHY" | "WARNING" | "CRITICAL"; components: Component[]; checkedAt: string };
type Metrics = {
  api: { requestCount: number; avgLatencyMs: number; p95LatencyMs: number; errorRate: number };
  uploadDownload: { upload: { avgMs: number }; download: { avgMs: number } };
  auth: { successCount: number; failureCount: number; successRate: number; failureRate: number };
  scanActivity: Record<string, number>;
  queueLength: number;
};
type Alert = { _id: string; rule: string; severity: string; message: string; active: boolean; triggeredAt: string };
type PlatformJob = { _id: string; queue: string; status: string; durationMs?: number; retryCount: number; createdAt: string };
type MetricSnapshot = { recordedAt: string; api: { requestCount: number; avgLatencyMs: number }; queueLength: number; auth: { successRate: number }; uploadDownload: { upload: { avgMs: number } } };
type HealthSnapshot = { checkedAt: string; overallScore: number };

type Dashboard = {
  health: Health;
  metrics: Metrics;
  alerts: Alert[];
  queue: { mode: string; queues: Record<string, unknown> };
  recentJobs: PlatformJob[];
  recentBackups: { _id: string; type: string; status: string; createdAt: string }[];
};

const STATUS_TONE: Record<string, StatusTone> = { UP: "success", HEALTHY: "success", WARNING: "warning", DEGRADED: "warning", DOWN: "danger", CRITICAL: "danger", UNKNOWN: "neutral" };
const SEVERITY_TONE: Record<string, StatusTone> = { CRITICAL: "danger", HIGH: "danger", MEDIUM: "warning", LOW: "info", INFO: "neutral" };
const CHART_TOOLTIP = { background: "#0F172A", border: "1px solid rgba(148,163,184,0.2)", borderRadius: 8, fontSize: 12 };

function componentValue(components: Component[], name: string) {
  return components.find((c) => c.name === name);
}

export default function PlatformPage() {
  const router = useRouter();
  const [dashboard, setDashboard] = useState<Dashboard | null>(null);
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState("");
  const [metricHistory, setMetricHistory] = useState<MetricSnapshot[]>([]);
  const [healthHistory, setHealthHistory] = useState<HealthSnapshot[]>([]);
  const [alertHistory, setAlertHistory] = useState<Alert[]>([]);

  const authHeader = () => ({ headers: { Authorization: `Bearer ${localStorage.getItem("token")}` } });

  const fetchDashboard = useCallback(
    async (token: string) => {
      try {
        setLoading(true);
        const headers = { Authorization: `Bearer ${token}` };
        const [dashRes, metricsHistRes, healthHistRes, alertHistRes] = await Promise.all([
          api.get<Dashboard>("/platform/dashboard", { headers }),
          api.get("/platform/metrics/history?hours=24", { headers }),
          api.get("/platform/health/history?hours=24", { headers }),
          api.get("/platform/alerts?active=false&limit=200", { headers }),
        ]);
        setDashboard(dashRes.data);
        setMetricHistory(metricsHistRes.data);
        setHealthHistory(healthHistRes.data);
        setAlertHistory(alertHistRes.data);
      } catch (err: unknown) {
        const status = apiErrorStatus(err);
        if (status === 401) {
          router.push("/login");
          return;
        }
        if (status === 403) {
          toast.error("Admin access required for Platform Operations");
          router.push("/dashboard");
          return;
        }
        setError("Failed to load platform data");
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
    if (!getIsAdminFromToken(token)) {
      toast.error("Admin access required for Platform Operations");
      router.push("/dashboard");
      return;
    }
    fetchDashboard(token);
  }, [fetchDashboard, router]);

  const runScan = async () => {
    try {
      setScanning(true);
      await api.post("/platform/scan", {}, authHeader());
      toast.success("Platform health scan completed");
      const token = localStorage.getItem("token");
      if (token) await fetchDashboard(token);
    } catch {
      toast.error("Failed to run platform scan");
    } finally {
      setScanning(false);
    }
  };

  const handleExport = async (format: "csv" | "json" | "pdf") => {
    try {
      const token = localStorage.getItem("token");
      const res = await api.get(`/platform/export/${format}?reportType=health`, {
        headers: { Authorization: `Bearer ${token}` },
        responseType: "blob",
      });
      const url = window.URL.createObjectURL(new Blob([res.data]));
      const a = document.createElement("a");
      a.href = url;
      a.download = `platform-health-report-${Date.now()}.${format}`;
      a.click();
      window.URL.revokeObjectURL(url);
      toast.success("Report generated");
    } catch {
      toast.error("Failed to generate report");
    }
  };

  const latencyHistoryData = useMemo(
    () => metricHistory.map((h) => ({ time: new Date(h.recordedAt).toLocaleTimeString(), avgLatencyMs: h.api.avgLatencyMs })),
    [metricHistory]
  );
  const requestVolumeData = useMemo(
    () => metricHistory.map((h) => ({ time: new Date(h.recordedAt).toLocaleTimeString(), requests: h.api.requestCount })),
    [metricHistory]
  );
  const healthTrendData = useMemo(
    () => healthHistory.map((h) => ({ time: new Date(h.checkedAt).toLocaleTimeString(), score: h.overallScore })),
    [healthHistory]
  );
  const queueLengthData = useMemo(
    () => metricHistory.map((h) => ({ time: new Date(h.recordedAt).toLocaleTimeString(), queueLength: h.queueLength })),
    [metricHistory]
  );
  const authTrendData = useMemo(
    () => metricHistory.map((h) => ({ time: new Date(h.recordedAt).toLocaleTimeString(), successRate: h.auth.successRate })),
    [metricHistory]
  );
  const uploadPerfData = useMemo(
    () => metricHistory.map((h) => ({ time: new Date(h.recordedAt).toLocaleTimeString(), uploadMs: h.uploadDownload.upload.avgMs })),
    [metricHistory]
  );
  const jobDurationData = useMemo(
    () => (dashboard?.recentJobs || []).slice(0, 15).map((j) => ({ name: j.queue, durationMs: j.durationMs ?? 0 })),
    [dashboard]
  );
  const alertTrendData = useMemo(() => {
    const byDay: Record<string, number> = {};
    for (const a of alertHistory) {
      const day = new Date(a.triggeredAt).toLocaleDateString();
      byDay[day] = (byDay[day] || 0) + 1;
    }
    return Object.entries(byDay).map(([day, count]) => ({ day, count }));
  }, [alertHistory]);

  const availabilityPct = useMemo(() => {
    if (!healthHistory.length) return 100;
    const healthy = healthHistory.filter((h) => h.overallScore >= 60).length;
    return Number(((healthy / healthHistory.length) * 100).toFixed(1));
  }, [healthHistory]);

  const componentColumns: DataTableColumn<Component>[] = [
    { key: "name", header: "Component", render: (c) => <span className="text-sm font-medium capitalize">{c.name.replace(/_/g, " ")}</span> },
    { key: "status", header: "Status", render: (c) => <StatusBadge label={c.status} tone={STATUS_TONE[c.status] || "neutral"} /> },
    { key: "latencyMs", header: "Latency", render: (c) => <span className="text-xs text-muted-foreground">{c.latencyMs != null ? `${c.latencyMs}ms` : "—"}</span> },
    { key: "message", header: "Message", render: (c) => <span className="text-xs text-muted-foreground max-w-xs truncate inline-block">{c.message || "—"}</span> },
  ];

  const alertColumns: DataTableColumn<Alert>[] = [
    { key: "rule", header: "Rule", render: (a) => <span className="text-xs font-mono">{a.rule}</span> },
    { key: "severity", header: "Severity", render: (a) => <StatusBadge label={a.severity} tone={SEVERITY_TONE[a.severity] || "neutral"} /> },
    { key: "message", header: "Message", render: (a) => <span className="text-xs max-w-md truncate inline-block">{a.message}</span> },
    { key: "triggeredAt", header: "Triggered", render: (a) => <span className="text-xs text-muted-foreground">{new Date(a.triggeredAt).toLocaleString()}</span> },
  ];

  const jobColumns: DataTableColumn<PlatformJob>[] = [
    { key: "queue", header: "Queue", render: (j) => <span className="text-xs font-mono">{j.queue}</span> },
    { key: "status", header: "Status", render: (j) => <StatusBadge label={j.status} tone={j.status === "completed" ? "success" : j.status === "failed" ? "danger" : "info"} /> },
    { key: "durationMs", header: "Duration", render: (j) => <span className="text-xs text-muted-foreground">{j.durationMs != null ? `${j.durationMs}ms` : "—"}</span> },
    { key: "retryCount", header: "Retries", render: (j) => <span className="text-xs">{j.retryCount}</span> },
    { key: "createdAt", header: "When", render: (j) => <span className="text-xs text-muted-foreground">{new Date(j.createdAt).toLocaleString()}</span> },
  ];

  return (
    <div>
      <PageHeader
        icon={Activity}
        title="Platform Operations"
        description="Cloud infrastructure health (MongoDB Atlas, Redis Cloud, Cloudinary, ClamAV), background jobs, alerts, and observability for SecureShare's deployed services."
        accent="primary"
        actions={
          <div className="flex gap-2">
            <button onClick={runScan} disabled={scanning} className="flex items-center gap-1.5 px-3 py-2 bg-primary text-primary-foreground rounded-lg text-xs font-semibold disabled:opacity-50">
              <RefreshCw size={14} className={scanning ? "animate-spin" : ""} /> {scanning ? "Scanning..." : "Run Health Scan"}
            </button>
            <button onClick={() => handleExport("csv")} className="flex items-center gap-1.5 px-3 py-2 bg-card border border-border rounded-lg text-xs hover:bg-muted">
              <Download size={14} /> CSV
            </button>
            <button onClick={() => handleExport("pdf")} className="flex items-center gap-1.5 px-3 py-2 bg-card border border-border rounded-lg text-xs hover:bg-muted">
              <Download size={14} /> PDF
            </button>
          </div>
        }
      />

      <div className="mb-6 flex flex-wrap gap-3">
        {[
          ["Scheduler", "/platform/scheduler"],
          ["Backups", "/platform/backups"],
          ["Reports", "/platform/reports"],
        ].map(([label, href]) => (
          <Link key={href} href={href} className="px-3 py-1.5 rounded-lg border border-border bg-card text-xs font-medium hover:bg-muted">
            {label}
          </Link>
        ))}
      </div>

      {error && (
        <div className="mb-6 p-4 bg-destructive/10 border border-destructive/30 rounded-lg flex items-center gap-2">
          <AlertTriangle className="text-destructive" size={18} />
          <p className="text-destructive text-sm">{error}</p>
        </div>
      )}

      {loading ? (
        <div className="space-y-8">
          <StatsSkeleton />
          <TableSkeleton />
        </div>
      ) : dashboard ? (
        <div className="space-y-8">
          {/* PART 5: dashboard cards - Platform Health, MongoDB, Redis, Cloudinary, ClamAV */}
          <motion.div variants={staggerContainer} initial="hidden" animate="show" className="grid grid-cols-2 md:grid-cols-5 gap-4">
            <StatCard
              label="Platform Health"
              value={`${dashboard.health.overallScore}/100`}
              icon={Server}
              variant={dashboard.health.overallStatus === "HEALTHY" ? "success" : dashboard.health.overallStatus === "WARNING" ? "warning" : "danger"}
            />
            <StatCard label="MongoDB" value={componentValue(dashboard.health.components, "mongodb")?.status || "UNKNOWN"} icon={Database} variant={STATUS_TONE[componentValue(dashboard.health.components, "mongodb")?.status || "UNKNOWN"] === "danger" ? "danger" : "muted"} />
            <StatCard label="Redis" value={componentValue(dashboard.health.components, "redis")?.status || "UNKNOWN"} icon={MemoryStick} variant={STATUS_TONE[componentValue(dashboard.health.components, "redis")?.status || "UNKNOWN"] === "danger" ? "danger" : "muted"} />
            <StatCard label="Cloudinary" value={componentValue(dashboard.health.components, "cloudinary")?.status || "UNKNOWN"} icon={Cloud} variant={STATUS_TONE[componentValue(dashboard.health.components, "cloudinary")?.status || "UNKNOWN"] === "danger" ? "danger" : "muted"} />
            <StatCard label="ClamAV" value={componentValue(dashboard.health.components, "clamav")?.status || "UNKNOWN"} icon={ShieldCheck} variant={STATUS_TONE[componentValue(dashboard.health.components, "clamav")?.status || "UNKNOWN"] === "danger" ? "danger" : "muted"} />
          </motion.div>

          <motion.div variants={staggerContainer} initial="hidden" animate="show" className="grid grid-cols-2 md:grid-cols-5 gap-4">
            <StatCard label="Avg Response Time" value={`${dashboard.metrics.api.avgLatencyMs}ms`} icon={Gauge} variant="muted" />
            <StatCard label="Background Queue" value={dashboard.metrics.queueLength} icon={ListChecks} variant="muted" />
            <StatCard label="Active Alerts" value={dashboard.alerts.length} icon={AlertTriangle} variant={dashboard.alerts.length ? "danger" : "success"} />
            <StatCard label="Availability (24h)" value={`${availabilityPct}%`} icon={Activity} variant={availabilityPct >= 99 ? "success" : "warning"} />
            <StatCard label="Auth Success Rate" value={`${dashboard.metrics.auth.successRate}%`} icon={KeyRound} variant={dashboard.metrics.auth.successRate >= 90 ? "success" : "warning"} />
          </motion.div>

          {/* PART 6: charts */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="rounded-xl border border-border bg-card p-6">
              <h3 className="text-sm font-semibold text-foreground mb-4">API Latency (24h)</h3>
              <ResponsiveContainer width="100%" height={200}>
                <AreaChart data={latencyHistoryData}>
                  <defs>
                    <linearGradient id="platformLatencyGradient" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#3B82F6" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#3B82F6" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.1)" />
                  <XAxis dataKey="time" stroke="#64748B" fontSize={10} tickLine={false} axisLine={false} />
                  <YAxis stroke="#64748B" fontSize={10} tickLine={false} axisLine={false} />
                  <Tooltip contentStyle={CHART_TOOLTIP} />
                  <Area type="monotone" dataKey="avgLatencyMs" stroke="#3B82F6" fill="url(#platformLatencyGradient)" strokeWidth={2} />
                </AreaChart>
              </ResponsiveContainer>
            </div>

            <div className="rounded-xl border border-border bg-card p-6">
              <h3 className="text-sm font-semibold text-foreground mb-4">Request Volume (24h)</h3>
              <ResponsiveContainer width="100%" height={200}>
                <BarChart data={requestVolumeData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.1)" />
                  <XAxis dataKey="time" stroke="#64748B" fontSize={10} tickLine={false} axisLine={false} />
                  <YAxis stroke="#64748B" fontSize={10} tickLine={false} axisLine={false} allowDecimals={false} />
                  <Tooltip contentStyle={CHART_TOOLTIP} />
                  <Bar dataKey="requests" fill="#8B5CF6" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>

            <div className="rounded-xl border border-border bg-card p-6">
              <h3 className="text-sm font-semibold text-foreground mb-4">Health Trend (24h)</h3>
              <ResponsiveContainer width="100%" height={200}>
                <LineChart data={healthTrendData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.1)" />
                  <XAxis dataKey="time" stroke="#64748B" fontSize={10} tickLine={false} axisLine={false} />
                  <YAxis domain={[0, 100]} stroke="#64748B" fontSize={10} tickLine={false} axisLine={false} />
                  <Tooltip contentStyle={CHART_TOOLTIP} />
                  <Line type="monotone" dataKey="score" stroke="#10B981" strokeWidth={2} dot={false} />
                </LineChart>
              </ResponsiveContainer>
            </div>

            <div className="rounded-xl border border-border bg-card p-6">
              <h3 className="text-sm font-semibold text-foreground mb-4">Queue Length (24h)</h3>
              <ResponsiveContainer width="100%" height={200}>
                <AreaChart data={queueLengthData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.1)" />
                  <XAxis dataKey="time" stroke="#64748B" fontSize={10} tickLine={false} axisLine={false} />
                  <YAxis stroke="#64748B" fontSize={10} tickLine={false} axisLine={false} allowDecimals={false} />
                  <Tooltip contentStyle={CHART_TOOLTIP} />
                  <Area type="monotone" dataKey="queueLength" stroke="#F59E0B" fill="#F59E0B33" strokeWidth={2} />
                </AreaChart>
              </ResponsiveContainer>
            </div>

            <div className="rounded-xl border border-border bg-card p-6">
              <h3 className="text-sm font-semibold text-foreground mb-4">Authentication Trend (24h)</h3>
              <ResponsiveContainer width="100%" height={200}>
                <LineChart data={authTrendData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.1)" />
                  <XAxis dataKey="time" stroke="#64748B" fontSize={10} tickLine={false} axisLine={false} />
                  <YAxis domain={[0, 100]} stroke="#64748B" fontSize={10} tickLine={false} axisLine={false} />
                  <Tooltip contentStyle={CHART_TOOLTIP} />
                  <Line type="monotone" dataKey="successRate" stroke="#06B6D4" strokeWidth={2} dot={false} />
                </LineChart>
              </ResponsiveContainer>
            </div>

            <div className="rounded-xl border border-border bg-card p-6">
              <h3 className="text-sm font-semibold text-foreground mb-4">Upload Performance (24h)</h3>
              <ResponsiveContainer width="100%" height={200}>
                <AreaChart data={uploadPerfData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.1)" />
                  <XAxis dataKey="time" stroke="#64748B" fontSize={10} tickLine={false} axisLine={false} />
                  <YAxis stroke="#64748B" fontSize={10} tickLine={false} axisLine={false} />
                  <Tooltip contentStyle={CHART_TOOLTIP} />
                  <Area type="monotone" dataKey="uploadMs" stroke="#EC4899" fill="#EC489933" strokeWidth={2} />
                </AreaChart>
              </ResponsiveContainer>
            </div>

            <div className="rounded-xl border border-border bg-card p-6">
              <h3 className="text-sm font-semibold text-foreground mb-4">Job Duration (recent)</h3>
              <ResponsiveContainer width="100%" height={200}>
                <BarChart data={jobDurationData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.1)" />
                  <XAxis dataKey="name" stroke="#64748B" fontSize={9} tickLine={false} axisLine={false} interval={0} angle={-20} textAnchor="end" height={50} />
                  <YAxis stroke="#64748B" fontSize={10} tickLine={false} axisLine={false} />
                  <Tooltip contentStyle={CHART_TOOLTIP} />
                  <Bar dataKey="durationMs" fill="#6366F1" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>

            <div className="rounded-xl border border-border bg-card p-6">
              <h3 className="text-sm font-semibold text-foreground mb-4">Alert Trend (by day)</h3>
              <ResponsiveContainer width="100%" height={200}>
                <BarChart data={alertTrendData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.1)" />
                  <XAxis dataKey="day" stroke="#64748B" fontSize={10} tickLine={false} axisLine={false} />
                  <YAxis stroke="#64748B" fontSize={10} tickLine={false} axisLine={false} allowDecimals={false} />
                  <Tooltip contentStyle={CHART_TOOLTIP} />
                  <Bar dataKey="count" fill="#EF4444" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          <div>
            <h3 className="text-sm font-semibold text-foreground mb-3 flex items-center gap-2"><Database size={16} /> Component Health</h3>
            <DataTable columns={componentColumns} rows={dashboard.health.components} rowKey={(c) => c.name} emptyLabel="No components checked yet." />
          </div>

          <div>
            <h3 className="text-sm font-semibold text-foreground mb-3 flex items-center gap-2"><AlertTriangle size={16} /> Active Alerts</h3>
            <DataTable columns={alertColumns} rows={dashboard.alerts} rowKey={(a) => a._id} emptyLabel="No active alerts." />
          </div>

          <div>
            <h3 className="text-sm font-semibold text-foreground mb-3 flex items-center gap-2"><ListChecks size={16} /> Recent Background Jobs</h3>
            <DataTable columns={jobColumns} rows={dashboard.recentJobs} rowKey={(j) => j._id} emptyLabel="No background jobs recorded yet." />
          </div>
        </div>
      ) : (
        <EmptyState
          icon={Server}
          title="No platform data available"
          description="Run a health scan to populate infrastructure status, metrics, and alerts."
          actionLabel="Run Health Scan"
          onAction={runScan}
        />
      )}
    </div>
  );
}
