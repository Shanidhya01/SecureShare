"use client";

import { useEffect, useState, useCallback, useMemo } from "react";
import { useRouter } from "next/navigation";
import api from "@/lib/api";
import { BarChart3, AlertCircle, Info } from "lucide-react";
import {
  AreaChart,
  Area,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import PageHeader from "@/components/design/PageHeader";
import { StatsSkeleton } from "@/components/design/Skeletons";
import { apiErrorStatus } from "@/lib/errors";
import { bucketByDay } from "@/lib/chartHelpers";

type FileMeta = { createdAt?: string; logs?: { time: string }[] };
type ThreatScan = { createdAt: string };
type ThreatStats = { byRiskLevel: Record<string, number> };
type DLPScan = { createdAt: string };
type DLPStats = { bySeverity: Record<string, number> };
type SessionEntry = { createdAt: string };

const chartTooltipStyle = { background: "#0F172A", border: "1px solid rgba(148,163,184,0.2)", borderRadius: 8, fontSize: 12 };
const RISK_COLORS: Record<string, string> = { Low: "#10B981", Medium: "#F59E0B", High: "#F59E0B", Critical: "#EF4444" };

function ChartCard({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="rounded-xl border border-border bg-card p-6">
      <h3 className="text-sm font-semibold text-foreground mb-4">{title}</h3>
      {children}
    </div>
  );
}

export default function AnalyticsPage() {
  const router = useRouter();
  const [files, setFiles] = useState<FileMeta[]>([]);
  const [threatScans, setThreatScans] = useState<ThreatScan[]>([]);
  const [threatStats, setThreatStats] = useState<ThreatStats | null>(null);
  const [dlpScans, setDlpScans] = useState<DLPScan[]>([]);
  const [dlpStats, setDlpStats] = useState<DLPStats | null>(null);
  const [sessions, setSessions] = useState<SessionEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const fetchAll = useCallback(
    async (token: string) => {
      try {
        setLoading(true);
        const headers = { Authorization: `Bearer ${token}` };
        const [filesRes, threatScansRes, threatStatsRes, dlpScansRes, dlpStatsRes, sessionsRes] = await Promise.all([
          api.get<FileMeta[]>("/files/my-files", { headers }),
          api.get<ThreatScan[]>("/threats/scans", { headers }),
          api.get<ThreatStats>("/threats/stats", { headers }),
          api.get<DLPScan[]>("/dlp/scans", { headers }),
          api.get<DLPStats>("/dlp/stats", { headers }),
          api.get<SessionEntry[]>("/sessions", { headers }),
        ]);
        setFiles(filesRes.data || []);
        setThreatScans(threatScansRes.data || []);
        setThreatStats(threatStatsRes.data || null);
        setDlpScans(dlpScansRes.data || []);
        setDlpStats(dlpStatsRes.data || null);
        setSessions(sessionsRes.data || []);
      } catch (err: unknown) {
        const status = apiErrorStatus(err);
        if (status === 401 || status === 403) {
          router.push("/login");
        }
        setError("Failed to load analytics data");
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

  const uploadTrend = useMemo(() => bucketByDay(files, (f) => f.createdAt || new Date(), 14), [files]);
  const downloadTrend = useMemo(() => bucketByDay(files.flatMap((f) => f.logs || []), (l) => l.time, 14), [files]);
  const threatTrend = useMemo(() => bucketByDay(threatScans, (s) => s.createdAt, 14), [threatScans]);
  const dlpTrend = useMemo(() => bucketByDay(dlpScans, (s) => s.createdAt, 14), [dlpScans]);
  const sessionTrend = useMemo(() => bucketByDay(sessions, (s) => s.createdAt, 14), [sessions]);

  const riskData = threatStats
    ? Object.entries(threatStats.byRiskLevel)
        .filter(([, count]) => count > 0)
        .map(([name, value]) => ({ name, value }))
    : [];
  const dlpSeverityData = dlpStats
    ? Object.entries(dlpStats.bySeverity)
        .filter(([name, count]) => name !== "None" && count > 0)
        .map(([name, value]) => ({ name, value }))
    : [];

  return (
    <div>
      <PageHeader
        icon={BarChart3}
        title="Analytics"
        description="Trends across uploads, downloads, threats, DLP findings, and sessions."
      />

      {error && (
        <div className="mb-6 p-4 bg-destructive/10 border border-destructive/30 rounded-lg flex items-center gap-2">
          <AlertCircle className="text-destructive" size={18} />
          <p className="text-destructive text-sm">{error}</p>
        </div>
      )}

      <div className="mb-6 flex items-start gap-2 text-xs text-muted-foreground">
        <Info size={14} className="shrink-0 mt-0.5" />
        <p>
          Charts are computed from data your account can already access - storage usage and geographic breakdowns
          aren&apos;t tracked by the backend yet, so those aren&apos;t shown here.
        </p>
      </div>

      {loading ? (
        <StatsSkeleton count={6} />
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <ChartCard title="Uploads (14 days)">
            <ResponsiveContainer width="100%" height={220}>
              <AreaChart data={uploadTrend}>
                <defs>
                  <linearGradient id="analyticsUpload" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#2563EB" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#2563EB" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.1)" />
                <XAxis dataKey="date" stroke="#64748B" fontSize={11} tickLine={false} axisLine={false} />
                <YAxis stroke="#64748B" fontSize={11} tickLine={false} axisLine={false} allowDecimals={false} />
                <Tooltip contentStyle={chartTooltipStyle} />
                <Area type="monotone" dataKey="count" stroke="#2563EB" fill="url(#analyticsUpload)" strokeWidth={2} />
              </AreaChart>
            </ResponsiveContainer>
          </ChartCard>

          <ChartCard title="Downloads (14 days)">
            <ResponsiveContainer width="100%" height={220}>
              <AreaChart data={downloadTrend}>
                <defs>
                  <linearGradient id="analyticsDownload" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#10B981" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#10B981" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.1)" />
                <XAxis dataKey="date" stroke="#64748B" fontSize={11} tickLine={false} axisLine={false} />
                <YAxis stroke="#64748B" fontSize={11} tickLine={false} axisLine={false} allowDecimals={false} />
                <Tooltip contentStyle={chartTooltipStyle} />
                <Area type="monotone" dataKey="count" stroke="#10B981" fill="url(#analyticsDownload)" strokeWidth={2} />
              </AreaChart>
            </ResponsiveContainer>
          </ChartCard>

          <ChartCard title="Threat Scans (14 days)">
            <ResponsiveContainer width="100%" height={220}>
              <AreaChart data={threatTrend}>
                <defs>
                  <linearGradient id="analyticsThreat" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#EF4444" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#EF4444" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.1)" />
                <XAxis dataKey="date" stroke="#64748B" fontSize={11} tickLine={false} axisLine={false} />
                <YAxis stroke="#64748B" fontSize={11} tickLine={false} axisLine={false} allowDecimals={false} />
                <Tooltip contentStyle={chartTooltipStyle} />
                <Area type="monotone" dataKey="count" stroke="#EF4444" fill="url(#analyticsThreat)" strokeWidth={2} />
              </AreaChart>
            </ResponsiveContainer>
          </ChartCard>

          <ChartCard title="Threat Risk Distribution">
            {riskData.length === 0 ? (
              <p className="text-sm text-muted-foreground py-16 text-center">No threat scans yet.</p>
            ) : (
              <ResponsiveContainer width="100%" height={220}>
                <PieChart>
                  <Pie data={riskData} dataKey="value" nameKey="name" innerRadius={50} outerRadius={80} paddingAngle={2}>
                    {riskData.map((entry) => (
                      <Cell key={entry.name} fill={RISK_COLORS[entry.name] || "#64748B"} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={chartTooltipStyle} />
                </PieChart>
              </ResponsiveContainer>
            )}
          </ChartCard>

          <ChartCard title="DLP Scans (14 days)">
            <ResponsiveContainer width="100%" height={220}>
              <AreaChart data={dlpTrend}>
                <defs>
                  <linearGradient id="analyticsDlp" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#A855F7" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#A855F7" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.1)" />
                <XAxis dataKey="date" stroke="#64748B" fontSize={11} tickLine={false} axisLine={false} />
                <YAxis stroke="#64748B" fontSize={11} tickLine={false} axisLine={false} allowDecimals={false} />
                <Tooltip contentStyle={chartTooltipStyle} />
                <Area type="monotone" dataKey="count" stroke="#A855F7" fill="url(#analyticsDlp)" strokeWidth={2} />
              </AreaChart>
            </ResponsiveContainer>
          </ChartCard>

          <ChartCard title="DLP Findings by Severity">
            {dlpSeverityData.length === 0 ? (
              <p className="text-sm text-muted-foreground py-16 text-center">No DLP findings yet.</p>
            ) : (
              <ResponsiveContainer width="100%" height={220}>
                <BarChart data={dlpSeverityData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.1)" />
                  <XAxis dataKey="name" stroke="#64748B" fontSize={11} tickLine={false} axisLine={false} />
                  <YAxis stroke="#64748B" fontSize={11} tickLine={false} axisLine={false} allowDecimals={false} />
                  <Tooltip contentStyle={chartTooltipStyle} />
                  <Bar dataKey="value" fill="#A855F7" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            )}
          </ChartCard>

          <ChartCard title="Sessions (14 days)">
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={sessionTrend}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.1)" />
                <XAxis dataKey="date" stroke="#64748B" fontSize={11} tickLine={false} axisLine={false} />
                <YAxis stroke="#64748B" fontSize={11} tickLine={false} axisLine={false} allowDecimals={false} />
                <Tooltip contentStyle={chartTooltipStyle} />
                <Bar dataKey="count" fill="#2563EB" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </ChartCard>
        </div>
      )}
    </div>
  );
}
