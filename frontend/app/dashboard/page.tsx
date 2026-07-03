"use client";
import { useEffect, useState, useCallback } from "react";
import api from "@/lib/api";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { motion } from "framer-motion";
import {
  LayoutDashboard,
  FileText,
  ShieldAlert,
  Laptop,
  Ban,
  Eye,
  FileCheck2,
  ArrowRight,
  UserPlus,
  Trash2,
  LogOut,
  Upload,
  ScanSearch,
  ShieldCheck,
  ScrollText,
  Download,
  Activity,
} from "lucide-react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  CartesianGrid,
} from "recharts";
import PageHeader from "@/components/design/PageHeader";
import StatCard from "@/components/design/StatCard";
import SecurityScoreGauge from "@/components/design/SecurityScoreGauge";
import EmptyState from "@/components/design/EmptyState";
import EventTimeline, { type EventTimelineItem } from "@/components/design/EventTimeline";
import { StatsSkeleton } from "@/components/design/Skeletons";
import { computeSecurityScore } from "@/lib/securityScore";
import { bucketByDay } from "@/lib/chartHelpers";
import { apiErrorStatus } from "@/lib/errors";
import { fadeInUp, staggerContainer } from "@/lib/motion";
import { hasZeroTrustPolicy, type FilePolicy } from "@/lib/types";

type FileMeta = {
  _id: string;
  filename: string;
  createdAt?: string;
  signature?: string | null;
  quarantined?: boolean;
  policy?: FilePolicy;
  logs?: { time: string }[];
};

type ThreatStats = {
  totalScans: number;
  quarantinedFiles: number;
  malwareDetections: number;
  byRiskLevel: Record<string, number>;
};

type DLPStats = {
  totalScans: number;
  policyViolations: number;
  blockedUploads: number;
  bySeverity: Record<string, number>;
};

type DeviceEntry = { deviceId: string; trusted: boolean };
type SecurityEventEntry = { id: string; type: string; message: string; createdAt: string };

const RISK_COLORS: Record<string, string> = {
  Low: "#10B981",
  Medium: "#F59E0B",
  High: "#F59E0B",
  Critical: "#EF4444",
};

export default function DashboardOverview() {
  const router = useRouter();
  const [files, setFiles] = useState<FileMeta[]>([]);
  const [threatStats, setThreatStats] = useState<ThreatStats | null>(null);
  const [dlpStats, setDlpStats] = useState<DLPStats | null>(null);
  const [devices, setDevices] = useState<DeviceEntry[]>([]);
  const [events, setEvents] = useState<SecurityEventEntry[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchAll = useCallback(
    async (token: string) => {
      try {
        setLoading(true);
        const [filesRes, threatRes, dlpRes, devicesRes, eventsRes] = await Promise.all([
          api.get<FileMeta[]>("/files/my-files", { headers: { Authorization: `Bearer ${token}` } }),
          api.get<ThreatStats>("/threats/stats", { headers: { Authorization: `Bearer ${token}` } }),
          api.get<DLPStats>("/dlp/stats", { headers: { Authorization: `Bearer ${token}` } }),
          api.get<DeviceEntry[]>("/devices", { headers: { Authorization: `Bearer ${token}` } }),
          api.get<SecurityEventEntry[]>("/security/events", { headers: { Authorization: `Bearer ${token}` } }),
        ]);
        setFiles(filesRes.data || []);
        setThreatStats(threatRes.data || null);
        setDlpStats(dlpRes.data || null);
        setDevices(devicesRes.data || []);
        setEvents((eventsRes.data || []).slice(0, 8));
      } catch (err: unknown) {
        const status = apiErrorStatus(err);
        if (status === 401 || status === 403) {
          router.push("/login");
        }
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

  const trustedDevices = devices.filter((d) => d.trusted).length;
  const signedFiles = files.filter((f) => f.signature).length;
  const policiesConfigured = files.filter((f) => hasZeroTrustPolicy(f.policy)).length;
  const quarantinedInFiles = files.filter((f) => f.quarantined).length;

  const securityScore = computeSecurityScore({
    totalDevices: devices.length,
    trustedDevices,
    totalScans: threatStats?.totalScans ?? 0,
    malwareDetections: threatStats?.malwareDetections ?? 0,
    quarantinedFiles: threatStats?.quarantinedFiles ?? quarantinedInFiles,
    dlpTotalScans: dlpStats?.totalScans ?? 0,
    dlpViolations: dlpStats?.policyViolations ?? 0,
    totalFiles: files.length,
    signedFiles,
    policiesConfigured,
  });

  const uploadTrend = bucketByDay(files, (f) => f.createdAt || new Date(), 14);
  const allDownloadLogs = files.flatMap((f) => f.logs || []);
  const downloadTrend = bucketByDay(allDownloadLogs, (l) => l.time, 14);
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

  const eventIcon = (type: string) => {
    switch (type) {
      case "new_device":
        return UserPlus;
      case "device_removed":
        return Trash2;
      case "session_revoked":
        return LogOut;
      case "download_denied":
        return Ban;
      default:
        return ShieldAlert;
    }
  };

  const securityTimeline: EventTimelineItem[] = events.map((e) => ({
    key: e.id,
    icon: eventIcon(e.type),
    title: e.message,
    timestamp: e.createdAt,
    tone: e.type === "download_denied" ? "danger" : e.type === "session_revoked" || e.type === "device_removed" ? "warning" : "info",
  }));

  const quickActions = [
    { label: "Upload File", href: "/upload", icon: Upload },
    { label: "Threat Center", href: "/threats", icon: ScanSearch },
    { label: "DLP Center", href: "/dlp", icon: Eye },
    { label: "Security Center", href: "/security", icon: ShieldCheck },
    { label: "Audit Logs", href: "/audit", icon: ScrollText },
  ];

  return (
    <div>
      <PageHeader
        icon={LayoutDashboard}
        title="Dashboard"
        description="Your security posture and activity, at a glance."
        actions={
          <Link
            href="/files"
            className="inline-flex items-center gap-2 px-4 py-2.5 bg-card hover:bg-white/5 text-foreground font-semibold rounded-lg text-sm ring-1 ring-border transition-colors"
          >
            View all files <ArrowRight size={16} />
          </Link>
        }
      />

      {loading ? (
        <StatsSkeleton count={5} />
      ) : (
        <motion.div variants={staggerContainer} initial="hidden" animate="show" className="grid grid-cols-2 lg:grid-cols-5 gap-4">
          <StatCard label="Protected Files" value={files.length} icon={FileText} variant="primary" />
          <StatCard label="Threats Blocked" value={threatStats?.malwareDetections ?? 0} icon={ShieldAlert} variant="danger" />
          <StatCard label="Trusted Devices" value={`${trustedDevices}/${devices.length}`} icon={Laptop} variant="success" />
          <StatCard label="DLP Alerts" value={dlpStats?.policyViolations ?? 0} icon={Eye} variant="purple" />
          <StatCard label="Quarantined Files" value={threatStats?.quarantinedFiles ?? quarantinedInFiles} icon={Ban} variant="warning" />
        </motion.div>
      )}

      <div className="mt-6 rounded-xl border border-border bg-card p-6">
        <h3 className="text-sm font-semibold text-foreground mb-4">Quick Actions</h3>
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
          {quickActions.map((action) => (
            <Link
              key={action.href}
              href={action.href}
              className="flex flex-col items-center gap-2 rounded-lg border border-border bg-background/40 px-3 py-4 text-center hover:border-primary/40 hover:bg-white/5 transition-colors"
            >
              <action.icon size={20} className="text-primary" />
              <span className="text-xs font-medium text-foreground">{action.label}</span>
            </Link>
          ))}
        </div>
      </div>

      <div className="mt-6 grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="rounded-xl border border-border bg-card p-6 flex flex-col items-center justify-center">
          <h3 className="text-sm font-semibold text-foreground mb-4 self-start">Security Score</h3>
          {loading ? <div className="h-40 w-40 rounded-full bg-muted animate-pulse" /> : <SecurityScoreGauge score={securityScore} />}
          <p className="text-xs text-muted-foreground mt-4 text-center">
            Based on device trust, malware &amp; DLP scan history, signature usage, and access policies.
          </p>
        </div>

        <div className="rounded-xl border border-border bg-card p-6">
          <h3 className="text-sm font-semibold text-foreground mb-4">Uploads (last 14 days)</h3>
          <ResponsiveContainer width="100%" height={220}>
            <AreaChart data={uploadTrend}>
              <defs>
                <linearGradient id="uploadGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#2563EB" stopOpacity={0.4} />
                  <stop offset="95%" stopColor="#2563EB" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.1)" />
              <XAxis dataKey="date" stroke="#64748B" fontSize={11} tickLine={false} axisLine={false} />
              <YAxis stroke="#64748B" fontSize={11} tickLine={false} axisLine={false} allowDecimals={false} />
              <Tooltip contentStyle={{ background: "#0F172A", border: "1px solid rgba(148,163,184,0.2)", borderRadius: 8, fontSize: 12 }} />
              <Area type="monotone" dataKey="count" stroke="#2563EB" fill="url(#uploadGradient)" strokeWidth={2} />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        <div className="rounded-xl border border-border bg-card p-6">
          <h3 className="flex items-center gap-2 text-sm font-semibold text-foreground mb-4">
            <Download size={14} className="text-success" />
            Downloads (last 14 days)
          </h3>
          <ResponsiveContainer width="100%" height={220}>
            <AreaChart data={downloadTrend}>
              <defs>
                <linearGradient id="downloadGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#10B981" stopOpacity={0.4} />
                  <stop offset="95%" stopColor="#10B981" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.1)" />
              <XAxis dataKey="date" stroke="#64748B" fontSize={11} tickLine={false} axisLine={false} />
              <YAxis stroke="#64748B" fontSize={11} tickLine={false} axisLine={false} allowDecimals={false} />
              <Tooltip contentStyle={{ background: "#0F172A", border: "1px solid rgba(148,163,184,0.2)", borderRadius: 8, fontSize: 12 }} />
              <Area type="monotone" dataKey="count" stroke="#10B981" fill="url(#downloadGradient)" strokeWidth={2} />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="mt-6 grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="rounded-xl border border-border bg-card p-6">
          <h3 className="text-sm font-semibold text-foreground mb-4">Threat Risk Levels</h3>
          {riskData.length === 0 ? (
            <p className="text-sm text-muted-foreground py-10 text-center">No threat scans yet.</p>
          ) : (
            <ResponsiveContainer width="100%" height={200}>
              <PieChart>
                <Pie data={riskData} dataKey="value" nameKey="name" innerRadius={45} outerRadius={75} paddingAngle={2}>
                  {riskData.map((entry) => (
                    <Cell key={entry.name} fill={RISK_COLORS[entry.name] || "#64748B"} />
                  ))}
                </Pie>
                <Tooltip contentStyle={{ background: "#0F172A", border: "1px solid rgba(148,163,184,0.2)", borderRadius: 8, fontSize: 12 }} />
              </PieChart>
            </ResponsiveContainer>
          )}
        </div>

        <div className="rounded-xl border border-border bg-card p-6">
          <h3 className="text-sm font-semibold text-foreground mb-4">DLP Findings by Severity</h3>
          {dlpSeverityData.length === 0 ? (
            <p className="text-sm text-muted-foreground py-10 text-center">No DLP findings yet.</p>
          ) : (
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={dlpSeverityData}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.1)" />
                <XAxis dataKey="name" stroke="#64748B" fontSize={11} tickLine={false} axisLine={false} />
                <YAxis stroke="#64748B" fontSize={11} tickLine={false} axisLine={false} allowDecimals={false} />
                <Tooltip contentStyle={{ background: "#0F172A", border: "1px solid rgba(148,163,184,0.2)", borderRadius: 8, fontSize: 12 }} />
                <Bar dataKey="value" fill="#A855F7" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>

        <div className="rounded-xl border border-border bg-card p-6">
          <h3 className="text-sm font-semibold text-foreground mb-4">Recent Activity</h3>
          {events.length === 0 ? (
            <p className="text-sm text-muted-foreground py-10 text-center">No recent security events.</p>
          ) : (
            <ul className="space-y-3 max-h-52 overflow-y-auto scrollbar-thin pr-1">
              {events.map((e) => {
                const Icon = eventIcon(e.type);
                return (
                  <li key={e.id} className="flex items-start gap-2.5 text-xs">
                    <Icon size={14} className="text-primary shrink-0 mt-0.5" />
                    <div className="min-w-0">
                      <p className="text-foreground truncate">{e.message}</p>
                      <p className="text-muted-foreground">{new Date(e.createdAt).toLocaleString()}</p>
                    </div>
                  </li>
                );
              })}
            </ul>
          )}
        </div>
      </div>

      <div className="mt-6 rounded-xl border border-border bg-card p-6">
        <h3 className="flex items-center gap-2 text-sm font-semibold text-foreground mb-4">
          <Activity size={16} className="text-primary" />
          Security Timeline
        </h3>
        <EventTimeline items={securityTimeline} emptyLabel="No security events recorded yet." />
      </div>

      <div className="mt-6 rounded-xl border border-border bg-card p-6">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-sm font-semibold text-foreground">Recent Files</h3>
          <Link href="/files" className="text-xs font-semibold text-primary hover:text-primary/80 flex items-center gap-1">
            View all <ArrowRight size={12} />
          </Link>
        </div>
        {files.length === 0 && !loading ? (
          <EmptyState
            icon={FileCheck2}
            title="No files yet"
            description="Upload your first file to see it appear here with its full security status."
            actionLabel="Upload a file"
            actionHref="/upload"
          />
        ) : (
          <motion.div variants={staggerContainer} initial="hidden" animate="show" className="divide-y divide-border">
            {files.slice(0, 5).map((f) => (
              <motion.div key={f._id} variants={fadeInUp} className="flex items-center justify-between gap-3 py-3">
                <div className="flex items-center gap-3 min-w-0">
                  <FileText size={16} className="text-primary shrink-0" />
                  <span className="text-sm text-foreground truncate">{f.filename}</span>
                </div>
                <span className="text-xs text-muted-foreground shrink-0">
                  {f.createdAt ? new Date(f.createdAt).toLocaleDateString() : ""}
                </span>
              </motion.div>
            ))}
          </motion.div>
        )}
      </div>
    </div>
  );
}
