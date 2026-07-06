"use client";

import { useEffect, useState, useCallback, useMemo } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import api from "@/lib/api";
import { RequireRole } from "@/components/rbac/RoleGuard";
import {
  Cloud,
  ShieldAlert,
  ServerCog,
  Radar,
  Award,
  Download,
  RefreshCw,
  AlertCircle,
  Lock,
} from "lucide-react";
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, AreaChart, Area } from "recharts";
import { motion } from "framer-motion";
import toast from "react-hot-toast";
import PageHeader from "@/components/design/PageHeader";
import StatCard from "@/components/design/StatCard";
import StatusBadge, { type StatusTone } from "@/components/design/StatusBadge";
import EmptyState from "@/components/design/EmptyState";
import DataTable, { type DataTableColumn } from "@/components/design/DataTable";
import { StatsSkeleton, TableSkeleton } from "@/components/design/Skeletons";
import { apiErrorStatus } from "@/lib/errors";
import { staggerContainer } from "@/lib/motion";

type Asset = { _id: string; name: string; type: string; environment: string; criticality: string; riskScore: number; status: string };
type Certificate = { _id: string; domain: string; status: string; daysRemaining: number | null; issuer: string };
type ScanEvent = { _id: string; siemType: string; message: string; severity: string; createdAt: string };
type TrendPoint = { overallScore: number; scannedAt: string };

type Dashboard = {
  overallScore: number;
  scores: { assetScore: number; configScore: number; exposureScore: number; certScore: number; identityScore: number; complianceScore: number } | null;
  assetCount: number;
  assetsByType: Record<string, number>;
  highRiskAssets: Asset[];
  findingCount: number;
  findingsBySeverity: Record<string, number>;
  findingsByCategory: Record<string, number>;
  certificates: Certificate[];
  certSummary: { valid: number; expiring: number; expired: number; unreachable: number };
  recentScans: ScanEvent[];
  trend: TrendPoint[];
  recommendations: string[];
};

const SEVERITY_TONE: Record<string, StatusTone> = { CRITICAL: "danger", HIGH: "danger", MEDIUM: "warning", LOW: "info", INFO: "neutral" };
const SEVERITY_COLORS: Record<string, string> = { CRITICAL: "#EF4444", HIGH: "#F97316", MEDIUM: "#F59E0B", LOW: "#3B82F6", INFO: "#64748B" };
const CATEGORY_COLORS: Record<string, string> = { CONFIGURATION: "#6366F1", EXPOSURE: "#EF4444", CERTIFICATE: "#F59E0B", THREAT_INTEL: "#8B5CF6" };
const CERT_COLORS: Record<string, string> = { valid: "#10B981", expiring: "#F59E0B", expired: "#EF4444", unreachable: "#64748B" };

function CloudSecurityPageContent() {
  const router = useRouter();
  const [dashboard, setDashboard] = useState<Dashboard | null>(null);
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState("");

  const authHeader = () => ({ headers: { Authorization: `Bearer ${localStorage.getItem("token")}` } });

  const fetchDashboard = useCallback(
    async (token: string) => {
      try {
        setLoading(true);
        const res = await api.get<Dashboard>("/cloud/dashboard", { headers: { Authorization: `Bearer ${token}` } });
        setDashboard(res.data);
      } catch (err: unknown) {
        const status = apiErrorStatus(err);
        if (status === 401) {
          router.push("/login");
          return;
        }
        if (status === 403) {
          toast.error("Admin access required for Cloud Security");
          router.push("/dashboard");
          return;
        }
        setError("Failed to load cloud security data");
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
    fetchDashboard(token);
  }, [fetchDashboard, router]);

  const runScan = async () => {
    try {
      setScanning(true);
      await api.post("/cloud/scan", {}, authHeader());
      toast.success("Cloud security scan completed");
      const token = localStorage.getItem("token");
      if (token) await fetchDashboard(token);
    } catch {
      toast.error("Failed to run cloud security scan");
    } finally {
      setScanning(false);
    }
  };

  const handleExport = async (format: "csv" | "json" | "pdf") => {
    try {
      const token = localStorage.getItem("token");
      const res = await api.get(`/cloud/export/${format}`, {
        headers: { Authorization: `Bearer ${token}` },
        responseType: "blob",
      });
      const url = window.URL.createObjectURL(new Blob([res.data]));
      const a = document.createElement("a");
      a.href = url;
      a.download = `cloud-security-report-${Date.now()}.${format}`;
      a.click();
      window.URL.revokeObjectURL(url);
      toast.success("Report generated");
    } catch {
      toast.error("Failed to generate report");
    }
  };

  const assetDistributionData = useMemo(
    () => Object.entries(dashboard?.assetsByType || {}).filter(([, v]) => v > 0).map(([name, value]) => ({ name, value })),
    [dashboard]
  );

  const exposureData = useMemo(
    () => Object.entries(dashboard?.findingsByCategory || {}).filter(([, v]) => v > 0).map(([name, value]) => ({ name, value })),
    [dashboard]
  );

  const findingsBySeverityData = useMemo(
    () => Object.entries(dashboard?.findingsBySeverity || {}).filter(([, v]) => v > 0).map(([name, value]) => ({ name, value })),
    [dashboard]
  );

  const certData = useMemo(
    () => Object.entries(dashboard?.certSummary || {}).filter(([, v]) => v > 0).map(([name, value]) => ({ name, value })),
    [dashboard]
  );

  const scoreHistoryData = useMemo(
    () => (dashboard?.trend || []).map((t) => ({ date: new Date(t.scannedAt).toLocaleDateString(), score: t.overallScore })),
    [dashboard]
  );

  const assetColumns: DataTableColumn<Asset>[] = [
    { key: "name", header: "Asset", render: (a) => <span className="text-xs font-medium">{a.name}</span> },
    { key: "type", header: "Type", render: (a) => <span className="text-xs text-muted-foreground">{a.type}</span> },
    { key: "criticality", header: "Criticality", render: (a) => <StatusBadge label={a.criticality} tone={a.criticality === "critical" || a.criticality === "high" ? "danger" : a.criticality === "medium" ? "warning" : "neutral"} /> },
    { key: "riskScore", header: "Risk Score", render: (a) => `${a.riskScore}/100` },
    { key: "status", header: "Status", render: (a) => <StatusBadge label={a.status} tone={a.status === "active" ? "success" : "neutral"} /> },
    { key: "actions", header: "", render: (a) => <Link href={`/cloud-security/assets/${a._id}`} className="text-xs text-primary hover:underline">View</Link> },
  ];

  const scanColumns: DataTableColumn<ScanEvent>[] = [
    { key: "siemType", header: "Event", render: (e) => <StatusBadge label={e.siemType || "—"} tone={SEVERITY_TONE[e.severity] || "neutral"} /> },
    { key: "message", header: "Message", render: (e) => <span className="text-xs max-w-md truncate inline-block">{e.message}</span> },
    { key: "createdAt", header: "When", render: (e) => <span className="text-xs text-muted-foreground">{new Date(e.createdAt).toLocaleString()}</span> },
  ];

  return (
    <div>
      <PageHeader
        icon={Cloud}
        title="Cloud Security Posture"
        description="Continuous CSPM/ASM scanning of SecureShare's own deployment - assets, configuration, certificates, and attack surface."
        accent="primary"
        actions={
          <div className="flex gap-2">
            <button onClick={runScan} disabled={scanning} className="flex items-center gap-1.5 px-3 py-2 bg-primary text-primary-foreground rounded-lg text-xs font-semibold disabled:opacity-50">
              <RefreshCw size={14} className={scanning ? "animate-spin" : ""} /> {scanning ? "Scanning..." : "Run Scan"}
            </button>
            <button onClick={() => handleExport("csv")} className="flex items-center gap-1.5 px-3 py-2 bg-card border border-border rounded-lg text-xs hover:bg-muted">
              <Download size={14} /> CSV
            </button>
            <button onClick={() => handleExport("json")} className="flex items-center gap-1.5 px-3 py-2 bg-card border border-border rounded-lg text-xs hover:bg-muted">
              <Download size={14} /> JSON
            </button>
            <button onClick={() => handleExport("pdf")} className="flex items-center gap-1.5 px-3 py-2 bg-card border border-border rounded-lg text-xs hover:bg-muted">
              <Download size={14} /> PDF
            </button>
          </div>
        }
      />

      <div className="mb-6 flex flex-wrap gap-3">
        {[
          ["Assets", "/cloud-security/assets"],
          ["Findings", "/cloud-security/findings"],
          ["Certificates", "/cloud-security/certificates"],
          ["Reports", "/cloud-security/reports"],
        ].map(([label, href]) => (
          <Link key={href} href={href} className="px-3 py-1.5 rounded-lg border border-border bg-card text-xs font-medium hover:bg-muted">
            {label}
          </Link>
        ))}
      </div>

      {error && (
        <div className="mb-6 p-4 bg-destructive/10 border border-destructive/30 rounded-lg flex items-center gap-2">
          <AlertCircle className="text-destructive" size={18} />
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
          <motion.div variants={staggerContainer} initial="hidden" animate="show" className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <StatCard label="Overall Security Score" value={`${dashboard.overallScore}/100`} icon={Award} variant={dashboard.overallScore >= 85 ? "success" : dashboard.overallScore >= 60 ? "warning" : "danger"} />
            <StatCard label="Assets Tracked" value={dashboard.assetCount} icon={ServerCog} variant="primary" />
            <StatCard label="Open Findings" value={dashboard.findingCount} icon={ShieldAlert} variant={dashboard.findingCount ? "danger" : "success"} />
            <StatCard label="Certificates Expiring/Expired" value={dashboard.certSummary.expiring + dashboard.certSummary.expired} icon={Lock} variant={dashboard.certSummary.expired ? "danger" : dashboard.certSummary.expiring ? "warning" : "success"} />
          </motion.div>

          {dashboard.scores && (
            <motion.div variants={staggerContainer} initial="hidden" animate="show" className="grid grid-cols-2 md:grid-cols-6 gap-4">
              <StatCard label="Asset" value={`${dashboard.scores.assetScore}`} icon={ServerCog} variant="muted" />
              <StatCard label="Configuration" value={`${dashboard.scores.configScore}`} icon={ShieldAlert} variant="muted" />
              <StatCard label="Exposure" value={`${dashboard.scores.exposureScore}`} icon={Radar} variant="muted" />
              <StatCard label="Certificate" value={`${dashboard.scores.certScore}`} icon={Lock} variant="muted" />
              <StatCard label="Identity" value={`${dashboard.scores.identityScore}`} icon={Award} variant="muted" />
              <StatCard label="Compliance" value={`${dashboard.scores.complianceScore}`} icon={Award} variant="muted" />
            </motion.div>
          )}

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="rounded-xl border border-border bg-card p-6">
              <h3 className="text-sm font-semibold text-foreground mb-4">Asset Distribution</h3>
              {assetDistributionData.length === 0 ? (
                <p className="text-sm text-muted-foreground py-10 text-center">No assets discovered yet - run a scan.</p>
              ) : (
                <ResponsiveContainer width="100%" height={260}>
                  <PieChart>
                    <Pie data={assetDistributionData} dataKey="value" nameKey="name" innerRadius={50} outerRadius={90} paddingAngle={2}>
                      {assetDistributionData.map((entry, i) => (
                        <Cell key={entry.name} fill={["#6366F1", "#10B981", "#F59E0B", "#EF4444", "#8B5CF6", "#3B82F6", "#F97316", "#64748B"][i % 8]} />
                      ))}
                    </Pie>
                    <Tooltip contentStyle={{ background: "#0F172A", border: "1px solid rgba(148,163,184,0.2)", borderRadius: 8, fontSize: 12 }} />
                  </PieChart>
                </ResponsiveContainer>
              )}
            </div>

            <div className="rounded-xl border border-border bg-card p-6">
              <h3 className="text-sm font-semibold text-foreground mb-4">Exposure Breakdown (by category)</h3>
              {exposureData.length === 0 ? (
                <p className="text-sm text-muted-foreground py-10 text-center">No open findings.</p>
              ) : (
                <ResponsiveContainer width="100%" height={260}>
                  <PieChart>
                    <Pie data={exposureData} dataKey="value" nameKey="name" innerRadius={50} outerRadius={90} paddingAngle={2}>
                      {exposureData.map((entry) => (
                        <Cell key={entry.name} fill={CATEGORY_COLORS[entry.name] || "#64748B"} />
                      ))}
                    </Pie>
                    <Tooltip contentStyle={{ background: "#0F172A", border: "1px solid rgba(148,163,184,0.2)", borderRadius: 8, fontSize: 12 }} />
                  </PieChart>
                </ResponsiveContainer>
              )}
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="rounded-xl border border-border bg-card p-6">
              <h3 className="text-sm font-semibold text-foreground mb-4">Configuration Findings by Severity</h3>
              {findingsBySeverityData.length === 0 ? (
                <p className="text-sm text-muted-foreground py-10 text-center">No findings recorded.</p>
              ) : (
                <ResponsiveContainer width="100%" height={220}>
                  <BarChart data={findingsBySeverityData} layout="vertical" margin={{ left: 8 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.1)" horizontal={false} />
                    <XAxis type="number" stroke="#64748B" fontSize={11} tickLine={false} axisLine={false} allowDecimals={false} />
                    <YAxis type="category" dataKey="name" stroke="#64748B" fontSize={11} tickLine={false} axisLine={false} width={70} />
                    <Tooltip contentStyle={{ background: "#0F172A", border: "1px solid rgba(148,163,184,0.2)", borderRadius: 8, fontSize: 12 }} />
                    <Bar dataKey="value" radius={[0, 4, 4, 0]}>
                      {findingsBySeverityData.map((entry) => (
                        <Cell key={entry.name} fill={SEVERITY_COLORS[entry.name] || "#64748B"} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              )}
            </div>

            <div className="rounded-xl border border-border bg-card p-6">
              <h3 className="text-sm font-semibold text-foreground mb-4">Certificates</h3>
              {certData.length === 0 ? (
                <p className="text-sm text-muted-foreground py-10 text-center">No certificates monitored yet.</p>
              ) : (
                <ResponsiveContainer width="100%" height={220}>
                  <PieChart>
                    <Pie data={certData} dataKey="value" nameKey="name" innerRadius={50} outerRadius={90} paddingAngle={2}>
                      {certData.map((entry) => (
                        <Cell key={entry.name} fill={CERT_COLORS[entry.name] || "#64748B"} />
                      ))}
                    </Pie>
                    <Tooltip contentStyle={{ background: "#0F172A", border: "1px solid rgba(148,163,184,0.2)", borderRadius: 8, fontSize: 12 }} />
                  </PieChart>
                </ResponsiveContainer>
              )}
            </div>
          </div>

          <div className="rounded-xl border border-border bg-card p-6">
            <h3 className="text-sm font-semibold text-foreground mb-4">Score History (90 days)</h3>
            {scoreHistoryData.length === 0 ? (
              <p className="text-sm text-muted-foreground py-10 text-center">No score history yet - run a scan to start tracking trend.</p>
            ) : (
              <ResponsiveContainer width="100%" height={220}>
                <AreaChart data={scoreHistoryData}>
                  <defs>
                    <linearGradient id="cloudScoreTrendGradient" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#6366F1" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#6366F1" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.1)" />
                  <XAxis dataKey="date" stroke="#64748B" fontSize={11} tickLine={false} axisLine={false} />
                  <YAxis domain={[0, 100]} stroke="#64748B" fontSize={11} tickLine={false} axisLine={false} />
                  <Tooltip contentStyle={{ background: "#0F172A", border: "1px solid rgba(148,163,184,0.2)", borderRadius: 8, fontSize: 12 }} />
                  <Area type="monotone" dataKey="score" stroke="#6366F1" fill="url(#cloudScoreTrendGradient)" strokeWidth={2} />
                </AreaChart>
              </ResponsiveContainer>
            )}
          </div>

          <section>
            <h2 className="flex items-center gap-2 text-lg font-bold text-foreground mb-4">
              <ShieldAlert size={20} className="text-destructive" />
              High Risk Assets
            </h2>
            {dashboard.highRiskAssets.length === 0 ? (
              <EmptyState icon={ServerCog} title="No high-risk assets" description="Every tracked asset is within acceptable risk thresholds." />
            ) : (
              <DataTable columns={assetColumns} rows={dashboard.highRiskAssets} rowKey={(a) => a._id} emptyLabel="No high-risk assets." />
            )}
          </section>

          <section>
            <h2 className="flex items-center gap-2 text-lg font-bold text-foreground mb-4">
              <Radar size={20} className="text-primary" />
              Recent Scans
            </h2>
            <DataTable columns={scanColumns} rows={dashboard.recentScans} rowKey={(e) => e._id} stickyHeader maxHeight="40vh" emptyLabel="No scans recorded yet - run a scan to get started." />
          </section>

          <section>
            <h2 className="flex items-center gap-2 text-lg font-bold text-foreground mb-4">
              <Award size={20} className="text-success" />
              Security Recommendations
            </h2>
            {dashboard.recommendations.length === 0 ? (
              <EmptyState icon={Award} title="No open recommendations" description="No outstanding cloud security recommendations at this time." />
            ) : (
              <div className="rounded-xl border border-border bg-card p-5 space-y-2">
                {dashboard.recommendations.map((r, i) => (
                  <p key={i} className="text-sm text-foreground flex items-start gap-2">
                    <span className="text-primary mt-0.5">•</span> {r}
                  </p>
                ))}
              </div>
            )}
          </section>
        </div>
      ) : null}
    </div>
  );
}

export default function CloudSecurityPage() {
  return (
    <RequireRole role="admin">
      <CloudSecurityPageContent />
    </RequireRole>
  );
}
