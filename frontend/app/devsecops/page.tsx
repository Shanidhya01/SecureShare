"use client";

import { useEffect, useState, useCallback, useMemo } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import api from "@/lib/api";
import { getIsAdminFromToken } from "@/lib/auth";
import {
  ShieldHalf,
  GitBranch,
  ShieldAlert,
  KeyRound,
  Boxes,
  Workflow,
  Download,
  RefreshCw,
  AlertCircle,
  Award,
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

type Repository = { _id: string; name: string; provider: string; branch: string; commit: string; riskScore: number; lastScan: string | null };
type ScanEvent = { _id: string; siemType: string; message: string; severity: string; createdAt: string };
type TrendPoint = { overallScore: number; scannedAt: string };
type Sbom = { _id: string; format: string; serialization: string; componentCount: number; createdAt: string };
type PipelineRun = { _id: string; provider: string; name: string; status: string; source: string; createdAt: string };

type Dashboard = {
  overallScore: number;
  scores: { repositoryScore: number; dependencyScore: number; secretScore: number; containerScore: number; pipelineScore: number } | null;
  repository: Repository | null;
  findingCount: number;
  findingsBySeverity: Record<string, number>;
  findingsByCategory: Record<string, number>;
  sboms: Sbom[];
  pipelineRuns: PipelineRun[];
  recentScans: ScanEvent[];
  trend: TrendPoint[];
  recommendations: string[];
};

const SEVERITY_TONE: Record<string, StatusTone> = { CRITICAL: "danger", HIGH: "danger", MEDIUM: "warning", LOW: "info", INFO: "neutral" };
const SEVERITY_COLORS: Record<string, string> = { CRITICAL: "#EF4444", HIGH: "#F97316", MEDIUM: "#F59E0B", LOW: "#3B82F6", INFO: "#64748B" };
const CATEGORY_COLORS: Record<string, string> = { DEPENDENCY: "#6366F1", SECRET: "#EF4444", SAST: "#F59E0B", CONTAINER: "#8B5CF6", IAC: "#10B981", PIPELINE: "#3B82F6" };

export default function DevSecOpsPage() {
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
        const res = await api.get<Dashboard>("/devsecops/dashboard", { headers: { Authorization: `Bearer ${token}` } });
        setDashboard(res.data);
      } catch (err: unknown) {
        const status = apiErrorStatus(err);
        if (status === 401) {
          router.push("/login");
          return;
        }
        if (status === 403) {
          toast.error("Admin access required for DevSecOps");
          router.push("/dashboard");
          return;
        }
        setError("Failed to load DevSecOps data");
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
      toast.error("Admin access required for DevSecOps");
      router.push("/dashboard");
      return;
    }
    fetchDashboard(token);
  }, [fetchDashboard, router]);

  const runScan = async () => {
    try {
      setScanning(true);
      await api.post("/devsecops/scan", {}, authHeader());
      toast.success("DevSecOps scan completed");
      const token = localStorage.getItem("token");
      if (token) await fetchDashboard(token);
    } catch {
      toast.error("Failed to run DevSecOps scan");
    } finally {
      setScanning(false);
    }
  };

  const handleExport = async (format: "csv" | "json" | "pdf") => {
    try {
      const token = localStorage.getItem("token");
      const res = await api.get(`/devsecops/export/${format}`, {
        headers: { Authorization: `Bearer ${token}` },
        responseType: "blob",
      });
      const url = window.URL.createObjectURL(new Blob([res.data]));
      const a = document.createElement("a");
      a.href = url;
      a.download = `devsecops-report-${Date.now()}.${format}`;
      a.click();
      window.URL.revokeObjectURL(url);
      toast.success("Report generated");
    } catch {
      toast.error("Failed to generate report");
    }
  };

  const findingsBySeverityData = useMemo(
    () => Object.entries(dashboard?.findingsBySeverity || {}).filter(([, v]) => v > 0).map(([name, value]) => ({ name, value })),
    [dashboard]
  );

  const findingsByCategoryData = useMemo(
    () => Object.entries(dashboard?.findingsByCategory || {}).filter(([, v]) => v > 0).map(([name, value]) => ({ name, value })),
    [dashboard]
  );

  const pipelineStatusData = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const run of dashboard?.pipelineRuns || []) counts[run.status] = (counts[run.status] || 0) + 1;
    return Object.entries(counts).map(([name, value]) => ({ name, value }));
  }, [dashboard]);

  const scoreHistoryData = useMemo(
    () => (dashboard?.trend || []).map((t) => ({ date: new Date(t.scannedAt).toLocaleDateString(), score: t.overallScore })),
    [dashboard]
  );

  const scanColumns: DataTableColumn<ScanEvent>[] = [
    { key: "siemType", header: "Event", render: (e) => <StatusBadge label={e.siemType || "—"} tone={SEVERITY_TONE[e.severity] || "neutral"} /> },
    { key: "message", header: "Message", render: (e) => <span className="text-xs max-w-md truncate inline-block">{e.message}</span> },
    { key: "createdAt", header: "When", render: (e) => <span className="text-xs text-muted-foreground">{new Date(e.createdAt).toLocaleString()}</span> },
  ];

  const pipelineColumns: DataTableColumn<PipelineRun>[] = [
    { key: "provider", header: "Provider", render: (p) => <span className="text-xs">{p.provider}</span> },
    { key: "name", header: "Name", render: (p) => <span className="text-xs font-medium">{p.name}</span> },
    { key: "status", header: "Status", render: (p) => <StatusBadge label={p.status} tone={p.status === "success" ? "success" : p.status === "failed" || p.status === "blocked" ? "danger" : "neutral"} /> },
    { key: "source", header: "Source", render: (p) => <span className="text-xs text-muted-foreground">{p.source}</span> },
  ];

  return (
    <div>
      <PageHeader
        icon={ShieldHalf}
        title="DevSecOps & Supply Chain Security"
        description="Repository, dependency, secret, SAST, container, IaC, SBOM, and CI/CD posture for SecureShare's own codebase."
        accent="purple"
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
          ["Findings", "/devsecops/findings"],
          ["SBOM", "/devsecops/sbom"],
          ["Reports", "/devsecops/reports"],
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
            <StatCard label="Overall DevSecOps Score" value={`${dashboard.overallScore}/100`} icon={Award} variant={dashboard.overallScore >= 85 ? "success" : dashboard.overallScore >= 60 ? "warning" : "danger"} />
            <StatCard label="Repository" value={dashboard.repository?.name || "Not scanned"} icon={GitBranch} variant="primary" />
            <StatCard label="Open Findings" value={dashboard.findingCount} icon={ShieldAlert} variant={dashboard.findingCount ? "danger" : "success"} />
            <StatCard label="SBOM Components" value={dashboard.sboms[0]?.componentCount ?? 0} icon={Boxes} variant="purple" />
          </motion.div>

          {dashboard.scores && (
            <motion.div variants={staggerContainer} initial="hidden" animate="show" className="grid grid-cols-2 md:grid-cols-5 gap-4">
              <StatCard label="Repository" value={`${dashboard.scores.repositoryScore}`} icon={GitBranch} variant="muted" />
              <StatCard label="Dependency" value={`${dashboard.scores.dependencyScore}`} icon={Boxes} variant="muted" />
              <StatCard label="Secret" value={`${dashboard.scores.secretScore}`} icon={KeyRound} variant="muted" />
              <StatCard label="Container" value={`${dashboard.scores.containerScore}`} icon={ShieldAlert} variant="muted" />
              <StatCard label="Pipeline" value={`${dashboard.scores.pipelineScore}`} icon={Workflow} variant="muted" />
            </motion.div>
          )}

          {dashboard.repository && (
            <div className="rounded-xl border border-border bg-card p-6 grid grid-cols-2 md:grid-cols-4 gap-4">
              <div>
                <p className="text-xs text-muted-foreground uppercase">Provider</p>
                <p className="text-sm mt-1">{dashboard.repository.provider}</p>
              </div>
              <div>
                <p className="text-xs text-muted-foreground uppercase">Branch</p>
                <p className="text-sm mt-1">{dashboard.repository.branch}</p>
              </div>
              <div>
                <p className="text-xs text-muted-foreground uppercase">Commit</p>
                <p className="text-sm mt-1 font-mono">{dashboard.repository.commit?.slice(0, 10) || "—"}</p>
              </div>
              <div>
                <p className="text-xs text-muted-foreground uppercase">Last Scan</p>
                <p className="text-sm mt-1">{dashboard.repository.lastScan ? new Date(dashboard.repository.lastScan).toLocaleString() : "—"}</p>
              </div>
            </div>
          )}

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="rounded-xl border border-border bg-card p-6">
              <h3 className="text-sm font-semibold text-foreground mb-4">Findings by Severity</h3>
              {findingsBySeverityData.length === 0 ? (
                <p className="text-sm text-muted-foreground py-10 text-center">No findings recorded - run a scan.</p>
              ) : (
                <ResponsiveContainer width="100%" height={260}>
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
              <h3 className="text-sm font-semibold text-foreground mb-4">Findings by Category</h3>
              {findingsByCategoryData.length === 0 ? (
                <p className="text-sm text-muted-foreground py-10 text-center">No findings recorded.</p>
              ) : (
                <ResponsiveContainer width="100%" height={260}>
                  <PieChart>
                    <Pie data={findingsByCategoryData} dataKey="value" nameKey="name" innerRadius={50} outerRadius={90} paddingAngle={2}>
                      {findingsByCategoryData.map((entry) => (
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
              <h3 className="text-sm font-semibold text-foreground mb-4">Score History (90 days)</h3>
              {scoreHistoryData.length === 0 ? (
                <p className="text-sm text-muted-foreground py-10 text-center">No score history yet - run a scan to start tracking trend.</p>
              ) : (
                <ResponsiveContainer width="100%" height={220}>
                  <AreaChart data={scoreHistoryData}>
                    <defs>
                      <linearGradient id="devsecopsTrendGradient" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#8B5CF6" stopOpacity={0.4} />
                        <stop offset="95%" stopColor="#8B5CF6" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.1)" />
                    <XAxis dataKey="date" stroke="#64748B" fontSize={11} tickLine={false} axisLine={false} />
                    <YAxis domain={[0, 100]} stroke="#64748B" fontSize={11} tickLine={false} axisLine={false} />
                    <Tooltip contentStyle={{ background: "#0F172A", border: "1px solid rgba(148,163,184,0.2)", borderRadius: 8, fontSize: 12 }} />
                    <Area type="monotone" dataKey="score" stroke="#8B5CF6" fill="url(#devsecopsTrendGradient)" strokeWidth={2} />
                  </AreaChart>
                </ResponsiveContainer>
              )}
            </div>

            <div className="rounded-xl border border-border bg-card p-6">
              <h3 className="text-sm font-semibold text-foreground mb-4">Pipeline Status</h3>
              {pipelineStatusData.length === 0 ? (
                <p className="text-sm text-muted-foreground py-10 text-center">No pipeline runs recorded.</p>
              ) : (
                <ResponsiveContainer width="100%" height={220}>
                  <PieChart>
                    <Pie data={pipelineStatusData} dataKey="value" nameKey="name" innerRadius={50} outerRadius={90} paddingAngle={2}>
                      {pipelineStatusData.map((entry, i) => (
                        <Cell key={entry.name} fill={["#10B981", "#EF4444", "#F59E0B", "#64748B"][i % 4]} />
                      ))}
                    </Pie>
                    <Tooltip contentStyle={{ background: "#0F172A", border: "1px solid rgba(148,163,184,0.2)", borderRadius: 8, fontSize: 12 }} />
                  </PieChart>
                </ResponsiveContainer>
              )}
            </div>
          </div>

          <section>
            <h2 className="flex items-center gap-2 text-lg font-bold text-foreground mb-4">
              <Workflow size={20} className="text-primary" />
              CI/CD Pipeline Runs
            </h2>
            {dashboard.pipelineRuns.length === 0 ? (
              <EmptyState icon={Workflow} title="No pipeline runs recorded" description="Run a scan to detect CI/CD configuration." />
            ) : (
              <DataTable columns={pipelineColumns} rows={dashboard.pipelineRuns} rowKey={(p) => p._id} emptyLabel="No pipeline runs." />
            )}
          </section>

          <section>
            <h2 className="flex items-center gap-2 text-lg font-bold text-foreground mb-4">
              <ShieldHalf size={20} className="text-primary" />
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
              <EmptyState icon={Award} title="No open recommendations" description="No outstanding DevSecOps recommendations at this time." />
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
