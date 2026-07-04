"use client";

import { useEffect, useState, useCallback, useMemo } from "react";
import { useRouter } from "next/navigation";
import api from "@/lib/api";
import { getIsAdminFromToken } from "@/lib/auth";
import {
  ClipboardCheck,
  ShieldAlert,
  FileCheck2,
  Database,
  Download,
  RefreshCw,
  AlertCircle,
  Settings2,
  Gauge,
  Activity,
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

type FrameworkStatus = { framework: string; name: string; score: number; controlCount: number };
type Assessment = {
  _id: string;
  control: { controlId: string; title: string; category: string; severity: string } | null;
  framework: { key: string; name: string } | null;
  status: "PASS" | "FAIL" | "PARTIAL" | "NOT_APPLICABLE";
  score: number;
  recommendations: string[];
  evaluatedAt: string;
};
type Policy = { name: string; value: unknown; version: number; enabled: boolean; updatedAt: string | null };
type Report = { _id: string; format: string; overallScore: number; filename: string; createdAt: string };
type Evidence = {
  _id: string;
  sourceType: string;
  summary: string;
  control: { controlId: string; title: string } | null;
  approved: boolean;
  collectedAt: string;
};

type TrendPoint = { day: string; averageScore: number };

type Dashboard = {
  overallScore: number;
  riskScore: number;
  riskDistribution: Record<string, number>;
  frameworkStatus: FrameworkStatus[];
  controlCoverage: Record<string, number>;
  openFindings: Assessment[];
  recentAssessments: Assessment[];
  evidenceCount: number;
  policies: Policy[];
  recentReports: Report[];
  recommendations: string[];
  trend: TrendPoint[];
  policyViolations30d: number;
  auditActivity30d: number;
};

const STATUS_TONE: Record<string, StatusTone> = { PASS: "success", FAIL: "danger", PARTIAL: "warning", NOT_APPLICABLE: "neutral" };
const COVERAGE_COLORS: Record<string, string> = { PASS: "#10B981", FAIL: "#EF4444", PARTIAL: "#F59E0B", NOT_APPLICABLE: "#64748B" };
const RISK_COLORS: Record<string, string> = { Low: "#10B981", Medium: "#F59E0B", High: "#F97316", Critical: "#EF4444" };

export default function CompliancePage() {
  const router = useRouter();
  const [dashboard, setDashboard] = useState<Dashboard | null>(null);
  const [evidence, setEvidence] = useState<Evidence[]>([]);
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState("");

  const authHeader = () => ({ headers: { Authorization: `Bearer ${localStorage.getItem("token")}` } });

  const fetchDashboard = useCallback(
    async (token: string) => {
      try {
        setLoading(true);
        const [dashboardRes, evidenceRes] = await Promise.all([
          api.get<Dashboard>("/compliance/dashboard", { headers: { Authorization: `Bearer ${token}` } }),
          api.get<Evidence[]>("/compliance/evidence", { headers: { Authorization: `Bearer ${token}` } }),
        ]);
        setDashboard(dashboardRes.data);
        setEvidence(evidenceRes.data || []);
      } catch (err: unknown) {
        const status = apiErrorStatus(err);
        if (status === 401) {
          router.push("/login");
          return;
        }
        if (status === 403) {
          toast.error("Admin access required for the Compliance Center");
          router.push("/dashboard");
          return;
        }
        setError("Failed to load compliance data");
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
      toast.error("Admin access required for the Compliance Center");
      router.push("/dashboard");
      return;
    }
    fetchDashboard(token);
  }, [fetchDashboard, router]);

  const runScan = async () => {
    try {
      setScanning(true);
      await api.post("/compliance/scan", {}, authHeader());
      toast.success("Compliance scan completed");
      const token = localStorage.getItem("token");
      if (token) await fetchDashboard(token);
    } catch {
      toast.error("Failed to run compliance scan");
    } finally {
      setScanning(false);
    }
  };

  const handleExport = async (format: "csv" | "json" | "pdf") => {
    try {
      const token = localStorage.getItem("token");
      const res = await api.get(`/compliance/reports/export`, {
        params: { format },
        headers: { Authorization: `Bearer ${token}` },
        responseType: "blob",
      });
      const url = window.URL.createObjectURL(new Blob([res.data]));
      const a = document.createElement("a");
      a.href = url;
      a.download = `compliance-report-${Date.now()}.${format}`;
      a.click();
      window.URL.revokeObjectURL(url);
      toast.success("Report generated");
    } catch {
      toast.error("Failed to generate report");
    }
  };

  const approveEvidence = async (id: string) => {
    try {
      await api.post(`/compliance/evidence/${id}/approve`, {}, authHeader());
      setEvidence((prev) => prev.map((e) => (e._id === id ? { ...e, approved: true } : e)));
      toast.success("Evidence approved");
    } catch {
      toast.error("Failed to approve evidence");
    }
  };

  const togglePolicy = async (policy: Policy) => {
    try {
      await api.put(`/compliance/policies/${policy.name}`, { value: policy.value, enabled: !policy.enabled }, authHeader());
      toast.success(`Policy "${policy.name}" ${!policy.enabled ? "enabled" : "disabled"}`);
      const token = localStorage.getItem("token");
      if (token) await fetchDashboard(token);
    } catch {
      toast.error("Failed to update policy");
    }
  };

  const frameworkChartData = useMemo(
    () => (dashboard?.frameworkStatus || []).map((f) => ({ name: f.framework, value: f.score })),
    [dashboard]
  );

  const coverageChartData = useMemo(
    () =>
      Object.entries(dashboard?.controlCoverage || {})
        .filter(([, v]) => v > 0)
        .map(([name, value]) => ({ name, value })),
    [dashboard]
  );

  const riskDistributionData = useMemo(
    () =>
      Object.entries(dashboard?.riskDistribution || {})
        .filter(([, v]) => v > 0)
        .map(([name, value]) => ({ name, value })),
    [dashboard]
  );

  const trendData = useMemo(
    () => (dashboard?.trend || []).map((t) => ({ date: new Date(t.day).toLocaleDateString(), score: t.averageScore })),
    [dashboard]
  );

  const governanceActivityData = useMemo(
    () => [
      { name: "Policy Violations", value: dashboard?.policyViolations30d || 0 },
      { name: "Audit Activity", value: dashboard?.auditActivity30d || 0 },
    ],
    [dashboard]
  );

  const findingsColumns: DataTableColumn<Assessment>[] = [
    { key: "framework", header: "Framework", render: (a) => <span className="text-xs font-medium">{a.framework?.key || "—"}</span> },
    { key: "control", header: "Control", render: (a) => <span className="text-xs">{a.control?.controlId} — {a.control?.title}</span> },
    { key: "severity", header: "Severity", render: (a) => <StatusBadge label={a.control?.severity || "—"} tone={STATUS_TONE[a.status]} /> },
    { key: "score", header: "Score", render: (a) => `${a.score}/100` },
    { key: "status", header: "Status", render: (a) => <StatusBadge label={a.status} tone={STATUS_TONE[a.status]} /> },
  ];

  const assessmentColumns: DataTableColumn<Assessment>[] = [
    { key: "framework", header: "Framework", render: (a) => <span className="text-xs font-medium">{a.framework?.key || "—"}</span> },
    { key: "control", header: "Control", render: (a) => <span className="text-xs">{a.control?.controlId} — {a.control?.title}</span> },
    { key: "score", header: "Score", render: (a) => `${a.score}/100` },
    { key: "status", header: "Status", render: (a) => <StatusBadge label={a.status} tone={STATUS_TONE[a.status]} /> },
    { key: "evaluatedAt", header: "Evaluated", render: (a) => <span className="text-xs text-muted-foreground">{new Date(a.evaluatedAt).toLocaleString()}</span> },
  ];

  const evidenceColumns: DataTableColumn<Evidence>[] = [
    { key: "sourceType", header: "Source", render: (e) => <StatusBadge label={e.sourceType.replace(/_/g, " ")} tone="info" /> },
    { key: "control", header: "Control", render: (e) => <span className="text-xs">{e.control ? `${e.control.controlId} — ${e.control.title}` : "—"}</span> },
    { key: "summary", header: "Summary", render: (e) => <span className="text-xs max-w-md truncate inline-block">{e.summary}</span> },
    { key: "collectedAt", header: "Collected", render: (e) => <span className="text-xs text-muted-foreground">{new Date(e.collectedAt).toLocaleString()}</span> },
    {
      key: "actions",
      header: "Status",
      render: (e) =>
        e.approved ? (
          <StatusBadge label="Approved" tone="success" />
        ) : (
          <button onClick={() => approveEvidence(e._id)} className="flex items-center gap-1.5 px-2 py-1 bg-card border border-border rounded text-xs hover:bg-muted">
            Approve
          </button>
        ),
    },
  ];

  const policyColumns: DataTableColumn<Policy>[] = [
    { key: "name", header: "Policy", render: (p) => <span className="font-medium text-xs">{p.name}</span> },
    { key: "value", header: "Value", render: (p) => <span className="text-xs text-muted-foreground">{JSON.stringify(p.value)}</span> },
    { key: "version", header: "Version", render: (p) => `v${p.version}` },
    { key: "status", header: "Status", render: (p) => <StatusBadge label={p.enabled ? "Enabled" : "Disabled"} tone={p.enabled ? "success" : "neutral"} /> },
    {
      key: "actions",
      header: "Actions",
      render: (p) => (
        <button onClick={() => togglePolicy(p)} className="flex items-center gap-1.5 px-2 py-1 bg-card border border-border rounded text-xs hover:bg-muted">
          <Settings2 size={12} /> {p.enabled ? "Disable" : "Enable"}
        </button>
      ),
    },
  ];

  return (
    <div>
      <PageHeader
        icon={ClipboardCheck}
        title="Compliance & Governance"
        description="Continuous compliance assessment across ISO 27001, SOC 2, GDPR, HIPAA, PCI DSS, NIST CSF, CIS Controls, and OWASP ASVS."
        accent="success"
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
          <motion.div variants={staggerContainer} initial="hidden" animate="show" className="grid grid-cols-2 md:grid-cols-5 gap-4">
            <StatCard label="Overall Compliance Score" value={`${dashboard.overallScore}/100`} icon={ClipboardCheck} variant={dashboard.overallScore >= 85 ? "success" : dashboard.overallScore >= 60 ? "warning" : "danger"} />
            <StatCard label="Risk Score" value={`${dashboard.riskScore}/100`} icon={Gauge} variant={dashboard.riskScore <= 20 ? "success" : dashboard.riskScore <= 50 ? "warning" : "danger"} />
            <StatCard label="Frameworks Tracked" value={dashboard.frameworkStatus.length} icon={FileCheck2} variant="primary" />
            <StatCard label="Failed Controls" value={dashboard.controlCoverage.FAIL || 0} icon={ShieldAlert} variant={dashboard.controlCoverage.FAIL ? "danger" : "success"} />
            <StatCard label="Evidence Collected" value={dashboard.evidenceCount} icon={Database} variant="purple" />
          </motion.div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="rounded-xl border border-border bg-card p-6">
              <h3 className="text-sm font-semibold text-foreground mb-4">Framework Scores</h3>
              {frameworkChartData.length === 0 ? (
                <p className="text-sm text-muted-foreground py-10 text-center">No framework assessments yet - run a scan.</p>
              ) : (
                <ResponsiveContainer width="100%" height={260}>
                  <BarChart data={frameworkChartData} layout="vertical" margin={{ left: 8 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.1)" horizontal={false} />
                    <XAxis type="number" domain={[0, 100]} stroke="#64748B" fontSize={11} tickLine={false} axisLine={false} />
                    <YAxis type="category" dataKey="name" stroke="#64748B" fontSize={11} tickLine={false} axisLine={false} width={90} />
                    <Tooltip contentStyle={{ background: "#0F172A", border: "1px solid rgba(148,163,184,0.2)", borderRadius: 8, fontSize: 12 }} />
                    <Bar dataKey="value" fill="#10B981" radius={[0, 4, 4, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              )}
            </div>

            <div className="rounded-xl border border-border bg-card p-6">
              <h3 className="text-sm font-semibold text-foreground mb-4">Control Coverage</h3>
              {coverageChartData.length === 0 ? (
                <p className="text-sm text-muted-foreground py-10 text-center">No controls assessed yet.</p>
              ) : (
                <ResponsiveContainer width="100%" height={260}>
                  <PieChart>
                    <Pie data={coverageChartData} dataKey="value" nameKey="name" innerRadius={50} outerRadius={90} paddingAngle={2}>
                      {coverageChartData.map((entry) => (
                        <Cell key={entry.name} fill={COVERAGE_COLORS[entry.name] || "#64748B"} />
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
              <h3 className="text-sm font-semibold text-foreground mb-4">Compliance Trend &amp; Assessment History (90 days)</h3>
              {trendData.length === 0 ? (
                <p className="text-sm text-muted-foreground py-10 text-center">No assessment history yet - run a scan to start tracking trend.</p>
              ) : (
                <ResponsiveContainer width="100%" height={220}>
                  <AreaChart data={trendData}>
                    <defs>
                      <linearGradient id="complianceTrendGradient" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#10B981" stopOpacity={0.4} />
                        <stop offset="95%" stopColor="#10B981" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.1)" />
                    <XAxis dataKey="date" stroke="#64748B" fontSize={11} tickLine={false} axisLine={false} />
                    <YAxis domain={[0, 100]} stroke="#64748B" fontSize={11} tickLine={false} axisLine={false} />
                    <Tooltip contentStyle={{ background: "#0F172A", border: "1px solid rgba(148,163,184,0.2)", borderRadius: 8, fontSize: 12 }} />
                    <Area type="monotone" dataKey="score" stroke="#10B981" fill="url(#complianceTrendGradient)" strokeWidth={2} />
                  </AreaChart>
                </ResponsiveContainer>
              )}
            </div>

            <div className="rounded-xl border border-border bg-card p-6">
              <h3 className="text-sm font-semibold text-foreground mb-4">Risk Distribution</h3>
              {riskDistributionData.length === 0 ? (
                <p className="text-sm text-muted-foreground py-10 text-center">No open risk findings.</p>
              ) : (
                <ResponsiveContainer width="100%" height={220}>
                  <PieChart>
                    <Pie data={riskDistributionData} dataKey="value" nameKey="name" innerRadius={50} outerRadius={90} paddingAngle={2}>
                      {riskDistributionData.map((entry) => (
                        <Cell key={entry.name} fill={RISK_COLORS[entry.name] || "#64748B"} />
                      ))}
                    </Pie>
                    <Tooltip contentStyle={{ background: "#0F172A", border: "1px solid rgba(148,163,184,0.2)", borderRadius: 8, fontSize: 12 }} />
                  </PieChart>
                </ResponsiveContainer>
              )}
            </div>
          </div>

          <div className="rounded-xl border border-border bg-card p-6">
            <h3 className="flex items-center gap-2 text-sm font-semibold text-foreground mb-4">
              <Activity size={16} className="text-primary" />
              Governance Activity (last 30 days)
            </h3>
            <ResponsiveContainer width="100%" height={180}>
              <BarChart data={governanceActivityData}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.1)" />
                <XAxis dataKey="name" stroke="#64748B" fontSize={11} tickLine={false} axisLine={false} />
                <YAxis stroke="#64748B" fontSize={11} tickLine={false} axisLine={false} allowDecimals={false} />
                <Tooltip contentStyle={{ background: "#0F172A", border: "1px solid rgba(148,163,184,0.2)", borderRadius: 8, fontSize: 12 }} />
                <Bar dataKey="value" fill="#6366F1" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>

          <section>
            <h2 className="flex items-center gap-2 text-lg font-bold text-foreground mb-4">
              <ShieldAlert size={20} className="text-destructive" />
              Open Findings / Failed Controls
            </h2>
            {dashboard.openFindings.length === 0 ? (
              <EmptyState icon={FileCheck2} title="No open findings" description="Every assessed control is currently passing." />
            ) : (
              <DataTable columns={findingsColumns} rows={dashboard.openFindings} rowKey={(a) => a._id} emptyLabel="No open findings." />
            )}
          </section>

          <section>
            <h2 className="flex items-center gap-2 text-lg font-bold text-foreground mb-4">
              <ClipboardCheck size={20} className="text-primary" />
              Recent Assessments
            </h2>
            <DataTable columns={assessmentColumns} rows={dashboard.recentAssessments} rowKey={(a) => a._id} emptyLabel="No assessments recorded yet - run a scan to get started." />
          </section>

          <section>
            <h2 className="flex items-center gap-2 text-lg font-bold text-foreground mb-4">
              <Database size={20} className="text-purple-300" />
              Evidence Browser
            </h2>
            <DataTable columns={evidenceColumns} rows={evidence.slice(0, 50)} rowKey={(e) => e._id} stickyHeader maxHeight="50vh" emptyLabel="No evidence collected yet - run a scan to get started." />
          </section>

          <section>
            <h2 className="flex items-center gap-2 text-lg font-bold text-foreground mb-4">
              <Settings2 size={20} className="text-primary" />
              Policy Status
            </h2>
            <DataTable columns={policyColumns} rows={dashboard.policies} rowKey={(p) => p.name} emptyLabel="No governance policies configured." />
          </section>

          <section>
            <h2 className="flex items-center gap-2 text-lg font-bold text-foreground mb-4">
              <ClipboardCheck size={20} className="text-success" />
              Recommendations
            </h2>
            {dashboard.recommendations.length === 0 ? (
              <EmptyState icon={FileCheck2} title="No open recommendations" description="No outstanding compliance recommendations at this time." />
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
