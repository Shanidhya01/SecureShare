"use client";

import { useEffect, useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import api from "@/lib/api";
import { apiErrorStatus } from "@/lib/errors";
import { Eye, ShieldAlert, Ban, Fingerprint, BarChart3, AlertCircle } from "lucide-react";
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from "recharts";
import { motion } from "framer-motion";
import PageHeader from "@/components/design/PageHeader";
import StatCard from "@/components/design/StatCard";
import StatusBadge, { severityTone, decisionTone } from "@/components/design/StatusBadge";
import EmptyState from "@/components/design/EmptyState";
import DataTable, { type DataTableColumn } from "@/components/design/DataTable";
import { StatsSkeleton, TableSkeleton } from "@/components/design/Skeletons";
import { staggerContainer } from "@/lib/motion";

type Severity = "None" | "Low" | "Medium" | "High" | "Critical";
type Decision = "allow" | "warn" | "require_approval" | "block";

type Finding = { detectorId: string; label: string; category: string; severity: Severity; count: number; samples: string[] };

type ScanEntry = {
  _id: string;
  originalFilename?: string;
  fileSizeBytes?: number;
  supported: boolean;
  skipReason?: string | null;
  truncated?: boolean;
  findings: Finding[];
  matchedPatterns: string[];
  severity: Severity;
  decision: Decision;
  scanStatus: string;
  createdAt: string;
};

type DLPStats = {
  totalScans: number;
  bySeverity: Record<Severity, number>;
  byDecision: Record<Decision, number>;
  policyViolations: number;
  blockedUploads: number;
  topDetectedTypes: { detectorId: string; label: string; count: number }[];
};

const decisionLabel: Record<Decision, string> = {
  allow: "Allowed",
  warn: "Warned",
  require_approval: "Approval Required",
  block: "Blocked",
};

export default function DLPCenterPage() {
  const router = useRouter();
  const [scans, setScans] = useState<ScanEntry[]>([]);
  const [stats, setStats] = useState<DLPStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const fetchAll = useCallback(
    async (token: string) => {
      try {
        setLoading(true);
        const [scansRes, statsRes] = await Promise.all([
          api.get<ScanEntry[]>("/dlp/scans", { headers: { Authorization: `Bearer ${token}` } }),
          api.get<DLPStats>("/dlp/stats", { headers: { Authorization: `Bearer ${token}` } }),
        ]);
        setScans(scansRes.data || []);
        setStats(statsRes.data || null);
      } catch (err: unknown) {
        const status = apiErrorStatus(err);
        if (status === 401 || status === 403) {
          router.push("/login");
          return;
        }
        setError("Failed to load DLP data");
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

  const blockedScans = scans.filter((s) => s.decision === "block");
  const violationScans = scans.filter((s) => s.decision !== "allow" && s.findings.length > 0);

  const formatDate = (d: string) => new Date(d).toLocaleString();
  const formatBytes = (n?: number) => {
    if (!n) return "-";
    if (n < 1024) return `${n} B`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
    return `${(n / (1024 * 1024)).toFixed(1)} MB`;
  };

  const severityData = stats
    ? (Object.keys(stats.bySeverity) as Severity[]).filter((k) => k !== "None" && stats.bySeverity[k] > 0).map((k) => ({ name: k, value: stats.bySeverity[k] }))
    : [];
  const DECISION_COLORS = ["#10B981", "#F59E0B", "#F59E0B", "#EF4444"];

  const columns: DataTableColumn<ScanEntry>[] = [
    { key: "file", header: "File", render: (s) => <span className="max-w-[180px] truncate inline-block" title={s.originalFilename}>{s.originalFilename}</span> },
    { key: "size", header: "Size", render: (s) => formatBytes(s.fileSizeBytes) },
    {
      key: "patterns",
      header: "Matched Patterns",
      render: (s) => (
        <span className="text-xs text-muted-foreground max-w-[220px] truncate inline-block">
          {!s.supported ? "skipped (binary/unsupported)" : s.matchedPatterns.length > 0 ? s.matchedPatterns.join(", ") : "none"}
        </span>
      ),
    },
    { key: "severity", header: "Severity", render: (s) => <StatusBadge label={s.severity} tone={severityTone[s.severity] ?? "neutral"} /> },
    { key: "decision", header: "Decision", render: (s) => <StatusBadge label={decisionLabel[s.decision]} tone={decisionTone[s.decision] ?? "neutral"} /> },
    { key: "scanned", header: "Scanned", className: "whitespace-nowrap text-xs text-muted-foreground", render: (s) => formatDate(s.createdAt) },
  ];

  return (
    <div>
      <PageHeader icon={Eye} title="DLP Center" description="Data loss prevention: sensitive data scans, policy violations, and blocked uploads." accent="purple" />

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
      ) : (
        <div className="space-y-8">
          {stats && (
            <motion.div variants={staggerContainer} initial="hidden" animate="show" className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <StatCard label="Total Scans" value={stats.totalScans} icon={Fingerprint} variant="primary" />
              <StatCard label="Policy Violations" value={stats.policyViolations} icon={ShieldAlert} variant="warning" />
              <StatCard label="Blocked Uploads" value={stats.blockedUploads} icon={Ban} variant="danger" />
              <StatCard label="Clean Rate" value={stats.totalScans > 0 ? `${Math.round(((stats.totalScans - stats.policyViolations) / stats.totalScans) * 100)}%` : "100%"} icon={Eye} variant="success" />
            </motion.div>
          )}

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {stats && stats.topDetectedTypes.length > 0 && (
              <div className="rounded-xl border border-border bg-card p-6">
                <h3 className="flex items-center gap-2 text-sm font-semibold text-foreground mb-4">
                  <BarChart3 size={16} className="text-purple-300" />
                  Top Detected Secret Types
                </h3>
                <ResponsiveContainer width="100%" height={220}>
                  <BarChart data={stats.topDetectedTypes} layout="vertical" margin={{ left: 8 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.1)" horizontal={false} />
                    <XAxis type="number" stroke="#64748B" fontSize={11} tickLine={false} axisLine={false} allowDecimals={false} />
                    <YAxis type="category" dataKey="label" stroke="#64748B" fontSize={11} tickLine={false} axisLine={false} width={110} />
                    <Tooltip contentStyle={{ background: "#0F172A", border: "1px solid rgba(148,163,184,0.2)", borderRadius: 8, fontSize: 12 }} />
                    <Bar dataKey="count" fill="#A855F7" radius={[0, 4, 4, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            )}

            <div className="rounded-xl border border-border bg-card p-6">
              <h3 className="text-sm font-semibold text-foreground mb-4">Findings by Severity</h3>
              {severityData.length === 0 ? (
                <p className="text-sm text-muted-foreground py-10 text-center">No DLP findings yet.</p>
              ) : (
                <ResponsiveContainer width="100%" height={220}>
                  <PieChart>
                    <Pie data={severityData} dataKey="value" nameKey="name" innerRadius={50} outerRadius={80} paddingAngle={2}>
                      {severityData.map((entry, i) => (
                        <Cell key={entry.name} fill={DECISION_COLORS[i % DECISION_COLORS.length]} />
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
              <Ban size={20} className="text-destructive" />
              Blocked Uploads
            </h2>
            {blockedScans.length === 0 ? (
              <EmptyState icon={Ban} title="Nothing blocked" description="No uploads have been blocked by the DLP scanner." />
            ) : (
              <div className="space-y-2">
                {blockedScans.map((s) => (
                  <div key={s._id} className="rounded-xl border border-destructive/30 bg-destructive/5 px-4 py-3">
                    <div className="flex items-center justify-between gap-2">
                      <p className="text-foreground text-sm font-semibold truncate">{s.originalFilename}</p>
                      <div className="flex items-center gap-2 shrink-0">
                        <StatusBadge label={s.severity} tone={severityTone[s.severity] ?? "neutral"} />
                        <StatusBadge label={decisionLabel[s.decision]} tone={decisionTone[s.decision] ?? "neutral"} />
                      </div>
                    </div>
                    <p className="text-muted-foreground text-xs mt-1">
                      {formatDate(s.createdAt)} · {s.matchedPatterns.length > 0 ? s.matchedPatterns.join(", ") : "sensitive data"}
                    </p>
                  </div>
                ))}
              </div>
            )}
          </section>

          <section>
            <h2 className="flex items-center gap-2 text-lg font-bold text-foreground mb-4">
              <ShieldAlert size={20} className="text-warning" />
              Sensitive Data Findings
            </h2>
            {violationScans.length === 0 ? (
              <EmptyState icon={ShieldAlert} title="No sensitive data detected" description="Nothing in your uploads has triggered a DLP finding." />
            ) : (
              <div className="space-y-2">
                {violationScans.map((s) => (
                  <div key={s._id} className="rounded-xl border border-warning/30 bg-warning/5 px-4 py-3">
                    <div className="flex items-center justify-between gap-2 mb-2">
                      <p className="text-foreground text-sm font-semibold truncate">{s.originalFilename}</p>
                      <div className="flex items-center gap-2 shrink-0">
                        <StatusBadge label={s.severity} tone={severityTone[s.severity] ?? "neutral"} />
                        <StatusBadge label={decisionLabel[s.decision]} tone={decisionTone[s.decision] ?? "neutral"} />
                      </div>
                    </div>
                    <div className="flex flex-wrap gap-1.5">
                      {s.findings.map((f) => (
                        <span key={f.detectorId} title={f.samples.join(", ")} className="text-[10px] font-medium rounded-full px-2 py-0.5 bg-muted text-muted-foreground ring-1 ring-border">
                          {f.label} × {f.count}
                        </span>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </section>

          <section>
            <h2 className="flex items-center gap-2 text-lg font-bold text-foreground mb-4">
              <Fingerprint size={20} className="text-primary" />
              Scan History
            </h2>
            <DataTable columns={columns} rows={scans} rowKey={(s) => s._id} emptyLabel="No scans yet - text-based files are scanned automatically before upload." />
          </section>
        </div>
      )}
    </div>
  );
}
