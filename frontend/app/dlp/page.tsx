"use client";

import { useEffect, useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import api from "@/lib/api";
import {
  Eye,
  ShieldAlert,
  Ban,
  Loader,
  AlertCircle,
  Fingerprint,
  BarChart3,
} from "lucide-react";

type Severity = "None" | "Low" | "Medium" | "High" | "Critical";
type Decision = "allow" | "warn" | "require_approval" | "block";

type Finding = {
  detectorId: string;
  label: string;
  category: string;
  severity: Severity;
  count: number;
  samples: string[];
};

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

const severityBadgeClass: Record<Severity, string> = {
  None: "text-slate-400 bg-slate-500/10 ring-slate-500/30",
  Low: "text-green-300 bg-green-500/10 ring-green-500/30",
  Medium: "text-yellow-300 bg-yellow-500/10 ring-yellow-500/30",
  High: "text-orange-300 bg-orange-500/10 ring-orange-500/30",
  Critical: "text-red-300 bg-red-500/10 ring-red-500/30",
};

const decisionBadgeClass: Record<Decision, string> = {
  allow: "text-green-300 bg-green-500/10 ring-green-500/30",
  warn: "text-yellow-300 bg-yellow-500/10 ring-yellow-500/30",
  require_approval: "text-orange-300 bg-orange-500/10 ring-orange-500/30",
  block: "text-red-300 bg-red-500/10 ring-red-500/30",
};

const decisionLabel: Record<Decision, string> = {
  allow: "Allowed",
  warn: "Warned",
  require_approval: "Approval Required",
  block: "Blocked",
};

function SeverityBadge({ level }: { level: Severity | null | undefined }) {
  const lvl = level || "None";
  return (
    <span className={`text-[10px] font-bold uppercase tracking-wide rounded-full px-2 py-0.5 ring-1 ${severityBadgeClass[lvl]}`}>
      {lvl}
    </span>
  );
}

function DecisionBadge({ decision }: { decision: Decision }) {
  return (
    <span className={`text-[10px] font-bold uppercase tracking-wide rounded-full px-2 py-0.5 ring-1 ${decisionBadgeClass[decision]}`}>
      {decisionLabel[decision]}
    </span>
  );
}

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
      } catch (err: any) {
        if (err?.response?.status === 401 || err?.response?.status === 403) {
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

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 text-white">
      <div className="max-w-5xl mx-auto px-4 py-12">
        <div className="mb-10 flex items-center gap-3">
          <div className="inline-flex h-11 w-11 items-center justify-center rounded-xl bg-purple-500/10 text-purple-300 ring-1 ring-purple-500/30">
            <Eye size={22} />
          </div>
          <div>
            <h1 className="text-3xl font-black text-transparent bg-clip-text bg-gradient-to-r from-purple-400 to-pink-400">
              DLP Center
            </h1>
            <p className="text-slate-400 text-sm">Data loss prevention: sensitive data scans, policy violations, and blocked uploads.</p>
          </div>
        </div>

        {error && (
          <div className="mb-6 p-4 bg-red-500/20 border border-red-500/40 rounded-lg flex items-center gap-2">
            <AlertCircle className="text-red-400" size={18} />
            <p className="text-red-200 text-sm">{error}</p>
          </div>
        )}

        {loading ? (
          <div className="flex flex-col items-center py-20">
            <Loader className="animate-spin text-purple-400" size={40} />
            <p className="mt-4 text-slate-400">Loading DLP data…</p>
          </div>
        ) : (
          <div className="space-y-10">
            {/* Stats */}
            {stats && (
              <section className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="bg-slate-800 border border-slate-700 rounded-xl p-4">
                  <p className="text-slate-400 text-xs">Total Scans</p>
                  <p className="text-2xl font-bold mt-1">{stats.totalScans}</p>
                </div>
                <div className="bg-slate-800 border border-slate-700 rounded-xl p-4">
                  <p className="text-slate-400 text-xs">Policy Violations</p>
                  <p className="text-2xl font-bold mt-1 text-yellow-300">{stats.policyViolations}</p>
                </div>
                <div className="bg-slate-800 border border-slate-700 rounded-xl p-4">
                  <p className="text-slate-400 text-xs">Blocked Uploads</p>
                  <p className="text-2xl font-bold mt-1 text-red-300">{stats.blockedUploads}</p>
                </div>
                <div className="bg-slate-800 border border-slate-700 rounded-xl p-4">
                  <p className="text-slate-400 text-xs">Severity Breakdown</p>
                  <div className="flex gap-1.5 mt-2 flex-wrap">
                    {(Object.keys(stats.bySeverity) as Severity[])
                      .filter((lvl) => lvl !== "None")
                      .map((lvl) => (
                        <span key={lvl} className={`text-[10px] font-bold rounded-full px-2 py-0.5 ring-1 ${severityBadgeClass[lvl]}`}>
                          {lvl}: {stats.bySeverity[lvl]}
                        </span>
                      ))}
                  </div>
                </div>
              </section>
            )}

            {/* Top Detected Types */}
            {stats && stats.topDetectedTypes.length > 0 && (
              <section>
                <h2 className="flex items-center gap-2 text-lg font-bold text-white mb-4">
                  <BarChart3 size={20} className="text-purple-300" />
                  Top Detected Secret Types
                </h2>
                <div className="rounded-2xl border border-slate-800/80 bg-slate-900/80 p-4 space-y-2">
                  {stats.topDetectedTypes.map((t) => {
                    const max = stats.topDetectedTypes[0]?.count || 1;
                    const pct = Math.max(8, Math.round((t.count / max) * 100));
                    return (
                      <div key={t.detectorId} className="flex items-center gap-3">
                        <p className="text-slate-300 text-xs w-40 truncate shrink-0">{t.label}</p>
                        <div className="flex-1 bg-slate-800 rounded-full h-2 overflow-hidden">
                          <div className="bg-gradient-to-r from-purple-500 to-pink-500 h-full" style={{ width: `${pct}%` }} />
                        </div>
                        <p className="text-slate-400 text-xs w-8 text-right shrink-0">{t.count}</p>
                      </div>
                    );
                  })}
                </div>
              </section>
            )}

            {/* Blocked Uploads */}
            <section>
              <h2 className="flex items-center gap-2 text-lg font-bold text-white mb-4">
                <Ban size={20} className="text-red-300" />
                Blocked Uploads
              </h2>
              {blockedScans.length === 0 ? (
                <p className="text-slate-500 text-sm">No uploads have been blocked by the DLP scanner.</p>
              ) : (
                <div className="space-y-2">
                  {blockedScans.map((s) => (
                    <div key={s._id} className="rounded-xl border border-red-500/30 bg-red-500/5 px-4 py-3">
                      <div className="flex items-center justify-between gap-2">
                        <p className="text-red-100 text-sm font-semibold truncate">{s.originalFilename}</p>
                        <div className="flex items-center gap-2 shrink-0">
                          <SeverityBadge level={s.severity} />
                          <DecisionBadge decision={s.decision} />
                        </div>
                      </div>
                      <p className="text-slate-500 text-xs mt-1">
                        {formatDate(s.createdAt)} · {s.matchedPatterns.length > 0 ? s.matchedPatterns.join(", ") : "sensitive data"}
                      </p>
                    </div>
                  ))}
                </div>
              )}
            </section>

            {/* Policy Violations / Findings */}
            <section>
              <h2 className="flex items-center gap-2 text-lg font-bold text-white mb-4">
                <ShieldAlert size={20} className="text-orange-300" />
                Sensitive Data Findings
              </h2>
              {violationScans.length === 0 ? (
                <p className="text-slate-500 text-sm">No sensitive data has been detected in your uploads.</p>
              ) : (
                <div className="space-y-2">
                  {violationScans.map((s) => (
                    <div key={s._id} className="rounded-xl border border-orange-500/30 bg-orange-500/5 px-4 py-3">
                      <div className="flex items-center justify-between gap-2 mb-2">
                        <p className="text-orange-100 text-sm font-semibold truncate">{s.originalFilename}</p>
                        <div className="flex items-center gap-2 shrink-0">
                          <SeverityBadge level={s.severity} />
                          <DecisionBadge decision={s.decision} />
                        </div>
                      </div>
                      <div className="flex flex-wrap gap-1.5">
                        {s.findings.map((f) => (
                          <span
                            key={f.detectorId}
                            title={f.samples.join(", ")}
                            className="text-[10px] font-medium rounded-full px-2 py-0.5 bg-slate-800 text-slate-300 ring-1 ring-slate-700"
                          >
                            {f.label} × {f.count}
                          </span>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </section>

            {/* Scan History */}
            <section>
              <h2 className="flex items-center gap-2 text-lg font-bold text-white mb-4">
                <Fingerprint size={20} className="text-blue-300" />
                Scan History
              </h2>
              {scans.length === 0 ? (
                <p className="text-slate-500 text-sm">No scans yet - text-based files are scanned automatically before upload.</p>
              ) : (
                <div className="rounded-2xl border border-slate-800/80 bg-slate-900/80 overflow-hidden">
                  <div className="overflow-x-auto">
                    <table className="min-w-full w-full text-sm">
                      <thead className="bg-slate-900 text-xs uppercase tracking-wide text-slate-400">
                        <tr>
                          <th className="px-4 py-3 text-left">File</th>
                          <th className="px-4 py-3 text-left">Size</th>
                          <th className="px-4 py-3 text-left">Matched Patterns</th>
                          <th className="px-4 py-3 text-left">Severity</th>
                          <th className="px-4 py-3 text-left">Decision</th>
                          <th className="px-4 py-3 text-left">Scanned</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/80">
                        {scans.map((s) => (
                          <tr key={s._id} className="hover:bg-slate-900/70">
                            <td className="px-4 py-3 max-w-[180px] truncate" title={s.originalFilename}>
                              {s.originalFilename}
                            </td>
                            <td className="px-4 py-3 text-slate-300">{formatBytes(s.fileSizeBytes)}</td>
                            <td className="px-4 py-3 text-slate-400 text-xs max-w-[220px] truncate">
                              {!s.supported
                                ? "skipped (binary/unsupported)"
                                : s.matchedPatterns.length > 0
                                ? s.matchedPatterns.join(", ")
                                : "none"}
                            </td>
                            <td className="px-4 py-3">
                              <SeverityBadge level={s.severity} />
                            </td>
                            <td className="px-4 py-3">
                              <DecisionBadge decision={s.decision} />
                            </td>
                            <td className="px-4 py-3 text-slate-400 text-xs whitespace-nowrap">{formatDate(s.createdAt)}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </section>
          </div>
        )}
      </div>
    </div>
  );
}
