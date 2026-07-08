"use client";

import { useEffect, useState, useCallback, useMemo } from "react";
import { useRouter } from "next/navigation";
import api from "@/lib/api";
import Link from "next/link";
import { ShieldAlert, Bug, Ban, ScanSearch, AlertCircle, Fingerprint, RotateCcw, Radar, Crosshair, ArrowUpRight } from "lucide-react";
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, AreaChart, Area, XAxis, YAxis, CartesianGrid, BarChart, Bar } from "recharts";
import toast from "react-hot-toast";
import PageHeader from "@/components/design/PageHeader";
import StatCard from "@/components/design/StatCard";
import StatusBadge, { riskTone } from "@/components/design/StatusBadge";
import EmptyState from "@/components/design/EmptyState";
import DataTable, { type DataTableColumn } from "@/components/design/DataTable";
import EventTimeline, { type EventTimelineItem } from "@/components/design/EventTimeline";
import { StatsSkeleton, TableSkeleton } from "@/components/design/Skeletons";
import { apiErrorStatus } from "@/lib/errors";
import { bucketByDay } from "@/lib/chartHelpers";
import { motion } from "framer-motion";
import { staggerContainer } from "@/lib/motion";
import ExplainWithAIButton from "@/components/ai/ExplainWithAIButton";

type RiskLevel = "Low" | "Medium" | "High" | "Critical";

type ScanEntry = {
  _id: string;
  originalFilename?: string;
  fileSizeBytes?: number;
  claimedMimeType?: string | null;
  detectedMimeType?: string;
  mimeMismatch?: boolean;
  hashes?: { sha256?: string; sha1?: string; md5?: string };
  clamav?: { status: string; threatNames: string[] };
  virusTotal?: { status: string; maliciousCount: number; totalEngines: number; threatNames: string[] };
  riskLevel: RiskLevel;
  quarantined: boolean;
  scanStatus: string;
  createdAt: string;
};

type QuarantinedFile = {
  _id: string;
  filename: string;
  riskLevel: RiskLevel | null;
  scanId?: ScanEntry;
  createdAt: string;
};

type ThreatStats = {
  totalScans: number;
  quarantinedFiles: number;
  byRiskLevel: Record<RiskLevel, number>;
  malwareDetections: number;
  clamavUnavailableCount: number;
};

const RISK_COLORS: Record<string, string> = { Low: "#10B981", Medium: "#F59E0B", High: "#F59E0B", Critical: "#EF4444" };

export default function ThreatCenterPage() {
  const router = useRouter();
  const [scans, setScans] = useState<ScanEntry[]>([]);
  const [quarantined, setQuarantined] = useState<QuarantinedFile[]>([]);
  const [stats, setStats] = useState<ThreatStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [busyId, setBusyId] = useState<string | null>(null);
  const [mitreCount, setMitreCount] = useState<number | null>(null);

  const fetchAll = useCallback(
    async (token: string) => {
      try {
        setLoading(true);
        const [scansRes, quarantinedRes, statsRes] = await Promise.all([
          api.get<ScanEntry[]>("/threats/scans", { headers: { Authorization: `Bearer ${token}` } }),
          api.get<QuarantinedFile[]>("/threats/quarantined", { headers: { Authorization: `Bearer ${token}` } }),
          api.get<ThreatStats>("/threats/stats", { headers: { Authorization: `Bearer ${token}` } }),
        ]);
        setScans(scansRes.data || []);
        setQuarantined(quarantinedRes.data || []);
        setStats(statsRes.data || null);
      } catch (err: unknown) {
        const status = apiErrorStatus(err);
        if (status === 401 || status === 403) {
          router.push("/login");
          return;
        }
        setError("Failed to load threat data");
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
    // Phase 7: MITRE ATT&CK technique count surfaced from Threat Intelligence enrichment -
    // best-effort, never blocks the Threat Center page if unavailable.
    api
      .get<{ byMitreTechnique: Record<string, number> }>("/threat-intel/stats", { headers: { Authorization: `Bearer ${token}` } })
      .then((res) => setMitreCount(Object.keys(res.data.byMitreTechnique || {}).length))
      .catch(() => setMitreCount(null));
  }, [fetchAll, router]);

  const handleRelease = async (fileId: string) => {
    const token = localStorage.getItem("token");
    if (!token) return;
    setBusyId(fileId);
    try {
      await api.post(`/threats/quarantine/${fileId}/release`, {}, { headers: { Authorization: `Bearer ${token}` } });
      setQuarantined((prev) => prev.filter((f) => f._id !== fileId));
      toast.success("File released from quarantine");
    } catch {
      toast.error("Failed to release file");
    } finally {
      setBusyId(null);
    }
  };

  const malwareDetections = scans.filter((s) => s.clamav?.status === "infected" || s.virusTotal?.status === "malicious");

  const formatDate = (d: string) => new Date(d).toLocaleString();
  const formatBytes = (n?: number) => {
    if (!n) return "-";
    if (n < 1024) return `${n} B`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
    return `${(n / (1024 * 1024)).toFixed(1)} MB`;
  };

  const riskData = stats
    ? (Object.keys(stats.byRiskLevel) as RiskLevel[]).filter((k) => stats.byRiskLevel[k] > 0).map((k) => ({ name: k, value: stats.byRiskLevel[k] }))
    : [];
  const scanTrend = bucketByDay(scans, (s) => s.createdAt, 14);

  const topThreatTypes = useMemo(() => {
    const counts = new Map<string, number>();
    for (const s of scans) {
      for (const name of s.clamav?.threatNames || []) counts.set(name, (counts.get(name) || 0) + 1);
      for (const name of s.virusTotal?.threatNames || []) counts.set(name, (counts.get(name) || 0) + 1);
    }
    return Array.from(counts.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8)
      .map(([name, count]) => ({ name, count }));
  }, [scans]);

  const threatFeed: EventTimelineItem[] = useMemo(() => {
    const quarantineEvents: EventTimelineItem[] = quarantined.map((f) => ({
      key: `q-${f._id}`,
      icon: Ban,
      title: `${f.filename} quarantined`,
      description: f.scanId?.clamav?.threatNames?.length ? f.scanId.clamav.threatNames.join(", ") : "Flagged by threat scanner",
      timestamp: f.createdAt,
      tone: "danger",
      badgeLabel: f.riskLevel || "Low",
    }));
    const malwareEvents: EventTimelineItem[] = malwareDetections.map((s) => ({
      key: `m-${s._id}`,
      icon: Bug,
      title: `${s.originalFilename || "File"} flagged as malware`,
      description:
        s.clamav?.status === "infected"
          ? `ClamAV: ${s.clamav.threatNames.join(", ")}`
          : s.virusTotal?.status === "malicious"
          ? `VirusTotal: ${s.virusTotal.maliciousCount}/${s.virusTotal.totalEngines} engines flagged`
          : undefined,
      timestamp: s.createdAt,
      tone: "warning",
      badgeLabel: s.riskLevel,
    }));
    return [...quarantineEvents, ...malwareEvents]
      .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
      .slice(0, 10);
  }, [quarantined, malwareDetections]);

  const columns: DataTableColumn<ScanEntry>[] = [
    {
      key: "file",
      header: "File",
      render: (s) => (
        <span className="max-w-[180px] truncate inline-block" title={s.originalFilename}>
          {s.originalFilename}
          {s.mimeMismatch && <span title="Claimed type didn't match detected content" className="ml-1 text-warning">⚠</span>}
        </span>
      ),
    },
    { key: "size", header: "Size", render: (s) => formatBytes(s.fileSizeBytes) },
    {
      key: "sha256",
      header: "SHA-256",
      render: (s) => (
        <span className="font-mono text-xs text-muted-foreground max-w-[140px] truncate inline-block" title={s.hashes?.sha256}>
          {s.hashes?.sha256?.slice(0, 16)}…
        </span>
      ),
    },
    {
      key: "clamav",
      header: "ClamAV",
      render: (s) =>
        s.clamav?.status === "clean" ? (
          <StatusBadge label="Clean" tone="success" />
        ) : s.clamav?.status === "infected" ? (
          <StatusBadge label="Infected" tone="danger" />
        ) : s.clamav?.status === "unavailable" ? (
          <StatusBadge label="Unavailable" tone="neutral" />
        ) : s.clamav?.status === "error" ? (
          <StatusBadge label="Error" tone="warning" />
        ) : null,
    },
    {
      key: "vt",
      header: "VirusTotal",
      render: (s) =>
        s.virusTotal?.status === "skipped" ? (
          <StatusBadge label="Skipped" tone="neutral" />
        ) : s.virusTotal?.status === "clean" ? (
          <StatusBadge label="Clean" tone="success" />
        ) : s.virusTotal?.status === "unknown" ? (
          <StatusBadge label="Unknown" tone="neutral" />
        ) : s.virusTotal?.status === "suspicious" ? (
          <StatusBadge label="Suspicious" tone="warning" />
        ) : s.virusTotal?.status === "malicious" ? (
          <StatusBadge label="Malicious" tone="danger" />
        ) : s.virusTotal?.status === "error" ? (
          <StatusBadge label="Error" tone="warning" />
        ) : null,
    },
    { key: "risk", header: "Risk", render: (s) => <StatusBadge label={s.riskLevel} tone={riskTone[s.riskLevel] ?? "neutral"} /> },
    { key: "scanned", header: "Scanned", className: "whitespace-nowrap text-xs text-muted-foreground", render: (s) => formatDate(s.createdAt) },
  ];

  return (
    <div>
      <PageHeader icon={ScanSearch} title="Threat Center" description="Malware scanning, quarantine, and threat intelligence for your uploads." accent="danger" />

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
              <StatCard label="Quarantined Files" value={stats.quarantinedFiles} icon={Ban} variant="danger" />
              <StatCard label="Malware Detections" value={stats.malwareDetections} icon={ShieldAlert} variant="warning" />
              <StatCard label="Clean Rate" value={stats.totalScans > 0 ? `${Math.round(((stats.totalScans - stats.malwareDetections) / stats.totalScans) * 100)}%` : "100%"} icon={ScanSearch} variant="success" />
            </motion.div>
          )}
          {stats && stats.clamavUnavailableCount > 0 && (
            <p className="flex items-center gap-2 text-muted-foreground text-xs -mt-4">
              <AlertCircle size={12} />
              ClamAV was unavailable for {stats.clamavUnavailableCount} scan(s) in this environment - those scans still ran
              magic-byte, MIME-mismatch, and VirusTotal checks.
            </p>
          )}

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="rounded-xl border border-border bg-card p-6">
              <h3 className="text-sm font-semibold text-foreground mb-4">Risk Levels</h3>
              {riskData.length === 0 ? (
                <p className="text-sm text-muted-foreground py-10 text-center">No scans yet.</p>
              ) : (
                <ResponsiveContainer width="100%" height={220}>
                  <PieChart>
                    <Pie data={riskData} dataKey="value" nameKey="name" innerRadius={50} outerRadius={80} paddingAngle={2}>
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
              <h3 className="text-sm font-semibold text-foreground mb-4">Scan Volume (14 days)</h3>
              <ResponsiveContainer width="100%" height={220}>
                <AreaChart data={scanTrend}>
                  <defs>
                    <linearGradient id="threatGradient" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#EF4444" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#EF4444" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.1)" />
                  <XAxis dataKey="date" stroke="#64748B" fontSize={11} tickLine={false} axisLine={false} />
                  <YAxis stroke="#64748B" fontSize={11} tickLine={false} axisLine={false} allowDecimals={false} />
                  <Tooltip contentStyle={{ background: "#0F172A", border: "1px solid rgba(148,163,184,0.2)", borderRadius: 8, fontSize: 12 }} />
                  <Area type="monotone" dataKey="count" stroke="#EF4444" fill="url(#threatGradient)" strokeWidth={2} />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>

          {topThreatTypes.length > 0 && (
            <div className="rounded-xl border border-border bg-card p-6">
              <h3 className="flex items-center gap-2 text-sm font-semibold text-foreground mb-4">
                <Radar size={16} className="text-destructive" />
                Top Threat Types
              </h3>
              <ResponsiveContainer width="100%" height={220}>
                <BarChart data={topThreatTypes} layout="vertical" margin={{ left: 8 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.1)" horizontal={false} />
                  <XAxis type="number" stroke="#64748B" fontSize={11} tickLine={false} axisLine={false} allowDecimals={false} />
                  <YAxis type="category" dataKey="name" stroke="#64748B" fontSize={11} tickLine={false} axisLine={false} width={130} />
                  <Tooltip contentStyle={{ background: "#0F172A", border: "1px solid rgba(148,163,184,0.2)", borderRadius: 8, fontSize: 12 }} />
                  <Bar dataKey="count" fill="#EF4444" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}

          <Link
            href="/threat-intelligence"
            className="flex items-center justify-between gap-3 rounded-xl border border-border bg-card p-5 hover:border-primary/40 transition-colors"
          >
            <div className="flex items-center gap-3">
              <div className="inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-lg ring-1 text-purple-300 bg-purple-500/10 ring-purple-500/25">
                <Crosshair size={20} />
              </div>
              <div>
                <p className="text-sm font-semibold text-foreground">Threat Intelligence &amp; MITRE ATT&amp;CK Mapping</p>
                <p className="text-xs text-muted-foreground mt-0.5">
                  {mitreCount !== null ? `${mitreCount} technique(s) mapped from IOC/YARA enrichment` : "IOC lookups, MITRE mapping, and YARA matches"} — view full dashboard
                </p>
              </div>
            </div>
            <ArrowUpRight size={18} className="text-muted-foreground shrink-0" />
          </Link>

          <section>
            <h2 className="flex items-center gap-2 text-lg font-bold text-foreground mb-4">
              <Radar size={20} className="text-destructive" />
              Threat Timeline
            </h2>
            <div className="rounded-xl border border-border bg-card p-5">
              <EventTimeline items={threatFeed} emptyLabel="No threat activity recorded yet." />
            </div>
          </section>

          <section>
            <h2 className="flex items-center gap-2 text-lg font-bold text-foreground mb-4">
              <Ban size={20} className="text-destructive" />
              Quarantined Files
            </h2>
            {quarantined.length === 0 ? (
              <EmptyState icon={Ban} title="Nothing quarantined" description="No uploads have been blocked by the threat scanner." />
            ) : (
              <div className="space-y-2">
                {quarantined.map((f) => (
                  <div key={f._id} className="flex items-start justify-between gap-3 rounded-xl border border-destructive/30 bg-destructive/5 px-4 py-3">
                    <div className="flex items-start gap-3 min-w-0">
                      <Bug size={16} className="text-destructive shrink-0 mt-0.5" />
                      <div className="min-w-0">
                        <p className="text-foreground text-sm font-semibold truncate">{f.filename}</p>
                        <p className="text-muted-foreground text-xs mt-1">
                          Quarantined {formatDate(f.createdAt)}
                          {f.scanId?.clamav?.threatNames?.length ? ` · ${f.scanId.clamav.threatNames.join(", ")}` : ""}
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      <StatusBadge label={f.riskLevel || "Low"} tone={riskTone[f.riskLevel || "Low"] ?? "neutral"} />
                      <ExplainWithAIButton sourceType="File" sourceId={f._id} />
                      <button
                        type="button"
                        onClick={() => handleRelease(f._id)}
                        disabled={busyId === f._id}
                        className="flex items-center gap-1 px-3 py-1.5 text-xs font-semibold text-muted-foreground hover:text-foreground hover:bg-white/5 rounded-lg disabled:opacity-50"
                        title="Release from quarantine (owner override)"
                      >
                        <RotateCcw size={12} />
                        Release
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </section>

          <section>
            <h2 className="flex items-center gap-2 text-lg font-bold text-foreground mb-4">
              <ShieldAlert size={20} className="text-warning" />
              Recent Malware Detections
            </h2>
            {malwareDetections.length === 0 ? (
              <EmptyState icon={ShieldAlert} title="No malware detected" description="Nothing in your uploads has triggered a malware detection." />
            ) : (
              <div className="space-y-2">
                {malwareDetections.map((s) => (
                  <div key={s._id} className="rounded-xl border border-warning/30 bg-warning/5 px-4 py-3">
                    <div className="flex items-center justify-between gap-2">
                      <p className="text-foreground text-sm font-semibold truncate">{s.originalFilename}</p>
                      <div className="flex items-center gap-2 shrink-0">
                        <StatusBadge label={s.riskLevel} tone={riskTone[s.riskLevel] ?? "neutral"} />
                        <ExplainWithAIButton sourceType="ThreatScan" sourceId={s._id} />
                      </div>
                    </div>
                    <p className="text-muted-foreground text-xs mt-1">
                      {s.clamav?.status === "infected" && `ClamAV: ${s.clamav.threatNames.join(", ")}`}
                      {s.clamav?.status === "infected" && s.virusTotal?.status === "malicious" && " · "}
                      {s.virusTotal?.status === "malicious" && `VirusTotal: ${s.virusTotal.maliciousCount}/${s.virusTotal.totalEngines} engines flagged`}
                    </p>
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
            <DataTable columns={columns} rows={scans} rowKey={(s) => s._id} emptyLabel="No scans yet - files are scanned automatically before upload." />
          </section>
        </div>
      )}
    </div>
  );
}
