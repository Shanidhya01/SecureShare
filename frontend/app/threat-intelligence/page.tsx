"use client";

import { useEffect, useState, useCallback, useMemo } from "react";
import { useRouter } from "next/navigation";
import api from "@/lib/api";
import {
  Crosshair,
  Fingerprint,
  Globe,
  ShieldAlert,
  BarChart3,
  AlertCircle,
  Search,
  Radar,
  FileCode2,
  Download,
} from "lucide-react";
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, AreaChart, Area } from "recharts";
import { motion } from "framer-motion";
import PageHeader from "@/components/design/PageHeader";
import StatCard from "@/components/design/StatCard";
import StatusBadge, { severityTone } from "@/components/design/StatusBadge";
import EmptyState from "@/components/design/EmptyState";
import DataTable, { type DataTableColumn } from "@/components/design/DataTable";
import { StatsSkeleton, TableSkeleton } from "@/components/design/Skeletons";
import { apiErrorStatus } from "@/lib/errors";
import { staggerContainer } from "@/lib/motion";

type Severity = "None" | "Low" | "Medium" | "High" | "Critical";

type IocMatch = { type: string; value: string; confidence: number; severity: Severity; source: string; description?: string };
type MitreEntry = { techniqueId: string; name: string; tactic: string };
type YaraMatch = { ruleName: string; severity: Severity; mitreTechniques: string[] };

type ScanEntry = {
  _id: string;
  originalFilename?: string;
  iocMatches: IocMatch[];
  mitreMapping: MitreEntry[];
  yaraMatches: YaraMatch[];
  threatSources: string[];
  providerErrors: string[];
  threatScore: number;
  threatConfidence: number;
  severity: Severity;
  createdAt: string;
};

type Stats = {
  totalScans: number;
  totalIocMatches: number;
  byIocType: Record<string, number>;
  bySeverity: Record<Severity, number>;
  confidenceBuckets: Record<string, number>;
  bySources: Record<string, number>;
  byMitreTechnique: Record<string, number>;
  yaraMatchCount: number;
  timeline: { createdAt: string; severity: Severity; threatConfidence: number; iocMatchCount: number }[];
};

const COLORS = ["#A855F7", "#6366F1", "#F59E0B", "#EF4444", "#10B981", "#0EA5E9"];

export default function ThreatIntelligencePage() {
  const router = useRouter();
  const [scans, setScans] = useState<ScanEntry[]>([]);
  const [stats, setStats] = useState<Stats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [searchResults, setSearchResults] = useState<{ scans: ScanEntry[] } | null>(null);

  const fetchAll = useCallback(
    async (token: string) => {
      try {
        setLoading(true);
        const [scansRes, statsRes] = await Promise.all([
          api.get<ScanEntry[]>("/threat-intel/scans", { headers: { Authorization: `Bearer ${token}` } }),
          api.get<Stats>("/threat-intel/stats", { headers: { Authorization: `Bearer ${token}` } }),
        ]);
        setScans(scansRes.data || []);
        setStats(statsRes.data || null);
      } catch (err: unknown) {
        const status = apiErrorStatus(err);
        if (status === 401 || status === 403) {
          router.push("/login");
          return;
        }
        setError("Failed to load threat intelligence data");
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

  useEffect(() => {
    const token = localStorage.getItem("token");
    if (!token || !search.trim()) {
      setSearchResults(null);
      return;
    }
    const handle = setTimeout(async () => {
      try {
        const res = await api.get(`/threat-intel/search`, {
          params: { q: search },
          headers: { Authorization: `Bearer ${token}` },
        });
        setSearchResults(res.data);
      } catch {
        setSearchResults(null);
      }
    }, 300);
    return () => clearTimeout(handle);
  }, [search]);

  const handleExport = async (format: "csv" | "json") => {
    const token = localStorage.getItem("token");
    if (!token) return;
    const res = await api.get(`/threat-intel/export`, {
      params: { format },
      headers: { Authorization: `Bearer ${token}` },
      responseType: "blob",
    });
    const url = window.URL.createObjectURL(new Blob([res.data]));
    const a = document.createElement("a");
    a.href = url;
    a.download = `threat-intel-export-${Date.now()}.${format}`;
    a.click();
    window.URL.revokeObjectURL(url);
  };

  const formatDate = (d: string) => new Date(d).toLocaleString();

  const iocTypeData = useMemo(
    () => (stats ? Object.entries(stats.byIocType).map(([name, value]) => ({ name, value })) : []),
    [stats]
  );

  const confidenceData = useMemo(
    () => (stats ? Object.entries(stats.confidenceBuckets).map(([name, value]) => ({ name, value })) : []),
    [stats]
  );

  const mitreData = useMemo(
    () => (stats ? Object.entries(stats.byMitreTechnique).map(([name, value]) => ({ name, value })).sort((a, b) => b.value - a.value).slice(0, 10) : []),
    [stats]
  );

  const timelineData = useMemo(
    () =>
      stats
        ? [...stats.timeline]
            .sort((a, b) => new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime())
            .map((t) => ({ date: new Date(t.createdAt).toLocaleDateString(), matches: t.iocMatchCount }))
        : [],
    [stats]
  );

  const feedRows = search.trim() && searchResults ? searchResults.scans : scans;

  const allYaraMatches = useMemo(
    () => scans.flatMap((s) => s.yaraMatches.map((m) => ({ ...m, filename: s.originalFilename, createdAt: s.createdAt, scanId: s._id }))),
    [scans]
  );

  const allMitreMatches = useMemo(
    () => scans.flatMap((s) => s.mitreMapping.map((m) => ({ ...m, filename: s.originalFilename, createdAt: s.createdAt, scanId: s._id }))),
    [scans]
  );

  const columns: DataTableColumn<ScanEntry>[] = [
    { key: "file", header: "File", render: (s) => <span className="max-w-[160px] truncate inline-block" title={s.originalFilename}>{s.originalFilename || "—"}</span> },
    { key: "severity", header: "Severity", render: (s) => <StatusBadge label={s.severity} tone={severityTone[s.severity] ?? "neutral"} /> },
    { key: "confidence", header: "Confidence", render: (s) => `${s.threatConfidence}%` },
    {
      key: "iocType",
      header: "IOC Type",
      render: (s) => (
        <span className="text-xs text-muted-foreground">{s.iocMatches.length > 0 ? [...new Set(s.iocMatches.map((m) => m.type))].join(", ") : "none"}</span>
      ),
    },
    {
      key: "description",
      header: "Description",
      render: (s) => (
        <span className="text-xs text-muted-foreground max-w-[220px] truncate inline-block">
          {s.iocMatches.map((m) => m.value).join(", ") || "—"}
        </span>
      ),
    },
    { key: "source", header: "Source", render: (s) => <span className="text-xs text-muted-foreground">{s.threatSources.join(", ") || "local"}</span> },
    { key: "scanned", header: "Timestamp", className: "whitespace-nowrap text-xs text-muted-foreground", render: (s) => formatDate(s.createdAt) },
  ];

  return (
    <div>
      <PageHeader
        icon={Crosshair}
        title="Threat Intelligence"
        description="IOC reputation, MITRE ATT&CK mapping, and YARA rule matches enriching every uploaded file."
        accent="purple"
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
      ) : (
        <div className="space-y-8">
          {stats && (
            <motion.div variants={staggerContainer} initial="hidden" animate="show" className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <StatCard label="Enrichment Scans" value={stats.totalScans} icon={Fingerprint} variant="primary" />
              <StatCard label="IOC Matches" value={stats.totalIocMatches} icon={Radar} variant="danger" />
              <StatCard label="YARA Matches" value={stats.yaraMatchCount} icon={FileCode2} variant="warning" />
              <StatCard label="MITRE Techniques Seen" value={Object.keys(stats.byMitreTechnique).length} icon={ShieldAlert} variant="purple" />
            </motion.div>
          )}

          <section>
            <div className="mb-4 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
              <h2 className="flex items-center gap-2 text-lg font-bold text-foreground">
                <Search size={18} className="text-primary" />
                IOC Search
              </h2>
              <div className="flex gap-2">
                <div className="relative">
                  <Search size={14} className="absolute left-3 top-2.5 text-muted-foreground" />
                  <input
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                    placeholder="Search hash, IP, domain, URL, filename, email, MITRE ID, or YARA rule..."
                    className="pl-8 pr-3 py-2 bg-card border border-border rounded-lg text-xs text-foreground placeholder-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/60 w-80"
                  />
                </div>
                <button onClick={() => handleExport("csv")} className="flex items-center gap-1.5 px-3 py-2 bg-card border border-border rounded-lg text-xs text-foreground hover:bg-muted">
                  <Download size={14} /> CSV
                </button>
                <button onClick={() => handleExport("json")} className="flex items-center gap-1.5 px-3 py-2 bg-card border border-border rounded-lg text-xs text-foreground hover:bg-muted">
                  <Download size={14} /> JSON
                </button>
              </div>
            </div>
          </section>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="rounded-xl border border-border bg-card p-6">
              <h3 className="flex items-center gap-2 text-sm font-semibold text-foreground mb-4">
                <BarChart3 size={16} className="text-purple-300" />
                Top IOC Types
              </h3>
              {iocTypeData.length === 0 ? (
                <p className="text-sm text-muted-foreground py-10 text-center">No IOC matches yet.</p>
              ) : (
                <ResponsiveContainer width="100%" height={220}>
                  <PieChart>
                    <Pie data={iocTypeData} dataKey="value" nameKey="name" innerRadius={50} outerRadius={80} paddingAngle={2}>
                      {iocTypeData.map((entry, i) => (
                        <Cell key={entry.name} fill={COLORS[i % COLORS.length]} />
                      ))}
                    </Pie>
                    <Tooltip contentStyle={{ background: "#0F172A", border: "1px solid rgba(148,163,184,0.2)", borderRadius: 8, fontSize: 12 }} />
                  </PieChart>
                </ResponsiveContainer>
              )}
            </div>

            <div className="rounded-xl border border-border bg-card p-6">
              <h3 className="text-sm font-semibold text-foreground mb-4">Confidence Distribution</h3>
              {confidenceData.every((d) => d.value === 0) ? (
                <p className="text-sm text-muted-foreground py-10 text-center">No confidence data yet.</p>
              ) : (
                <ResponsiveContainer width="100%" height={220}>
                  <BarChart data={confidenceData}>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.1)" />
                    <XAxis dataKey="name" stroke="#64748B" fontSize={11} tickLine={false} axisLine={false} />
                    <YAxis stroke="#64748B" fontSize={11} tickLine={false} axisLine={false} allowDecimals={false} />
                    <Tooltip contentStyle={{ background: "#0F172A", border: "1px solid rgba(148,163,184,0.2)", borderRadius: 8, fontSize: 12 }} />
                    <Bar dataKey="value" fill="#6366F1" radius={[4, 4, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              )}
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="rounded-xl border border-border bg-card p-6">
              <h3 className="text-sm font-semibold text-foreground mb-4">Threat Timeline</h3>
              {timelineData.length === 0 ? (
                <p className="text-sm text-muted-foreground py-10 text-center">No enrichment activity yet.</p>
              ) : (
                <ResponsiveContainer width="100%" height={220}>
                  <AreaChart data={timelineData}>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.1)" />
                    <XAxis dataKey="date" stroke="#64748B" fontSize={11} tickLine={false} axisLine={false} />
                    <YAxis stroke="#64748B" fontSize={11} tickLine={false} axisLine={false} allowDecimals={false} />
                    <Tooltip contentStyle={{ background: "#0F172A", border: "1px solid rgba(148,163,184,0.2)", borderRadius: 8, fontSize: 12 }} />
                    <Area type="monotone" dataKey="matches" stroke="#A855F7" fill="rgba(168,85,247,0.2)" />
                  </AreaChart>
                </ResponsiveContainer>
              )}
            </div>

            <div className="rounded-xl border border-border bg-card p-6">
              <h3 className="flex items-center gap-2 text-sm font-semibold text-foreground mb-4">
                <ShieldAlert size={16} className="text-warning" />
                MITRE ATT&CK Techniques
              </h3>
              {mitreData.length === 0 ? (
                <p className="text-sm text-muted-foreground py-10 text-center">No MITRE mappings yet.</p>
              ) : (
                <ResponsiveContainer width="100%" height={220}>
                  <BarChart data={mitreData} layout="vertical" margin={{ left: 8 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.1)" horizontal={false} />
                    <XAxis type="number" stroke="#64748B" fontSize={11} tickLine={false} axisLine={false} allowDecimals={false} />
                    <YAxis type="category" dataKey="name" stroke="#64748B" fontSize={11} tickLine={false} axisLine={false} width={60} />
                    <Tooltip contentStyle={{ background: "#0F172A", border: "1px solid rgba(148,163,184,0.2)", borderRadius: 8, fontSize: 12 }} />
                    <Bar dataKey="value" fill="#F59E0B" radius={[0, 4, 4, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              )}
            </div>
          </div>

          <section>
            <h2 className="flex items-center gap-2 text-lg font-bold text-foreground mb-4">
              <Globe size={20} className="text-primary" />
              MITRE ATT&CK Mapping
            </h2>
            {allMitreMatches.length === 0 ? (
              <EmptyState icon={Globe} title="No techniques mapped" description="No uploaded files have matched a MITRE ATT&CK technique yet." />
            ) : (
              <div className="flex flex-wrap gap-2">
                {allMitreMatches.slice(0, 30).map((m, i) => (
                  <span key={`${m.scanId}-${m.techniqueId}-${i}`} title={`${m.tactic} · ${m.filename || ""}`} className="text-[11px] font-medium rounded-full px-3 py-1 bg-muted text-foreground ring-1 ring-border">
                    {m.techniqueId} · {m.name}
                  </span>
                ))}
              </div>
            )}
          </section>

          <section>
            <h2 className="flex items-center gap-2 text-lg font-bold text-foreground mb-4">
              <FileCode2 size={20} className="text-warning" />
              YARA Matches
            </h2>
            {allYaraMatches.length === 0 ? (
              <EmptyState icon={FileCode2} title="No YARA matches" description="No uploaded files have matched a stored YARA rule yet." />
            ) : (
              <div className="space-y-2">
                {allYaraMatches.map((m, i) => (
                  <div key={`${m.scanId}-${i}`} className="rounded-xl border border-warning/30 bg-warning/5 px-4 py-3 flex items-center justify-between gap-2">
                    <div>
                      <p className="text-foreground text-sm font-semibold">{m.ruleName}</p>
                      <p className="text-muted-foreground text-xs mt-0.5">{m.filename || "—"} · {formatDate(m.createdAt)}</p>
                    </div>
                    <StatusBadge label={m.severity} tone={severityTone[m.severity] ?? "neutral"} />
                  </div>
                ))}
              </div>
            )}
          </section>

          <section>
            <h2 className="flex items-center gap-2 text-lg font-bold text-foreground mb-4">
              <Radar size={20} className="text-primary" />
              Threat Feed
            </h2>
            <DataTable columns={columns} rows={feedRows} rowKey={(s) => s._id} emptyLabel="No threat intelligence matches yet - files are enriched automatically after upload." />
          </section>
        </div>
      )}
    </div>
  );
}
