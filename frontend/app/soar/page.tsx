"use client";

import { useEffect, useState, useCallback, useMemo, useRef } from "react";
import { useRouter } from "next/navigation";
import api from "@/lib/api";
import { getIsAdminFromToken } from "@/lib/auth";
import {
  Bot,
  Zap,
  BookOpen,
  Activity,
  AlertCircle,
  Trash2,
  Copy,
  Download,
  Upload,
  Plus,
  Power,
  Timer,
  ShieldCheck,
} from "lucide-react";
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, AreaChart, Area } from "recharts";
import { motion } from "framer-motion";
import toast from "react-hot-toast";
import PageHeader from "@/components/design/PageHeader";
import StatCard from "@/components/design/StatCard";
import StatusBadge from "@/components/design/StatusBadge";
import EmptyState from "@/components/design/EmptyState";
import DataTable, { type DataTableColumn } from "@/components/design/DataTable";
import EventTimeline, { type EventTimelineItem } from "@/components/design/EventTimeline";
import { StatsSkeleton, TableSkeleton } from "@/components/design/Skeletons";
import { apiErrorStatus } from "@/lib/errors";
import { staggerContainer } from "@/lib/motion";

type Rule = {
  _id: string;
  name: string;
  description?: string;
  trigger: string;
  enabled: boolean;
  priority: number;
  playbookId?: string | null;
  actions: { type: string }[];
};

type Playbook = {
  _id: string;
  name: string;
  description?: string;
  category: string;
  steps: { type: string; params?: Record<string, unknown> }[];
  enabled: boolean;
};

type Execution = {
  _id: string;
  ruleName: string;
  playbookName?: string | null;
  trigger: string;
  status: "completed" | "partial" | "failed";
  durationMs: number;
  result: string;
  incident?: string | null;
  createdAt: string;
};

type Stats = {
  totalExecutions: number;
  byStatus: Record<string, number>;
  successRate: number;
  avgResponseTimeMs: number;
  topRules: Record<string, number>;
  topPlaybooks: Record<string, number>;
  actionDistribution: Record<string, number>;
  timeline: { createdAt: string; status: string; durationMs: number }[];
  rulesCount: number;
  playbooksCount: number;
};

const STATUS_TONE: Record<string, "success" | "warning" | "danger"> = { completed: "success", partial: "warning", failed: "danger" };
const COLORS = ["#A855F7", "#6366F1", "#F59E0B", "#EF4444", "#10B981", "#0EA5E9"];

export default function SoarPage() {
  const router = useRouter();
  const importInputRef = useRef<HTMLInputElement>(null);

  const [isAdmin, setIsAdmin] = useState(false);
  const [rules, setRules] = useState<Rule[]>([]);
  const [playbooks, setPlaybooks] = useState<Playbook[]>([]);
  const [executions, setExecutions] = useState<Execution[]>([]);
  const [stats, setStats] = useState<Stats | null>(null);
  const [actionTypes, setActionTypes] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const [newRule, setNewRule] = useState({ name: "", trigger: "THREAT_FOUND", playbookId: "", priority: 100 });
  const [newPlaybook, setNewPlaybook] = useState({ name: "", category: "General", description: "", stepsJson: "[]" });

  const fetchAll = useCallback(
    async (token: string) => {
      try {
        setLoading(true);
        const [rulesRes, playbooksRes, execRes, statsRes, actionsRes] = await Promise.all([
          api.get<Rule[]>("/soar/rules", { headers: { Authorization: `Bearer ${token}` } }),
          api.get<Playbook[]>("/soar/playbooks", { headers: { Authorization: `Bearer ${token}` } }),
          api.get<Execution[]>("/soar/executions", { headers: { Authorization: `Bearer ${token}` } }),
          api.get<Stats>("/soar/stats", { headers: { Authorization: `Bearer ${token}` } }),
          api.get<string[]>("/soar/action-types", { headers: { Authorization: `Bearer ${token}` } }),
        ]);
        setRules(rulesRes.data || []);
        setPlaybooks(playbooksRes.data || []);
        setExecutions(execRes.data || []);
        setStats(statsRes.data || null);
        setActionTypes(actionsRes.data || []);
      } catch (err: unknown) {
        const status = apiErrorStatus(err);
        if (status === 401 || status === 403) {
          router.push("/login");
          return;
        }
        setError("Failed to load SOAR data");
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
    setIsAdmin(getIsAdminFromToken(token));
    fetchAll(token);
  }, [fetchAll, router]);

  const authHeader = () => ({ headers: { Authorization: `Bearer ${localStorage.getItem("token")}` } });

  const toggleRule = async (rule: Rule) => {
    try {
      await api.patch(`/soar/rules/${rule._id}/enabled`, { enabled: !rule.enabled }, authHeader());
      setRules((prev) => prev.map((r) => (r._id === rule._id ? { ...r, enabled: !r.enabled } : r)));
    } catch {
      toast.error("Failed to update rule");
    }
  };

  const deleteRule = async (id: string) => {
    try {
      await api.delete(`/soar/rules/${id}`, authHeader());
      setRules((prev) => prev.filter((r) => r._id !== id));
      toast.success("Rule deleted");
    } catch {
      toast.error("Failed to delete rule");
    }
  };

  const createRule = async () => {
    if (!newRule.name.trim()) return toast.error("Rule name is required");
    try {
      const res = await api.post(
        "/soar/rules",
        { name: newRule.name, trigger: newRule.trigger, playbookId: newRule.playbookId || null, priority: newRule.priority },
        authHeader()
      );
      setRules((prev) => [...prev, res.data]);
      setNewRule({ name: "", trigger: "THREAT_FOUND", playbookId: "", priority: 100 });
      toast.success("Rule created");
    } catch {
      toast.error("Failed to create rule");
    }
  };

  const clonePlaybook = async (id: string) => {
    try {
      const res = await api.post(`/soar/playbooks/${id}/clone`, {}, authHeader());
      setPlaybooks((prev) => [res.data, ...prev]);
      toast.success("Playbook cloned");
    } catch {
      toast.error("Failed to clone playbook");
    }
  };

  const deletePlaybook = async (id: string) => {
    try {
      await api.delete(`/soar/playbooks/${id}`, authHeader());
      setPlaybooks((prev) => prev.filter((p) => p._id !== id));
      toast.success("Playbook deleted");
    } catch {
      toast.error("Failed to delete playbook");
    }
  };

  const exportPlaybook = async (playbook: Playbook) => {
    const token = localStorage.getItem("token");
    const res = await api.get(`/soar/playbooks/${playbook._id}/export`, {
      headers: { Authorization: `Bearer ${token}` },
      responseType: "blob",
    });
    const url = window.URL.createObjectURL(new Blob([res.data]));
    const a = document.createElement("a");
    a.href = url;
    a.download = `playbook-${playbook.name.replace(/\W+/g, "-")}.json`;
    a.click();
    window.URL.revokeObjectURL(url);
  };

  const createPlaybook = async () => {
    if (!newPlaybook.name.trim()) return toast.error("Playbook name is required");
    let steps;
    try {
      steps = JSON.parse(newPlaybook.stepsJson);
      if (!Array.isArray(steps)) throw new Error();
    } catch {
      return toast.error('Steps must be valid JSON, e.g. [{"type":"quarantineFile"}]');
    }
    try {
      const res = await api.post(
        "/soar/playbooks",
        { name: newPlaybook.name, category: newPlaybook.category, description: newPlaybook.description, steps },
        authHeader()
      );
      setPlaybooks((prev) => [res.data, ...prev]);
      setNewPlaybook({ name: "", category: "General", description: "", stepsJson: "[]" });
      toast.success("Playbook created");
    } catch (err: unknown) {
      const status = apiErrorStatus(err);
      toast.error(status === 409 ? "A playbook with this name already exists" : "Failed to create playbook");
    }
  };

  const handleImportFile = async (file: File) => {
    try {
      const text = await file.text();
      const parsed = JSON.parse(text);
      const res = await api.post("/soar/playbooks/import", parsed, authHeader());
      setPlaybooks((prev) => [res.data, ...prev]);
      toast.success("Playbook imported");
    } catch {
      toast.error("Failed to import playbook - check the file is valid JSON");
    }
  };

  const handleExport = async (format: "csv" | "json") => {
    const token = localStorage.getItem("token");
    const res = await api.get(`/soar/export`, {
      params: { format },
      headers: { Authorization: `Bearer ${token}` },
      responseType: "blob",
    });
    const url = window.URL.createObjectURL(new Blob([res.data]));
    const a = document.createElement("a");
    a.href = url;
    a.download = `soar-export-${Date.now()}.${format}`;
    a.click();
    window.URL.revokeObjectURL(url);
  };

  const formatDate = (d: string) => new Date(d).toLocaleString();
  const formatMs = (ms: number) => (ms < 1000 ? `${ms}ms` : `${(ms / 1000).toFixed(1)}s`);

  const failedExecutions = useMemo(() => executions.filter((e) => e.status === "failed"), [executions]);

  const executionTimeline: EventTimelineItem[] = useMemo(
    () =>
      executions.slice(0, 15).map((e) => ({
        key: e._id,
        icon: e.status === "failed" ? AlertCircle : Zap,
        title: `${e.ruleName}${e.playbookName ? ` → ${e.playbookName}` : ""}`,
        description: `${e.trigger} · ${e.result} · ${formatMs(e.durationMs)}`,
        timestamp: e.createdAt,
        tone: e.status === "completed" ? "success" : e.status === "partial" ? "warning" : "danger",
        badgeLabel: e.status,
      })),
    [executions]
  );

  const statusData = stats
    ? Object.entries(stats.byStatus).filter(([, v]) => v > 0).map(([name, value]) => ({ name, value }))
    : [];
  const topRulesData = stats ? Object.entries(stats.topRules).map(([name, value]) => ({ name, value })).sort((a, b) => b.value - a.value).slice(0, 8) : [];
  const topPlaybooksData = stats ? Object.entries(stats.topPlaybooks).map(([name, value]) => ({ name, value })).sort((a, b) => b.value - a.value).slice(0, 8) : [];
  const actionData = stats ? Object.entries(stats.actionDistribution).map(([name, value]) => ({ name, value })) : [];
  const frequencyData = useMemo(
    () =>
      stats
        ? [...stats.timeline]
            .sort((a, b) => new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime())
            .reduce<{ date: string; count: number }[]>((acc, t) => {
              const date = new Date(t.createdAt).toLocaleDateString();
              const last = acc[acc.length - 1];
              if (last && last.date === date) last.count++;
              else acc.push({ date, count: 1 });
              return acc;
            }, [])
        : [],
    [stats]
  );

  const ruleColumns: DataTableColumn<Rule>[] = [
    { key: "name", header: "Name", render: (r) => <span className="font-medium">{r.name}</span> },
    { key: "trigger", header: "Trigger", render: (r) => <span className="text-xs text-muted-foreground">{r.trigger}</span> },
    { key: "priority", header: "Priority", render: (r) => r.priority },
    { key: "enabled", header: "Status", render: (r) => <StatusBadge label={r.enabled ? "Enabled" : "Disabled"} tone={r.enabled ? "success" : "neutral"} /> },
    {
      key: "actions",
      header: "Actions",
      render: (r) =>
        isAdmin ? (
          <div className="flex items-center gap-2">
            <button onClick={() => toggleRule(r)} title="Enable/disable" aria-label={`${r.enabled ? "Disable" : "Enable"} rule ${r.name}`} className="p-1.5 rounded hover:bg-muted text-muted-foreground hover:text-foreground">
              <Power size={14} />
            </button>
            <button onClick={() => deleteRule(r._id)} title="Delete" aria-label={`Delete rule ${r.name}`} className="p-1.5 rounded hover:bg-destructive/10 text-muted-foreground hover:text-destructive">
              <Trash2 size={14} />
            </button>
          </div>
        ) : (
          <span className="text-xs text-muted-foreground">—</span>
        ),
    },
  ];

  const playbookColumns: DataTableColumn<Playbook>[] = [
    { key: "name", header: "Name", render: (p) => <span className="font-medium">{p.name}</span> },
    { key: "category", header: "Category", render: (p) => <span className="text-xs text-muted-foreground">{p.category}</span> },
    { key: "steps", header: "Steps", render: (p) => p.steps.length },
    { key: "status", header: "Status", render: (p) => <StatusBadge label={p.enabled ? "Enabled" : "Disabled"} tone={p.enabled ? "success" : "neutral"} /> },
    {
      key: "actions",
      header: "Actions",
      render: (p) => (
        <div className="flex items-center gap-2">
          <button onClick={() => exportPlaybook(p)} title="Export" aria-label={`Export playbook ${p.name}`} className="p-1.5 rounded hover:bg-muted text-muted-foreground hover:text-foreground">
            <Download size={14} />
          </button>
          {isAdmin && (
            <>
              <button onClick={() => clonePlaybook(p._id)} title="Clone" aria-label={`Clone playbook ${p.name}`} className="p-1.5 rounded hover:bg-muted text-muted-foreground hover:text-foreground">
                <Copy size={14} />
              </button>
              <button onClick={() => deletePlaybook(p._id)} title="Delete" aria-label={`Delete playbook ${p.name}`} className="p-1.5 rounded hover:bg-destructive/10 text-muted-foreground hover:text-destructive">
                <Trash2 size={14} />
              </button>
            </>
          )}
        </div>
      ),
    },
  ];

  return (
    <div>
      <PageHeader icon={Bot} title="SOAR" description="Security Orchestration, Automation & Response - automation rules, playbooks, and execution history." accent="purple" />

      {error && (
        <div className="mb-6 p-4 bg-destructive/10 border border-destructive/30 rounded-lg flex items-center gap-2">
          <AlertCircle className="text-destructive" size={18} />
          <p className="text-destructive text-sm">{error}</p>
        </div>
      )}

      {!isAdmin && (
        <div className="mb-6 p-3 bg-muted/50 border border-border rounded-lg flex items-center gap-2 text-xs text-muted-foreground">
          <ShieldCheck size={14} />
          Viewing automation affecting your own files. Rule and playbook management is admin-only.
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
              <StatCard label="Automation Rules" value={stats.rulesCount} icon={Zap} variant="primary" />
              <StatCard label="Playbooks" value={stats.playbooksCount} icon={BookOpen} variant="purple" />
              <StatCard label="Executions" value={stats.totalExecutions} icon={Activity} variant="muted" />
              <StatCard label="Success Rate" value={`${stats.successRate}%`} icon={ShieldCheck} variant={stats.successRate >= 80 ? "success" : "warning"} />
            </motion.div>
          )}

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="rounded-xl border border-border bg-card p-6">
              <h3 className="text-sm font-semibold text-foreground mb-4">Automation Success Rate</h3>
              {statusData.length === 0 ? (
                <p className="text-sm text-muted-foreground py-10 text-center">No executions yet.</p>
              ) : (
                <ResponsiveContainer width="100%" height={200}>
                  <PieChart>
                    <Pie data={statusData} dataKey="value" nameKey="name" innerRadius={45} outerRadius={75} paddingAngle={2}>
                      {statusData.map((entry) => (
                        <Cell key={entry.name} fill={entry.name === "completed" ? "#10B981" : entry.name === "partial" ? "#F59E0B" : "#EF4444"} />
                      ))}
                    </Pie>
                    <Tooltip contentStyle={{ background: "#0F172A", border: "1px solid rgba(148,163,184,0.2)", borderRadius: 8, fontSize: 12 }} />
                  </PieChart>
                </ResponsiveContainer>
              )}
            </div>

            <div className="rounded-xl border border-border bg-card p-6 flex flex-col items-center justify-center">
              <Timer size={28} className="text-primary mb-2" />
              <p className="text-3xl font-bold text-foreground">{stats ? formatMs(stats.avgResponseTimeMs) : "—"}</p>
              <p className="text-xs text-muted-foreground mt-1 uppercase tracking-wide">Average Response Time</p>
            </div>

            <div className="rounded-xl border border-border bg-card p-6">
              <h3 className="text-sm font-semibold text-foreground mb-4">Action Distribution</h3>
              {actionData.length === 0 ? (
                <p className="text-sm text-muted-foreground py-10 text-center">No actions executed yet.</p>
              ) : (
                <ResponsiveContainer width="100%" height={200}>
                  <PieChart>
                    <Pie data={actionData} dataKey="value" nameKey="name" innerRadius={45} outerRadius={75} paddingAngle={2}>
                      {actionData.map((entry, i) => (
                        <Cell key={entry.name} fill={COLORS[i % COLORS.length]} />
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
              <h3 className="text-sm font-semibold text-foreground mb-4">Top Triggered Rules</h3>
              {topRulesData.length === 0 ? (
                <p className="text-sm text-muted-foreground py-10 text-center">No rule executions yet.</p>
              ) : (
                <ResponsiveContainer width="100%" height={220}>
                  <BarChart data={topRulesData} layout="vertical" margin={{ left: 8 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.1)" horizontal={false} />
                    <XAxis type="number" stroke="#64748B" fontSize={11} tickLine={false} axisLine={false} allowDecimals={false} />
                    <YAxis type="category" dataKey="name" stroke="#64748B" fontSize={11} tickLine={false} axisLine={false} width={130} />
                    <Tooltip contentStyle={{ background: "#0F172A", border: "1px solid rgba(148,163,184,0.2)", borderRadius: 8, fontSize: 12 }} />
                    <Bar dataKey="value" fill="#A855F7" radius={[0, 4, 4, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              )}
            </div>

            <div className="rounded-xl border border-border bg-card p-6">
              <h3 className="text-sm font-semibold text-foreground mb-4">Top Playbooks</h3>
              {topPlaybooksData.length === 0 ? (
                <p className="text-sm text-muted-foreground py-10 text-center">No playbook executions yet.</p>
              ) : (
                <ResponsiveContainer width="100%" height={220}>
                  <BarChart data={topPlaybooksData} layout="vertical" margin={{ left: 8 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.1)" horizontal={false} />
                    <XAxis type="number" stroke="#64748B" fontSize={11} tickLine={false} axisLine={false} allowDecimals={false} />
                    <YAxis type="category" dataKey="name" stroke="#64748B" fontSize={11} tickLine={false} axisLine={false} width={130} />
                    <Tooltip contentStyle={{ background: "#0F172A", border: "1px solid rgba(148,163,184,0.2)", borderRadius: 8, fontSize: 12 }} />
                    <Bar dataKey="value" fill="#6366F1" radius={[0, 4, 4, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              )}
            </div>
          </div>

          <div className="rounded-xl border border-border bg-card p-6">
            <h3 className="text-sm font-semibold text-foreground mb-4">Automation Frequency</h3>
            {frequencyData.length === 0 ? (
              <p className="text-sm text-muted-foreground py-10 text-center">No automation activity yet.</p>
            ) : (
              <ResponsiveContainer width="100%" height={200}>
                <AreaChart data={frequencyData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.1)" />
                  <XAxis dataKey="date" stroke="#64748B" fontSize={11} tickLine={false} axisLine={false} />
                  <YAxis stroke="#64748B" fontSize={11} tickLine={false} axisLine={false} allowDecimals={false} />
                  <Tooltip contentStyle={{ background: "#0F172A", border: "1px solid rgba(148,163,184,0.2)", borderRadius: 8, fontSize: 12 }} />
                  <Area type="monotone" dataKey="count" stroke="#A855F7" fill="rgba(168,85,247,0.2)" />
                </AreaChart>
              </ResponsiveContainer>
            )}
          </div>

          <section>
            <div className="mb-4 flex items-center justify-between gap-3">
              <h2 className="flex items-center gap-2 text-lg font-bold text-foreground">
                <Zap size={20} className="text-primary" />
                Automation Rules
              </h2>
              <div className="flex gap-2">
                <button onClick={() => handleExport("csv")} className="flex items-center gap-1.5 px-3 py-2 bg-card border border-border rounded-lg text-xs text-foreground hover:bg-muted">
                  <Download size={14} /> CSV
                </button>
                <button onClick={() => handleExport("json")} className="flex items-center gap-1.5 px-3 py-2 bg-card border border-border rounded-lg text-xs text-foreground hover:bg-muted">
                  <Download size={14} /> JSON
                </button>
              </div>
            </div>
            <DataTable columns={ruleColumns} rows={rules} rowKey={(r) => r._id} emptyLabel="No automation rules configured." />

            {isAdmin && (
              <div className="mt-4 rounded-xl border border-border bg-card p-4 flex flex-wrap items-end gap-3">
                <div className="flex flex-col gap-1">
                  <label className="text-[11px] text-muted-foreground uppercase tracking-wide">Name</label>
                  <input value={newRule.name} onChange={(e) => setNewRule({ ...newRule, name: e.target.value })} className="px-3 py-2 bg-background border border-border rounded-lg text-xs w-48" />
                </div>
                <div className="flex flex-col gap-1">
                  <label className="text-[11px] text-muted-foreground uppercase tracking-wide">Trigger</label>
                  <select value={newRule.trigger} onChange={(e) => setNewRule({ ...newRule, trigger: e.target.value })} className="px-3 py-2 bg-background border border-border rounded-lg text-xs">
                    {["THREAT_FOUND", "IOC_MATCH", "DLP_BLOCK", "SIGNATURE_FAILED", "SESSION_COMPROMISED", "NEW_DEVICE", "MULTIPLE_FAILED_LOGINS", "YARA_MATCH", "MITRE_CRITICAL"].map((t) => (
                      <option key={t} value={t}>{t}</option>
                    ))}
                  </select>
                </div>
                <div className="flex flex-col gap-1">
                  <label className="text-[11px] text-muted-foreground uppercase tracking-wide">Playbook</label>
                  <select value={newRule.playbookId} onChange={(e) => setNewRule({ ...newRule, playbookId: e.target.value })} className="px-3 py-2 bg-background border border-border rounded-lg text-xs">
                    <option value="">None (inline actions via API)</option>
                    {playbooks.map((p) => (
                      <option key={p._id} value={p._id}>{p.name}</option>
                    ))}
                  </select>
                </div>
                <div className="flex flex-col gap-1">
                  <label className="text-[11px] text-muted-foreground uppercase tracking-wide">Priority</label>
                  <input type="number" value={newRule.priority} onChange={(e) => setNewRule({ ...newRule, priority: Number(e.target.value) })} className="px-3 py-2 bg-background border border-border rounded-lg text-xs w-20" />
                </div>
                <button onClick={createRule} className="flex items-center gap-1.5 px-3 py-2 bg-primary text-primary-foreground rounded-lg text-xs font-semibold">
                  <Plus size={14} /> Create Rule
                </button>
              </div>
            )}
          </section>

          <section>
            <div className="mb-4 flex items-center justify-between gap-3">
              <h2 className="flex items-center gap-2 text-lg font-bold text-foreground">
                <BookOpen size={20} className="text-primary" />
                Playbooks
              </h2>
              {isAdmin && (
                <>
                  <input ref={importInputRef} type="file" accept="application/json" className="hidden" onChange={(e) => e.target.files?.[0] && handleImportFile(e.target.files[0])} />
                  <button onClick={() => importInputRef.current?.click()} className="flex items-center gap-1.5 px-3 py-2 bg-card border border-border rounded-lg text-xs text-foreground hover:bg-muted">
                    <Upload size={14} /> Import
                  </button>
                </>
              )}
            </div>
            <DataTable columns={playbookColumns} rows={playbooks} rowKey={(p) => p._id} emptyLabel="No playbooks configured." />

            {isAdmin && (
              <div className="mt-4 rounded-xl border border-border bg-card p-4 space-y-3">
                <div className="flex flex-wrap gap-3">
                  <input placeholder="Name" value={newPlaybook.name} onChange={(e) => setNewPlaybook({ ...newPlaybook, name: e.target.value })} className="px-3 py-2 bg-background border border-border rounded-lg text-xs w-48" />
                  <input placeholder="Category" value={newPlaybook.category} onChange={(e) => setNewPlaybook({ ...newPlaybook, category: e.target.value })} className="px-3 py-2 bg-background border border-border rounded-lg text-xs w-40" />
                  <input placeholder="Description" value={newPlaybook.description} onChange={(e) => setNewPlaybook({ ...newPlaybook, description: e.target.value })} className="px-3 py-2 bg-background border border-border rounded-lg text-xs flex-1 min-w-[200px]" />
                </div>
                <div>
                  <label className="text-[11px] text-muted-foreground uppercase tracking-wide">Steps (JSON array)</label>
                  <textarea
                    value={newPlaybook.stepsJson}
                    onChange={(e) => setNewPlaybook({ ...newPlaybook, stepsJson: e.target.value })}
                    placeholder={`[{"type":"quarantineFile"},{"type":"notifyUser","params":{"title":"Alert"}}]`}
                    className="mt-1 w-full h-20 px-3 py-2 bg-background border border-border rounded-lg text-xs font-mono"
                  />
                  <p className="text-[11px] text-muted-foreground mt-1">Available action types: {actionTypes.join(", ")}</p>
                </div>
                <button onClick={createPlaybook} className="flex items-center gap-1.5 px-3 py-2 bg-primary text-primary-foreground rounded-lg text-xs font-semibold">
                  <Plus size={14} /> Create Playbook
                </button>
              </div>
            )}
          </section>

          <section>
            <h2 className="flex items-center gap-2 text-lg font-bold text-foreground mb-4">
              <Activity size={20} className="text-primary" />
              Recent Executions
            </h2>
            <div className="rounded-xl border border-border bg-card p-5">
              <EventTimeline items={executionTimeline} emptyLabel="No automation has run yet." />
            </div>
          </section>

          <section>
            <h2 className="flex items-center gap-2 text-lg font-bold text-foreground mb-4">
              <AlertCircle size={20} className="text-destructive" />
              Failed Executions
            </h2>
            {failedExecutions.length === 0 ? (
              <EmptyState icon={ShieldCheck} title="No failures" description="Every automation execution has completed successfully." />
            ) : (
              <div className="space-y-2">
                {failedExecutions.map((e) => (
                  <div key={e._id} className="rounded-xl border border-destructive/30 bg-destructive/5 px-4 py-3 flex items-center justify-between gap-2">
                    <div>
                      <p className="text-foreground text-sm font-semibold">{e.ruleName}{e.playbookName ? ` → ${e.playbookName}` : ""}</p>
                      <p className="text-muted-foreground text-xs mt-0.5">{e.result} · {formatDate(e.createdAt)}</p>
                    </div>
                    <StatusBadge label="Failed" tone={STATUS_TONE[e.status] ?? "danger"} />
                  </div>
                ))}
              </div>
            )}
          </section>
        </div>
      )}
    </div>
  );
}
