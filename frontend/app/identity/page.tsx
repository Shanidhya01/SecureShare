"use client";

import { useEffect, useState, useCallback, useMemo } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import Image from "next/image";
import api from "@/lib/api";
import { useRole } from "@/hooks/useRole";
import { AdminOnly } from "@/components/rbac/RoleGuard";
import { registerPasskey } from "@/lib/webauthn";
import {
  Fingerprint,
  ShieldCheck,
  Smartphone,
  KeyRound,
  Users,
  SlidersHorizontal,
  History,
  AlertCircle,
  Trash2,
  Plus,
  Copy,
  Check,
  ArrowUpRight,
  BarChart3,
} from "lucide-react";
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, CartesianGrid, AreaChart, Area } from "recharts";
import toast from "react-hot-toast";
import PageHeader from "@/components/design/PageHeader";
import StatusBadge from "@/components/design/StatusBadge";
import EmptyState from "@/components/design/EmptyState";
import DataTable, { type DataTableColumn } from "@/components/design/DataTable";
import EventTimeline, { type EventTimelineItem } from "@/components/design/EventTimeline";
import StatCard from "@/components/design/StatCard";
import { StatsSkeleton, TableSkeleton } from "@/components/design/Skeletons";
import { apiErrorStatus, apiErrorMessage } from "@/lib/errors";

type Device = { deviceId: string; label?: string; browser?: string; operatingSystem?: string; lastSeenAt: string; lastIp?: string; trusted: boolean; isCurrent: boolean; mfaTrustedUntil?: string | null };
type Session = { sessionId: string; deviceId?: string; browser?: string; operatingSystem?: string; ip?: string; country?: string; createdAt: string; lastActiveAt: string; isCurrent: boolean };
type Passkey = { _id: string; label: string; deviceType?: string; createdAt: string; lastUsedAt?: string | null };
type Policy = {
  requireMFA: boolean;
  passwordExpiryDays: number;
  sessionTimeoutMinutes: number;
  maxSessions: number;
  allowedCountries: string[];
  blockUntrustedDevices: boolean;
  allowedDeviceIds: string[];
  minPasswordLength: number;
  requirePasswordComplexity: boolean;
};
type UserRow = { _id: string; name: string; email: string; role: string; isAdmin: boolean };
type LoginEvent = { _id: string; type: string; message: string; ip?: string; country?: string; createdAt: string };
type IdentityStats = {
  totalLogins: number;
  byRiskLevel: Record<string, number>;
  mfaUsage: { withMfaOrPasskey: number; passwordOnly: number };
  byCountry: Record<string, number>;
  byDevice: Record<string, number>;
  failedLoginsTotal: number;
  failedLoginsByDay: Record<string, number>;
};

const ROLES = ["user", "moderator", "security_analyst", "administrator", "org_owner"];
const RISK_COLORS: Record<string, string> = { Low: "#10B981", Medium: "#F59E0B", High: "#F97316", Critical: "#EF4444" };
const CHART_COLORS = ["#A855F7", "#6366F1", "#F59E0B", "#EF4444", "#10B981", "#0EA5E9"];

export default function IdentityPage() {
  const router = useRouter();
  const { ready, isAdmin, isOrgOwner } = useRole();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const [mfaEnabled, setMfaEnabled] = useState(false);
  const [mfaSetup, setMfaSetup] = useState<{ qrCodeDataUrl: string; secret: string } | null>(null);
  const [mfaCode, setMfaCode] = useState("");
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null);
  const [disablePassword, setDisablePassword] = useState("");
  const [copied, setCopied] = useState(false);

  const [devices, setDevices] = useState<Device[]>([]);
  const [sessions, setSessions] = useState<Session[]>([]);
  const [passkeys, setPasskeys] = useState<Passkey[]>([]);
  const [policy, setPolicy] = useState<Policy | null>(null);
  const [users, setUsers] = useState<UserRow[]>([]);
  const [loginHistory, setLoginHistory] = useState<LoginEvent[]>([]);
  const [stats, setStats] = useState<IdentityStats | null>(null);

  const authHeader = () => ({ headers: { Authorization: `Bearer ${localStorage.getItem("token")}` } });

  const fetchAll = useCallback(async (token: string, admin: boolean) => {
    try {
      setLoading(true);

      const requests: Promise<unknown>[] = [
        api.get("/mfa/status", { headers: { Authorization: `Bearer ${token}` } }),
        api.get("/devices", { headers: { Authorization: `Bearer ${token}` } }),
        api.get("/sessions", { headers: { Authorization: `Bearer ${token}` } }),
        api.get("/passkeys", { headers: { Authorization: `Bearer ${token}` } }),
        api.get("/iam/policy", { headers: { Authorization: `Bearer ${token}` } }),
        api.get("/iam/login-history", { headers: { Authorization: `Bearer ${token}` } }),
        api.get("/iam/stats", { headers: { Authorization: `Bearer ${token}` } }),
      ];
      const [mfaRes, devicesRes, sessionsRes, passkeysRes, policyRes, historyRes, statsRes] = await Promise.all(requests);

      setMfaEnabled((mfaRes as { data: { enabled: boolean } }).data.enabled);
      setDevices((devicesRes as { data: Device[] }).data || []);
      setSessions((sessionsRes as { data: Session[] }).data || []);
      setPasskeys((passkeysRes as { data: Passkey[] }).data || []);
      setPolicy((policyRes as { data: Policy }).data);
      setLoginHistory((historyRes as { data: LoginEvent[] }).data || []);
      setStats((statsRes as { data: IdentityStats }).data || null);

      if (admin) {
        const usersRes = await api.get("/iam/users", { headers: { Authorization: `Bearer ${token}` } });
        setUsers(usersRes.data || []);
      }
    } catch (err: unknown) {
      const status = apiErrorStatus(err);
      if (status === 401 || status === 403) {
        router.push("/login");
        return;
      }
      setError("Failed to load identity data");
    } finally {
      setLoading(false);
    }
  }, [router]);

  useEffect(() => {
    if (!ready) return;
    const token = localStorage.getItem("token");
    if (!token) {
      router.push("/login");
      return;
    }
    fetchAll(token, isAdmin);
  }, [fetchAll, router, ready, isAdmin]);

  const startMfaSetup = async () => {
    try {
      const res = await api.post("/mfa/setup", {}, authHeader());
      setMfaSetup(res.data);
    } catch (err: unknown) {
      toast.error(apiErrorMessage(err, "Failed to start MFA setup"));
    }
  };

  const confirmMfaSetup = async () => {
    try {
      const res = await api.post("/mfa/verify", { token: mfaCode }, authHeader());
      setRecoveryCodes(res.data.recoveryCodes);
      setMfaEnabled(true);
      setMfaSetup(null);
      setMfaCode("");
      toast.success("MFA enabled");
    } catch (err: unknown) {
      toast.error(apiErrorMessage(err, "Invalid code"));
    }
  };

  const disableMfa = async () => {
    try {
      await api.post("/mfa/disable", { password: disablePassword }, authHeader());
      setMfaEnabled(false);
      setDisablePassword("");
      toast.success("MFA disabled");
    } catch (err: unknown) {
      toast.error(apiErrorMessage(err, "Incorrect password"));
    }
  };

  const regenerateCodes = async () => {
    try {
      const res = await api.post("/mfa/recovery/regenerate", {}, authHeader());
      setRecoveryCodes(res.data.recoveryCodes);
    } catch (err: unknown) {
      toast.error(apiErrorMessage(err, "Failed to regenerate codes"));
    }
  };

  const revokeDevice = async (deviceId: string) => {
    try {
      await api.delete(`/devices/${deviceId}`, authHeader());
      setDevices((prev) => prev.filter((d) => d.deviceId !== deviceId));
      toast.success("Device revoked");
    } catch {
      toast.error("Failed to revoke device");
    }
  };

  const revokeSession = async (sessionId: string) => {
    try {
      await api.delete(`/sessions/${sessionId}`, authHeader());
      setSessions((prev) => prev.filter((s) => s.sessionId !== sessionId));
      toast.success("Session revoked");
    } catch {
      toast.error("Failed to revoke session");
    }
  };

  const addPasskey = async () => {
    const token = localStorage.getItem("token");
    if (!token) return;
    try {
      const label = window.prompt("Name this passkey (e.g. \"MacBook Touch ID\")", "Passkey") || "Passkey";
      await registerPasskey(token, label);
      const res = await api.get("/passkeys", authHeader());
      setPasskeys(res.data || []);
      toast.success("Passkey registered");
    } catch (err: unknown) {
      toast.error(apiErrorMessage(err, "Failed to register passkey"));
    }
  };

  const removePasskey = async (id: string) => {
    try {
      await api.delete(`/passkeys/${id}`, authHeader());
      setPasskeys((prev) => prev.filter((p) => p._id !== id));
      toast.success("Passkey removed");
    } catch {
      toast.error("Failed to remove passkey");
    }
  };

  const savePolicy = async () => {
    if (!policy) return;
    try {
      const res = await api.put("/iam/policy", policy, authHeader());
      setPolicy(res.data);
      toast.success("Policy updated");
    } catch (err: unknown) {
      toast.error(apiErrorMessage(err, "Failed to update policy"));
    }
  };

  const updateRole = async (userId: string, role: string) => {
    try {
      await api.patch(`/iam/users/${userId}/role`, { role }, authHeader());
      setUsers((prev) => prev.map((u) => (u._id === userId ? { ...u, role } : u)));
      toast.success("Role updated");
    } catch (err: unknown) {
      toast.error(apiErrorMessage(err, "Failed to update role"));
    }
  };

  const copyRecoveryCodes = () => {
    if (!recoveryCodes) return;
    navigator.clipboard.writeText(recoveryCodes.join("\n"));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const formatDate = (d: string) => new Date(d).toLocaleString();

  const deviceColumns: DataTableColumn<Device>[] = [
    { key: "label", header: "Device", render: (d) => <span>{d.label || d.browser}{d.isCurrent && <span className="ml-2 text-[10px] text-primary">(this device)</span>}</span> },
    { key: "lastSeen", header: "Last Seen", render: (d) => formatDate(d.lastSeenAt) },
    { key: "mfaTrust", header: "MFA Trust", render: (d) => (d.mfaTrustedUntil && new Date(d.mfaTrustedUntil) > new Date() ? <StatusBadge label="Trusted" tone="success" /> : <StatusBadge label="Not trusted" tone="neutral" />) },
    { key: "actions", header: "", render: (d) => (
      <button type="button" onClick={() => revokeDevice(d.deviceId)} title="Revoke device" aria-label="Revoke device" className="p-1.5 rounded hover:bg-destructive/10 text-muted-foreground hover:text-destructive">
        <Trash2 size={14} />
      </button>
    ) },
  ];

  const sessionColumns: DataTableColumn<Session>[] = [
    { key: "browser", header: "Session", render: (s) => <span>{s.browser} on {s.operatingSystem}{s.isCurrent && <span className="ml-2 text-[10px] text-primary">(current)</span>}</span> },
    { key: "location", header: "Location", render: (s) => `${s.ip || "—"} ${s.country ? `(${s.country})` : ""}` },
    { key: "lastActive", header: "Last Active", render: (s) => formatDate(s.lastActiveAt) },
    { key: "actions", header: "", render: (s) => (
      <button type="button" onClick={() => revokeSession(s.sessionId)} title="Revoke session" aria-label="Revoke session" className="p-1.5 rounded hover:bg-destructive/10 text-muted-foreground hover:text-destructive">
        <Trash2 size={14} />
      </button>
    ) },
  ];

  const riskData = useMemo(
    () => (stats ? Object.entries(stats.byRiskLevel).filter(([, v]) => v > 0).map(([name, value]) => ({ name, value })) : []),
    [stats]
  );
  const mfaUsageData = useMemo(
    () =>
      stats
        ? [
            { name: "MFA/Passkey", value: stats.mfaUsage.withMfaOrPasskey },
            { name: "Password only", value: stats.mfaUsage.passwordOnly },
          ].filter((d) => d.value > 0)
        : [],
    [stats]
  );
  const countryData = useMemo(
    () => (stats ? Object.entries(stats.byCountry).map(([name, value]) => ({ name, value })).sort((a, b) => b.value - a.value).slice(0, 8) : []),
    [stats]
  );
  const deviceData = useMemo(
    () => (stats ? Object.entries(stats.byDevice).map(([name, value]) => ({ name, value })).sort((a, b) => b.value - a.value).slice(0, 8) : []),
    [stats]
  );
  const failedLoginsData = useMemo(
    () =>
      stats
        ? Object.entries(stats.failedLoginsByDay).sort(([a], [b]) => a.localeCompare(b)).map(([date, count]) => ({ date, count }))
        : [],
    [stats]
  );

  const historyTimeline: EventTimelineItem[] = loginHistory.map((e) => ({
    key: e._id,
    icon: e.type.includes("failed") || e.type === "policy_block" || e.type === "impossible_travel" ? AlertCircle : ShieldCheck,
    title: e.message,
    description: `${e.ip || ""} ${e.country ? `· ${e.country}` : ""}`,
    timestamp: e.createdAt,
    tone:
      e.type.includes("failed") || e.type === "policy_block" || e.type === "impossible_travel"
        ? "danger"
        : e.type === "step_up_auth"
        ? "warning"
        : "success",
    badgeLabel: e.type,
  }));

  return (
    <div>
      <PageHeader icon={Fingerprint} title="Identity & Access" description="Multi-factor authentication, passkeys, trusted devices, sessions, roles, and security policies." accent="purple" />

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
        <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
          <StatCard label="MFA Status" value={mfaEnabled ? "Enabled" : "Disabled"} icon={ShieldCheck} variant={mfaEnabled ? "success" : "muted"} />
          <StatCard label="Passkeys" value={passkeys.length} icon={KeyRound} variant="primary" />
          <StatCard label="Trusted Devices" value={devices.filter((d) => d.trusted).length} icon={Smartphone} variant="primary" />
          <StatCard label="Failed Logins" value={stats?.failedLoginsTotal ?? 0} icon={AlertCircle} variant="danger" />
        </div>

        {/* MFA */}
        <section className="rounded-xl border border-border bg-card p-6">
          <h2 className="flex items-center gap-2 text-lg font-bold text-foreground mb-4">
            <ShieldCheck size={20} className="text-primary" /> Multi-Factor Authentication
          </h2>

          {recoveryCodes ? (
            <div className="space-y-3">
              <p className="text-sm text-warning">Save these recovery codes now - they won&apos;t be shown again.</p>
              <div className="grid grid-cols-2 gap-2 font-mono text-sm bg-muted p-4 rounded-lg">
                {recoveryCodes.map((c) => <span key={c}>{c}</span>)}
              </div>
              <button type="button" onClick={copyRecoveryCodes} className="flex items-center gap-1.5 px-3 py-2 bg-card border border-border rounded-lg text-xs">
                {copied ? <Check size={14} /> : <Copy size={14} />} Copy codes
              </button>
              <button type="button" onClick={() => setRecoveryCodes(null)} className="ml-2 text-xs text-muted-foreground hover:text-foreground">Done</button>
            </div>
          ) : mfaEnabled ? (
            <div className="space-y-3">
              <StatusBadge label="Enabled" tone="success" />
              <div className="flex gap-2">
                <button type="button" onClick={regenerateCodes} className="px-3 py-2 bg-card border border-border rounded-lg text-xs">Regenerate recovery codes</button>
              </div>
              <div className="flex items-end gap-2 pt-2">
                <input type="password" placeholder="Current password" value={disablePassword} onChange={(e) => setDisablePassword(e.target.value)} className="px-3 py-2 bg-background border border-border rounded-lg text-xs" />
                <button type="button" onClick={disableMfa} className="px-3 py-2 bg-destructive/10 text-destructive rounded-lg text-xs font-semibold">Disable MFA</button>
              </div>
            </div>
          ) : mfaSetup ? (
            <div className="space-y-3">
              <Image src={mfaSetup.qrCodeDataUrl} alt="MFA QR code" width={180} height={180} unoptimized className="rounded-lg border border-border" />
              <p className="text-xs text-muted-foreground">Scan with an authenticator app, or enter manually: <span className="font-mono">{mfaSetup.secret}</span></p>
              <div className="flex gap-2">
                <input value={mfaCode} onChange={(e) => setMfaCode(e.target.value)} placeholder="6-digit code" className="px-3 py-2 bg-background border border-border rounded-lg text-xs w-32" />
                <button type="button" onClick={confirmMfaSetup} className="px-3 py-2 bg-primary text-primary-foreground rounded-lg text-xs font-semibold">Confirm</button>
              </div>
            </div>
          ) : (
            <div className="space-y-2">
              <StatusBadge label="Disabled" tone="neutral" />
              <div><button type="button" onClick={startMfaSetup} className="mt-2 flex items-center gap-1.5 px-3 py-2 bg-primary text-primary-foreground rounded-lg text-xs font-semibold"><Plus size={14} /> Enable MFA</button></div>
            </div>
          )}
        </section>

        {/* Passkeys */}
        <section>
          <div className="mb-4 flex items-center justify-between">
            <h2 className="flex items-center gap-2 text-lg font-bold text-foreground"><KeyRound size={20} className="text-primary" /> Passkeys</h2>
            <button type="button" onClick={addPasskey} className="flex items-center gap-1.5 px-3 py-2 bg-primary text-primary-foreground rounded-lg text-xs font-semibold"><Plus size={14} /> Add Passkey</button>
          </div>
          {passkeys.length === 0 ? (
            <EmptyState icon={KeyRound} title="No passkeys" description="Register a passkey for fast, phishing-resistant sign-in." />
          ) : (
            <div className="space-y-2">
              {passkeys.map((p) => (
                <div key={p._id} className="flex items-center justify-between rounded-xl border border-border bg-card px-4 py-3">
                  <div>
                    <p className="text-sm font-semibold text-foreground">{p.label}</p>
                    <p className="text-xs text-muted-foreground">Added {formatDate(p.createdAt)}{p.lastUsedAt ? ` · Last used ${formatDate(p.lastUsedAt)}` : ""}</p>
                  </div>
                  <button type="button" onClick={() => removePasskey(p._id)} title="Remove passkey" aria-label="Remove passkey" className="p-1.5 rounded hover:bg-destructive/10 text-muted-foreground hover:text-destructive"><Trash2 size={14} /></button>
                </div>
              ))}
            </div>
          )}
        </section>

        {/* Trusted Devices */}
        <section>
          <div className="mb-4 flex items-center justify-between">
            <h2 className="flex items-center gap-2 text-lg font-bold text-foreground"><Smartphone size={20} className="text-primary" /> Trusted Devices</h2>
            <Link href="/identity/devices" className="flex items-center gap-1 text-xs text-primary hover:text-primary/80 font-semibold">
              Full device dashboard <ArrowUpRight size={14} />
            </Link>
          </div>
          <DataTable columns={deviceColumns} rows={devices} rowKey={(d) => d.deviceId} emptyLabel="No devices recorded." />
        </section>

        {/* Sessions */}
        <section>
          <h2 className="flex items-center gap-2 text-lg font-bold text-foreground mb-4"><History size={20} className="text-primary" /> Sessions</h2>
          <DataTable columns={sessionColumns} rows={sessions} rowKey={(s) => s.sessionId} emptyLabel="No active sessions." />
        </section>

        {/* Policies (admin) */}
        {policy && (
        <AdminOnly>
          <section className="rounded-xl border border-border bg-card p-6">
            <h2 className="flex items-center gap-2 text-lg font-bold text-foreground mb-4"><SlidersHorizontal size={20} className="text-primary" /> Security Policies</h2>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={policy.requireMFA} onChange={(e) => setPolicy({ ...policy, requireMFA: e.target.checked })} /> Require MFA</label>
              <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={policy.blockUntrustedDevices} onChange={(e) => setPolicy({ ...policy, blockUntrustedDevices: e.target.checked })} /> Block untrusted devices</label>
              <label className="flex flex-col gap-1 text-xs text-muted-foreground">Password expiry (days, 0=off)
                <input type="number" value={policy.passwordExpiryDays} onChange={(e) => setPolicy({ ...policy, passwordExpiryDays: Number(e.target.value) })} className="px-3 py-2 bg-background border border-border rounded-lg text-sm text-foreground" />
              </label>
              <label className="flex flex-col gap-1 text-xs text-muted-foreground">Session timeout (minutes, 0=off)
                <input type="number" value={policy.sessionTimeoutMinutes} onChange={(e) => setPolicy({ ...policy, sessionTimeoutMinutes: Number(e.target.value) })} className="px-3 py-2 bg-background border border-border rounded-lg text-sm text-foreground" />
              </label>
              <label className="flex flex-col gap-1 text-xs text-muted-foreground">Max sessions (0=unlimited)
                <input type="number" value={policy.maxSessions} onChange={(e) => setPolicy({ ...policy, maxSessions: Number(e.target.value) })} className="px-3 py-2 bg-background border border-border rounded-lg text-sm text-foreground" />
              </label>
              <label className="flex flex-col gap-1 text-xs text-muted-foreground">Allowed countries (comma-separated ISO codes, empty=all)
                <input value={policy.allowedCountries.join(", ")} onChange={(e) => setPolicy({ ...policy, allowedCountries: e.target.value.split(",").map((s) => s.trim()).filter(Boolean) })} className="px-3 py-2 bg-background border border-border rounded-lg text-sm text-foreground" />
              </label>
              <label className="flex flex-col gap-1 text-xs text-muted-foreground">Allowed device IDs (comma-separated, empty=all)
                <input value={policy.allowedDeviceIds.join(", ")} onChange={(e) => setPolicy({ ...policy, allowedDeviceIds: e.target.value.split(",").map((s) => s.trim()).filter(Boolean) })} className="px-3 py-2 bg-background border border-border rounded-lg text-sm text-foreground" />
              </label>
              <label className="flex flex-col gap-1 text-xs text-muted-foreground">Minimum password length
                <input type="number" value={policy.minPasswordLength} onChange={(e) => setPolicy({ ...policy, minPasswordLength: Number(e.target.value) })} className="px-3 py-2 bg-background border border-border rounded-lg text-sm text-foreground" />
              </label>
              <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={policy.requirePasswordComplexity} onChange={(e) => setPolicy({ ...policy, requirePasswordComplexity: e.target.checked })} /> Require password complexity</label>
            </div>
            <button type="button" onClick={savePolicy} className="mt-4 px-4 py-2 bg-primary text-primary-foreground rounded-lg text-sm font-semibold">Save Policy</button>
          </section>
        </AdminOnly>
        )}

        {/* Roles (admin) */}
        <AdminOnly>
          <section>
            <h2 className="flex items-center gap-2 text-lg font-bold text-foreground mb-4"><Users size={20} className="text-primary" /> Roles</h2>
            <div className="rounded-2xl border border-border bg-card overflow-hidden">
              <table className="w-full text-sm">
                <thead><tr className="text-xs uppercase tracking-wide text-muted-foreground border-b border-border"><th className="text-left p-3">Name</th><th className="text-left p-3">Email</th><th className="text-left p-3">Role</th></tr></thead>
                <tbody>
                  {users.map((u) => (
                    <tr key={u._id} className="border-b border-border last:border-0">
                      <td className="p-3">{u.name}</td>
                      <td className="p-3 text-muted-foreground">{u.email}</td>
                      <td className="p-3">
                        <select
                          value={u.role}
                          disabled={!isOrgOwner}
                          onChange={(e) => updateRole(u._id, e.target.value)}
                          aria-label={`Role for ${u.name}`}
                          title={`Role for ${u.name}`}
                          className="px-2 py-1 bg-background border border-border rounded-lg text-xs disabled:opacity-50"
                        >
                          {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
                        </select>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {!isOrgOwner && <p className="text-xs text-muted-foreground mt-2">Only an Organization Owner can change roles.</p>}
          </section>
        </AdminOnly>

        {/* Analytics (Phase 9.5) */}
        <section>
          <h2 className="flex items-center gap-2 text-lg font-bold text-foreground mb-4"><BarChart3 size={20} className="text-primary" /> Analytics</h2>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="rounded-xl border border-border bg-card p-6">
              <h3 className="text-sm font-semibold text-foreground mb-4">Risk Levels</h3>
              {riskData.length === 0 ? (
                <p className="text-sm text-muted-foreground py-10 text-center">No login data yet.</p>
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
              <h3 className="text-sm font-semibold text-foreground mb-4">MFA Usage</h3>
              {mfaUsageData.length === 0 ? (
                <p className="text-sm text-muted-foreground py-10 text-center">No login data yet.</p>
              ) : (
                <ResponsiveContainer width="100%" height={200}>
                  <PieChart>
                    <Pie data={mfaUsageData} dataKey="value" nameKey="name" innerRadius={45} outerRadius={75} paddingAngle={2}>
                      {mfaUsageData.map((entry, i) => (
                        <Cell key={entry.name} fill={CHART_COLORS[i % CHART_COLORS.length]} />
                      ))}
                    </Pie>
                    <Tooltip contentStyle={{ background: "#0F172A", border: "1px solid rgba(148,163,184,0.2)", borderRadius: 8, fontSize: 12 }} />
                  </PieChart>
                </ResponsiveContainer>
              )}
            </div>

            <div className="rounded-xl border border-border bg-card p-6">
              <h3 className="text-sm font-semibold text-foreground mb-4">Countries</h3>
              {countryData.length === 0 ? (
                <p className="text-sm text-muted-foreground py-10 text-center">No login data yet.</p>
              ) : (
                <ResponsiveContainer width="100%" height={200}>
                  <BarChart data={countryData} layout="vertical" margin={{ left: 8 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.1)" horizontal={false} />
                    <XAxis type="number" stroke="#64748B" fontSize={11} tickLine={false} axisLine={false} allowDecimals={false} />
                    <YAxis type="category" dataKey="name" stroke="#64748B" fontSize={11} tickLine={false} axisLine={false} width={60} />
                    <Tooltip contentStyle={{ background: "#0F172A", border: "1px solid rgba(148,163,184,0.2)", borderRadius: 8, fontSize: 12 }} />
                    <Bar dataKey="value" fill="#6366F1" radius={[0, 4, 4, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              )}
            </div>

            <div className="rounded-xl border border-border bg-card p-6">
              <h3 className="text-sm font-semibold text-foreground mb-4">Devices</h3>
              {deviceData.length === 0 ? (
                <p className="text-sm text-muted-foreground py-10 text-center">No login data yet.</p>
              ) : (
                <ResponsiveContainer width="100%" height={200}>
                  <BarChart data={deviceData} layout="vertical" margin={{ left: 8 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.1)" horizontal={false} />
                    <XAxis type="number" stroke="#64748B" fontSize={11} tickLine={false} axisLine={false} allowDecimals={false} />
                    <YAxis type="category" dataKey="name" stroke="#64748B" fontSize={11} tickLine={false} axisLine={false} width={100} />
                    <Tooltip contentStyle={{ background: "#0F172A", border: "1px solid rgba(148,163,184,0.2)", borderRadius: 8, fontSize: 12 }} />
                    <Bar dataKey="value" fill="#A855F7" radius={[0, 4, 4, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              )}
            </div>
          </div>

          <div className="mt-6 rounded-xl border border-border bg-card p-6">
            <h3 className="text-sm font-semibold text-foreground mb-4">Failed Logins</h3>
            {failedLoginsData.length === 0 ? (
              <p className="text-sm text-muted-foreground py-10 text-center">No failed logins recorded.</p>
            ) : (
              <ResponsiveContainer width="100%" height={200}>
                <AreaChart data={failedLoginsData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.1)" />
                  <XAxis dataKey="date" stroke="#64748B" fontSize={11} tickLine={false} axisLine={false} />
                  <YAxis stroke="#64748B" fontSize={11} tickLine={false} axisLine={false} allowDecimals={false} />
                  <Tooltip contentStyle={{ background: "#0F172A", border: "1px solid rgba(148,163,184,0.2)", borderRadius: 8, fontSize: 12 }} />
                  <Area type="monotone" dataKey="count" stroke="#EF4444" fill="rgba(239,68,68,0.2)" />
                </AreaChart>
              </ResponsiveContainer>
            )}
          </div>
        </section>

        {/* Login History */}
        <section>
          <h2 className="flex items-center gap-2 text-lg font-bold text-foreground mb-4"><History size={20} className="text-primary" /> Login History</h2>
          <div className="rounded-xl border border-border bg-card p-5">
            <EventTimeline items={historyTimeline} emptyLabel="No login activity yet." />
          </div>
        </section>
      </div>
      )}
    </div>
  );
}
