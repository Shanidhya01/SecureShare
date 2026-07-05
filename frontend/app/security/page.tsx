"use client";

import { useEffect, useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import api from "@/lib/api";
import { apiErrorStatus } from "@/lib/errors";
import Link from "next/link";
import { ShieldCheck, Laptop, Trash2, Monitor, AlertCircle, Ban, UserPlus, KeyRound, LogOut, LogIn, ClipboardCheck, Cloud, ShieldHalf } from "lucide-react";
import toast from "react-hot-toast";
import { motion } from "framer-motion";
import { getIsAdminFromToken } from "@/lib/auth";
import PageHeader from "@/components/design/PageHeader";
import EmptyState from "@/components/design/EmptyState";
import DataTable, { type DataTableColumn } from "@/components/design/DataTable";
import SecurityScoreGauge from "@/components/design/SecurityScoreGauge";
import StatCard from "@/components/design/StatCard";
import StatusBadge from "@/components/design/StatusBadge";
import EventTimeline, { type EventTimelineItem } from "@/components/design/EventTimeline";
import { StatsSkeleton, TableSkeleton } from "@/components/design/Skeletons";
import { computeSecurityScore } from "@/lib/securityScore";
import { fadeInUp, staggerContainer } from "@/lib/motion";
import { hasZeroTrustPolicy, type FilePolicy } from "@/lib/types";

type DeviceEntry = {
  deviceId: string;
  label?: string;
  browser?: string;
  operatingSystem?: string;
  firstSeenAt: string;
  lastSeenAt: string;
  lastIp?: string;
  trusted: boolean;
  isCurrent: boolean;
};

type SessionEntry = {
  sessionId: string;
  deviceId?: string;
  browser?: string;
  operatingSystem?: string;
  ip?: string;
  country?: string;
  createdAt: string;
  lastActiveAt: string;
  isCurrent: boolean;
};

type SecurityEventEntry = {
  id: string;
  type: "new_device" | "device_removed" | "session_revoked" | "download_denied";
  message: string;
  filename?: string | null;
  deviceId?: string | null;
  ip?: string | null;
  country?: string | null;
  createdAt: string;
};

type FileMeta = { signature?: string | null; policy?: FilePolicy };
type ThreatStats = { totalScans: number; quarantinedFiles: number; malwareDetections: number };
type DLPStats = { totalScans: number; policyViolations: number };

const eventIcon = (type: SecurityEventEntry["type"]) => {
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
      return AlertCircle;
  }
};

export default function SecurityCenterPage() {
  const router = useRouter();
  const [devices, setDevices] = useState<DeviceEntry[]>([]);
  const [sessions, setSessions] = useState<SessionEntry[]>([]);
  const [events, setEvents] = useState<SecurityEventEntry[]>([]);
  const [files, setFiles] = useState<FileMeta[]>([]);
  const [threatStats, setThreatStats] = useState<ThreatStats | null>(null);
  const [dlpStats, setDlpStats] = useState<DLPStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [busyId, setBusyId] = useState<string | null>(null);
  const [isAdmin, setIsAdmin] = useState(false);

  const fetchAll = useCallback(async (token: string) => {
    try {
      setLoading(true);
      const [devicesRes, sessionsRes, eventsRes, filesRes, threatRes, dlpRes] = await Promise.all([
        api.get<DeviceEntry[]>("/devices", { headers: { Authorization: `Bearer ${token}` } }),
        api.get<SessionEntry[]>("/sessions", { headers: { Authorization: `Bearer ${token}` } }),
        api.get<SecurityEventEntry[]>("/security/events", { headers: { Authorization: `Bearer ${token}` } }),
        api.get<FileMeta[]>("/files/my-files", { headers: { Authorization: `Bearer ${token}` } }),
        api.get<ThreatStats>("/threats/stats", { headers: { Authorization: `Bearer ${token}` } }),
        api.get<DLPStats>("/dlp/stats", { headers: { Authorization: `Bearer ${token}` } }),
      ]);
      setDevices(devicesRes.data || []);
      setSessions(sessionsRes.data || []);
      setEvents(eventsRes.data || []);
      setFiles(filesRes.data || []);
      setThreatStats(threatRes.data || null);
      setDlpStats(dlpRes.data || null);
    } catch (err: unknown) {
      const status = apiErrorStatus(err);
      if (status === 401 || status === 403) {
        router.push("/login");
        return;
      }
      setError("Failed to load security data");
    } finally {
      setLoading(false);
    }
  }, [router]);

  useEffect(() => {
    const token = localStorage.getItem("token");
    if (!token) {
      router.push("/login");
      return;
    }
    setIsAdmin(getIsAdminFromToken(token));
    fetchAll(token);
  }, [fetchAll, router]);

  const handleRemoveDevice = async (deviceId: string) => {
    const token = localStorage.getItem("token");
    if (!token) return;
    setBusyId(deviceId);
    try {
      await api.delete(`/devices/${deviceId}`, { headers: { Authorization: `Bearer ${token}` } });
      setDevices((prev) => prev.filter((d) => d.deviceId !== deviceId));
      toast.success("Device removed");
      fetchAll(token);
    } catch {
      toast.error("Failed to remove device");
    } finally {
      setBusyId(null);
    }
  };

  const handleRevokeSession = async (sessionId: string) => {
    const token = localStorage.getItem("token");
    if (!token) return;
    setBusyId(sessionId);
    try {
      await api.delete(`/sessions/${sessionId}`, { headers: { Authorization: `Bearer ${token}` } });
      setSessions((prev) => prev.filter((s) => s.sessionId !== sessionId));
      toast.success("Session revoked");
      fetchAll(token);
    } catch {
      toast.error("Failed to revoke session");
    } finally {
      setBusyId(null);
    }
  };

  const blockedAttempts = events.filter((e) => e.type === "download_denied");
  const activityEvents = events.filter((e) => e.type !== "download_denied");
  const trustedDevices = devices.filter((d) => d.trusted).length;

  const recentLogins: EventTimelineItem[] = [...sessions]
    .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())
    .slice(0, 8)
    .map((s) => ({
      key: s.sessionId,
      icon: LogIn,
      title: `${s.browser || "Unknown browser"} on ${s.operatingSystem || "Unknown OS"}`,
      description: `${s.ip || "unknown IP"}${s.country && s.country !== "Unknown" ? ` · ${s.country}` : ""}`,
      timestamp: s.createdAt,
      tone: s.isCurrent ? "success" : "neutral",
      badgeLabel: s.isCurrent ? "Current" : undefined,
    }));

  const activityTimeline: EventTimelineItem[] = activityEvents.map((e) => ({
    key: e.id,
    icon: eventIcon(e.type),
    title: e.message,
    description: e.ip ? `${e.ip}${e.country && e.country !== "Unknown" ? ` · ${e.country}` : ""}` : undefined,
    timestamp: e.createdAt,
    tone: e.type === "session_revoked" || e.type === "device_removed" ? "warning" : "info",
  }));

  const securityScore = computeSecurityScore({
    totalDevices: devices.length,
    trustedDevices,
    totalScans: threatStats?.totalScans ?? 0,
    malwareDetections: threatStats?.malwareDetections ?? 0,
    quarantinedFiles: threatStats?.quarantinedFiles ?? 0,
    dlpTotalScans: dlpStats?.totalScans ?? 0,
    dlpViolations: dlpStats?.policyViolations ?? 0,
    totalFiles: files.length,
    signedFiles: files.filter((f) => f.signature).length,
    policiesConfigured: files.filter((f) => hasZeroTrustPolicy(f.policy)).length,
  });

  const formatDate = (d: string) => new Date(d).toLocaleString();

  const sessionColumns: DataTableColumn<SessionEntry>[] = [
    {
      key: "browser",
      header: "Browser / OS",
      render: (s) => (
        <>
          {s.browser || "Unknown"} / {s.operatingSystem || "Unknown"}
          {s.isCurrent && <span className="ml-2"><StatusBadge label="Current" tone="success" /></span>}
        </>
      ),
    },
    { key: "ip", header: "IP / Country", render: (s) => <span className="font-mono text-xs">{s.ip || "unknown"} {s.country && s.country !== "Unknown" ? `(${s.country})` : ""}</span> },
    { key: "created", header: "Signed in", render: (s) => formatDate(s.createdAt) },
    { key: "active", header: "Last active", render: (s) => formatDate(s.lastActiveAt) },
    {
      key: "action",
      header: "Action",
      align: "right",
      render: (s) => (
        <button
          type="button"
          onClick={() => handleRevokeSession(s.sessionId)}
          disabled={busyId === s.sessionId}
          className="px-3 py-1.5 text-xs font-semibold text-destructive hover:text-destructive/80 hover:bg-destructive/10 rounded-lg disabled:opacity-50"
        >
          Revoke
        </button>
      ),
    },
  ];

  return (
    <div>
      <PageHeader
        icon={ShieldCheck}
        title="Security Center"
        description="Zero Trust device, session, and access controls for your account."
        actions={
          isAdmin ? (
            <div className="flex flex-wrap gap-2">
              <Link
                href="/compliance"
                className="inline-flex items-center gap-2 px-4 py-2.5 bg-card hover:bg-white/5 text-foreground font-semibold rounded-lg text-sm ring-1 ring-border transition-colors"
              >
                <ClipboardCheck size={16} /> Compliance Center
              </Link>
              <Link
                href="/cloud-security"
                className="inline-flex items-center gap-2 px-4 py-2.5 bg-card hover:bg-white/5 text-foreground font-semibold rounded-lg text-sm ring-1 ring-border transition-colors"
              >
                <Cloud size={16} /> Cloud Security
              </Link>
              <Link
                href="/devsecops"
                className="inline-flex items-center gap-2 px-4 py-2.5 bg-card hover:bg-white/5 text-foreground font-semibold rounded-lg text-sm ring-1 ring-border transition-colors"
              >
                <ShieldHalf size={16} /> DevSecOps
              </Link>
            </div>
          ) : undefined
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
          <StatsSkeleton count={4} />
          <TableSkeleton />
        </div>
      ) : (
        <div className="space-y-10">
          <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
            <StatCard label="Trusted Devices" value={trustedDevices} icon={Laptop} variant="primary" />
            <StatCard label="Active Sessions" value={sessions.length} icon={Monitor} variant="success" />
            <StatCard label="Blocked Attempts" value={blockedAttempts.length} icon={Ban} variant="danger" />
            <StatCard label="Malware Detections" value={threatStats?.malwareDetections ?? 0} icon={AlertCircle} variant="warning" />
          </div>

          <div className="rounded-xl border border-border bg-card p-6 flex flex-col sm:flex-row items-center gap-8">
            <SecurityScoreGauge score={securityScore} />
            <div>
              <h3 className="text-sm font-semibold text-foreground mb-2">Overall Security Score</h3>
              <p className="text-sm text-muted-foreground max-w-md">
                Computed from device trust ratio, malware/DLP scan history, digital signature usage, and Zero Trust
                access policies configured across your files.
              </p>
            </div>
          </div>

          <section>
            <h2 className="flex items-center gap-2 text-lg font-bold text-foreground mb-4">
              <Laptop size={20} className="text-primary" />
              Trusted Devices
            </h2>
            {devices.length === 0 ? (
              <EmptyState icon={Laptop} title="No devices yet" description="Devices are added automatically when you log in." />
            ) : (
              <motion.div variants={staggerContainer} initial="hidden" animate="show" className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {devices.map((d) => (
                  <motion.div key={d.deviceId} variants={fadeInUp} className="bg-card border border-border rounded-xl p-4">
                    <div className="flex items-start justify-between gap-2">
                      <div className="min-w-0">
                        <p className="font-semibold text-foreground truncate">
                          {d.label || `${d.browser || "Unknown"} on ${d.operatingSystem || "Unknown"}`}
                          {d.isCurrent && <span className="ml-2"><StatusBadge label="This device" tone="success" /></span>}
                        </p>
                        <p className="text-muted-foreground text-xs mt-1">Last seen {formatDate(d.lastSeenAt)}</p>
                        {d.lastIp && <p className="text-muted-foreground/70 text-xs font-mono">{d.lastIp}</p>}
                      </div>
                      <button
                        type="button"
                        onClick={() => handleRemoveDevice(d.deviceId)}
                        disabled={busyId === d.deviceId}
                        className="shrink-0 p-2 text-destructive hover:text-destructive/80 hover:bg-destructive/10 rounded-lg disabled:opacity-50"
                        title="Remove device"
                        aria-label="Remove device"
                      >
                        <Trash2 size={16} />
                      </button>
                    </div>
                  </motion.div>
                ))}
              </motion.div>
            )}
          </section>

          <section>
            <h2 className="flex items-center gap-2 text-lg font-bold text-foreground mb-4">
              <Monitor size={20} className="text-primary" />
              Active Sessions
            </h2>
            <DataTable columns={sessionColumns} rows={sessions} rowKey={(s) => s.sessionId} emptyLabel="No active sessions recorded." />
          </section>

          <section>
            <h2 className="flex items-center gap-2 text-lg font-bold text-foreground mb-4">
              <LogIn size={20} className="text-primary" />
              Recent Logins
            </h2>
            <div className="rounded-xl border border-border bg-card p-5">
              <EventTimeline items={recentLogins} emptyLabel="No login history recorded yet." />
            </div>
          </section>

          <section>
            <h2 className="flex items-center gap-2 text-lg font-bold text-foreground mb-4">
              <Ban size={20} className="text-destructive" />
              Blocked Access Attempts
            </h2>
            {blockedAttempts.length === 0 ? (
              <EmptyState icon={Ban} title="No blocked attempts" description="No blocked download attempts on your files." />
            ) : (
              <div className="space-y-2">
                {blockedAttempts.map((e) => (
                  <div key={e.id} className="flex items-start gap-3 rounded-xl border border-destructive/30 bg-destructive/5 px-4 py-3">
                    <Ban size={16} className="text-destructive shrink-0 mt-0.5" />
                    <div className="min-w-0">
                      <p className="text-foreground text-sm">
                        {e.filename && <span className="font-semibold">{e.filename}: </span>}
                        {e.message}
                      </p>
                      <p className="text-muted-foreground text-xs mt-1">
                        {formatDate(e.createdAt)}
                        {e.ip ? ` · ${e.ip}` : ""}
                        {e.country && e.country !== "Unknown" ? ` · ${e.country}` : ""}
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </section>

          <section>
            <h2 className="flex items-center gap-2 text-lg font-bold text-foreground mb-4">
              <KeyRound size={20} className="text-primary" />
              Recent Security Events
            </h2>
            {activityEvents.length === 0 ? (
              <EmptyState icon={KeyRound} title="No events yet" description="Security events will appear here as they happen." />
            ) : (
              <div className="rounded-xl border border-border bg-card p-5">
                <EventTimeline items={activityTimeline} />
              </div>
            )}
          </section>
        </div>
      )}
    </div>
  );
}
