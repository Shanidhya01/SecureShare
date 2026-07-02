"use client";

import { useEffect, useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import api from "@/lib/api";
import {
  ShieldCheck,
  Laptop,
  Trash2,
  Monitor,
  Clock,
  AlertCircle,
  Ban,
  UserPlus,
  KeyRound,
  LogOut,
  Loader,
} from "lucide-react";
import toast from "react-hot-toast";

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
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [busyId, setBusyId] = useState<string | null>(null);

  const fetchAll = useCallback(async (token: string) => {
    try {
      setLoading(true);
      const [devicesRes, sessionsRes, eventsRes] = await Promise.all([
        api.get<DeviceEntry[]>("/devices", { headers: { Authorization: `Bearer ${token}` } }),
        api.get<SessionEntry[]>("/sessions", { headers: { Authorization: `Bearer ${token}` } }),
        api.get<SecurityEventEntry[]>("/security/events", { headers: { Authorization: `Bearer ${token}` } }),
      ]);
      setDevices(devicesRes.data || []);
      setSessions(sessionsRes.data || []);
      setEvents(eventsRes.data || []);
    } catch (err: any) {
      if (err?.response?.status === 401 || err?.response?.status === 403) {
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

  const formatDate = (d: string) => new Date(d).toLocaleString();

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 text-white">
      <div className="max-w-5xl mx-auto px-4 py-12">
        <div className="mb-10 flex items-center gap-3">
          <div className="inline-flex h-11 w-11 items-center justify-center rounded-xl bg-blue-500/10 text-blue-300 ring-1 ring-blue-500/30">
            <ShieldCheck size={22} />
          </div>
          <div>
            <h1 className="text-3xl font-black text-transparent bg-clip-text bg-gradient-to-r from-blue-400 to-cyan-400">
              Security Center
            </h1>
            <p className="text-slate-400 text-sm">Zero Trust device, session, and access controls for your account.</p>
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
            <Loader className="animate-spin text-blue-400" size={40} />
            <p className="mt-4 text-slate-400">Loading security data…</p>
          </div>
        ) : (
          <div className="space-y-10">
            {/* Trusted Devices */}
            <section>
              <h2 className="flex items-center gap-2 text-lg font-bold text-white mb-4">
                <Laptop size={20} className="text-blue-300" />
                Trusted Devices
              </h2>
              {devices.length === 0 ? (
                <p className="text-slate-500 text-sm">No devices recorded yet - they're added automatically when you log in.</p>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {devices.map((d) => (
                    <div key={d.deviceId} className="bg-slate-800 border border-slate-700 rounded-xl p-4">
                      <div className="flex items-start justify-between gap-2">
                        <div className="min-w-0">
                          <p className="font-semibold text-white truncate">
                            {d.label || `${d.browser || "Unknown"} on ${d.operatingSystem || "Unknown"}`}
                            {d.isCurrent && (
                              <span className="ml-2 text-[10px] font-bold uppercase tracking-wide text-green-300 bg-green-500/10 ring-1 ring-green-500/30 rounded-full px-2 py-0.5">
                                This device
                              </span>
                            )}
                          </p>
                          <p className="text-slate-400 text-xs mt-1">Last seen {formatDate(d.lastSeenAt)}</p>
                          {d.lastIp && <p className="text-slate-500 text-xs font-mono">{d.lastIp}</p>}
                        </div>
                        <button
                          onClick={() => handleRemoveDevice(d.deviceId)}
                          disabled={busyId === d.deviceId}
                          className="flex-shrink-0 p-2 text-red-400 hover:text-red-300 hover:bg-red-500/10 rounded-lg disabled:opacity-50"
                          title="Remove device"
                        >
                          <Trash2 size={16} />
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </section>

            {/* Active Sessions */}
            <section>
              <h2 className="flex items-center gap-2 text-lg font-bold text-white mb-4">
                <Monitor size={20} className="text-blue-300" />
                Active Sessions
              </h2>
              {sessions.length === 0 ? (
                <p className="text-slate-500 text-sm">No active sessions recorded.</p>
              ) : (
                <div className="rounded-2xl border border-slate-800/80 bg-slate-900/80 overflow-hidden">
                  <div className="overflow-x-auto">
                    <table className="min-w-full w-full text-sm">
                      <thead className="bg-slate-900 text-xs uppercase tracking-wide text-slate-400">
                        <tr>
                          <th className="px-4 py-3 text-left">Browser / OS</th>
                          <th className="px-4 py-3 text-left">IP / Country</th>
                          <th className="px-4 py-3 text-left">Signed in</th>
                          <th className="px-4 py-3 text-left">Last active</th>
                          <th className="px-4 py-3 text-right">Action</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/80">
                        {sessions.map((s) => (
                          <tr key={s.sessionId} className="hover:bg-slate-900/70">
                            <td className="px-4 py-3">
                              {s.browser || "Unknown"} / {s.operatingSystem || "Unknown"}
                              {s.isCurrent && (
                                <span className="ml-2 text-[10px] font-bold uppercase tracking-wide text-green-300 bg-green-500/10 ring-1 ring-green-500/30 rounded-full px-2 py-0.5">
                                  Current
                                </span>
                              )}
                            </td>
                            <td className="px-4 py-3 font-mono text-xs">
                              {s.ip || "unknown"} {s.country && s.country !== "Unknown" ? `(${s.country})` : ""}
                            </td>
                            <td className="px-4 py-3 text-slate-300">{formatDate(s.createdAt)}</td>
                            <td className="px-4 py-3 text-slate-300">{formatDate(s.lastActiveAt)}</td>
                            <td className="px-4 py-3 text-right">
                              <button
                                onClick={() => handleRevokeSession(s.sessionId)}
                                disabled={busyId === s.sessionId}
                                className="px-3 py-1.5 text-xs font-semibold text-red-300 hover:text-red-200 hover:bg-red-500/10 rounded-lg disabled:opacity-50"
                              >
                                Revoke
                              </button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </section>

            {/* Blocked Access Attempts */}
            <section>
              <h2 className="flex items-center gap-2 text-lg font-bold text-white mb-4">
                <Ban size={20} className="text-red-300" />
                Blocked Access Attempts
              </h2>
              {blockedAttempts.length === 0 ? (
                <p className="text-slate-500 text-sm">No blocked download attempts on your files.</p>
              ) : (
                <div className="space-y-2">
                  {blockedAttempts.map((e) => (
                    <div
                      key={e.id}
                      className="flex items-start gap-3 rounded-xl border border-red-500/30 bg-red-500/5 px-4 py-3"
                    >
                      <Ban size={16} className="text-red-400 flex-shrink-0 mt-0.5" />
                      <div className="min-w-0">
                        <p className="text-red-100 text-sm">
                          {e.filename && <span className="font-semibold">{e.filename}: </span>}
                          {e.message}
                        </p>
                        <p className="text-slate-500 text-xs mt-1">
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

            {/* Recent Security Events */}
            <section>
              <h2 className="flex items-center gap-2 text-lg font-bold text-white mb-4">
                <KeyRound size={20} className="text-blue-300" />
                Recent Security Events
              </h2>
              {activityEvents.length === 0 ? (
                <p className="text-slate-500 text-sm">No security events yet.</p>
              ) : (
                <div className="space-y-2">
                  {activityEvents.map((e) => {
                    const Icon = eventIcon(e.type);
                    return (
                      <div
                        key={e.id}
                        className="flex items-start gap-3 rounded-xl border border-slate-800/80 bg-slate-900/70 px-4 py-3"
                      >
                        <Icon size={16} className="text-blue-300 flex-shrink-0 mt-0.5" />
                        <div className="min-w-0">
                          <p className="text-slate-200 text-sm">{e.message}</p>
                          <p className="text-slate-500 text-xs mt-1 flex items-center gap-2">
                            <Clock size={12} />
                            {formatDate(e.createdAt)}
                            {e.ip ? ` · ${e.ip}` : ""}
                          </p>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </section>
          </div>
        )}
      </div>
    </div>
  );
}
