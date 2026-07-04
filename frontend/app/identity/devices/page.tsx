"use client";

import { useEffect, useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import api from "@/lib/api";
import { Smartphone, Trash2, ArrowLeft, AlertCircle, ShieldCheck, ShieldOff } from "lucide-react";
import toast from "react-hot-toast";
import PageHeader from "@/components/design/PageHeader";
import StatusBadge from "@/components/design/StatusBadge";
import EmptyState from "@/components/design/EmptyState";
import { TableSkeleton } from "@/components/design/Skeletons";
import { apiErrorStatus } from "@/lib/errors";

type Device = {
  deviceId: string;
  label?: string;
  browser?: string;
  operatingSystem?: string;
  firstSeenAt?: string;
  lastSeenAt: string;
  lastIp?: string;
  trusted: boolean;
  isCurrent: boolean;
  mfaTrustedUntil?: string | null;
};

/** Phase 9.5 (IAM): dedicated trusted-devices dashboard - a fuller view than the summary table
 *  embedded in the main /identity page, for accounts managing many devices. */
export default function DevicesPage() {
  const router = useRouter();
  const [devices, setDevices] = useState<Device[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const authHeader = () => ({ headers: { Authorization: `Bearer ${localStorage.getItem("token")}` } });

  const fetchDevices = useCallback(
    async (token: string) => {
      try {
        setLoading(true);
        const res = await api.get<Device[]>("/devices", { headers: { Authorization: `Bearer ${token}` } });
        setDevices(res.data || []);
      } catch (err: unknown) {
        const status = apiErrorStatus(err);
        if (status === 401 || status === 403) {
          router.push("/login");
          return;
        }
        setError("Failed to load devices");
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
    fetchDevices(token);
  }, [fetchDevices, router]);

  const revokeDevice = async (deviceId: string) => {
    try {
      await api.delete(`/devices/${deviceId}`, authHeader());
      setDevices((prev) => prev.filter((d) => d.deviceId !== deviceId));
      toast.success("Device revoked");
    } catch {
      toast.error("Failed to revoke device");
    }
  };

  const formatDate = (d?: string) => (d ? new Date(d).toLocaleString() : "—");
  const isMfaTrusted = (d: Device) => !!(d.mfaTrustedUntil && new Date(d.mfaTrustedUntil) > new Date());

  return (
    <div>
      <Link href="/identity" className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground mb-4">
        <ArrowLeft size={14} /> Back to Identity & Access
      </Link>
      <PageHeader icon={Smartphone} title="Trusted Devices" description="Every device that has ever signed in to your account - revoke any you don't recognize." accent="purple" />

      {error && (
        <div className="mb-6 p-4 bg-destructive/10 border border-destructive/30 rounded-lg flex items-center gap-2">
          <AlertCircle className="text-destructive" size={18} />
          <p className="text-destructive text-sm">{error}</p>
        </div>
      )}

      {loading ? (
        <TableSkeleton />
      ) : devices.length === 0 ? (
        <EmptyState icon={Smartphone} title="No devices recorded" description="Devices are recorded the first time you sign in from them." />
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {devices.map((d) => (
            <div key={d.deviceId} className="rounded-xl border border-border bg-card p-5">
              <div className="flex items-start justify-between gap-2 mb-3">
                <div className="min-w-0">
                  <p className="text-sm font-semibold text-foreground truncate">
                    {d.label || `${d.browser} on ${d.operatingSystem}`}
                    {d.isCurrent && <span className="ml-2 text-[10px] text-primary">(this device)</span>}
                  </p>
                  <p className="text-xs text-muted-foreground mt-0.5">{d.browser} · {d.operatingSystem}</p>
                </div>
                <button
                  type="button"
                  onClick={() => revokeDevice(d.deviceId)}
                  title="Revoke device"
                  aria-label="Revoke device"
                  className="p-1.5 rounded hover:bg-destructive/10 text-muted-foreground hover:text-destructive shrink-0"
                >
                  <Trash2 size={14} />
                </button>
              </div>

              <div className="flex flex-wrap gap-2 mb-3">
                <StatusBadge label={d.trusted ? "Trusted" : "Untrusted"} tone={d.trusted ? "success" : "neutral"} />
                {isMfaTrusted(d) ? (
                  <StatusBadge label="MFA Trusted" tone="success" />
                ) : (
                  <StatusBadge label="MFA Challenge Required" tone="neutral" />
                )}
              </div>

              <dl className="text-xs text-muted-foreground space-y-1">
                <div className="flex justify-between"><dt>First seen</dt><dd>{formatDate(d.firstSeenAt)}</dd></div>
                <div className="flex justify-between"><dt>Last seen</dt><dd>{formatDate(d.lastSeenAt)}</dd></div>
                <div className="flex justify-between"><dt>Last IP</dt><dd>{d.lastIp || "—"}</dd></div>
                {isMfaTrusted(d) && (
                  <div className="flex justify-between"><dt>MFA trust expires</dt><dd>{formatDate(d.mfaTrustedUntil || undefined)}</dd></div>
                )}
              </dl>

              <div className="mt-3 flex items-center gap-1.5 text-[11px] text-muted-foreground">
                {isMfaTrusted(d) ? <ShieldCheck size={12} className="text-success" /> : <ShieldOff size={12} />}
                {isMfaTrusted(d) ? "Skips MFA challenges until trust expires" : "Will be challenged for MFA if enrolled"}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
