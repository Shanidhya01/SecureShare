"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import api from "@/lib/api";
import toast from "react-hot-toast";
import { Settings as SettingsIcon, User, ShieldCheck, Sliders, Bell, TriangleAlert, KeyRound, LogOut, Trash2 } from "lucide-react";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Switch } from "@/components/ui/switch";
import PageHeader from "@/components/design/PageHeader";
import { useCryptoKey } from "@/context/CryptoKeyContext";
import { clearPrivateKeyIndexedDB } from "@/lib/crypto/keyStorage";
import { sha256Base64 } from "@/lib/crypto/hash";
import { base64ToBuf } from "@/lib/crypto/base64";

type PrefKey = "emailAlerts" | "downloadAlerts" | "compactTables";

const PREFS_STORAGE_KEY = "secureshare:preferences";

function loadPrefs(): Record<PrefKey, boolean> {
  const defaults: Record<PrefKey, boolean> = { emailAlerts: true, downloadAlerts: true, compactTables: false };
  if (typeof window === "undefined") return defaults;
  try {
    const raw = localStorage.getItem(PREFS_STORAGE_KEY);
    return raw ? { ...defaults, ...JSON.parse(raw) } : defaults;
  } catch {
    return defaults;
  }
}

export default function SettingsPage() {
  const router = useRouter();
  const { lock } = useCryptoKey();
  const [user, setUser] = useState<{ email?: string; name?: string } | null>(null);
  const [fingerprint, setFingerprint] = useState<string>("");
  const [prefs, setPrefs] = useState<Record<PrefKey, boolean>>(loadPrefs());
  const [revoking, setRevoking] = useState(false);
  const [clearingKeys, setClearingKeys] = useState(false);

  useEffect(() => {
    const raw = localStorage.getItem("user");
    setUser(raw ? JSON.parse(raw) : null);

    const token = localStorage.getItem("token");
    if (!token) {
      router.push("/login");
      return;
    }
    api
      .get("/users/publickey", { headers: { Authorization: `Bearer ${token}` } })
      .then(async (res) => {
        const publicKey = res.data?.publicKey;
        if (!publicKey) return;
        const digest = await sha256Base64(base64ToBuf(publicKey));
        setFingerprint(digest.replace(/=+$/, "").match(/.{1,4}/g)?.join(" ") || digest);
      })
      .catch(() => {});
  }, [router]);

  const updatePref = (key: PrefKey, value: boolean) => {
    const next = { ...prefs, [key]: value };
    setPrefs(next);
    localStorage.setItem(PREFS_STORAGE_KEY, JSON.stringify(next));
  };

  const handleRevokeAllSessions = async () => {
    const token = localStorage.getItem("token");
    if (!token) return;
    setRevoking(true);
    try {
      const res = await api.get<{ sessionId: string }[]>("/sessions", { headers: { Authorization: `Bearer ${token}` } });
      const sessions = res.data || [];
      await Promise.all(
        sessions.map((s) => api.delete(`/sessions/${s.sessionId}`, { headers: { Authorization: `Bearer ${token}` } }).catch(() => null))
      );
      toast.success(`Revoked ${sessions.length} session(s)`);
    } catch {
      toast.error("Failed to revoke sessions");
    } finally {
      setRevoking(false);
    }
  };

  const handleClearLocalKeys = async () => {
    if (!user?.email) return;
    setClearingKeys(true);
    try {
      await clearPrivateKeyIndexedDB(user.email.toLowerCase().trim());
      lock();
      toast.success("Local encryption keys cleared from this device");
    } catch {
      toast.error("Failed to clear local keys");
    } finally {
      setClearingKeys(false);
    }
  };

  return (
    <div className="max-w-4xl">
      <PageHeader icon={SettingsIcon} title="Settings" description="Manage your profile, security, and preferences." />

      <Tabs defaultValue="profile">
        <TabsList variant="line" className="mb-6 border-b border-border w-full justify-start overflow-x-auto">
          <TabsTrigger value="profile" className="gap-1.5"><User size={14} /> Profile</TabsTrigger>
          <TabsTrigger value="security" className="gap-1.5"><ShieldCheck size={14} /> Security</TabsTrigger>
          <TabsTrigger value="preferences" className="gap-1.5"><Sliders size={14} /> Preferences</TabsTrigger>
          <TabsTrigger value="notifications" className="gap-1.5"><Bell size={14} /> Notifications</TabsTrigger>
          <TabsTrigger value="danger" className="gap-1.5"><TriangleAlert size={14} /> Danger Zone</TabsTrigger>
        </TabsList>

        <TabsContent value="profile">
          <div className="rounded-xl border border-border bg-card p-6 space-y-5">
            <div>
              <p className="text-xs text-muted-foreground uppercase tracking-wide mb-1">Name</p>
              <p className="text-foreground font-medium">{user?.name || "-"}</p>
            </div>
            <div>
              <p className="text-xs text-muted-foreground uppercase tracking-wide mb-1">Email</p>
              <p className="text-foreground font-medium">{user?.email || "-"}</p>
            </div>
            <div>
              <p className="text-xs text-muted-foreground uppercase tracking-wide mb-1 flex items-center gap-1.5">
                <KeyRound size={12} /> Encryption Key Fingerprint (SHA-256)
              </p>
              <p className="text-foreground font-mono text-xs break-all">{fingerprint || "Not available"}</p>
              <p className="text-muted-foreground text-xs mt-1">
                A fingerprint of your account&apos;s public encryption key - share this out-of-band to let others verify it&apos;s really you.
              </p>
            </div>
          </div>
        </TabsContent>

        <TabsContent value="security">
          <div className="rounded-xl border border-border bg-card p-6">
            <p className="text-sm text-muted-foreground mb-4">
              Manage trusted devices, active sessions, and blocked access attempts from the Security Center.
            </p>
            <Link
              href="/security"
              className="inline-flex items-center gap-2 px-4 py-2.5 bg-primary hover:bg-primary/90 text-white font-semibold rounded-lg text-sm transition-colors"
            >
              <ShieldCheck size={16} />
              Open Security Center
            </Link>
          </div>
        </TabsContent>

        <TabsContent value="preferences">
          <div className="rounded-xl border border-border bg-card p-6 space-y-5">
            <PrefRow
              label="Compact tables"
              description="Show more rows per screen in Threat Center, DLP Center, and Audit Logs."
              checked={prefs.compactTables}
              onChange={(v) => updatePref("compactTables", v)}
            />
            <p className="text-xs text-muted-foreground">
              Theme is fixed to SecureShare&apos;s dark enterprise palette for consistency across every security console.
            </p>
          </div>
        </TabsContent>

        <TabsContent value="notifications">
          <div className="rounded-xl border border-border bg-card p-6 space-y-5">
            <PrefRow
              label="Email alerts"
              description="Receive an email summary of new security events (display preference only)."
              checked={prefs.emailAlerts}
              onChange={(v) => updatePref("emailAlerts", v)}
            />
            <PrefRow
              label="Download alerts"
              description="Show a toast notification when one of your files is downloaded."
              checked={prefs.downloadAlerts}
              onChange={(v) => updatePref("downloadAlerts", v)}
            />
            <p className="text-xs text-muted-foreground">
              These preferences are stored locally on this device and control in-app display only.
            </p>
          </div>
        </TabsContent>

        <TabsContent value="danger">
          <div className="rounded-xl border border-destructive/30 bg-destructive/5 p-6 space-y-5">
            <div className="flex items-start justify-between gap-4 flex-wrap">
              <div>
                <p className="text-foreground font-semibold text-sm flex items-center gap-2">
                  <LogOut size={14} className="text-destructive" /> Revoke all sessions
                </p>
                <p className="text-muted-foreground text-xs mt-1 max-w-md">
                  Signs out every active session on every device, including this one on next request.
                </p>
              </div>
              <button
                type="button"
                onClick={handleRevokeAllSessions}
                disabled={revoking}
                className="px-4 py-2 text-sm font-semibold text-destructive bg-destructive/10 hover:bg-destructive/20 rounded-lg disabled:opacity-50 shrink-0"
              >
                {revoking ? "Revoking..." : "Revoke All"}
              </button>
            </div>

            <div className="flex items-start justify-between gap-4 flex-wrap pt-5 border-t border-destructive/20">
              <div>
                <p className="text-foreground font-semibold text-sm flex items-center gap-2">
                  <Trash2 size={14} className="text-destructive" /> Clear local encryption keys
                </p>
                <p className="text-muted-foreground text-xs mt-1 max-w-md">
                  Removes your encrypted private keys from this device&apos;s storage. You&apos;ll need your account password to set them up again next time you upload or decrypt a file here.
                </p>
              </div>
              <button
                type="button"
                onClick={handleClearLocalKeys}
                disabled={clearingKeys}
                className="px-4 py-2 text-sm font-semibold text-destructive bg-destructive/10 hover:bg-destructive/20 rounded-lg disabled:opacity-50 shrink-0"
              >
                {clearingKeys ? "Clearing..." : "Clear Keys"}
              </button>
            </div>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}

function PrefRow({
  label,
  description,
  checked,
  onChange,
}: {
  label: string;
  description: string;
  checked: boolean;
  onChange: (value: boolean) => void;
}) {
  return (
    <div className="flex items-start justify-between gap-4">
      <div>
        <p className="text-foreground font-medium text-sm">{label}</p>
        <p className="text-muted-foreground text-xs mt-0.5 max-w-md">{description}</p>
      </div>
      <Switch checked={checked} onCheckedChange={onChange} />
    </div>
  );
}
