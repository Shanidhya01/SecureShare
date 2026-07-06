"use client";

import { useEffect, useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import api from "@/lib/api";
import { RequireRole } from "@/components/rbac/RoleGuard";
import { Lock, AlertCircle, ArrowLeft } from "lucide-react";
import toast from "react-hot-toast";
import PageHeader from "@/components/design/PageHeader";
import StatusBadge, { type StatusTone } from "@/components/design/StatusBadge";
import DataTable, { type DataTableColumn } from "@/components/design/DataTable";
import { TableSkeleton } from "@/components/design/Skeletons";
import { apiErrorStatus } from "@/lib/errors";

type Certificate = {
  _id: string;
  domain: string;
  issuer: string;
  status: string;
  daysRemaining: number | null;
  algorithm: string;
  tlsVersion: string;
  cipher: string;
  validTo: string | null;
  lastCheckedAt: string | null;
};

const STATUS_TONE: Record<string, StatusTone> = { valid: "success", expiring: "warning", expired: "danger", unreachable: "neutral" };

function CloudCertificatesPageContent() {
  const router = useRouter();
  const [certificates, setCertificates] = useState<Certificate[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const fetchCertificates = useCallback(
    async (token: string) => {
      try {
        setLoading(true);
        const res = await api.get<Certificate[]>("/cloud/certificates", { headers: { Authorization: `Bearer ${token}` } });
        setCertificates(res.data || []);
      } catch (err: unknown) {
        const status = apiErrorStatus(err);
        if (status === 401) {
          router.push("/login");
          return;
        }
        if (status === 403) {
          toast.error("Admin access required for Cloud Security");
          router.push("/dashboard");
          return;
        }
        setError("Failed to load certificates");
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
    fetchCertificates(token);
  }, [fetchCertificates, router]);

  const columns: DataTableColumn<Certificate>[] = [
    { key: "domain", header: "Domain", render: (c) => <span className="text-xs font-medium">{c.domain}</span> },
    { key: "issuer", header: "Issuer", render: (c) => <span className="text-xs text-muted-foreground">{c.issuer || "—"}</span> },
    { key: "status", header: "Status", render: (c) => <StatusBadge label={c.status} tone={STATUS_TONE[c.status] || "neutral"} /> },
    { key: "daysRemaining", header: "Days Remaining", render: (c) => (c.daysRemaining ?? "—") },
    { key: "tlsVersion", header: "TLS Version", render: (c) => <span className="text-xs">{c.tlsVersion || "—"}</span> },
    { key: "validTo", header: "Valid To", render: (c) => <span className="text-xs text-muted-foreground">{c.validTo ? new Date(c.validTo).toLocaleDateString() : "—"}</span> },
    { key: "lastCheckedAt", header: "Last Checked", render: (c) => <span className="text-xs text-muted-foreground">{c.lastCheckedAt ? new Date(c.lastCheckedAt).toLocaleString() : "—"}</span> },
  ];

  return (
    <div>
      <PageHeader
        icon={Lock}
        title="Certificate Monitoring"
        description="TLS certificates tracked across every monitored domain, with 30/15/7-day and expired alerting."
        accent="warning"
        actions={
          <Link href="/cloud-security" className="flex items-center gap-1.5 px-3 py-2 bg-card border border-border rounded-lg text-xs hover:bg-muted">
            <ArrowLeft size={14} /> Back to Dashboard
          </Link>
        }
      />

      {error && (
        <div className="mb-6 p-4 bg-destructive/10 border border-destructive/30 rounded-lg flex items-center gap-2">
          <AlertCircle className="text-destructive" size={18} />
          <p className="text-destructive text-sm">{error}</p>
        </div>
      )}

      {loading ? (
        <TableSkeleton />
      ) : (
        <DataTable
          columns={columns}
          rows={certificates}
          rowKey={(c) => c._id}
          emptyLabel="No certificates monitored yet - set CLOUD_MONITORED_DOMAINS or WEBAUTHN_ORIGIN and run a scan."
        />
      )}
    </div>
  );
}

export default function CloudCertificatesPage() {
  return (
    <RequireRole role="admin">
      <CloudCertificatesPageContent />
    </RequireRole>
  );
}
