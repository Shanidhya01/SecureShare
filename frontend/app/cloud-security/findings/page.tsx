"use client";

import { useEffect, useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import api from "@/lib/api";
import { RequireRole } from "@/components/rbac/RoleGuard";
import { ShieldAlert, AlertCircle, ArrowLeft, Check } from "lucide-react";
import toast from "react-hot-toast";
import PageHeader from "@/components/design/PageHeader";
import StatusBadge, { type StatusTone } from "@/components/design/StatusBadge";
import DataTable, { type DataTableColumn } from "@/components/design/DataTable";
import { TableSkeleton } from "@/components/design/Skeletons";
import { apiErrorStatus } from "@/lib/errors";

type Finding = {
  _id: string;
  asset: { name: string; type: string } | null;
  category: string;
  ruleId: string;
  title: string;
  severity: string;
  status: string;
  recommendation: string;
  reference: string;
  detectedAt: string;
};

const SEVERITY_TONE: Record<string, StatusTone> = { CRITICAL: "danger", HIGH: "danger", MEDIUM: "warning", LOW: "info", INFO: "neutral" };

function CloudFindingsPageContent() {
  const router = useRouter();
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const authHeader = () => ({ headers: { Authorization: `Bearer ${localStorage.getItem("token")}` } });

  const fetchFindings = useCallback(
    async (token: string) => {
      try {
        setLoading(true);
        const res = await api.get<Finding[]>("/cloud/findings", { headers: { Authorization: `Bearer ${token}` } });
        setFindings(res.data || []);
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
        setError("Failed to load cloud security findings");
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
    fetchFindings(token);
  }, [fetchFindings, router]);

  const resolveFinding = async (id: string) => {
    try {
      await api.post(`/cloud/findings/${id}/resolve`, {}, authHeader());
      setFindings((prev) => prev.filter((f) => f._id !== id));
      toast.success("Finding resolved");
    } catch {
      toast.error("Failed to resolve finding");
    }
  };

  const columns: DataTableColumn<Finding>[] = [
    { key: "category", header: "Category", render: (f) => <span className="text-xs text-muted-foreground">{f.category}</span> },
    { key: "title", header: "Finding", render: (f) => <span className="text-xs font-medium">{f.title}</span> },
    { key: "asset", header: "Asset", render: (f) => <span className="text-xs">{f.asset?.name || "—"}</span> },
    { key: "severity", header: "Severity", render: (f) => <StatusBadge label={f.severity} tone={SEVERITY_TONE[f.severity] || "neutral"} /> },
    { key: "detectedAt", header: "Detected", render: (f) => <span className="text-xs text-muted-foreground">{new Date(f.detectedAt).toLocaleString()}</span> },
    {
      key: "actions",
      header: "Actions",
      render: (f) => (
        <button onClick={() => resolveFinding(f._id)} className="flex items-center gap-1.5 px-2 py-1 bg-card border border-border rounded text-xs hover:bg-muted">
          <Check size={12} /> Resolve
        </button>
      ),
    },
  ];

  return (
    <div>
      <PageHeader
        icon={ShieldAlert}
        title="Configuration & Attack Surface Findings"
        description="Open findings from the configuration scanner, attack surface scan, and threat intelligence correlation."
        accent="danger"
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

      {loading ? <TableSkeleton /> : <DataTable columns={columns} rows={findings} rowKey={(f) => f._id} stickyHeader maxHeight="75vh" emptyLabel="No open findings - run a scan from the dashboard." />}
    </div>
  );
}

export default function CloudFindingsPage() {
  return (
    <RequireRole role="admin">
      <CloudFindingsPageContent />
    </RequireRole>
  );
}
