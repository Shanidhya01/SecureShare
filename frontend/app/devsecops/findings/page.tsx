"use client";

import { useEffect, useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import api from "@/lib/api";
import { RequireRole } from "@/components/rbac/RoleGuard";
import { ShieldAlert, AlertCircle, ArrowLeft } from "lucide-react";
import toast from "react-hot-toast";
import PageHeader from "@/components/design/PageHeader";
import StatusBadge, { type StatusTone } from "@/components/design/StatusBadge";
import DataTable, { type DataTableColumn } from "@/components/design/DataTable";
import { TableSkeleton } from "@/components/design/Skeletons";
import { apiErrorStatus } from "@/lib/errors";

type Finding = {
  _id: string;
  category: string;
  ruleId: string;
  title: string;
  severity: string;
  status: string;
  file?: string;
  line?: number;
  package?: string;
  recommendation?: string;
  detectedAt: string;
};

const SEVERITY_TONE: Record<string, StatusTone> = { CRITICAL: "danger", HIGH: "danger", MEDIUM: "warning", LOW: "info", INFO: "neutral" };
const CATEGORIES = ["DEPENDENCY", "SECRET", "SAST", "CONTAINER", "IAC"] as const;
const ENDPOINT_BY_CATEGORY: Record<string, string> = {
  DEPENDENCY: "/devsecops/dependencies",
  SECRET: "/devsecops/secrets",
  SAST: "/devsecops/sast",
  CONTAINER: "/devsecops/container",
  IAC: "/devsecops/iac",
};

function DevSecOpsFindingsPageContent() {
  const router = useRouter();
  const [category, setCategory] = useState<string>("DEPENDENCY");
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const fetchFindings = useCallback(
    async (token: string, cat: string) => {
      try {
        setLoading(true);
        const res = await api.get<Finding[]>(ENDPOINT_BY_CATEGORY[cat], { headers: { Authorization: `Bearer ${token}` } });
        setFindings(res.data || []);
      } catch (err: unknown) {
        const status = apiErrorStatus(err);
        if (status === 401) {
          router.push("/login");
          return;
        }
        if (status === 403) {
          toast.error("Admin access required for DevSecOps");
          router.push("/dashboard");
          return;
        }
        setError("Failed to load findings");
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
    fetchFindings(token, category);
  }, [fetchFindings, router, category]);

  const columns: DataTableColumn<Finding>[] = [
    { key: "title", header: "Finding", render: (f) => <span className="text-xs font-medium">{f.title}</span> },
    { key: "location", header: "Location", render: (f) => <span className="text-xs text-muted-foreground">{f.package || (f.file ? `${f.file}${f.line ? `:${f.line}` : ""}` : "—")}</span> },
    { key: "severity", header: "Severity", render: (f) => <StatusBadge label={f.severity} tone={SEVERITY_TONE[f.severity] || "neutral"} /> },
    { key: "status", header: "Status", render: (f) => <StatusBadge label={f.status} tone={f.status === "resolved" ? "success" : f.status === "acknowledged" ? "warning" : "danger"} /> },
    { key: "detectedAt", header: "Detected", render: (f) => <span className="text-xs text-muted-foreground">{new Date(f.detectedAt).toLocaleString()}</span> },
  ];

  return (
    <div>
      <PageHeader
        icon={ShieldAlert}
        title="DevSecOps Findings"
        description="Dependency, secret, SAST, container, and IaC findings from the supply-chain scanner."
        accent="danger"
        actions={
          <Link href="/devsecops" className="flex items-center gap-1.5 px-3 py-2 bg-card border border-border rounded-lg text-xs hover:bg-muted">
            <ArrowLeft size={14} /> Back to Dashboard
          </Link>
        }
      />

      <div className="mb-6 flex flex-wrap gap-2">
        {CATEGORIES.map((cat) => (
          <button
            key={cat}
            onClick={() => setCategory(cat)}
            className={`px-3 py-1.5 rounded-lg border text-xs font-medium ${category === cat ? "bg-primary text-primary-foreground border-primary" : "bg-card border-border hover:bg-muted"}`}
          >
            {cat}
          </button>
        ))}
      </div>

      {error && (
        <div className="mb-6 p-4 bg-destructive/10 border border-destructive/30 rounded-lg flex items-center gap-2">
          <AlertCircle className="text-destructive" size={18} />
          <p className="text-destructive text-sm">{error}</p>
        </div>
      )}

      {loading ? <TableSkeleton /> : <DataTable columns={columns} rows={findings} rowKey={(f) => f._id} stickyHeader maxHeight="70vh" emptyLabel="No open findings in this category - run a scan from the dashboard." />}
    </div>
  );
}

export default function DevSecOpsFindingsPage() {
  return (
    <RequireRole role="admin">
      <DevSecOpsFindingsPageContent />
    </RequireRole>
  );
}
