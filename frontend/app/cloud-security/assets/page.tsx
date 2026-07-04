"use client";

import { useEffect, useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import api from "@/lib/api";
import { getIsAdminFromToken } from "@/lib/auth";
import { ServerCog, AlertCircle, ArrowLeft } from "lucide-react";
import toast from "react-hot-toast";
import PageHeader from "@/components/design/PageHeader";
import StatusBadge from "@/components/design/StatusBadge";
import DataTable, { type DataTableColumn } from "@/components/design/DataTable";
import { TableSkeleton } from "@/components/design/Skeletons";
import { apiErrorStatus } from "@/lib/errors";

type Asset = {
  _id: string;
  name: string;
  type: string;
  environment: string;
  criticality: string;
  riskScore: number;
  status: string;
  tags: string[];
  lastScan: string | null;
};

export default function CloudAssetsPage() {
  const router = useRouter();
  const [assets, setAssets] = useState<Asset[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const fetchAssets = useCallback(
    async (token: string) => {
      try {
        setLoading(true);
        const res = await api.get<Asset[]>("/cloud/assets", { headers: { Authorization: `Bearer ${token}` } });
        setAssets(res.data || []);
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
        setError("Failed to load cloud assets");
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
    if (!getIsAdminFromToken(token)) {
      toast.error("Admin access required for Cloud Security");
      router.push("/dashboard");
      return;
    }
    fetchAssets(token);
  }, [fetchAssets, router]);

  const columns: DataTableColumn<Asset>[] = [
    { key: "name", header: "Asset", render: (a) => <span className="text-xs font-medium">{a.name}</span> },
    { key: "type", header: "Type", render: (a) => <span className="text-xs text-muted-foreground">{a.type}</span> },
    { key: "environment", header: "Environment", render: (a) => <span className="text-xs">{a.environment}</span> },
    { key: "criticality", header: "Criticality", render: (a) => <StatusBadge label={a.criticality} tone={a.criticality === "critical" || a.criticality === "high" ? "danger" : a.criticality === "medium" ? "warning" : "neutral"} /> },
    { key: "riskScore", header: "Risk Score", render: (a) => `${a.riskScore}/100` },
    { key: "status", header: "Status", render: (a) => <StatusBadge label={a.status} tone={a.status === "active" ? "success" : "neutral"} /> },
    { key: "lastScan", header: "Last Scan", render: (a) => <span className="text-xs text-muted-foreground">{a.lastScan ? new Date(a.lastScan).toLocaleString() : "—"}</span> },
    { key: "actions", header: "", render: (a) => <Link href={`/cloud-security/assets/${a._id}`} className="text-xs text-primary hover:underline">View</Link> },
  ];

  return (
    <div>
      <PageHeader
        icon={ServerCog}
        title="Cloud Asset Inventory"
        description="Every server, service, endpoint, and dependency discovered by the CSPM/ASM scanner."
        accent="primary"
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

      {loading ? <TableSkeleton /> : <DataTable columns={columns} rows={assets} rowKey={(a) => a._id} stickyHeader maxHeight="75vh" emptyLabel="No assets discovered yet - run a scan from the dashboard." />}
    </div>
  );
}
