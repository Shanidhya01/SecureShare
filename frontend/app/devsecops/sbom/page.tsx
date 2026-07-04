"use client";

import { useEffect, useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import api from "@/lib/api";
import { getIsAdminFromToken } from "@/lib/auth";
import { Boxes, AlertCircle, ArrowLeft, Download } from "lucide-react";
import toast from "react-hot-toast";
import PageHeader from "@/components/design/PageHeader";
import StatusBadge from "@/components/design/StatusBadge";
import DataTable, { type DataTableColumn } from "@/components/design/DataTable";
import { TableSkeleton } from "@/components/design/Skeletons";
import { apiErrorStatus } from "@/lib/errors";

type Sbom = { _id: string; format: string; serialization: string; componentCount: number; filename: string; createdAt: string };

export default function DevSecOpsSbomPage() {
  const router = useRouter();
  const [sboms, setSboms] = useState<Sbom[]>([]);
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState(false);
  const [error, setError] = useState("");

  const authHeader = () => ({ headers: { Authorization: `Bearer ${localStorage.getItem("token")}` } });

  const fetchSboms = useCallback(
    async (token: string) => {
      try {
        setLoading(true);
        const res = await api.get<Sbom[]>("/devsecops/sbom", { headers: { Authorization: `Bearer ${token}` } });
        setSboms(res.data || []);
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
        setError("Failed to load SBOM documents");
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
      toast.error("Admin access required for DevSecOps");
      router.push("/dashboard");
      return;
    }
    fetchSboms(token);
  }, [fetchSboms, router]);

  const generate = async (format: "CycloneDX" | "SPDX", serialization: "JSON" | "XML") => {
    try {
      setGenerating(true);
      await api.post("/devsecops/sbom", { format, serialization }, authHeader());
      toast.success(`${format} SBOM (${serialization}) generated`);
      const token = localStorage.getItem("token");
      if (token) await fetchSboms(token);
    } catch {
      toast.error("Failed to generate SBOM");
    } finally {
      setGenerating(false);
    }
  };

  const columns: DataTableColumn<Sbom>[] = [
    { key: "format", header: "Format", render: (s) => <StatusBadge label={s.format} tone="info" /> },
    { key: "serialization", header: "Serialization", render: (s) => <span className="text-xs">{s.serialization}</span> },
    { key: "componentCount", header: "Components", render: (s) => s.componentCount },
    { key: "filename", header: "Filename", render: (s) => <span className="text-xs text-muted-foreground">{s.filename}</span> },
    { key: "createdAt", header: "Generated", render: (s) => <span className="text-xs text-muted-foreground">{new Date(s.createdAt).toLocaleString()}</span> },
  ];

  return (
    <div>
      <PageHeader
        icon={Boxes}
        title="Software Bill of Materials"
        description="CycloneDX and SPDX SBOM generation from this repo's real package-lock.json dependency trees."
        accent="purple"
        actions={
          <Link href="/devsecops" className="flex items-center gap-1.5 px-3 py-2 bg-card border border-border rounded-lg text-xs hover:bg-muted">
            <ArrowLeft size={14} /> Back to Dashboard
          </Link>
        }
      />

      <div className="mb-6 rounded-xl border border-border bg-card p-6">
        <h3 className="text-sm font-semibold text-foreground mb-4">Generate a New SBOM</h3>
        <div className="flex flex-wrap gap-2">
          <button disabled={generating} onClick={() => generate("CycloneDX", "JSON")} className="flex items-center gap-1.5 px-3 py-2 bg-primary text-primary-foreground rounded-lg text-xs font-semibold disabled:opacity-50">
            <Download size={14} /> CycloneDX (JSON)
          </button>
          <button disabled={generating} onClick={() => generate("CycloneDX", "XML")} className="flex items-center gap-1.5 px-3 py-2 bg-card border border-border rounded-lg text-xs hover:bg-muted disabled:opacity-50">
            <Download size={14} /> CycloneDX (XML)
          </button>
          <button disabled={generating} onClick={() => generate("SPDX", "JSON")} className="flex items-center gap-1.5 px-3 py-2 bg-card border border-border rounded-lg text-xs hover:bg-muted disabled:opacity-50">
            <Download size={14} /> SPDX (JSON)
          </button>
        </div>
      </div>

      {error && (
        <div className="mb-6 p-4 bg-destructive/10 border border-destructive/30 rounded-lg flex items-center gap-2">
          <AlertCircle className="text-destructive" size={18} />
          <p className="text-destructive text-sm">{error}</p>
        </div>
      )}

      {loading ? <TableSkeleton /> : <DataTable columns={columns} rows={sboms} rowKey={(s) => s._id} emptyLabel="No SBOM generated yet." />}
    </div>
  );
}
