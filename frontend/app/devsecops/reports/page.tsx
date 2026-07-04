"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import api from "@/lib/api";
import { getIsAdminFromToken } from "@/lib/auth";
import { FileText, Download, ArrowLeft } from "lucide-react";
import toast from "react-hot-toast";
import PageHeader from "@/components/design/PageHeader";

const REPORT_TYPES: { key: string; label: string }[] = [
  { key: "executive", label: "Executive Report" },
  { key: "sbom", label: "SBOM Report" },
  { key: "dependency", label: "Dependency Report" },
  { key: "secret", label: "Secret Report" },
  { key: "container", label: "Container Report" },
  { key: "pipeline", label: "Pipeline Report" },
];

function ReportCard({ reportKey, label, onExport }: { reportKey: string; label: string; onExport: (reportType: string, format: "csv" | "json" | "pdf") => void }) {
  return (
    <div className="rounded-xl border border-border bg-card p-6">
      <h3 className="text-sm font-semibold text-foreground mb-4">{label}</h3>
      <div className="flex flex-wrap gap-2">
        <button onClick={() => onExport(reportKey, "csv")} className="flex items-center gap-1.5 px-3 py-2 bg-card border border-border rounded-lg text-xs hover:bg-muted">
          <Download size={14} /> CSV
        </button>
        <button onClick={() => onExport(reportKey, "json")} className="flex items-center gap-1.5 px-3 py-2 bg-card border border-border rounded-lg text-xs hover:bg-muted">
          <Download size={14} /> JSON
        </button>
        <button onClick={() => onExport(reportKey, "pdf")} className="flex items-center gap-1.5 px-3 py-2 bg-primary text-primary-foreground rounded-lg text-xs font-semibold">
          <Download size={14} /> PDF
        </button>
      </div>
    </div>
  );
}

export default function DevSecOpsReportsPage() {
  const router = useRouter();
  const [ready] = useState(() => typeof window !== "undefined" && !!localStorage.getItem("token") && getIsAdminFromToken(localStorage.getItem("token") as string));

  useEffect(() => {
    const token = localStorage.getItem("token");
    if (!token) {
      router.push("/login");
      return;
    }
    if (!getIsAdminFromToken(token)) {
      toast.error("Admin access required for DevSecOps");
      router.push("/dashboard");
    }
  }, [router]);

  const handleExport = async (reportType: string, format: "csv" | "json" | "pdf") => {
    try {
      const token = localStorage.getItem("token");
      const res = await api.get(`/devsecops/export/${format}`, {
        params: { reportType },
        headers: { Authorization: `Bearer ${token}` },
        responseType: "blob",
      });
      const url = window.URL.createObjectURL(new Blob([res.data]));
      const a = document.createElement("a");
      a.href = url;
      a.download = `devsecops-${reportType}-report-${Date.now()}.${format}`;
      a.click();
      window.URL.revokeObjectURL(url);
      toast.success("Report generated");
    } catch {
      toast.error("Failed to generate report");
    }
  };

  if (!ready) return null;

  return (
    <div>
      <PageHeader
        icon={FileText}
        title="DevSecOps Reports"
        description="Export executive, SBOM, dependency, secret, container, and pipeline reports."
        accent="purple"
        actions={
          <Link href="/devsecops" className="flex items-center gap-1.5 px-3 py-2 bg-card border border-border rounded-lg text-xs hover:bg-muted">
            <ArrowLeft size={14} /> Back to Dashboard
          </Link>
        }
      />

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {REPORT_TYPES.map((report) => (
          <ReportCard key={report.key} reportKey={report.key} label={report.label} onExport={handleExport} />
        ))}
      </div>
    </div>
  );
}
