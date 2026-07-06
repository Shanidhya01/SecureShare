"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import api from "@/lib/api";
import { RequireRole } from "@/components/rbac/RoleGuard";
import { FileText, Download, ArrowLeft } from "lucide-react";
import toast from "react-hot-toast";
import PageHeader from "@/components/design/PageHeader";

function CloudReportsPageContent() {
  const router = useRouter();
  const [ready, setReady] = useState(false);

  useEffect(() => {
    const checkAccess = () => {
      const token = localStorage.getItem("token");
      if (!token) {
        router.push("/login");
        return;
      }
      setReady(true);
    };
    checkAccess();
  }, [router]);

  const handleExport = async (format: "csv" | "json" | "pdf") => {
    try {
      const token = localStorage.getItem("token");
      const res = await api.get(`/cloud/export/${format}`, {
        headers: { Authorization: `Bearer ${token}` },
        responseType: "blob",
      });
      const url = window.URL.createObjectURL(new Blob([res.data]));
      const a = document.createElement("a");
      a.href = url;
      a.download = `cloud-security-report-${Date.now()}.${format}`;
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
        title="Cloud Security Reports"
        description="Export the current asset inventory, open findings, and certificate status as a point-in-time report."
        accent="purple"
        actions={
          <Link href="/cloud-security" className="flex items-center gap-1.5 px-3 py-2 bg-card border border-border rounded-lg text-xs hover:bg-muted">
            <ArrowLeft size={14} /> Back to Dashboard
          </Link>
        }
      />

      <div className="rounded-xl border border-border bg-card p-6 max-w-xl">
        <h3 className="text-sm font-semibold text-foreground mb-4">Export Formats</h3>
        <div className="flex flex-col gap-3">
          <button onClick={() => handleExport("csv")} className="flex items-center justify-center gap-2 px-4 py-3 bg-card border border-border rounded-lg text-sm hover:bg-muted">
            <Download size={16} /> Download CSV
          </button>
          <button onClick={() => handleExport("json")} className="flex items-center justify-center gap-2 px-4 py-3 bg-card border border-border rounded-lg text-sm hover:bg-muted">
            <Download size={16} /> Download JSON
          </button>
          <button onClick={() => handleExport("pdf")} className="flex items-center justify-center gap-2 px-4 py-3 bg-primary text-primary-foreground rounded-lg text-sm font-semibold">
            <Download size={16} /> Download PDF
          </button>
        </div>
      </div>
    </div>
  );
}

export default function CloudReportsPage() {
  return (
    <RequireRole role="admin">
      <CloudReportsPageContent />
    </RequireRole>
  );
}
