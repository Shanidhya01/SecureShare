"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { RequireRole } from "@/components/rbac/RoleGuard";
import api from "@/lib/api";
import { FileText, Download } from "lucide-react";
import toast from "react-hot-toast";
import PageHeader from "@/components/design/PageHeader";

const REPORT_TYPES = [
  { key: "health", label: "Platform Health Report" },
  { key: "availability", label: "Availability Report" },
  { key: "performance", label: "Performance Report" },
  { key: "queue", label: "Queue Report" },
  { key: "infrastructure", label: "Infrastructure Report" }
];
const FORMATS = ["pdf", "csv", "json"] as const;

function PlatformReportsPageContent() {
  const router = useRouter();
  const [generating, setGenerating] = useState<string | null>(null);

  useEffect(() => {
    const token = localStorage.getItem("token");
    if (!token) {
      router.push("/login");
    }
  }, [router]);

  const generate = async (reportType: string, format: (typeof FORMATS)[number]) => {
    const key = `${reportType}-${format}`;
    try {
      setGenerating(key);
      const token = localStorage.getItem("token");
      const res = await api.get(`/platform/export/${format}?reportType=${reportType}`, {
        headers: { Authorization: `Bearer ${token}` },
        responseType: "blob",
      });
      const url = window.URL.createObjectURL(new Blob([res.data]));
      const a = document.createElement("a");
      a.href = url;
      a.download = `platform-${reportType}-report-${Date.now()}.${format}`;
      a.click();
      window.URL.revokeObjectURL(url);
      toast.success("Report generated");
    } catch {
      toast.error("Failed to generate report");
    } finally {
      setGenerating(null);
    }
  };

  return (
    <div>
      <PageHeader icon={FileText} title="Platform Reports" description="Health, availability, performance, queue, and infrastructure reports in PDF, CSV, or JSON." accent="primary" />
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {REPORT_TYPES.map((r) => (
          <div key={r.key} className="rounded-xl border border-border bg-card p-5">
            <h3 className="text-sm font-semibold mb-3">{r.label}</h3>
            <div className="flex gap-2">
              {FORMATS.map((f) => {
                const key = `${r.key}-${f}`;
                return (
                  <button
                    key={f}
                    disabled={generating === key}
                    onClick={() => generate(r.key, f)}
                    className="flex items-center gap-1.5 px-3 py-1.5 bg-card border border-border rounded-lg text-xs hover:bg-muted disabled:opacity-50 uppercase"
                  >
                    <Download size={12} /> {generating === key ? "..." : f}
                  </button>
                );
              })}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function PlatformReportsPage() {
  return (
    <RequireRole role="admin">
      <PlatformReportsPageContent />
    </RequireRole>
  );
}
