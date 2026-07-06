"use client";

import { useEffect, useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import api from "@/lib/api";
import { RequireRole } from "@/components/rbac/RoleGuard";
import { Archive, ShieldCheck, Play } from "lucide-react";
import toast from "react-hot-toast";
import PageHeader from "@/components/design/PageHeader";
import StatusBadge, { type StatusTone } from "@/components/design/StatusBadge";
import DataTable, { type DataTableColumn } from "@/components/design/DataTable";
import { TableSkeleton } from "@/components/design/Skeletons";
import { apiErrorStatus } from "@/lib/errors";

type Backup = {
  _id: string;
  type: string;
  filename: string;
  sizeBytes?: number;
  status: "completed" | "failed";
  validated: boolean;
  createdAt: string;
};

const TYPES = ["database", "configuration", "metadata", "audit", "full"];

function BackupsPageContent() {
  const router = useRouter();
  const [backups, setBackups] = useState<Backup[]>([]);
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState<string | null>(null);
  const [validating, setValidating] = useState<string | null>(null);

  const authHeader = () => ({ headers: { Authorization: `Bearer ${localStorage.getItem("token")}` } });

  const fetchBackups = useCallback(async () => {
    try {
      setLoading(true);
      const res = await api.get<Backup[]>("/platform/backup", authHeader());
      setBackups(res.data);
    } catch (err: unknown) {
      const status = apiErrorStatus(err);
      if (status === 401) return router.push("/login");
      if (status === 403) {
        toast.error("Admin access required");
        return router.push("/dashboard");
      }
      toast.error("Failed to load backups");
    } finally {
      setLoading(false);
    }
  }, [router]);

  useEffect(() => {
    const token = localStorage.getItem("token");
    if (!token) {
      router.push("/login");
      return;
    }
    fetchBackups();
  }, [fetchBackups, router]);

  const runBackup = async (type: string) => {
    try {
      setRunning(type);
      await api.post("/platform/backup", { type }, authHeader());
      toast.success(`${type} backup completed`);
      await fetchBackups();
    } catch {
      toast.error(`Failed to run ${type} backup`);
    } finally {
      setRunning(null);
    }
  };

  const validate = async (backupId: string) => {
    try {
      setValidating(backupId);
      const res = await api.post("/platform/backup/validate", { backupId }, authHeader());
      toast[res.data.valid ? "success" : "error"](res.data.valid ? "Backup checksum valid" : "Backup checksum invalid");
      await fetchBackups();
    } catch {
      toast.error("Validation failed");
    } finally {
      setValidating(null);
    }
  };

  const columns: DataTableColumn<Backup>[] = [
    { key: "type", header: "Type", render: (b) => <span className="text-sm font-medium capitalize">{b.type}</span> },
    { key: "filename", header: "File", render: (b) => <span className="text-xs font-mono text-muted-foreground">{b.filename || "—"}</span> },
    { key: "sizeBytes", header: "Size", render: (b) => <span className="text-xs">{b.sizeBytes ? `${(b.sizeBytes / 1024).toFixed(1)} KB` : "—"}</span> },
    { key: "status", header: "Status", render: (b) => <StatusBadge label={b.status} tone={(b.status === "completed" ? "success" : "danger") as StatusTone} /> },
    { key: "validated", header: "Validated", render: (b) => <StatusBadge label={b.validated ? "Valid" : "Unvalidated"} tone={(b.validated ? "success" : "neutral") as StatusTone} /> },
    { key: "createdAt", header: "Created", render: (b) => <span className="text-xs text-muted-foreground">{new Date(b.createdAt).toLocaleString()}</span> },
    {
      key: "actions",
      header: "Actions",
      render: (b) => (
        <button disabled={validating === b._id} onClick={() => validate(b._id)} className="flex items-center gap-1 px-2 py-1 rounded-md border border-border hover:bg-muted text-xs disabled:opacity-50">
          <ShieldCheck size={12} /> Validate
        </button>
      )
    }
  ];

  return (
    <div>
      <PageHeader
        icon={Archive}
        title="Backup Manager"
        description="Database, configuration, metadata, and audit backups. No destructive restore is provided - validation only re-checks the archive's checksum."
        accent="primary"
        actions={
          <div className="flex gap-2 flex-wrap">
            {TYPES.map((t) => (
              <button key={t} disabled={running === t} onClick={() => runBackup(t)} className="flex items-center gap-1.5 px-3 py-2 bg-primary text-primary-foreground rounded-lg text-xs font-semibold disabled:opacity-50 capitalize">
                <Play size={12} /> {running === t ? "Running..." : t}
              </button>
            ))}
          </div>
        }
      />
      {loading ? <TableSkeleton /> : <DataTable columns={columns} rows={backups} rowKey={(b) => b._id} emptyLabel="No backups have been created yet." />}
    </div>
  );
}

export default function BackupsPage() {
  return (
    <RequireRole role="admin">
      <BackupsPageContent />
    </RequireRole>
  );
}
