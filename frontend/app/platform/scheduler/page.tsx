"use client";

import { useEffect, useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import api from "@/lib/api";
import { getIsAdminFromToken } from "@/lib/auth";
import { CalendarClock, Play, Pause, PlayCircle } from "lucide-react";
import toast from "react-hot-toast";
import PageHeader from "@/components/design/PageHeader";
import StatusBadge, { type StatusTone } from "@/components/design/StatusBadge";
import DataTable, { type DataTableColumn } from "@/components/design/DataTable";
import { TableSkeleton } from "@/components/design/Skeletons";
import { apiErrorStatus } from "@/lib/errors";

type ScheduledJob = {
  key: string;
  label: string;
  cronExpression: string;
  enabled: boolean;
  lastRunAt: string | null;
  lastDurationMs: number | null;
  lastStatus: "success" | "failed" | "never_run";
  lastError?: string;
  nextRunAt: string | null;
  failureCount: number;
};

const STATUS_TONE: Record<string, StatusTone> = { success: "success", failed: "danger", never_run: "neutral" };

export default function SchedulerPage() {
  const router = useRouter();
  const [jobs, setJobs] = useState<ScheduledJob[]>([]);
  const [loading, setLoading] = useState(true);
  const [busyKey, setBusyKey] = useState<string | null>(null);

  const authHeader = () => ({ headers: { Authorization: `Bearer ${localStorage.getItem("token")}` } });

  const fetchJobs = useCallback(async () => {
    try {
      setLoading(true);
      const res = await api.get<ScheduledJob[]>("/platform/scheduler", authHeader());
      setJobs(res.data);
    } catch (err: unknown) {
      const status = apiErrorStatus(err);
      if (status === 401) return router.push("/login");
      if (status === 403) {
        toast.error("Admin access required");
        return router.push("/dashboard");
      }
      toast.error("Failed to load scheduled jobs");
    } finally {
      setLoading(false);
    }
  }, [router]);

  useEffect(() => {
    const token = localStorage.getItem("token");
    if (!token || !getIsAdminFromToken(token)) {
      router.push(token ? "/dashboard" : "/login");
      return;
    }
    fetchJobs();
  }, [fetchJobs, router]);

  const act = async (key: string, action: "run" | "pause" | "resume") => {
    try {
      setBusyKey(key);
      const path = action === "run" ? "run-now" : action;
      await api.post(`/platform/scheduler/${path}`, { key }, authHeader());
      toast.success(`Job ${action === "run" ? "triggered" : action + "d"}`);
      await fetchJobs();
    } catch {
      toast.error(`Failed to ${action} job`);
    } finally {
      setBusyKey(null);
    }
  };

  const columns: DataTableColumn<ScheduledJob>[] = [
    { key: "label", header: "Job", render: (j) => <span className="text-sm font-medium">{j.label}</span> },
    { key: "cronExpression", header: "Schedule", render: (j) => <span className="text-xs font-mono text-muted-foreground">{j.cronExpression}</span> },
    { key: "enabled", header: "Enabled", render: (j) => <StatusBadge label={j.enabled ? "Enabled" : "Paused"} tone={j.enabled ? "success" : "neutral"} /> },
    { key: "lastStatus", header: "Last Status", render: (j) => <StatusBadge label={j.lastStatus} tone={STATUS_TONE[j.lastStatus]} /> },
    { key: "lastRunAt", header: "Last Run", render: (j) => <span className="text-xs text-muted-foreground">{j.lastRunAt ? new Date(j.lastRunAt).toLocaleString() : "Never"}</span> },
    { key: "lastDurationMs", header: "Duration", render: (j) => <span className="text-xs text-muted-foreground">{j.lastDurationMs != null ? `${j.lastDurationMs}ms` : "—"}</span> },
    { key: "nextRunAt", header: "Next Run", render: (j) => <span className="text-xs text-muted-foreground">{j.nextRunAt ? new Date(j.nextRunAt).toLocaleString() : "—"}</span> },
    { key: "failureCount", header: "Failures", render: (j) => <span className="text-xs">{j.failureCount}</span> },
    {
      key: "actions",
      header: "Actions",
      render: (j) => (
        <div className="flex gap-1.5">
          <button disabled={busyKey === j.key} onClick={() => act(j.key, "run")} className="p-1.5 rounded-md border border-border hover:bg-muted disabled:opacity-50" title="Run Now">
            <PlayCircle size={14} />
          </button>
          {j.enabled ? (
            <button disabled={busyKey === j.key} onClick={() => act(j.key, "pause")} className="p-1.5 rounded-md border border-border hover:bg-muted disabled:opacity-50" title="Pause">
              <Pause size={14} />
            </button>
          ) : (
            <button disabled={busyKey === j.key} onClick={() => act(j.key, "resume")} className="p-1.5 rounded-md border border-border hover:bg-muted disabled:opacity-50" title="Resume">
              <Play size={14} />
            </button>
          )}
        </div>
      )
    }
  ];

  return (
    <div>
      <PageHeader icon={CalendarClock} title="Scheduler" description="Scheduled scans and platform jobs - run now, pause, or resume. Admin only." accent="primary" />
      {loading ? <TableSkeleton /> : <DataTable columns={columns} rows={jobs} rowKey={(j) => j.key} emptyLabel="No scheduled jobs registered yet." />}
    </div>
  );
}
