"use client";

import { ShieldAlert } from "lucide-react";
import DataTable, { type DataTableColumn } from "@/components/design/DataTable";
import EmptyState from "@/components/design/EmptyState";
import StatusBadge from "@/components/design/StatusBadge";
import { SEVERITY_TONE, CATEGORY_LABELS, type Severity } from "@/lib/severity";

export type Incident = {
  id: string;
  ruleId: string;
  title: string;
  summary?: string;
  category: string | null;
  severity: Severity;
  status: "open" | "investigating" | "resolved";
  fileId: string | null;
  eventCount: number;
  firstEventAt: string;
  lastEventAt: string;
};

const statusTone: Record<Incident["status"], "warning" | "info" | "success"> = {
  open: "warning",
  investigating: "info",
  resolved: "success",
};

export default function IncidentList({ incidents, onSelect }: { incidents: Incident[]; onSelect?: (incident: Incident) => void }) {
  if (incidents.length === 0) {
    return <EmptyState icon={ShieldAlert} title="No incidents" description="No related events have been automatically grouped into an incident yet." />;
  }

  const columns: DataTableColumn<Incident>[] = [
    { key: "severity", header: "Severity", render: (i) => <StatusBadge label={i.severity} tone={SEVERITY_TONE[i.severity]} /> },
    { key: "status", header: "Status", render: (i) => <StatusBadge label={i.status} tone={statusTone[i.status]} /> },
    {
      key: "title",
      header: "Incident",
      render: (i) => (
        <button
          type="button"
          onClick={() => onSelect?.(i)}
          className="max-w-md text-left hover:underline decoration-primary/60 underline-offset-2"
        >
          <p className="font-medium text-foreground truncate">{i.title}</p>
          {i.summary && <p className="text-xs text-muted-foreground truncate">{i.summary}</p>}
        </button>
      ),
    },
    { key: "category", header: "Category", render: (i) => (i.category ? CATEGORY_LABELS[i.category] || i.category : "-") },
    { key: "eventCount", header: "Events", className: "text-right", render: (i) => i.eventCount },
    { key: "lastEventAt", header: "Last Activity", className: "whitespace-nowrap text-xs text-muted-foreground", render: (i) => new Date(i.lastEventAt).toLocaleString() },
  ];

  return <DataTable columns={columns} rows={incidents} rowKey={(i) => i.id} />;
}
