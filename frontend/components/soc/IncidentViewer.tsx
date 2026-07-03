"use client";

import { useEffect, useState } from "react";
import api from "@/lib/api";
import { FileText, Loader, ShieldAlert } from "lucide-react";
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import StatusBadge from "@/components/design/StatusBadge";
import EventTimeline, { type EventTimelineItem } from "@/components/design/EventTimeline";
import { SEVERITY_TONE, CATEGORY_LABELS, type Severity } from "@/lib/severity";
import type { Incident } from "@/components/soc/IncidentList";

type IncidentEvent = {
  id: string;
  type: string;
  siemType: string | null;
  severity: Severity;
  category: string | null;
  message: string;
  filename: string | null;
  fileId: string | null;
  deviceId: string | null;
  ip: string | null;
  country: string | null;
  metadata: Record<string, unknown> | null;
  createdAt: string;
};

type IncidentDetail = Incident & { events: IncidentEvent[] };

const statusTone: Record<Incident["status"], "warning" | "info" | "success"> = {
  open: "warning",
  investigating: "info",
  resolved: "success",
};

/** Phase 6 (SOC): drill-down view for a single Incident - title/severity/status, its chronological
 *  event timeline, per-event evidence (metadata), and the distinct files referenced. Fetches
 *  GET /api/siem/incidents/:id on open; purely a read view, no mutation. */
export default function IncidentViewer({ incidentId, onClose }: { incidentId: string | null; onClose: () => void }) {
  const [detail, setDetail] = useState<IncidentDetail | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!incidentId) return;
    let cancelled = false;

    const load = async () => {
      setLoading(true);
      const token = localStorage.getItem("token");
      try {
        const res = await api.get<IncidentDetail>(`/siem/incidents/${incidentId}`, { headers: { Authorization: `Bearer ${token}` } });
        if (!cancelled) setDetail(res.data);
      } catch {
        if (!cancelled) setDetail(null);
      } finally {
        if (!cancelled) setLoading(false);
      }
    };

    load();
    return () => {
      cancelled = true;
    };
  }, [incidentId]);

  const files = detail
    ? Array.from(
        new Map(
          detail.events.filter((e) => e.fileId).map((e) => [e.fileId as string, e.filename || e.fileId])
        ).entries()
      )
    : [];

  const timelineItems: EventTimelineItem[] =
    detail?.events.map((e) => ({
      key: e.id,
      icon: ["HIGH", "CRITICAL"].includes(e.severity) ? ShieldAlert : FileText,
      title: e.message,
      description: [e.filename, e.ip, e.country].filter(Boolean).join(" | ") || undefined,
      timestamp: e.createdAt,
      tone: SEVERITY_TONE[e.severity],
      badgeLabel: e.siemType || e.type,
    })) || [];

  return (
    <Sheet open={!!incidentId} onOpenChange={(open) => !open && onClose()}>
      <SheetContent side="right" className="w-full sm:max-w-xl overflow-y-auto p-0">
        <SheetHeader className="border-b border-border">
          <SheetTitle>Incident Details</SheetTitle>
        </SheetHeader>

        {loading && (
          <div className="flex items-center justify-center py-16 text-muted-foreground">
            <Loader size={20} className="animate-spin" />
          </div>
        )}

        {!loading && detail && (
          <div className="px-4 pb-6 space-y-6">
            <div>
              <div className="flex items-center gap-2 mb-2">
                <StatusBadge label={detail.severity} tone={SEVERITY_TONE[detail.severity]} />
                <StatusBadge label={detail.status} tone={statusTone[detail.status]} />
                {detail.category && <StatusBadge label={CATEGORY_LABELS[detail.category] || detail.category} tone="neutral" />}
              </div>
              <h3 className="text-lg font-semibold text-foreground">{detail.title}</h3>
              {detail.summary && <p className="text-sm text-muted-foreground mt-1">{detail.summary}</p>}
              <p className="text-xs text-muted-foreground mt-2">
                {detail.eventCount} event{detail.eventCount === 1 ? "" : "s"} - first seen {new Date(detail.firstEventAt).toLocaleString()}, last seen{" "}
                {new Date(detail.lastEventAt).toLocaleString()}
              </p>
            </div>

            {files.length > 0 && (
              <div>
                <h4 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground mb-2">Files</h4>
                <ul className="space-y-1">
                  {files.map(([id, name]) => (
                    <li key={id} className="text-sm text-foreground flex items-center gap-2">
                      <FileText size={14} className="text-muted-foreground" /> {name}
                    </li>
                  ))}
                </ul>
              </div>
            )}

            <div>
              <h4 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground mb-2">Timeline</h4>
              <EventTimeline items={timelineItems} />
            </div>

            <div>
              <h4 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground mb-2">Evidence</h4>
              <div className="space-y-2">
                {detail.events.map((e) => (
                  <details key={e.id} className="rounded-lg border border-border bg-card p-3">
                    <summary className="cursor-pointer text-sm text-foreground">{e.siemType || e.type}</summary>
                    <pre className="mt-2 text-xs text-muted-foreground overflow-x-auto whitespace-pre-wrap">
                      {JSON.stringify({ ip: e.ip, country: e.country, deviceId: e.deviceId, metadata: e.metadata }, null, 2)}
                    </pre>
                  </details>
                ))}
              </div>
            </div>
          </div>
        )}
      </SheetContent>
    </Sheet>
  );
}
