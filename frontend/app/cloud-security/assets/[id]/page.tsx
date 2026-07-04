"use client";

import { useEffect, useState, useCallback } from "react";
import { useRouter, useParams } from "next/navigation";
import Link from "next/link";
import api from "@/lib/api";
import { getIsAdminFromToken } from "@/lib/auth";
import { ServerCog, AlertCircle, ArrowLeft } from "lucide-react";
import toast from "react-hot-toast";
import PageHeader from "@/components/design/PageHeader";
import StatusBadge, { type StatusTone } from "@/components/design/StatusBadge";
import DataTable, { type DataTableColumn } from "@/components/design/DataTable";
import EmptyState from "@/components/design/EmptyState";
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
  metadata: Record<string, unknown>;
  lastScan: string | null;
};
type Finding = { _id: string; category: string; ruleId: string; title: string; severity: string; status: string; recommendation: string; detectedAt: string };
type EventRow = { _id: string; siemType: string; message: string; severity: string; createdAt: string };
type IncidentRow = { _id: string; title: string; severity: string; status: string; lastEventAt: string; automationStatus: string };

const SEVERITY_TONE: Record<string, StatusTone> = { CRITICAL: "danger", HIGH: "danger", MEDIUM: "warning", LOW: "info", INFO: "neutral" };

export default function CloudAssetDetailPage() {
  const router = useRouter();
  const params = useParams<{ id: string }>();
  const [asset, setAsset] = useState<Asset | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [relatedEvents, setRelatedEvents] = useState<EventRow[]>([]);
  const [relatedIncidents, setRelatedIncidents] = useState<IncidentRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const fetchAsset = useCallback(
    async (token: string) => {
      try {
        setLoading(true);
        const res = await api.get(`/cloud/assets/${params.id}`, { headers: { Authorization: `Bearer ${token}` } });
        setAsset(res.data.asset);
        setFindings(res.data.findings || []);
        setRelatedEvents(res.data.relatedEvents || []);
        setRelatedIncidents(res.data.relatedIncidents || []);
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
        if (status === 404) {
          setError("Asset not found");
          return;
        }
        setError("Failed to load asset details");
      } finally {
        setLoading(false);
      }
    },
    [params.id, router]
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
    fetchAsset(token);
  }, [fetchAsset, router]);

  const findingColumns: DataTableColumn<Finding>[] = [
    { key: "category", header: "Category", render: (f) => <span className="text-xs text-muted-foreground">{f.category}</span> },
    { key: "title", header: "Finding", render: (f) => <span className="text-xs font-medium">{f.title}</span> },
    { key: "severity", header: "Severity", render: (f) => <StatusBadge label={f.severity} tone={SEVERITY_TONE[f.severity] || "neutral"} /> },
    { key: "status", header: "Status", render: (f) => <StatusBadge label={f.status} tone={f.status === "resolved" ? "success" : f.status === "acknowledged" ? "warning" : "danger"} /> },
    { key: "detectedAt", header: "Detected", render: (f) => <span className="text-xs text-muted-foreground">{new Date(f.detectedAt).toLocaleString()}</span> },
  ];

  const eventColumns: DataTableColumn<EventRow>[] = [
    { key: "siemType", header: "Event", render: (e) => <StatusBadge label={e.siemType || "—"} tone={SEVERITY_TONE[e.severity] || "neutral"} /> },
    { key: "message", header: "Message", render: (e) => <span className="text-xs max-w-md truncate inline-block">{e.message}</span> },
    { key: "createdAt", header: "When", render: (e) => <span className="text-xs text-muted-foreground">{new Date(e.createdAt).toLocaleString()}</span> },
  ];

  const incidentColumns: DataTableColumn<IncidentRow>[] = [
    { key: "title", header: "Incident", render: (i) => <span className="text-xs font-medium">{i.title}</span> },
    { key: "severity", header: "Severity", render: (i) => <StatusBadge label={i.severity} tone={SEVERITY_TONE[i.severity] || "neutral"} /> },
    { key: "status", header: "Status", render: (i) => <StatusBadge label={i.status} tone={i.status === "resolved" ? "success" : "warning"} /> },
    { key: "automationStatus", header: "SOAR", render: (i) => <span className="text-xs text-muted-foreground">{i.automationStatus}</span> },
    { key: "lastEventAt", header: "Last Event", render: (i) => <span className="text-xs text-muted-foreground">{new Date(i.lastEventAt).toLocaleString()}</span> },
  ];

  return (
    <div>
      <PageHeader
        icon={ServerCog}
        title={asset?.name || "Asset Details"}
        description={asset ? `${asset.type} · ${asset.environment} · risk score ${asset.riskScore}/100` : "Configuration, risk, and history for this cloud asset."}
        accent="primary"
        actions={
          <Link href="/cloud-security/assets" className="flex items-center gap-1.5 px-3 py-2 bg-card border border-border rounded-lg text-xs hover:bg-muted">
            <ArrowLeft size={14} /> Back to Assets
          </Link>
        }
      />

      {error && (
        <div className="mb-6 p-4 bg-destructive/10 border border-destructive/30 rounded-lg flex items-center gap-2">
          <AlertCircle className="text-destructive" size={18} />
          <p className="text-destructive text-sm">{error}</p>
        </div>
      )}

      {loading ? (
        <TableSkeleton />
      ) : asset ? (
        <div className="space-y-8">
          <div className="rounded-xl border border-border bg-card p-6 grid grid-cols-2 md:grid-cols-4 gap-4">
            <div>
              <p className="text-xs text-muted-foreground uppercase">Criticality</p>
              <StatusBadge label={asset.criticality} tone={asset.criticality === "critical" || asset.criticality === "high" ? "danger" : asset.criticality === "medium" ? "warning" : "neutral"} className="mt-1" />
            </div>
            <div>
              <p className="text-xs text-muted-foreground uppercase">Status</p>
              <StatusBadge label={asset.status} tone={asset.status === "active" ? "success" : "neutral"} className="mt-1" />
            </div>
            <div>
              <p className="text-xs text-muted-foreground uppercase">Last Scan</p>
              <p className="text-sm mt-1">{asset.lastScan ? new Date(asset.lastScan).toLocaleString() : "—"}</p>
            </div>
            <div>
              <p className="text-xs text-muted-foreground uppercase">Tags</p>
              <p className="text-sm mt-1">{asset.tags?.join(", ") || "—"}</p>
            </div>
          </div>

          <section>
            <h2 className="flex items-center gap-2 text-lg font-bold text-foreground mb-4">Configuration Metadata</h2>
            <pre className="rounded-xl border border-border bg-card p-4 text-xs overflow-x-auto">{JSON.stringify(asset.metadata || {}, null, 2)}</pre>
          </section>

          <section>
            <h2 className="text-lg font-bold text-foreground mb-4">Findings</h2>
            {findings.length === 0 ? (
              <EmptyState icon={ServerCog} title="No findings for this asset" description="This asset currently has no open or historical findings." />
            ) : (
              <DataTable columns={findingColumns} rows={findings} rowKey={(f) => f._id} emptyLabel="No findings." />
            )}
          </section>

          <section>
            <h2 className="text-lg font-bold text-foreground mb-4">Related Security Events (30 days)</h2>
            <DataTable columns={eventColumns} rows={relatedEvents} rowKey={(e) => e._id} stickyHeader maxHeight="40vh" emptyLabel="No related events." />
          </section>

          <section>
            <h2 className="text-lg font-bold text-foreground mb-4">Related Incidents / SOAR Actions</h2>
            <DataTable columns={incidentColumns} rows={relatedIncidents} rowKey={(i) => i._id} emptyLabel="No related incidents." />
          </section>
        </div>
      ) : null}
    </div>
  );
}
