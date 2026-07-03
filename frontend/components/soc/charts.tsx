"use client";

import {
  AreaChart,
  Area,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from "recharts";
import { SEVERITY_COLORS, CATEGORY_LABELS, type Severity } from "@/lib/severity";
import { bucketByDay } from "@/lib/chartHelpers";

// Same tooltip convention as frontend/app/analytics/page.tsx, kept identical for visual consistency.
const chartTooltipStyle = { background: "#0F172A", border: "1px solid rgba(148,163,184,0.2)", borderRadius: 8, fontSize: 12 };

export function ChartCard({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="rounded-xl border border-border bg-card p-6">
      <h3 className="text-sm font-semibold text-foreground mb-4">{title}</h3>
      {children}
    </div>
  );
}

export function SeverityDistributionChart({ bySeverity }: { bySeverity: Record<string, number> }) {
  const data = Object.entries(bySeverity)
    .filter(([, count]) => count > 0)
    .map(([name, value]) => ({ name, value }));

  if (data.length === 0) {
    return <p className="text-sm text-muted-foreground text-center py-10">No events in the selected range.</p>;
  }

  return (
    <ResponsiveContainer width="100%" height={220}>
      <PieChart>
        <Pie data={data} dataKey="value" nameKey="name" innerRadius={50} outerRadius={80} paddingAngle={2}>
          {data.map((d) => (
            <Cell key={d.name} fill={SEVERITY_COLORS[d.name as Severity] || "#64748B"} />
          ))}
        </Pie>
        <Tooltip contentStyle={chartTooltipStyle} />
        <Legend wrapperStyle={{ fontSize: 12 }} />
      </PieChart>
    </ResponsiveContainer>
  );
}

export function CategoryBarChart({ byCategory }: { byCategory: Record<string, number> }) {
  const data = Object.entries(byCategory)
    .filter(([, count]) => count > 0)
    .map(([name, value]) => ({ name: CATEGORY_LABELS[name] || name, value }));

  if (data.length === 0) {
    return <p className="text-sm text-muted-foreground text-center py-10">No events in the selected range.</p>;
  }

  return (
    <ResponsiveContainer width="100%" height={220}>
      <BarChart data={data} layout="vertical" margin={{ left: 24 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.1)" horizontal={false} />
        <XAxis type="number" tick={{ fontSize: 11 }} allowDecimals={false} />
        <YAxis type="category" dataKey="name" tick={{ fontSize: 11 }} width={110} />
        <Tooltip contentStyle={chartTooltipStyle} />
        <Bar dataKey="value" fill="#38BDF8" radius={[0, 4, 4, 0]} />
      </BarChart>
    </ResponsiveContainer>
  );
}

const INCIDENT_STATUS_COLORS: Record<string, string> = {
  open: "#F59E0B",
  investigating: "#38BDF8",
  resolved: "#10B981",
};

export function IncidentsByStatusChart({ incidentsByStatus }: { incidentsByStatus: Record<string, number> }) {
  const data = Object.entries(incidentsByStatus)
    .filter(([, count]) => count > 0)
    .map(([name, value]) => ({ name, value }));

  if (data.length === 0) {
    return <p className="text-sm text-muted-foreground text-center py-10">No incidents yet.</p>;
  }

  return (
    <ResponsiveContainer width="100%" height={220}>
      <PieChart>
        <Pie data={data} dataKey="value" nameKey="name" innerRadius={50} outerRadius={80} paddingAngle={2}>
          {data.map((d) => (
            <Cell key={d.name} fill={INCIDENT_STATUS_COLORS[d.name] || "#64748B"} />
          ))}
        </Pie>
        <Tooltip contentStyle={chartTooltipStyle} />
        <Legend wrapperStyle={{ fontSize: 12 }} />
      </PieChart>
    </ResponsiveContainer>
  );
}

export type TimelinePoint = { createdAt: string; severity: string; category?: string | null; siemType?: string | null };

function AreaTrend({ trend, color, gradientId }: { trend: { date: string; count: number }[]; color: string; gradientId: string }) {
  return (
    <ResponsiveContainer width="100%" height={220}>
      <AreaChart data={trend}>
        <defs>
          <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor={color} stopOpacity={0.4} />
            <stop offset="95%" stopColor={color} stopOpacity={0} />
          </linearGradient>
        </defs>
        <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.1)" />
        <XAxis dataKey="date" tick={{ fontSize: 11 }} />
        <YAxis tick={{ fontSize: 11 }} allowDecimals={false} />
        <Tooltip contentStyle={chartTooltipStyle} />
        <Area type="monotone" dataKey="count" stroke={color} fill={`url(#${gradientId})`} />
      </AreaChart>
    </ResponsiveContainer>
  );
}

/** Overall security event volume over the last 30 days, bucketed client-side - same architecture
 *  as the existing /analytics page's trend charts (services/siem/stats returns the raw timeline,
 *  the frontend buckets it with the shared bucketByDay helper). */
export function EventTrendChart({ timeline }: { timeline: TimelinePoint[] }) {
  return <AreaTrend trend={bucketByDay(timeline, (t) => t.createdAt, 30)} color="#38BDF8" gradientId="socEventGradient" />;
}

/** Same overall volume as EventTrendChart, presented as the SOC's "Security Activity" panel. */
export function SecurityActivityChart({ timeline }: { timeline: TimelinePoint[] }) {
  return <AreaTrend trend={bucketByDay(timeline, (t) => t.createdAt, 30)} color="#A78BFA" gradientId="socActivityGradient" />;
}

export function ThreatTrendChart({ timeline }: { timeline: TimelinePoint[] }) {
  const filtered = timeline.filter((t) => t.category === "THREAT");
  if (filtered.length === 0) return <p className="text-sm text-muted-foreground text-center py-10">No threat events in the last 30 days.</p>;
  return <AreaTrend trend={bucketByDay(filtered, (t) => t.createdAt, 30)} color="#FB923C" gradientId="socThreatGradient" />;
}

export function DLPFindingsChart({ timeline }: { timeline: TimelinePoint[] }) {
  const filtered = timeline.filter((t) => t.category === "DLP");
  if (filtered.length === 0) return <p className="text-sm text-muted-foreground text-center py-10">No DLP findings in the last 30 days.</p>;
  return <AreaTrend trend={bucketByDay(filtered, (t) => t.createdAt, 30)} color="#F59E0B" gradientId="socDlpGradient" />;
}

export function ZeroTrustEventsChart({ timeline }: { timeline: TimelinePoint[] }) {
  const filtered = timeline.filter((t) => t.category === "ZERO_TRUST");
  if (filtered.length === 0) return <p className="text-sm text-muted-foreground text-center py-10">No Zero Trust events in the last 30 days.</p>;
  return <AreaTrend trend={bucketByDay(filtered, (t) => t.createdAt, 30)} color="#34D399" gradientId="socZeroTrustGradient" />;
}

const SEVERITY_WEIGHT: Record<string, number> = { INFO: 0, LOW: 1, MEDIUM: 3, HIGH: 6, CRITICAL: 10 };

/** A daily "risk score" trend - the sum of severity weights for events logged that day, so a
 *  handful of Critical events register more strongly than a flood of Info-level ones. */
export function RiskTrendChart({ timeline }: { timeline: TimelinePoint[] }) {
  const days = 30;
  const buckets = new Map<string, number>();
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  for (let i = days - 1; i >= 0; i--) {
    const d = new Date(today);
    d.setDate(d.getDate() - i);
    buckets.set(d.toISOString().slice(0, 10), 0);
  }
  for (const point of timeline) {
    const d = new Date(point.createdAt);
    if (Number.isNaN(d.getTime())) continue;
    d.setHours(0, 0, 0, 0);
    const key = d.toISOString().slice(0, 10);
    if (buckets.has(key)) buckets.set(key, (buckets.get(key) || 0) + (SEVERITY_WEIGHT[point.severity] ?? 0));
  }
  const trend = Array.from(buckets.entries()).map(([date, count]) => ({
    date: new Date(date).toLocaleDateString(undefined, { month: "short", day: "numeric" }),
    count,
  }));

  return <AreaTrend trend={trend} color="#EF4444" gradientId="socRiskGradient" />;
}

export type IncidentTimelinePoint = { lastEventAt: string };

/** Incident volume over the last 30 days (by last-activity date), bucketed the same way as the
 *  event trend charts above. */
export function IncidentTimelineChart({ incidents }: { incidents: IncidentTimelinePoint[] }) {
  if (incidents.length === 0) return <p className="text-sm text-muted-foreground text-center py-10">No incidents yet.</p>;
  return <AreaTrend trend={bucketByDay(incidents, (i) => i.lastEventAt, 30)} color="#F472B6" gradientId="socIncidentGradient" />;
}
