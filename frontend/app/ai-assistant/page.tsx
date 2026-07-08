"use client";

import { useEffect, useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import { Sparkles, AlertCircle, Fingerprint, CheckCircle2, XCircle, MinusCircle, History, FileBarChart, Copy, Download, FileDown, Loader2, Check } from "lucide-react";
import { motion } from "framer-motion";
import toast from "react-hot-toast";
import PageHeader from "@/components/design/PageHeader";
import StatCard from "@/components/design/StatCard";
import StatusBadge, { type StatusTone } from "@/components/design/StatusBadge";
import EmptyState from "@/components/design/EmptyState";
import DataTable, { type DataTableColumn } from "@/components/design/DataTable";
import { StatsSkeleton, TableSkeleton } from "@/components/design/Skeletons";
import SearchInput from "@/components/design/SearchInput";
import { Button } from "@/components/ui/button";
import { apiErrorStatus, apiErrorMessage } from "@/lib/errors";
import { staggerContainer } from "@/lib/motion";
import { getMyInsights, generateIncidentSummary, downloadIncidentSummaryPdf, type AIInsight, type GenerateSummaryResponse } from "@/lib/ai";

const STATUS_TONE: Record<AIInsight["status"], StatusTone> = {
  ok: "success",
  error: "danger",
  skipped: "neutral",
};

const TYPE_LABEL: Record<AIInsight["type"], string> = {
  threat_explanation: "Threat Explanation",
  incident_summary: "Incident Summary",
  chat_response: "Chat Response",
  risk_explanation: "Risk Explanation",
};

/**
 * AI Security Assistant landing page (Feature 1: history/entry point for AI Threat Explanation.
 * Features 2/3's Incident Summary and Security Chat sections land here in later passes). Follows
 * the same structure as app/security/page.tsx: token guard, PageHeader, StatCard grid, loading
 * skeletons, manual error banner, DataTable for history.
 */
export default function AIAssistantPage() {
  const router = useRouter();
  const [insights, setInsights] = useState<AIInsight[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  // Feature 3 (AI Incident Summary)
  const [summaryLoading, setSummaryLoading] = useState(false);
  const [summary, setSummary] = useState<GenerateSummaryResponse | null>(null);
  const [summaryNotice, setSummaryNotice] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [pdfLoading, setPdfLoading] = useState(false);

  // Part 4 (AI Assistant dashboard): search over Recent AI Insights history, client-side (same
  // scale/convention as app/files/page.tsx's in-memory filtering).
  const [insightSearch, setInsightSearch] = useState("");

  const fetchAll = useCallback(
    async (token: string) => {
      try {
        setLoading(true);
        const data = await getMyInsights(token);
        setInsights(data);
      } catch (err: unknown) {
        const status = apiErrorStatus(err);
        if (status === 401 || status === 403) {
          router.push("/login");
          return;
        }
        setError(apiErrorMessage(err, "Failed to load AI Security Assistant history"));
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
    fetchAll(token);
  }, [fetchAll, router]);

  const formatDate = (d: string) => new Date(d).toLocaleString();

  const handleGenerateSummary = async () => {
    const token = localStorage.getItem("token");
    if (!token) return;
    setSummaryLoading(true);
    setSummary(null);
    setSummaryNotice(null);
    try {
      const res = await generateIncidentSummary(token);
      setSummary(res);
      if (res.status === "skipped") setSummaryNotice(res.message);
      else if (res.status === "error") setSummaryNotice(res.message || "AI Incident Summary failed to generate.");
      // Refresh history so the new incident_summary insight shows up below immediately.
      getMyInsights(token).then(setInsights).catch(() => {});
    } catch (err: unknown) {
      setSummaryNotice(apiErrorMessage(err, "AI Incident Summary failed to generate. Try again later."));
    } finally {
      setSummaryLoading(false);
    }
  };

  const handleCopySummary = async () => {
    if (summary?.status !== "ok" && summary?.status !== "skipped") return;
    try {
      const text = summary.status === "ok" ? summary.markdown : JSON.stringify(summary.stats, null, 2);
      await navigator.clipboard.writeText(text);
      setCopied(true);
      toast.success("Copied to clipboard");
      setTimeout(() => setCopied(false), 2000);
    } catch {
      toast.error("Failed to copy");
    }
  };

  const handleDownloadMarkdown = () => {
    if (summary?.status !== "ok") return;
    const blob = new Blob([summary.markdown], { type: "text/markdown;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "secureshare-ai-incident-summary.md";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleDownloadPdf = async () => {
    if (!summary) return;
    const token = localStorage.getItem("token");
    if (!token) return;
    setPdfLoading(true);
    try {
      await downloadIncidentSummaryPdf(summary.insightId, token);
    } catch {
      toast.error("Failed to download PDF");
    } finally {
      setPdfLoading(false);
    }
  };

  const filteredInsights = insights.filter((i) => {
    if (!insightSearch.trim()) return true;
    const q = insightSearch.toLowerCase();
    return (
      (TYPE_LABEL[i.type] || i.type).toLowerCase().includes(q) ||
      (i.sourceType || "").toLowerCase().includes(q) ||
      i.status.toLowerCase().includes(q)
    );
  });

  const okCount = insights.filter((i) => i.status === "ok").length;
  const errorCount = insights.filter((i) => i.status === "error").length;
  const skippedCount = insights.filter((i) => i.status === "skipped").length;

  const columns: DataTableColumn<AIInsight>[] = [
    { key: "type", header: "Type", render: (i) => TYPE_LABEL[i.type] || i.type },
    { key: "source", header: "Source", render: (i) => (i.sourceType ? <span className="text-xs text-muted-foreground">{i.sourceType}</span> : <span className="text-xs text-muted-foreground">-</span>) },
    { key: "status", header: "Status", render: (i) => <StatusBadge label={i.status} tone={STATUS_TONE[i.status] ?? "neutral"} /> },
    { key: "generated", header: "Generated", className: "whitespace-nowrap text-xs text-muted-foreground", render: (i) => formatDate(i.createdAt) },
  ];

  return (
    <div>
      <PageHeader
        icon={Sparkles}
        title="AI Security Assistant"
        description="Gemini-powered explanations for detections SecureShare already found - malware, DLP violations, and suspicious activity."
        accent="purple"
      />

      {error && (
        <div className="mb-6 p-4 bg-destructive/10 border border-destructive/30 rounded-lg flex items-center gap-2">
          <AlertCircle className="text-destructive" size={18} />
          <p className="text-destructive text-sm">{error}</p>
        </div>
      )}

      {loading ? (
        <div className="space-y-8">
          <StatsSkeleton />
          <TableSkeleton />
        </div>
      ) : (
        <div className="space-y-8">
          <motion.div variants={staggerContainer} initial="hidden" animate="show" className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <StatCard label="Total AI Requests" value={insights.length} icon={Fingerprint} variant="primary" />
            <StatCard label="Explanations Generated" value={okCount} icon={CheckCircle2} variant="success" />
            <StatCard label="Failed Requests" value={errorCount} icon={XCircle} variant="danger" />
            <StatCard label="Assistant Unavailable" value={skippedCount} icon={MinusCircle} variant="muted" />
          </motion.div>

          <div className="rounded-xl border border-border bg-card p-5">
            <p className="text-sm text-muted-foreground">
              Look for the <span className="font-semibold text-foreground">Explain with AI</span> button next to
              quarantined files, malware detections, and DLP violations in the Threat Center and DLP Center - it
              sends that detection&apos;s real metadata to Gemini and explains what happened, why, and what to do
              next. Nothing is invented: if a detail is missing, the assistant says so explicitly instead of
              guessing.
            </p>
          </div>

          <section>
            <div className="mb-4 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
              <h2 className="flex items-center gap-2 text-lg font-bold text-foreground">
                <FileBarChart size={20} className="text-purple-300" />
                AI Incident Summary
              </h2>
              <Button type="button" onClick={handleGenerateSummary} disabled={summaryLoading} className="gap-1.5">
                {summaryLoading ? <Loader2 size={14} className="animate-spin" /> : <Sparkles size={14} />}
                Generate AI Incident Summary
              </Button>
            </div>

            {summaryNotice && (
              <div className="mb-4 p-4 bg-muted border border-border rounded-lg flex items-start gap-2">
                <AlertCircle className="text-muted-foreground shrink-0 mt-0.5" size={16} />
                <p className="text-muted-foreground text-sm">{summaryNotice}</p>
              </div>
            )}

            {summary && summary.status !== "error" && (
              <div className="space-y-4">
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  <StatCard label="Total Uploads" value={summary.stats.totalUploads} icon={Fingerprint} variant="primary" />
                  <StatCard label="Malware Detected" value={summary.stats.malwareDetected} icon={XCircle} variant="danger" />
                  <StatCard label="DLP Violations" value={summary.stats.dlpViolations} icon={AlertCircle} variant="warning" />
                  <StatCard label="Blocked Uploads" value={summary.stats.blockedUploads} icon={MinusCircle} variant="warning" />
                  <StatCard label="High Risk Files" value={summary.stats.highRiskFiles.count} icon={Fingerprint} variant="danger" />
                  <StatCard label="SIEM Events Today" value={summary.stats.siemEvents.eventsToday} icon={Fingerprint} variant="primary" />
                  <StatCard label="SOAR Success Rate" value={`${summary.stats.soarExecutions.successRate}%`} icon={CheckCircle2} variant="success" />
                  <StatCard label="Compliance Score" value={`${summary.stats.complianceFindings.overallScore}/100`} icon={Fingerprint} variant="success" />
                </div>

                {summary.status === "ok" && (
                  <div className="rounded-xl border border-border bg-card p-6 space-y-4">
                    <div>
                      <h3 className="text-sm font-semibold text-foreground mb-2">Executive Summary</h3>
                      <p className="text-sm text-muted-foreground leading-relaxed">{summary.narrative.executiveSummary}</p>
                    </div>
                    <div>
                      <h3 className="text-sm font-semibold text-foreground mb-2">Overall Security Health</h3>
                      <p className="text-sm text-muted-foreground leading-relaxed">{summary.narrative.overallSecurityHealth}</p>
                    </div>
                    {summary.narrative.recommendations?.length > 0 && (
                      <div>
                        <h3 className="text-sm font-semibold text-foreground mb-2">Executive Recommendations</h3>
                        <ul className="space-y-2">
                          {summary.narrative.recommendations.map((r, i) => (
                            <li key={i} className="flex items-start gap-2 text-sm text-muted-foreground">
                              <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-primary" />
                              {r}
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}

                    <div className="flex flex-wrap gap-2 pt-2 border-t border-border">
                      <Button type="button" variant="outline" size="sm" onClick={handleCopySummary} className="gap-1.5">
                        {copied ? <Check size={14} /> : <Copy size={14} />}
                        Copy
                      </Button>
                      <Button type="button" variant="outline" size="sm" onClick={handleDownloadMarkdown} className="gap-1.5">
                        <Download size={14} />
                        Download as Markdown
                      </Button>
                      <Button type="button" variant="outline" size="sm" onClick={handleDownloadPdf} disabled={pdfLoading} className="gap-1.5">
                        {pdfLoading ? <Loader2 size={14} className="animate-spin" /> : <FileDown size={14} />}
                        Download as PDF
                      </Button>
                    </div>
                  </div>
                )}
              </div>
            )}
          </section>

          <section>
            <div className="mb-4 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
              <h2 className="flex items-center gap-2 text-lg font-bold text-foreground">
                <History size={20} className="text-purple-300" />
                Recent AI Insights
              </h2>
              {insights.length > 0 && (
                <SearchInput value={insightSearch} onChange={setInsightSearch} placeholder="Search by type, source, or status..." className="sm:w-72" />
              )}
            </div>
            {insights.length === 0 ? (
              <EmptyState
                icon={Sparkles}
                title="No AI insights yet"
                description="Use the Explain with AI button on a detection in the Threat Center or DLP Center to generate your first insight."
              />
            ) : filteredInsights.length === 0 ? (
              <EmptyState icon={Sparkles} title="No matching insights" description="Nothing matches your current search." />
            ) : (
              <DataTable columns={columns} rows={filteredInsights} rowKey={(i) => i._id} emptyLabel="No AI insights yet." />
            )}
          </section>
        </div>
      )}
    </div>
  );
}
