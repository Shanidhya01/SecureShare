// AI Security Assistant: small typed API wrapper. Centralized here (unlike most single-page
// inline api.get(...) calls elsewhere in this codebase) because these calls are reused across
// multiple existing pages (Threat Center, DLP Center, Files, Security Center). Same manual
// "Authorization: Bearer <token>" convention as every other call site - lib/api.js has no
// interceptor, and this file doesn't add one either, to stay consistent.
import api from "@/lib/api";

export type SourceType = "ThreatScan" | "DLPScan" | "File" | "SecurityEvent";

// Feature 2 (AI Threat Explanation) - matches backend/services/ai/promptTemplates.js's
// THREAT_EXPLANATION_SCHEMA exactly.
export type ThreatExplanation = {
  executiveSummary: string;
  whatHappened: string;
  whyDetected: string;
  businessImpact: string;
  technicalImpact: string;
  riskLevel: "Low" | "Medium" | "High" | "Critical" | string;
  recommendedActions: string[];
  preventionTips: string[];
  assumptions: string[];
};

export type ExplainThreatResponse =
  | { insightId: string; status: "ok"; explanation: ThreatExplanation }
  | { insightId: string; status: "skipped"; message: string }
  | { insightId: string; status: "error"; message: string };

export async function explainThreat(sourceType: SourceType, sourceId: string, token: string): Promise<ExplainThreatResponse> {
  const res = await api.post<ExplainThreatResponse>(
    "/ai/explain",
    { sourceType, sourceId },
    { headers: { Authorization: `Bearer ${token}` } }
  );
  return res.data;
}

// Feature 4 (AI Risk Explanation) - matches promptTemplates.js's RISK_EXPLANATION_SCHEMA exactly.
export type RiskExplanation = {
  whyScoreIsHigh: string;
  contributingFactors: string[];
  riskSeverity: "Low" | "Medium" | "High" | "Critical" | string;
  businessImpact: string;
  technicalImpact: string;
  recommendedRemediation: string[];
  assumptions: string[];
};

export type ExplainRiskResponse =
  | { insightId: string; status: "ok"; explanation: RiskExplanation }
  | { insightId: string; status: "skipped"; message: string }
  | { insightId: string; status: "error"; message: string };

/** Feature 4 (AI Risk Explanation). Reuses the same /explain-risk endpoint/context pipeline as
 *  explainThreat - only the prompt and expected schema differ server-side. */
export async function explainRisk(sourceType: SourceType, sourceId: string, token: string): Promise<ExplainRiskResponse> {
  const res = await api.post<ExplainRiskResponse>(
    "/ai/explain-risk",
    { sourceType, sourceId },
    { headers: { Authorization: `Bearer ${token}` } }
  );
  return res.data;
}

export type AIInsight = {
  _id: string;
  type: "threat_explanation" | "incident_summary" | "chat_response" | "risk_explanation";
  sourceType: SourceType | null;
  sourceId: string | null;
  response: unknown;
  status: "ok" | "error" | "skipped";
  errorMessage?: string;
  createdAt: string;
};

export async function getMyInsights(token: string): Promise<AIInsight[]> {
  const res = await api.get<AIInsight[]>("/ai/insights", { headers: { Authorization: `Bearer ${token}` } });
  return res.data || [];
}

export type AskAssistantResponse =
  | { insightId: string; status: "ok"; answer: string }
  | { insightId: string; status: "skipped"; message: string }
  | { insightId: string; status: "error"; message: string };

/** Feature 1 (AI Security Assistant Q&A). Powers the dashboard widget now, and Feature 5's
 *  dedicated chat page later - same endpoint, same response shape. */
export async function askAssistant(question: string, token: string): Promise<AskAssistantResponse> {
  const res = await api.post<AskAssistantResponse>(
    "/ai/ask",
    { question },
    { headers: { Authorization: `Bearer ${token}` } }
  );
  return res.data;
}

// Feature 3 (AI Incident Summary)
export type IncidentSummaryStats = {
  generatedAt: string;
  totalUploads: number;
  malwareDetected: number;
  dlpViolations: number;
  blockedUploads: number;
  highRiskFiles: { count: number; topFiles: Array<{ filename: string; riskLevel?: string | null; dlpRisk?: string | null; threatScore?: number; quarantined?: boolean; createdAt?: string }> };
  siemEvents: { eventsToday: number; bySeverity: Record<string, number>; openIncidents: number; criticalEvents: Array<{ type: string; severity: string; message: string; at: string }> };
  soarExecutions: { recentExecutions: Array<{ rule: string; playbook?: string; status: string; at: string }>; byStatus: Record<string, number>; successRate: number };
  complianceFindings: { overallScore: number; controlCoverage: Record<string, number>; topFailingControls: Array<{ title: string; severity: string; category: string }> };
};

export type IncidentSummaryNarrative = {
  executiveSummary: string;
  overallSecurityHealth: string;
  recommendations: string[];
};

export type GenerateSummaryResponse =
  | { insightId: string; status: "ok"; stats: IncidentSummaryStats; narrative: IncidentSummaryNarrative; markdown: string }
  | { insightId: string; status: "skipped"; stats: IncidentSummaryStats; message: string }
  | { insightId: string; status: "error"; stats: IncidentSummaryStats; narrative: null; markdown: null; message?: string };

export async function generateIncidentSummary(token: string): Promise<GenerateSummaryResponse> {
  const res = await api.post<GenerateSummaryResponse>("/ai/incident-summary", {}, { headers: { Authorization: `Bearer ${token}` } });
  return res.data;
}

/** Streams the PDF export for an already-generated incident summary and triggers a browser
 *  download - never re-calls Gemini (the backend renders the AIInsight it already persisted). */
export async function downloadIncidentSummaryPdf(insightId: string, token: string): Promise<void> {
  const res = await api.get(`/ai/incident-summary/${insightId}/pdf`, {
    headers: { Authorization: `Bearer ${token}` },
    responseType: "blob"
  });
  const url = URL.createObjectURL(res.data as Blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "secureshare-ai-incident-summary.pdf";
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
