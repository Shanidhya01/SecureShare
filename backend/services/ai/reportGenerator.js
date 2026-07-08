/**
 * AI Security Assistant - Feature 3 (AI Incident Summary). Gathers real stats by reusing
 * services/ai/contextBuilder.js's existing domain-summary functions (no duplicated aggregation
 * logic), asks Gemini only for the narrative layer via promptTemplates.buildIncidentSummaryPrompt
 * (so the numbers themselves can never be hallucinated - only their interpretation is
 * AI-generated), and renders the result as Markdown or a PDF (via pdfkit, same convention as
 * services/compliance/reportGenerator.js).
 */
import PDFDocument from "pdfkit";
import File from "../../models/File.js";
import { getThreatSummary, getDLPSummary, getSIEMSummary, getSOARSummary, getComplianceSummary, getHighRiskFiles } from "./contextBuilder.js";
import { buildIncidentSummaryPrompt } from "./promptTemplates.js";
import { generateContent } from "./geminiService.js";

function parseNarrative(text) {
  const cleaned = text.trim().replace(/^```(?:json)?/i, "").replace(/```$/, "").trim();
  try {
    return JSON.parse(cleaned);
  } catch {
    return null;
  }
}

/**
 * @param {{ ownerId: string, isAdmin: boolean }} scope
 * @returns {Promise<{status: "ok"|"error"|"skipped", stats: object, narrative: object|null, markdown: string|null, errorMessage: string|null}>}
 */
export async function generateIncidentSummary(scope) {
  const [totalUploads, threat, dlp, siem, soar, compliance, fileRisk] = await Promise.all([
    File.countDocuments({ owner: scope.ownerId }),
    getThreatSummary(scope),
    getDLPSummary(scope),
    getSIEMSummary(scope),
    getSOARSummary(scope),
    getComplianceSummary(scope),
    getHighRiskFiles(scope)
  ]);

  const stats = {
    generatedAt: new Date(),
    totalUploads,
    malwareDetected: threat.malwareDetections,
    dlpViolations: dlp.policyViolations,
    blockedUploads: dlp.blockedUploads,
    highRiskFiles: { count: fileRisk.highRiskFileCount, topFiles: fileRisk.topFiles },
    siemEvents: { eventsToday: siem.eventsToday, bySeverity: siem.bySeverity, openIncidents: siem.openIncidents, criticalEvents: siem.criticalEvents },
    soarExecutions: { recentExecutions: soar.recentExecutions, byStatus: soar.byStatus, successRate: soar.successRate },
    complianceFindings: { overallScore: compliance.overallScore, controlCoverage: compliance.controlCoverage, topFailingControls: compliance.topFailingControls }
  };

  const prompt = buildIncidentSummaryPrompt(stats);
  const result = await generateContent(prompt);

  if (result.status === "skipped") {
    return { status: "skipped", stats, narrative: null, markdown: buildIncidentSummaryMarkdown({ stats, narrative: null }), errorMessage: null };
  }
  if (result.status === "error") {
    return { status: "error", stats, narrative: null, markdown: null, errorMessage: result.message };
  }

  const narrative = parseNarrative(result.text);
  if (!narrative) {
    return { status: "error", stats, narrative: null, markdown: null, errorMessage: "Gemini response was not valid JSON" };
  }

  return { status: "ok", stats, narrative, markdown: buildIncidentSummaryMarkdown({ stats, narrative }) };
}

/** Plain Markdown string built server-side once, so the frontend's "Download as Markdown" button
 *  never has to reimplement this formatting - it just downloads the string it already received. */
export function buildIncidentSummaryMarkdown({ stats, narrative }) {
  const lines = [
    "# SecureShare AI Incident Summary",
    "",
    `_Generated: ${new Date(stats.generatedAt).toISOString()}_`,
    ""
  ];

  if (narrative?.executiveSummary) {
    lines.push("## Executive Summary", "", narrative.executiveSummary, "");
  }

  lines.push(
    "## Key Metrics",
    "",
    `- **Total Uploads:** ${stats.totalUploads}`,
    `- **Malware Detected:** ${stats.malwareDetected}`,
    `- **DLP Violations:** ${stats.dlpViolations}`,
    `- **Blocked Uploads:** ${stats.blockedUploads}`,
    `- **High Risk Files:** ${stats.highRiskFiles.count}`,
    `- **SIEM Events Today:** ${stats.siemEvents.eventsToday}`,
    `- **Open Incidents:** ${stats.siemEvents.openIncidents}`,
    `- **SOAR Execution Success Rate:** ${stats.soarExecutions.successRate}%`,
    `- **Compliance Score:** ${stats.complianceFindings.overallScore}/100`,
    ""
  );

  if (stats.highRiskFiles.topFiles?.length) {
    lines.push("## High Risk Files", "");
    for (const f of stats.highRiskFiles.topFiles) {
      lines.push(`- ${f.filename} - risk level ${f.riskLevel || f.dlpRisk || "n/a"}${f.quarantined ? " (quarantined)" : ""}`);
    }
    lines.push("");
  }

  if (stats.complianceFindings.topFailingControls?.length) {
    lines.push("## Top Compliance Findings", "");
    for (const c of stats.complianceFindings.topFailingControls) {
      lines.push(`- [${c.severity}] ${c.title} (${c.category})`);
    }
    lines.push("");
  }

  if (narrative?.overallSecurityHealth) {
    lines.push("## Overall Security Health", "", narrative.overallSecurityHealth, "");
  }

  if (narrative?.recommendations?.length) {
    lines.push("## Executive Recommendations", "");
    for (const r of narrative.recommendations) lines.push(`- ${r}`);
    lines.push("");
  } else if (!narrative) {
    lines.push(
      "## Executive Recommendations",
      "",
      "_AI narrative unavailable (AI Security Assistant is not configured) - the metrics above are real and unaffected._",
      ""
    );
  }

  return lines.join("\n");
}

/** Streams a PDF directly to `res` (pipe, never buffered in full) - same pdfkit convention as
 *  services/compliance/reportGenerator.js's buildPdf. Caller (ai.controller.js) sets the response
 *  headers before calling this. */
export function streamIncidentSummaryPdf(res, { stats, narrative, generatedAt }) {
  const doc = new PDFDocument({ margin: 50 });
  doc.pipe(res);

  doc.fontSize(20).text("SecureShare AI Incident Summary", { align: "center" });
  doc.moveDown();
  doc.fontSize(10).fillColor("#666").text(`Generated: ${new Date(generatedAt || stats.generatedAt).toISOString()}`, { align: "center" });
  doc.moveDown(2);

  if (narrative?.executiveSummary) {
    doc.fillColor("#000").fontSize(14).text("Executive Summary");
    doc.fontSize(11).text(narrative.executiveSummary);
    doc.moveDown();
  }

  doc.fontSize(14).fillColor("#000").text("Key Metrics");
  doc.fontSize(11);
  doc.text(`Total Uploads: ${stats.totalUploads}`);
  doc.text(`Malware Detected: ${stats.malwareDetected}`);
  doc.text(`DLP Violations: ${stats.dlpViolations}`);
  doc.text(`Blocked Uploads: ${stats.blockedUploads}`);
  doc.text(`High Risk Files: ${stats.highRiskFiles.count}`);
  doc.text(`SIEM Events Today: ${stats.siemEvents.eventsToday}`);
  doc.text(`Open Incidents: ${stats.siemEvents.openIncidents}`);
  doc.text(`SOAR Execution Success Rate: ${stats.soarExecutions.successRate}%`);
  doc.text(`Compliance Score: ${stats.complianceFindings.overallScore}/100`);
  doc.moveDown();

  if (stats.highRiskFiles.topFiles?.length) {
    doc.fontSize(14).text("High Risk Files");
    doc.fontSize(10);
    for (const f of stats.highRiskFiles.topFiles) {
      doc.text(`- ${f.filename} (${f.riskLevel || f.dlpRisk || "n/a"})${f.quarantined ? " [quarantined]" : ""}`);
    }
    doc.moveDown();
  }

  if (narrative?.overallSecurityHealth) {
    doc.fontSize(14).fillColor("#000").text("Overall Security Health");
    doc.fontSize(11).text(narrative.overallSecurityHealth);
    doc.moveDown();
  }

  doc.fontSize(14).fillColor("#000").text("Executive Recommendations");
  doc.fontSize(11);
  if (narrative?.recommendations?.length) {
    for (const r of narrative.recommendations) doc.text(`- ${r}`);
  } else {
    doc.fillColor("#666").text("AI narrative unavailable (AI Security Assistant is not configured) - the metrics above are real and unaffected.");
  }

  doc.end();
}
