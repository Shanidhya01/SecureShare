/**
 * Phase 10 (Compliance & Governance): report builders. CSV/JSON follow the exact manual-string
 * convention already used by backend/controllers/soar.controller.js's exportReport - no new
 * dependency needed for those two. PDF is the one new dependency (`pdfkit`), used only here.
 */
import PDFDocument from "pdfkit";

function csvEscape(value) {
  return `"${String(value ?? "").replace(/"/g, '""')}"`;
}

export function buildCsv({ frameworkScores, assessments, riskScore }) {
  const header = ["Framework", "Control ID", "Title", "Category", "Severity", "Status", "Score", "Evaluated At"];
  const rows = assessments.map((a) => [
    a.frameworkKey, a.controlId, a.title, a.category, a.severity, a.status, a.score,
    new Date(a.evaluatedAt).toISOString()
  ]);
  const summaryLine = [`Overall Risk Score: ${riskScore ?? "n/a"}/100`];
  return [summaryLine, [], header, ...rows].map((r) => r.map(csvEscape).join(",")).join("\n");
}

export function buildJson({ overallScore, riskScore, riskDistribution, frameworkScores, assessments, trend, generatedAt }) {
  return { generatedAt, overallScore, riskScore, riskDistribution, frameworkScores, assessments, trend };
}

export function buildPdf({ overallScore, riskScore, riskDistribution, frameworkScores, assessments, trend, generatedAt }, res) {
  const doc = new PDFDocument({ margin: 50 });
  doc.pipe(res);

  doc.fontSize(20).text("SecureShare Compliance Report", { align: "center" });
  doc.moveDown();
  doc.fontSize(10).fillColor("#666").text(`Generated: ${new Date(generatedAt).toISOString()}`, { align: "center" });
  doc.moveDown(2);

  doc.fillColor("#000").fontSize(14).text("Executive Summary");
  doc.fontSize(11).text(`Overall Compliance Score: ${overallScore}/100`);
  doc.text(`Overall Risk Score: ${riskScore ?? "n/a"}/100`);
  if (riskDistribution) {
    doc.text(`Risk Distribution: Critical ${riskDistribution.Critical || 0}, High ${riskDistribution.High || 0}, Medium ${riskDistribution.Medium || 0}, Low ${riskDistribution.Low || 0}`);
  }
  doc.moveDown();

  doc.fontSize(14).text("Framework Scores");
  doc.fontSize(10);
  for (const f of frameworkScores) {
    doc.text(`${f.name} (${f.framework}): ${f.score}/100 - ${f.controlCount} control(s) assessed`);
  }
  doc.moveDown();

  if (trend?.length) {
    doc.fontSize(14).fillColor("#000").text("Trend Analysis");
    doc.fontSize(10);
    for (const point of trend.slice(-14)) {
      doc.text(`${point.day}: average score ${point.averageScore}/100`);
    }
    doc.moveDown();
  }

  doc.fontSize(14).fillColor("#000").text("Control Status & Recommendations");
  doc.fontSize(9);
  for (const a of assessments) {
    doc.moveDown(0.5);
    doc.fillColor(a.status === "FAIL" ? "#B91C1C" : a.status === "PARTIAL" ? "#B45309" : "#065F46")
      .text(`[${a.status}] ${a.frameworkKey} ${a.controlId} - ${a.title} (score ${a.score})`);
    doc.fillColor("#000");
    if (a.recommendations?.length) {
      doc.text(`Recommendation: ${a.recommendations.join("; ")}`, { indent: 10 });
    }
  }

  doc.end();
}
