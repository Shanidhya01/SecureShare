/**
 * Phase 11 (CSPM/ASM) - PART 15: report builders for the Cloud Security dashboard exports.
 * Structurally mirrors services/compliance/reportGenerator.js (same csvEscape convention, same
 * pdfkit usage - no new dependency needed).
 */
import PDFDocument from "pdfkit";

function csvEscape(value) {
  return `"${String(value ?? "").replace(/"/g, '""')}"`;
}

export function buildCsv({ assets, findings, certificates, overallScore }) {
  const summaryLine = [`Overall Security Score: ${overallScore ?? "n/a"}/100`];

  const assetHeader = ["Asset Name", "Type", "Environment", "Criticality", "Risk Score", "Status"];
  const assetRows = (assets || []).map((a) => [a.name, a.type, a.environment, a.criticality, a.riskScore, a.status]);

  const findingHeader = ["Category", "Rule ID", "Title", "Severity", "Status", "Detected At"];
  const findingRows = (findings || []).map((f) => [f.category, f.ruleId, f.title, f.severity, f.status, new Date(f.detectedAt).toISOString()]);

  const certHeader = ["Domain", "Issuer", "Status", "Days Remaining", "Valid To"];
  const certRows = (certificates || []).map((c) => [c.domain, c.issuer, c.status, c.daysRemaining, c.validTo ? new Date(c.validTo).toISOString() : ""]);

  return [
    summaryLine, [],
    ["Assets"], assetHeader, ...assetRows, [],
    ["Findings"], findingHeader, ...findingRows, [],
    ["Certificates"], certHeader, ...certRows
  ].map((r) => r.map(csvEscape).join(",")).join("\n");
}

export function buildJson({ overallScore, scores, assets, findings, certificates, trend, generatedAt }) {
  return { generatedAt, overallScore, scores, assets, findings, certificates, trend };
}

export function buildPdf({ overallScore, scores, assets, findings, certificates, trend, generatedAt }, res) {
  const doc = new PDFDocument({ margin: 50 });
  doc.pipe(res);

  doc.fontSize(20).text("SecureShare Cloud Security Report", { align: "center" });
  doc.moveDown();
  doc.fontSize(10).fillColor("#666").text(`Generated: ${new Date(generatedAt).toISOString()}`, { align: "center" });
  doc.moveDown(2);

  doc.fillColor("#000").fontSize(14).text("Executive Summary");
  doc.fontSize(11).text(`Overall Security Score: ${overallScore}/100`);
  if (scores) {
    doc.text(`Asset: ${scores.assetScore} | Configuration: ${scores.configScore} | Exposure: ${scores.exposureScore}`);
    doc.text(`Certificate: ${scores.certScore} | Identity: ${scores.identityScore} | Compliance: ${scores.complianceScore}`);
  }
  doc.moveDown();

  doc.fontSize(14).text("Asset Inventory");
  doc.fontSize(9);
  for (const a of (assets || []).slice(0, 50)) {
    doc.text(`${a.name} (${a.type}) - ${a.criticality} criticality, risk ${a.riskScore}/100, ${a.status}`);
  }
  doc.moveDown();

  doc.fontSize(14).fillColor("#000").text("Open Findings");
  doc.fontSize(9);
  for (const f of (findings || []).slice(0, 100)) {
    doc.fillColor(f.severity === "CRITICAL" || f.severity === "HIGH" ? "#B91C1C" : f.severity === "MEDIUM" ? "#B45309" : "#065F46")
      .text(`[${f.severity}] ${f.category} - ${f.title}`);
    doc.fillColor("#000");
    if (f.recommendation) doc.text(`Recommendation: ${f.recommendation}`, { indent: 10 });
  }
  doc.moveDown();

  doc.fontSize(14).fillColor("#000").text("Certificates");
  doc.fontSize(9);
  for (const c of certificates || []) {
    doc.text(`${c.domain}: ${c.status} (${c.daysRemaining ?? "n/a"} days remaining, issuer ${c.issuer || "unknown"})`);
  }

  if (trend?.length) {
    doc.moveDown();
    doc.fontSize(14).fillColor("#000").text("Score Trend");
    doc.fontSize(9);
    for (const point of trend.slice(-14)) {
      doc.text(`${new Date(point.scannedAt).toISOString().slice(0, 10)}: overall score ${point.overallScore}/100`);
    }
  }

  doc.end();
}
