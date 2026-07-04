/**
 * Phase 12 (DevSecOps/Supply Chain) - PART 18: report builders for the DevSecOps dashboard exports
 * and the named report variants (Executive/SBOM/Dependency/Secret/Container/Pipeline) - all built
 * from the same underlying payload shaped differently per `reportType`. Structurally mirrors
 * services/cloud/cloudReportGenerator.js (same csvEscape convention, same pdfkit usage).
 */
import PDFDocument from "pdfkit";

function csvEscape(value) {
  return `"${String(value ?? "").replace(/"/g, '""')}"`;
}

function filterFindings(findings, category) {
  return category ? (findings || []).filter((f) => f.category === category) : findings || [];
}

export function buildCsv({ repository, findings, overallScore, reportType = "executive" }) {
  const category = { sbom: null, dependency: "DEPENDENCY", secret: "SECRET", container: "CONTAINER", pipeline: "PIPELINE", executive: null }[reportType];
  const rows = filterFindings(findings, category);

  const summaryLine = [`Overall DevSecOps Score: ${overallScore ?? "n/a"}/100`, `Repository: ${repository?.name || "n/a"}`];
  const header = ["Category", "Rule ID", "Title", "Severity", "Status", "File", "Package", "Detected At"];
  const dataRows = rows.map((f) => [f.category, f.ruleId, f.title, f.severity, f.status, f.file || "", f.package || "", new Date(f.detectedAt).toISOString()]);

  return [summaryLine, [], header, ...dataRows].map((r) => r.map(csvEscape).join(",")).join("\n");
}

export function buildJson({ repository, findings, overallScore, scores, sbom, pipelineRuns, trend, generatedAt, reportType = "executive" }) {
  const category = { sbom: null, dependency: "DEPENDENCY", secret: "SECRET", container: "CONTAINER", pipeline: "PIPELINE", executive: null }[reportType];
  return {
    generatedAt,
    reportType,
    repository,
    overallScore,
    scores,
    findings: filterFindings(findings, category),
    sbom: reportType === "sbom" || reportType === "executive" ? sbom : undefined,
    pipelineRuns: reportType === "pipeline" || reportType === "executive" ? pipelineRuns : undefined,
    trend
  };
}

export function buildPdf({ repository, findings, overallScore, scores, trend, generatedAt, reportType = "executive" }, res) {
  const doc = new PDFDocument({ margin: 50 });
  doc.pipe(res);

  const titleByType = {
    executive: "SecureShare DevSecOps Executive Report",
    sbom: "SecureShare SBOM Report",
    dependency: "SecureShare Dependency Report",
    secret: "SecureShare Secret Scan Report",
    container: "SecureShare Container Security Report",
    pipeline: "SecureShare CI/CD Pipeline Report"
  };

  doc.fontSize(20).text(titleByType[reportType] || titleByType.executive, { align: "center" });
  doc.moveDown();
  doc.fontSize(10).fillColor("#666").text(`Generated: ${new Date(generatedAt).toISOString()}`, { align: "center" });
  doc.moveDown(2);

  doc.fillColor("#000").fontSize(14).text("Executive Summary");
  doc.fontSize(11).text(`Repository: ${repository?.name || "n/a"} (${repository?.provider || "unknown"})`);
  doc.text(`Overall DevSecOps Score: ${overallScore}/100`);
  if (scores) {
    doc.text(`Repository: ${scores.repositoryScore} | Dependency: ${scores.dependencyScore} | Secret: ${scores.secretScore}`);
    doc.text(`Container: ${scores.containerScore} | Pipeline: ${scores.pipelineScore}`);
  }
  doc.moveDown();

  const category = { sbom: null, dependency: "DEPENDENCY", secret: "SECRET", container: "CONTAINER", pipeline: "PIPELINE", executive: null }[reportType];
  const rows = filterFindings(findings, category);

  doc.fontSize(14).text("Findings");
  doc.fontSize(9);
  for (const f of rows.slice(0, 150)) {
    doc.fillColor(f.severity === "CRITICAL" || f.severity === "HIGH" ? "#B91C1C" : f.severity === "MEDIUM" ? "#B45309" : "#065F46")
      .text(`[${f.severity}] ${f.category} - ${f.title}${f.file ? ` (${f.file}${f.line ? `:${f.line}` : ""})` : ""}`);
    doc.fillColor("#000");
    if (f.recommendation) doc.text(`Recommendation: ${f.recommendation}`, { indent: 10 });
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
