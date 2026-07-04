/**
 * Phase 11 (CSPM/ASM) - PART 14: correlates discovered cloud assets (domains/IPs) against the
 * existing threat-intel data via services/threatIntel/iocLookupService.js - reused as-is, not
 * reimplemented, exactly like services/threatIntel/threatIntelIntegration.js already does for
 * uploaded files.
 */
import Asset from "../../models/Asset.js";
import CloudFinding from "../../models/CloudFinding.js";
import { lookupIOC } from "../threatIntel/iocLookupService.js";
import { logSecurityEvent } from "../siem/siemLogger.js";

export async function runThreatIntelCorrelation({ owner } = {}) {
  const findings = [];

  const domainAssets = await Asset.find({ type: { $in: ["Domain", "Subdomain"] }, status: "active" }).lean();

  for (const asset of domainAssets) {
    const verdict = await lookupIOC("domain", asset.name).catch(() => null);
    if (!verdict) continue;

    const ruleId = `threat-intel:${asset.name}`;
    if (!verdict.matched) {
      await CloudFinding.updateMany({ ruleId, category: "THREAT_INTEL", status: "open" }, { status: "resolved", resolvedAt: new Date() });
      continue;
    }

    const existing = await CloudFinding.findOne({ ruleId, category: "THREAT_INTEL", status: "open" });
    const finding = existing || await CloudFinding.create({
      asset: asset._id,
      category: "THREAT_INTEL",
      ruleId,
      title: `Cloud asset domain matched threat intelligence: ${asset.name}`,
      severity: verdict.severity?.toUpperCase() || "HIGH",
      recommendation: "Investigate why an owned domain matches known-malicious threat intelligence sources; rotate/replace the domain if compromised.",
      metadata: { sources: verdict.sources, tags: verdict.tags, confidence: verdict.confidence },
      status: "open"
    });
    findings.push(finding);

    if (!existing) {
      await logSecurityEvent({
        owner,
        type: "cloud_ioc_match",
        message: `Cloud asset "${asset.name}" matched threat intelligence (sources: ${verdict.sources.join(", ")})`,
        metadata: { assetId: String(asset._id), sources: verdict.sources, confidence: verdict.confidence }
      }).catch(() => {});
    }
  }

  return findings;
}
