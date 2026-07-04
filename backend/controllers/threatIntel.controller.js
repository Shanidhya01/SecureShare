import ThreatIntelScan from "../models/ThreatIntelScan.js";
import IOC from "../models/IOC.js";
import YaraRule from "../models/YaraRule.js";
import { runThreatIntelScan } from "../services/threatIntel/threatIntelEngine.js";
import { getMitreCatalog } from "../services/threatIntel/mitreMapping.js";
import { logSecurityEvent } from "../services/siem/siemLogger.js";

/* ON-DEMAND TEXT SCAN - the explicit, deliberate moment (mirroring Phase 4/5's pre-encryption
   scan endpoints) where a caller submits raw text to extract and look up IOCs from - never used
   against DLP's masked samples, which intentionally hold no raw values. */
export const scanText = async (req, res) => {
  try {
    const { text, filename, sha256, sha1, md5 } = req.body || {};
    if (!text && !sha256 && !sha1 && !md5) {
      return res.status(400).json({ error: "Provide text and/or a hash to scan" });
    }

    const result = await runThreatIntelScan({
      hashes: { sha256, sha1, md5 },
      text: text || null,
      filename: filename || null
    });

    const intelScan = await ThreatIntelScan.create({
      owner: req.user.id,
      originalFilename: filename || null,
      ...result
    });

    logSecurityEvent({
      owner: req.user.id,
      type: "ioc_lookup",
      message: `IOC lookup performed${filename ? ` for "${filename}"` : ""}`,
      metadata: { matchCount: intelScan.iocMatches.length }
    }).catch((e) => console.error("Failed to record security event:", e));

    res.json(intelScan);
  } catch (err) {
    console.error("Threat intel scan-text error:", err);
    res.status(500).json({ error: err?.message || "Threat intelligence scan failed" });
  }
};

/* SCAN HISTORY - the requesting user's own enrichment results, newest first. */
export const getMyScans = async (req, res) => {
  const scans = await ThreatIntelScan.find({ owner: req.user.id }).sort({ createdAt: -1 }).limit(100);
  res.json(scans);
};

/* STATS - summary for the Threat Intelligence dashboard: IOC type breakdown, confidence
   distribution, top sources, MITRE technique frequency, YARA match counts. */
export const getStats = async (req, res) => {
  const scans = await ThreatIntelScan.find({ owner: req.user.id })
    .select("iocMatches mitreMapping yaraMatches threatSources severity threatConfidence createdAt");

  const stats = {
    totalScans: scans.length,
    totalIocMatches: 0,
    byIocType: {},
    bySeverity: { None: 0, Low: 0, Medium: 0, High: 0, Critical: 0 },
    confidenceBuckets: { "0-25": 0, "26-50": 0, "51-75": 0, "76-100": 0 },
    bySources: {},
    byMitreTechnique: {},
    yaraMatchCount: 0,
    timeline: []
  };

  for (const scan of scans) {
    if (stats.bySeverity[scan.severity] !== undefined) stats.bySeverity[scan.severity]++;

    for (const m of scan.iocMatches || []) {
      stats.totalIocMatches++;
      stats.byIocType[m.type] = (stats.byIocType[m.type] || 0) + 1;
      const bucket = m.confidence <= 25 ? "0-25" : m.confidence <= 50 ? "26-50" : m.confidence <= 75 ? "51-75" : "76-100";
      stats.confidenceBuckets[bucket]++;
    }

    for (const source of scan.threatSources || []) {
      stats.bySources[source] = (stats.bySources[source] || 0) + 1;
    }

    for (const m of scan.mitreMapping || []) {
      stats.byMitreTechnique[m.techniqueId] = (stats.byMitreTechnique[m.techniqueId] || 0) + 1;
    }

    stats.yaraMatchCount += (scan.yaraMatches || []).length;

    stats.timeline.push({
      createdAt: scan.createdAt,
      severity: scan.severity,
      threatConfidence: scan.threatConfidence,
      iocMatchCount: (scan.iocMatches || []).length
    });
  }

  res.json(stats);
};

/* IOC SEARCH - global search across the local IOC DB, this user's threat intel scans (by hash,
   IP, domain, URL, filename, email), MITRE technique catalog, and YARA rule names. */
export const searchIOC = async (req, res) => {
  const q = (req.query.q || "").trim();
  if (!q) return res.json({ iocs: [], scans: [], mitreTechniques: [], yaraRules: [] });

  const re = new RegExp(q.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i");

  const [iocs, scans, yaraRules] = await Promise.all([
    IOC.find({ value: re }).limit(50),
    ThreatIntelScan.find({
      owner: req.user.id,
      $or: [
        { originalFilename: re },
        { "iocMatches.value": re },
        { "mitreMapping.techniqueId": re },
        { "yaraMatches.ruleName": re }
      ]
    }).sort({ createdAt: -1 }).limit(50),
    YaraRule.find({ name: re }).limit(20)
  ]);

  const mitreTechniques = getMitreCatalog().filter(
    (t) => t.techniqueId.toLowerCase().includes(q.toLowerCase()) || t.name.toLowerCase().includes(q.toLowerCase())
  );

  res.json({ iocs, scans, mitreTechniques, yaraRules });
};

/* IOC LISTING - browse the local IOC database. */
export const listIOCs = async (req, res) => {
  const filter = {};
  if (req.query.type) filter.type = req.query.type;
  if (req.query.severity) filter.severity = req.query.severity;
  if (req.query.status) filter.status = req.query.status;

  const iocs = await IOC.find(filter).sort({ createdAt: -1 }).limit(200);
  res.json(iocs);
};

/* MITRE CATALOG - static reference table for the frontend to render technique names/tactics. */
export const getMitreCatalogHandler = async (_req, res) => {
  res.json(getMitreCatalog());
};

/* YARA RULES - read-only listing for the dashboard's "YARA Matches"/rule reference views. */
export const getYaraRules = async (_req, res) => {
  const rules = await YaraRule.find().sort({ createdAt: -1 });
  res.json(rules);
};

/* EXPORT - CSV/JSON export of this user's threat intel scans, mirroring siem.controller.js's
   exportEvents shape/pattern. */
export const exportReport = async (req, res) => {
  const format = req.query.format === "json" ? "json" : "csv";
  const scans = await ThreatIntelScan.find({ owner: req.user.id }).sort({ createdAt: -1 }).limit(5000);

  const rows = scans.map((s) => ({
    id: s._id,
    filename: s.originalFilename,
    severity: s.severity,
    threatScore: s.threatScore,
    threatConfidence: s.threatConfidence,
    iocMatchCount: s.iocMatches.length,
    mitreTechniques: s.mitreMapping.map((m) => m.techniqueId).join("; "),
    yaraMatches: s.yaraMatches.map((m) => m.ruleName).join("; "),
    sources: s.threatSources.join("; "),
    createdAt: s.createdAt
  }));

  if (format === "json") {
    res.setHeader("Content-Disposition", `attachment; filename="threat-intel-export-${Date.now()}.json"`);
    return res.json(rows);
  }

  const header = ["ID", "Filename", "Severity", "Threat Score", "Confidence", "IOC Matches", "MITRE Techniques", "YARA Matches", "Sources", "CreatedAt"];
  const csvRows = rows.map((r) => [
    r.id, r.filename || "", r.severity, r.threatScore, r.threatConfidence,
    r.iocMatchCount, r.mitreTechniques, r.yaraMatches, r.sources, new Date(r.createdAt).toISOString()
  ]);
  const csv = [header, ...csvRows].map((r) => r.map((v) => `"${String(v).replace(/"/g, '""')}"`).join(",")).join("\n");

  res.setHeader("Content-Type", "text/csv; charset=utf-8");
  res.setHeader("Content-Disposition", `attachment; filename="threat-intel-export-${Date.now()}.csv"`);
  res.send(csv);
};
