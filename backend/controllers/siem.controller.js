import mongoose from "mongoose";
import SecurityEvent from "../models/SecurityEvent.js";
import Incident from "../models/Incident.js";
import File from "../models/File.js";
import { logSecurityEvent } from "../services/siem/siemLogger.js";
import { SEVERITY_LEVELS, CATEGORIES, TYPE_META } from "../services/siem/eventCatalog.js";

const DAY_MS = 24 * 60 * 60 * 1000;

/* Builds a Mongo filter from the SIEM list/search query params shared by /events, /search, /export. */
const buildEventFilter = (owner, query) => {
  const filter = { owner };
  if (query.severity) filter.severity = query.severity;
  if (query.category) filter.category = query.category;
  if (query.siemType) filter.siemType = query.siemType;
  if (query.deviceId) filter.deviceId = query.deviceId;
  if (query.country) filter.country = query.country;
  if (query.file) filter.file = query.file;
  if (query.incidentId) filter.correlationId = query.incidentId;
  if (query.from || query.to) {
    filter.createdAt = {};
    if (query.from) filter.createdAt.$gte = new Date(query.from);
    if (query.to) filter.createdAt.$lte = new Date(query.to);
  }
  return filter;
};

const serializeEvent = (e) => ({
  id: e._id,
  type: e.type,
  siemType: e.siemType || null,
  severity: e.severity || "INFO",
  category: e.category || null,
  message: e.message,
  filename: e.filename || null,
  fileId: e.file || null,
  deviceId: e.deviceId || null,
  ip: e.ip || null,
  country: e.country || null,
  correlationId: e.correlationId || null,
  metadata: e.metadata || null,
  createdAt: e.createdAt
});

const serializeIncident = (i) => ({
  id: i._id,
  ruleId: i.ruleId,
  title: i.title,
  summary: i.summary,
  category: i.category,
  severity: i.severity,
  status: i.status,
  fileId: i.file || null,
  eventCount: i.eventCount,
  firstEventAt: i.firstEventAt,
  lastEventAt: i.lastEventAt,
  createdAt: i.createdAt
});

/* DASHBOARD - snapshot summary for the SOC overview. */
export const getDashboard = async (req, res) => {
  const owner = req.user.id;
  const now = new Date();
  const since7d = new Date(now.getTime() - 7 * DAY_MS);
  const since30d = new Date(now.getTime() - 30 * DAY_MS);
  const startOfToday = new Date(now.getFullYear(), now.getMonth(), now.getDate());

  const [todayCount, last7dCount, last30dCount, allRecent, openIncidents, criticalEvents, recentIncidents] = await Promise.all([
    SecurityEvent.countDocuments({ owner, createdAt: { $gte: startOfToday } }),
    SecurityEvent.countDocuments({ owner, createdAt: { $gte: since7d } }),
    SecurityEvent.countDocuments({ owner, createdAt: { $gte: since30d } }),
    SecurityEvent.find({ owner, createdAt: { $gte: since30d } }).select("severity category"),
    Incident.countDocuments({ owner, status: { $ne: "resolved" } }),
    SecurityEvent.find({ owner, severity: { $in: ["HIGH", "CRITICAL"] } }).sort({ createdAt: -1 }).limit(10),
    Incident.find({ owner }).sort({ lastEventAt: -1 }).limit(5)
  ]);

  const bySeverity = Object.fromEntries(SEVERITY_LEVELS.map((s) => [s, 0]));
  const byCategory = Object.fromEntries(CATEGORIES.map((c) => [c, 0]));
  for (const e of allRecent) {
    if (e.severity && bySeverity[e.severity] !== undefined) bySeverity[e.severity]++;
    if (e.category && byCategory[e.category] !== undefined) byCategory[e.category]++;
  }

  res.json({
    counts: { today: todayCount, last7d: last7dCount, last30d: last30dCount },
    bySeverity,
    byCategory,
    openIncidents,
    criticalEvents: criticalEvents.map(serializeEvent),
    recentIncidents: recentIncidents.map(serializeIncident)
  });
};

/* EVENTS - paginated, filterable list. */
export const getEvents = async (req, res) => {
  const owner = req.user.id;
  const filter = buildEventFilter(owner, req.query);
  const page = Math.max(parseInt(req.query.page) || 1, 1);
  const limit = Math.min(Math.max(parseInt(req.query.limit) || 50, 1), 200);

  const [total, events] = await Promise.all([
    SecurityEvent.countDocuments(filter),
    SecurityEvent.find(filter).sort({ createdAt: -1 }).skip((page - 1) * limit).limit(limit)
  ]);

  res.json({ total, page, limit, events: events.map(serializeEvent) });
};

/* INCIDENTS - filterable list + detail. */
export const getIncidents = async (req, res) => {
  const owner = req.user.id;
  const filter = { owner };
  if (req.query.status) filter.status = req.query.status;
  if (req.query.severity) filter.severity = req.query.severity;
  if (req.query.category) filter.category = req.query.category;

  const incidents = await Incident.find(filter).sort({ lastEventAt: -1 }).limit(200);
  res.json(incidents.map(serializeIncident));
};

export const getIncidentById = async (req, res) => {
  const incident = await Incident.findOne({ _id: req.params.id, owner: req.user.id }).populate("events");
  if (!incident) return res.sendStatus(404);
  res.json({ ...serializeIncident(incident), events: incident.events.map(serializeEvent) });
};

/* SEARCH - full-text-ish search across events and incidents. */
export const search = async (req, res) => {
  const owner = req.user.id;
  const q = (req.query.q || "").trim();
  if (!q) return res.json({ events: [], incidents: [] });

  const re = new RegExp(q.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i");

  const [events, incidents] = await Promise.all([
    SecurityEvent.find({
      owner,
      $or: [{ message: re }, { filename: re }, { ip: re }, { deviceId: re }, { country: re }]
    }).sort({ createdAt: -1 }).limit(100),
    Incident.find({ owner, $or: [{ title: re }, { summary: re }] }).sort({ lastEventAt: -1 }).limit(50)
  ]);

  res.json({ events: events.map(serializeEvent), incidents: incidents.map(serializeIncident) });
};

/* EXPORT - server-side CSV/JSON export honoring the same filters as /events, unpaginated. */
export const exportEvents = async (req, res) => {
  const owner = req.user.id;
  const filter = buildEventFilter(owner, req.query);
  const format = req.query.format === "json" ? "json" : "csv";

  const events = await SecurityEvent.find(filter).sort({ createdAt: -1 }).limit(5000);
  const rows = events.map(serializeEvent);

  if (format === "json") {
    res.setHeader("Content-Disposition", `attachment; filename="siem-export-${Date.now()}.json"`);
    return res.json(rows);
  }

  const header = ["Type", "SIEM Type", "Severity", "Category", "Message", "IP", "Country", "Filename", "CreatedAt"];
  const csvRows = rows.map((e) => [
    e.type, e.siemType || "", e.severity, e.category || "", e.message || "",
    e.ip || "", e.country || "", e.filename || "", new Date(e.createdAt).toISOString()
  ]);
  const csv = [header, ...csvRows].map((r) => r.map((v) => `"${String(v).replace(/"/g, '""')}"`).join(",")).join("\n");

  res.setHeader("Content-Type", "text/csv; charset=utf-8");
  res.setHeader("Content-Disposition", `attachment; filename="siem-export-${Date.now()}.csv"`);
  res.send(csv);
};

/* STATS - aggregate counts + a 30-day timeline for client-side charting (bucketByDay). */
export const getStats = async (req, res) => {
  const owner = req.user.id;
  const since30d = new Date(Date.now() - 30 * DAY_MS);

  const [events, incidentsByStatusRaw] = await Promise.all([
    SecurityEvent.find({ owner, createdAt: { $gte: since30d } }).select("siemType severity category createdAt"),
    Incident.aggregate([
      { $match: { owner: new mongoose.Types.ObjectId(owner) } },
      { $group: { _id: "$status", count: { $sum: 1 } } }
    ]).catch(() => [])
  ]);

  const bySeverity = Object.fromEntries(SEVERITY_LEVELS.map((s) => [s, 0]));
  const byCategory = Object.fromEntries(CATEGORIES.map((c) => [c, 0]));
  const byType = {};
  for (const e of events) {
    if (e.severity && bySeverity[e.severity] !== undefined) bySeverity[e.severity]++;
    if (e.category && byCategory[e.category] !== undefined) byCategory[e.category]++;
    const t = e.siemType || "UNCATEGORIZED";
    byType[t] = (byType[t] || 0) + 1;
  }

  const incidentsByStatus = { open: 0, investigating: 0, resolved: 0 };
  for (const row of incidentsByStatusRaw) {
    if (incidentsByStatus[row._id] !== undefined) incidentsByStatus[row._id] = row.count;
  }

  res.json({
    bySeverity,
    byCategory,
    byType,
    incidentsByStatus,
    timeline: events.map((e) => ({
      createdAt: e.createdAt,
      severity: e.severity || "INFO",
      category: e.category || null,
      siemType: e.siemType || null
    }))
  });
};

/* CLIENT-REPORTED EVENTS - a narrow, whitelisted endpoint for the one event kind the server can
   never observe itself: client-side signature verification outcomes (zero-knowledge design means
   the server never sees plaintext or performs the ECDSA check). Only these two result values are
   accepted - this endpoint cannot be used to write arbitrary event types. */
export const reportSignatureEvent = async (req, res) => {
  const { fileId, result } = req.body;
  if (!["verified", "invalid"].includes(result)) {
    return res.status(400).json({ error: "result must be 'verified' or 'invalid'" });
  }

  const file = fileId ? await File.findById(fileId).select("filename") : null;
  if (fileId && !file) return res.status(404).json({ error: "not_found" });

  const type = result === "verified" ? "signature_verified" : "signature_invalid";
  await logSecurityEvent({
    owner: req.user.id,
    type,
    message: result === "verified"
      ? `Signature verified for "${file?.filename || "downloaded file"}"`
      : `Signature verification FAILED for "${file?.filename || "downloaded file"}" - possible tampering`,
    file: file?._id,
    filename: file?.filename
  });

  res.json({ message: "Recorded" });
};

/* Exposed so the frontend can render a legend/label for every siemType without hardcoding it twice. */
export const getCatalog = async (_req, res) => {
  res.json({ severityLevels: SEVERITY_LEVELS, categories: CATEGORIES, typeMeta: TYPE_META });
};
