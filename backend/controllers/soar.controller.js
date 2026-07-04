import AutomationRule from "../models/AutomationRule.js";
import Playbook from "../models/Playbook.js";
import AutomationExecution from "../models/AutomationExecution.js";
import User from "../models/User.js";
import { ACTION_TYPES } from "../services/soar/actions/index.js";

const isAdminReq = async (req) => {
  if (req.user.isAdmin) return true; // JWT convenience claim - fine for read-scoping decisions
  const user = await User.findById(req.user.id).select("isAdmin");
  return !!user?.isAdmin;
};

/* ============================== RULES ============================== */

export const listRules = async (_req, res) => {
  const rules = await AutomationRule.find().sort({ priority: 1, createdAt: -1 });
  res.json(rules);
};

export const createRule = async (req, res) => {
  const { name, description, trigger, conditions, actions, playbookId, priority, enabled } = req.body || {};
  if (!name || !trigger) return res.status(400).json({ error: "name and trigger are required" });

  const rule = await AutomationRule.create({
    name,
    description,
    trigger,
    conditions: conditions || [],
    actions: actions || [],
    playbookId: playbookId || null,
    priority: priority ?? 100,
    enabled: enabled !== false,
    createdBy: req.user.id
  });
  res.status(201).json(rule);
};

export const updateRule = async (req, res) => {
  const rule = await AutomationRule.findByIdAndUpdate(req.params.id, req.body, { new: true, runValidators: true });
  if (!rule) return res.sendStatus(404);
  res.json(rule);
};

export const setRuleEnabled = async (req, res) => {
  const rule = await AutomationRule.findByIdAndUpdate(req.params.id, { enabled: !!req.body?.enabled }, { new: true });
  if (!rule) return res.sendStatus(404);
  res.json(rule);
};

export const deleteRule = async (req, res) => {
  const rule = await AutomationRule.findByIdAndDelete(req.params.id);
  if (!rule) return res.sendStatus(404);
  res.json({ message: "Deleted" });
};

/* ============================ PLAYBOOKS ============================ */

export const listPlaybooks = async (_req, res) => {
  const playbooks = await Playbook.find().sort({ createdAt: -1 });
  res.json(playbooks);
};

export const createPlaybook = async (req, res) => {
  const { name, description, category, steps, enabled } = req.body || {};
  if (!name || !Array.isArray(steps)) return res.status(400).json({ error: "name and steps[] are required" });

  try {
    const playbook = await Playbook.create({
      name,
      description,
      category: category || "General",
      steps,
      enabled: enabled !== false,
      createdBy: req.user.id
    });
    res.status(201).json(playbook);
  } catch (err) {
    if (err?.code === 11000) return res.status(409).json({ error: "A playbook with this name already exists" });
    res.status(500).json({ error: err?.message || "Failed to create playbook" });
  }
};

export const updatePlaybook = async (req, res) => {
  const playbook = await Playbook.findByIdAndUpdate(req.params.id, req.body, { new: true, runValidators: true });
  if (!playbook) return res.sendStatus(404);
  res.json(playbook);
};

export const deletePlaybook = async (req, res) => {
  const playbook = await Playbook.findByIdAndDelete(req.params.id);
  if (!playbook) return res.sendStatus(404);
  await AutomationRule.updateMany({ playbookId: playbook._id }, { playbookId: null, enabled: false });
  res.json({ message: "Deleted" });
};

export const clonePlaybook = async (req, res) => {
  const source = await Playbook.findById(req.params.id).lean();
  if (!source) return res.sendStatus(404);

  let name = `${source.name} (Copy)`;
  let suffix = 2;
  while (await Playbook.exists({ name })) {
    name = `${source.name} (Copy ${suffix})`;
    suffix++;
  }

  const clone = await Playbook.create({
    name,
    description: source.description,
    category: source.category,
    steps: source.steps,
    enabled: true,
    createdBy: req.user.id
  });
  res.status(201).json(clone);
};

export const exportPlaybook = async (req, res) => {
  const playbook = await Playbook.findById(req.params.id).lean();
  if (!playbook) return res.sendStatus(404);

  const { name, description, category, steps } = playbook;
  res.setHeader("Content-Disposition", `attachment; filename="playbook-${playbook.name.replace(/\W+/g, "-")}.json"`);
  res.json({ name, description, category, steps });
};

export const importPlaybook = async (req, res) => {
  const { name, description, category, steps } = req.body || {};
  if (!name || !Array.isArray(steps)) return res.status(400).json({ error: "name and steps[] are required" });

  const invalidStep = steps.find((s) => !ACTION_TYPES.includes(s.type));
  if (invalidStep) return res.status(400).json({ error: `Unknown action type "${invalidStep.type}"` });

  try {
    const playbook = await Playbook.create({ name, description, category: category || "Imported", steps, createdBy: req.user.id });
    res.status(201).json(playbook);
  } catch (err) {
    if (err?.code === 11000) return res.status(409).json({ error: "A playbook with this name already exists" });
    res.status(500).json({ error: err?.message || "Failed to import playbook" });
  }
};

export const getActionTypes = async (_req, res) => {
  res.json(ACTION_TYPES);
};

/* ============================ EXECUTIONS ============================ */

export const listExecutions = async (req, res) => {
  const admin = await isAdminReq(req);
  const filter = admin ? {} : { owner: req.user.id };
  if (req.query.status) filter.status = req.query.status;

  const executions = await AutomationExecution.find(filter).sort({ createdAt: -1 }).limit(200);
  res.json(executions);
};

export const getExecution = async (req, res) => {
  const admin = await isAdminReq(req);
  const filter = { _id: req.params.id };
  if (!admin) filter.owner = req.user.id;

  const execution = await AutomationExecution.findOne(filter);
  if (!execution) return res.sendStatus(404);
  res.json(execution);
};

/* ============================== STATS ============================== */

export const getStats = async (req, res) => {
  const admin = await isAdminReq(req);
  const filter = admin ? {} : { owner: req.user.id };

  const executions = await AutomationExecution.find(filter)
    .select("ruleName playbookName status durationMs actionsExecuted createdAt");

  const stats = {
    totalExecutions: executions.length,
    byStatus: { completed: 0, partial: 0, failed: 0 },
    successRate: 0,
    avgResponseTimeMs: 0,
    topRules: {},
    topPlaybooks: {},
    actionDistribution: {},
    timeline: []
  };

  let totalDuration = 0;
  for (const exec of executions) {
    if (stats.byStatus[exec.status] !== undefined) stats.byStatus[exec.status]++;
    totalDuration += exec.durationMs || 0;
    if (exec.ruleName) stats.topRules[exec.ruleName] = (stats.topRules[exec.ruleName] || 0) + 1;
    if (exec.playbookName) stats.topPlaybooks[exec.playbookName] = (stats.topPlaybooks[exec.playbookName] || 0) + 1;
    for (const action of exec.actionsExecuted || []) {
      stats.actionDistribution[action.type] = (stats.actionDistribution[action.type] || 0) + 1;
    }
    stats.timeline.push({ createdAt: exec.createdAt, status: exec.status, durationMs: exec.durationMs });
  }

  stats.avgResponseTimeMs = executions.length > 0 ? Math.round(totalDuration / executions.length) : 0;
  stats.successRate = executions.length > 0 ? Math.round((stats.byStatus.completed / executions.length) * 100) : 100;

  const [rulesCount, playbooksCount] = await Promise.all([
    AutomationRule.countDocuments(),
    Playbook.countDocuments()
  ]);
  stats.rulesCount = rulesCount;
  stats.playbooksCount = playbooksCount;

  res.json(stats);
};

/* ============================== EXPORT =============================== */

export const exportReport = async (req, res) => {
  const admin = await isAdminReq(req);
  const filter = admin ? {} : { owner: req.user.id };
  const format = req.query.format === "json" ? "json" : "csv";

  const executions = await AutomationExecution.find(filter).sort({ createdAt: -1 }).limit(5000);
  const rows = executions.map((e) => ({
    id: e._id,
    rule: e.ruleName,
    playbook: e.playbookName || "",
    trigger: e.trigger,
    status: e.status,
    durationMs: e.durationMs,
    result: e.result,
    actionsCount: e.actionsExecuted.length,
    createdAt: e.createdAt
  }));

  if (format === "json") {
    res.setHeader("Content-Disposition", `attachment; filename="soar-export-${Date.now()}.json"`);
    return res.json(rows);
  }

  const header = ["ID", "Rule", "Playbook", "Trigger", "Status", "Duration (ms)", "Result", "Actions", "CreatedAt"];
  const csvRows = rows.map((r) => [
    r.id, r.rule, r.playbook, r.trigger, r.status, r.durationMs, r.result, r.actionsCount, new Date(r.createdAt).toISOString()
  ]);
  const csv = [header, ...csvRows].map((r) => r.map((v) => `"${String(v).replace(/"/g, '""')}"`).join(",")).join("\n");

  res.setHeader("Content-Type", "text/csv; charset=utf-8");
  res.setHeader("Content-Disposition", `attachment; filename="soar-export-${Date.now()}.csv"`);
  res.send(csv);
};
