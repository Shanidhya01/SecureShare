/**
 * Phase 13 (Platform Operations) - PART 7: Alert Engine. Pure rule array evaluated against the
 * output of healthChecker.js + metricsCollector.js (mirrors services/soar/ruleMatcher.js's
 * pure-function-over-context convention so rules are unit testable without touching Mongo). On
 * trigger, upserts an active PlatformAlert and emits the matching SIEM event, which automatically
 * fires SOAR (services/siem/siemLogger.js -> runSoarEngine) - no separate SOAR call needed here.
 * Every rule targets a managed cloud dependency (MongoDB Atlas/Redis Cloud/Cloudinary/ClamAV on
 * Render) or an application-level metric - none inspect local host CPU/disk/memory, since this
 * deployment has no VM to monitor those on.
 */
import PlatformAlert from "../../models/PlatformAlert.js";
import PlatformJob from "../../models/PlatformJob.js";
import { logSecurityEvent } from "../siem/siemLogger.js";

const RULES = [
  {
    rule: "MONGODB_OFFLINE",
    siemType: "mongodb_offline",
    severity: "CRITICAL",
    evaluate: (ctx) => ctx.health.components.find((c) => c.name === "mongodb")?.status === "DOWN",
    message: () => "MongoDB Atlas is unreachable"
  },
  {
    rule: "REDIS_OFFLINE",
    siemType: "redis_offline",
    severity: "MEDIUM",
    evaluate: (ctx) => ctx.health.components.find((c) => c.name === "redis")?.status === "DOWN",
    message: () => "Redis Cloud is unreachable - platform is running in fallback mode"
  },
  {
    rule: "CLOUDINARY_FAILURE",
    siemType: "cloudinary_failure",
    severity: "HIGH",
    evaluate: (ctx) => ctx.health.components.find((c) => c.name === "cloudinary")?.status === "DOWN",
    message: () => "Cloudinary file storage is unreachable"
  },
  {
    rule: "CLAMAV_OFFLINE",
    siemType: "clamav_offline",
    severity: "MEDIUM",
    evaluate: (ctx) => ctx.health.components.find((c) => c.name === "clamav")?.status === "DOWN",
    message: () => "ClamAV (Render) is unreachable"
  },
  {
    rule: "QUEUE_FAILURE",
    siemType: "queue_failure",
    severity: "HIGH",
    evaluate: (ctx) => ctx.health.components.find((c) => c.name === "queue")?.status === "DEGRADED",
    message: () => "Background job queue has an elevated failure count"
  },
  {
    rule: "HIGH_ERROR_RATE",
    siemType: "queue_failure",
    severity: "HIGH",
    evaluate: (ctx) => (ctx.metrics?.api?.errorRate ?? 0) > 10,
    message: (ctx) => `API error rate is ${ctx.metrics.api.errorRate}% over the last ${ctx.metrics.api.requestCount} requests`
  },
  {
    rule: "SLOW_API",
    siemType: "high_api_latency",
    severity: "MEDIUM",
    evaluate: (ctx) => (ctx.metrics?.api?.p95LatencyMs ?? 0) > 2000,
    message: (ctx) => `p95 API latency is ${ctx.metrics.api.p95LatencyMs}ms`
  },
  {
    rule: "BACKGROUND_JOB_FAILURE",
    siemType: "background_job_failed",
    severity: "MEDIUM",
    evaluate: (ctx) => (ctx.recentFailedJobs ?? 0) >= 3,
    message: (ctx) => `${ctx.recentFailedJobs} background jobs have failed recently`
  },
  {
    rule: "HEALTH_SCORE_DROP",
    siemType: "platform_health_changed",
    severity: "HIGH",
    evaluate: (ctx) => ctx.health.overallScore < 60,
    message: (ctx) => `Platform health score dropped to ${ctx.health.overallScore}`
  }
];

export async function evaluateAlerts({ health, metrics, owner } = {}) {
  const recentFailedJobs = await PlatformJob.countDocuments({
    status: "failed",
    createdAt: { $gte: new Date(Date.now() - 60 * 60 * 1000) }
  }).catch(() => 0);
  const ctx = { health, metrics, recentFailedJobs };
  const triggered = [];

  for (const rule of RULES) {
    let matched = false;
    try {
      matched = !!rule.evaluate(ctx);
    } catch {
      matched = false;
    }

    const existing = await PlatformAlert.findOne({ rule: rule.rule, active: true });

    if (matched && !existing) {
      const message = rule.message(ctx);
      const alert = await PlatformAlert.create({ rule: rule.rule, severity: rule.severity, message, active: true });
      await logSecurityEvent({ owner, type: rule.siemType, message, metadata: { rule: rule.rule } }).catch(() => {});
      triggered.push(alert);
    } else if (!matched && existing) {
      existing.active = false;
      existing.resolvedAt = new Date();
      await existing.save();
    }
  }

  return triggered;
}

export async function listActiveAlerts() {
  return PlatformAlert.find({ active: true }).sort({ triggeredAt: -1 }).lean();
}

export async function listAlertHistory({ limit = 100 } = {}) {
  return PlatformAlert.find().sort({ triggeredAt: -1 }).limit(limit).lean();
}

export const ALERT_RULES = RULES.map((r) => ({ rule: r.rule, severity: r.severity, siemType: r.siemType }));
