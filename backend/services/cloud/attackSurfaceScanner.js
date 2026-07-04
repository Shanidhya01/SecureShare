/**
 * Phase 11 (CSPM/ASM) - PART 5: Attack Surface Management. Self-probes SecureShare's own base URL
 * (never third-party hosts) for the well-known paths the spec calls out - never a target chosen by
 * a caller, so this can't be abused as an open-ended scanner. Uses Node's built-in global `fetch`
 * (Node 18+, already the runtime here) - no new HTTP-client dependency needed.
 */
import CloudFinding from "../../models/CloudFinding.js";
import { logSecurityEvent } from "../siem/siemLogger.js";

const REQUEST_TIMEOUT_MS = 4000;

/** path -> { severity, title, recommendation } if *reachable* (200) is worth flagging. */
const EXPOSURE_PATHS = {
  "/api-docs": { severity: "MEDIUM", title: "OpenAPI/Swagger Documentation Publicly Reachable", recommendation: "Restrict API documentation endpoints to authenticated/internal access." },
  "/swagger": { severity: "MEDIUM", title: "Swagger UI Publicly Reachable", recommendation: "Restrict Swagger UI to authenticated/internal access." },
  "/admin": { severity: "HIGH", title: "Admin Path Publicly Reachable", recommendation: "Ensure /admin (if it exists) requires authentication and is not a static route." },
  "/metrics": { severity: "MEDIUM", title: "Metrics Endpoint Publicly Reachable", recommendation: "Restrict /metrics to internal monitoring infrastructure only." },
  "/debug": { severity: "HIGH", title: "Debug Endpoint Publicly Reachable", recommendation: "Remove or authenticate any /debug endpoint before production deployment." },
  "/.well-known/security.txt": { severity: "INFO", title: "security.txt Present", recommendation: "Informational - security.txt found, no action needed.", informational: true },
  "/.env": { severity: "CRITICAL", title: "Environment File Publicly Reachable", recommendation: "Ensure .env is never served by the web server - remove it from any static/public directory." },
  "/.git/config": { severity: "CRITICAL", title: "Git Directory Publicly Reachable", recommendation: "Ensure .git is never served by the web server." }
};

/** Reachable and worth *noting* even though it's not a vulnerability by itself. */
const INFORMATIONAL_PATHS = ["/robots.txt", "/.well-known/security.txt", "/api/health"];

async function probe(baseUrl, pathname) {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    const res = await fetch(new URL(pathname, baseUrl), { method: "GET", signal: controller.signal, redirect: "manual" });
    clearTimeout(timeout);
    return { reachable: res.status >= 200 && res.status < 400, status: res.status };
  } catch {
    return { reachable: false, status: null };
  }
}

export function resolveBaseUrl() {
  return process.env.APP_BASE_URL || `http://localhost:${process.env.PORT || 5000}`;
}

export async function runAttackSurfaceScan({ owner, baseUrl } = {}) {
  const target = baseUrl || resolveBaseUrl();
  const findings = [];

  for (const [pathname, rule] of Object.entries(EXPOSURE_PATHS)) {
    const { reachable, status } = await probe(target, pathname);

    if (!reachable) {
      await CloudFinding.updateMany(
        { ruleId: `exposure:${pathname}`, category: "EXPOSURE", status: "open" },
        { status: "resolved", resolvedAt: new Date() }
      );
      continue;
    }

    const existing = await CloudFinding.findOne({ ruleId: `exposure:${pathname}`, category: "EXPOSURE", status: "open" });
    const finding = existing || await CloudFinding.create({
      category: "EXPOSURE",
      ruleId: `exposure:${pathname}`,
      title: rule.title,
      severity: rule.severity,
      recommendation: rule.recommendation,
      metadata: { path: pathname, status },
      status: "open"
    });
    findings.push(finding);

    if (!existing && !rule.informational) {
      await logSecurityEvent({
        owner,
        type: "public_exposure",
        message: `Attack surface exposure: ${rule.title} (${pathname})`,
        metadata: { path: pathname, severity: rule.severity, httpStatus: status }
      }).catch(() => {});
    }
  }

  for (const pathname of INFORMATIONAL_PATHS) {
    const { reachable, status } = await probe(target, pathname);
    findings.push({ path: pathname, reachable, status, informational: true });
  }

  return findings;
}
