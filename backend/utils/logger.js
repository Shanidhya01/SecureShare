/**
 * Phase 13 (Platform Operations): structured JSON logging via winston. Additive - existing
 * console.log/console.error call sites across Phases 1-12 are untouched; this is used by new
 * Phase 13 code and server.js's startup path only. Each log line carries requestId/correlationId
 * when called from within an HTTP request (see middleware/requestContext.middleware.js), so logs
 * can be traced end-to-end without changing every call site's signature.
 */
import winston from "winston";
import { getRequestContext } from "../middleware/requestContext.middleware.js";

const contextFormat = winston.format((info) => {
  const ctx = getRequestContext();
  if (ctx) {
    info.requestId = ctx.requestId;
    info.correlationId = ctx.correlationId;
    if (ctx.userId) info.userId = ctx.userId;
    if (ctx.ip) info.ip = ctx.ip;
    if (ctx.route) info.route = ctx.route;
  }
  return info;
});

export const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || "info",
  format: winston.format.combine(contextFormat(), winston.format.timestamp(), winston.format.errors({ stack: true }), winston.format.json()),
  defaultMeta: { service: "secureshare-backend" },
  transports: [new winston.transports.Console()]
});

export function logRequestCompletion({ method, route, statusCode, durationMs, error }) {
  const level = error || statusCode >= 500 ? "error" : statusCode >= 400 ? "warn" : "info";
  logger.log(level, "http_request", {
    method,
    route,
    status: statusCode,
    duration: durationMs,
    ...(error ? { error: error.message, stack: error.stack, severity: "ERROR" } : { severity: level.toUpperCase() })
  });
}

export default logger;
