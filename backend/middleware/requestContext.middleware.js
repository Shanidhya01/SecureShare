/**
 * Phase 13 (Platform Operations): request-scoped correlation IDs via AsyncLocalStorage so
 * logger.js and metrics.middleware.js can tag every log line/metric with requestId, an inbound
 * correlationId (propagated from `x-correlation-id` if the caller sent one, generated otherwise),
 * user, ip, and route - without threading those values through every function signature.
 */
import { AsyncLocalStorage } from "node:async_hooks";
import crypto from "node:crypto";

const als = new AsyncLocalStorage();

export function getRequestContext() {
  return als.getStore();
}

export function requestContext(req, res, next) {
  const requestId = crypto.randomUUID();
  const correlationId = req.headers["x-correlation-id"] || requestId;
  const store = { requestId, correlationId, ip: req.ip, route: req.originalUrl };
  res.setHeader("x-request-id", requestId);
  res.setHeader("x-correlation-id", correlationId);
  als.run(store, () => {
    req.on("close", () => {
      const ctx = getRequestContext();
      if (ctx && req.user?.id) ctx.userId = req.user.id;
    });
    next();
  });
}

/** Called after auth middleware sets req.user, so subsequent logs in the same request carry it. */
export function attachUserToContext(req, _res, next) {
  const ctx = getRequestContext();
  if (ctx && req.user?.id) ctx.userId = req.user.id;
  next();
}
