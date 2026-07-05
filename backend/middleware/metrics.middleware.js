/**
 * Phase 13 (Platform Operations) - PART 8: records API latency/count/status for every request into
 * services/platform/metricsCollector.js's in-memory ring buffer, and logs request completion via
 * the structured logger (PART 7). Mounted globally in server.js, after requestContext.middleware.js.
 */
import { recordApiRequest } from "../services/platform/metricsCollector.js";
import { logRequestCompletion } from "../utils/logger.js";

export function metrics(req, res, next) {
  const start = process.hrtime.bigint();
  res.on("finish", () => {
    const durationMs = Number(process.hrtime.bigint() - start) / 1e6;
    const route = req.route?.path ? `${req.baseUrl}${req.route.path}` : req.originalUrl;
    recordApiRequest({ route, method: req.method, statusCode: res.statusCode, durationMs: Math.round(durationMs) });
    logRequestCompletion({ method: req.method, route, statusCode: res.statusCode, durationMs: Math.round(durationMs) });
  });
  next();
}
