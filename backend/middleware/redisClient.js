/**
 * Phase 13 (Platform Operations): single shared ioredis client used by rate limiting, the
 * background job queue (services/platform/queue.js), and the health checker. Degrades gracefully
 * everywhere Redis is consulted - `REDIS_URL` unset or unreachable means `isRedisAvailable()`
 * returns false and callers fall back to their in-memory/in-process equivalents rather than
 * throwing, per Phase 13 spec Part 4 ("gracefully fall back if Redis is unavailable").
 */
import Redis from "ioredis";
import { logger } from "../utils/logger.js";

let client = null;
let available = false;
let lastError = null;

export function getRedisClient() {
  if (client) return client;
  const url = process.env.REDIS_URL;
  if (!url) return null;

  client = new Redis(url, {
    maxRetriesPerRequest: 1,
    retryStrategy: (times) => Math.min(times * 500, 5000),
    lazyConnect: false,
    reconnectOnError: () => true
  });

  client.on("ready", () => {
    available = true;
    lastError = null;
    logger.info("redis_connected", { severity: "INFO" });
  });

  client.on("error", (err) => {
    if (available) logger.warn("redis_connection_lost", { error: err.message, severity: "WARN" });
    available = false;
    lastError = err.message;
  });

  return client;
}

export function isRedisAvailable() {
  return available;
}

export function getRedisStatus() {
  return { configured: !!process.env.REDIS_URL, available, lastError };
}
