/**
 * OpenPhish provider for Phase 7 - free community phishing URL feed (a flat list of URLs, no
 * per-lookup API). We fetch and cache the list in-memory for a short TTL rather than hitting the
 * feed on every lookup; disabled gracefully if fetching ever fails, same "never break enrichment"
 * contract as the keyed providers.
 */
import https from "https";

export const name = "OpenPhish";
export const supportedTypes = ["url", "domain"];

const FEED_URL_HOST = "openphish.com";
const FEED_URL_PATH = "/feed.txt";
const CACHE_TTL_MS = 30 * 60 * 1000;

let cache = { urls: [], fetchedAt: 0 };

function fetchFeed() {
  return new Promise((resolve) => {
    const req = https.request({ hostname: FEED_URL_HOST, path: FEED_URL_PATH, method: "GET", timeout: 8000 }, (res) => {
      if (res.statusCode && res.statusCode >= 400) {
        res.resume();
        resolve([]);
        return;
      }
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => resolve(Buffer.concat(chunks).toString("utf8").split("\n").filter(Boolean)));
    });
    req.on("timeout", () => { req.destroy(); resolve([]); });
    req.on("error", () => resolve([]));
    req.end();
  });
}

export async function lookup(type, value) {
  if (process.env.THREAT_INTEL_ENABLE_OPENPHISH === "false") {
    return { status: "skipped", confidence: 0, severity: "Low", threatNames: [] };
  }
  if (!["url", "domain"].includes(type)) return { status: "skipped", confidence: 0, severity: "Low", threatNames: [] };

  try {
    if (Date.now() - cache.fetchedAt > CACHE_TTL_MS) {
      cache = { urls: await fetchFeed(), fetchedAt: Date.now() };
    }
    const hit = type === "url"
      ? cache.urls.includes(value)
      : cache.urls.some((u) => u.includes(value));

    if (!hit) return { status: "clean", confidence: 0, severity: "Low", threatNames: [] };
    return { status: "malicious", confidence: 85, severity: "High", threatNames: ["phishing"] };
  } catch (err) {
    return { status: "error", confidence: 0, severity: "Low", threatNames: [], error: err.message };
  }
}
