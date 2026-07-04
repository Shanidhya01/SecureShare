/**
 * Phase 11 (CSPM/ASM) - PART 1/2: builds the Asset inventory by introspecting SecureShare's own
 * deployment (this project has no multi-cloud footprint to enumerate, so "cloud asset discovery"
 * here means self-discovery of the running Express/Next.js stack - servers, the database, each
 * registered API route group, the frontend origin, file storage, and container/reverse-proxy
 * config already present in the repo). Upserts Asset docs (keyed by name+type) and logs
 * ASSET_DISCOVERED/ASSET_UPDATED via the existing services/siem/siemLogger.js - same fire-and-
 * forget pattern as services/threatIntel/threatIntelIntegration.js.
 */
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import Asset from "../../models/Asset.js";
import { logSecurityEvent } from "../siem/siemLogger.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const BACKEND_DIR = path.join(__dirname, "..", "..");
const REPO_ROOT = path.join(BACKEND_DIR, "..");
const ROUTES_DIR = path.join(BACKEND_DIR, "routes");

const ROUTE_METHOD_RE = /router\.(get|post|put|patch|delete)\(\s*["'`]([^"'`]+)["'`]/g;

const HIGH_CRITICALITY_MOUNTS = new Set(["compliance", "soar", "iam", "auth", "mfa", "passkey"]);

function discoverApiEndpoints() {
  const endpoints = [];
  if (!fs.existsSync(ROUTES_DIR)) return endpoints;

  for (const file of fs.readdirSync(ROUTES_DIR)) {
    if (!file.endsWith(".routes.js")) continue;
    const mountName = file.replace(".routes.js", "");
    const source = fs.readFileSync(path.join(ROUTES_DIR, file), "utf8");

    const paths = new Set();
    ROUTE_METHOD_RE.lastIndex = 0;
    let match;
    while ((match = ROUTE_METHOD_RE.exec(source))) {
      paths.add(`${match[1].toUpperCase()} ${match[2]}`);
    }
    endpoints.push({ mountName, routeCount: paths.size, paths: [...paths] });
  }
  return endpoints;
}

/** Upserts by (name, type) - the pair Asset.js indexes uniquely - refreshing metadata/lastScan on
 *  every rediscovery and logging a distinct SIEM event for new vs. previously-seen assets. */
async function upsertAsset({ name, type, environment, criticality = "medium", tags = [], metadata = {}, owner }) {
  const existing = await Asset.findOne({ name, type });
  const now = new Date();

  if (existing) {
    existing.environment = environment;
    existing.criticality = criticality;
    existing.tags = tags;
    existing.metadata = { ...(existing.metadata || {}), ...metadata };
    existing.lastScan = now;
    await existing.save();
    logSecurityEvent({
      owner,
      type: "asset_updated",
      message: `Asset "${name}" (${type}) refreshed by discovery scan`,
      metadata: { assetId: String(existing._id), assetType: type }
    }).catch(() => {});
    return existing;
  }

  const created = await Asset.create({ name, type, environment, criticality, tags, metadata, owner, status: "active", lastScan: now });
  logSecurityEvent({
    owner,
    type: "asset_discovered",
    message: `New cloud asset discovered: "${name}" (${type})`,
    metadata: { assetId: String(created._id), assetType: type }
  }).catch(() => {});
  return created;
}

export async function discoverAssets({ owner } = {}) {
  const environment = process.env.NODE_ENV === "production" ? "production" : "development";
  const assets = [];

  assets.push(await upsertAsset({
    name: "SecureShare API Server", type: "Server", environment, criticality: "critical", owner,
    tags: ["express", "node"], metadata: { nodeVersion: process.version, port: process.env.PORT || "5000" }
  }));

  assets.push(await upsertAsset({
    name: "MongoDB Primary Database", type: "Database", environment, criticality: "critical", owner,
    tags: ["mongodb", "mongoose"], metadata: { configured: !!process.env.MONGO_URI }
  }));

  for (const ep of discoverApiEndpoints()) {
    assets.push(await upsertAsset({
      name: `/api/${ep.mountName}`,
      type: "APIEndpoint",
      environment,
      criticality: HIGH_CRITICALITY_MOUNTS.has(ep.mountName) ? "high" : "medium",
      owner,
      tags: ["express-router"],
      metadata: { routeCount: ep.routeCount, sampleRoutes: ep.paths.slice(0, 15) }
    }));
  }

  const frontendOrigin = process.env.WEBAUTHN_ORIGIN || process.env.FRONTEND_URL || "http://localhost:3000";
  try {
    assets.push(await upsertAsset({
      name: new URL(frontendOrigin).hostname, type: "Domain", environment, criticality: "high", owner,
      tags: ["frontend"], metadata: { origin: frontendOrigin }
    }));
  } catch {
    // malformed WEBAUTHN_ORIGIN/FRONTEND_URL - skip rather than fail the whole scan
  }

  if (process.env.CLOUDINARY_CLOUD_NAME) {
    assets.push(await upsertAsset({
      name: "Cloudinary File Storage", type: "Storage", environment, criticality: "high", owner,
      tags: ["cloudinary"], metadata: { cloudName: process.env.CLOUDINARY_CLOUD_NAME }
    }));
  }

  if (process.env.CLAMAV_HOST) {
    assets.push(await upsertAsset({
      name: "ClamAV Malware Scanner", type: "Service", environment, criticality: "medium", owner,
      tags: ["clamav", "malware-scanning"], metadata: { host: process.env.CLAMAV_HOST, port: process.env.CLAMAV_PORT }
    }));
  }

  if (fs.existsSync(path.join(BACKEND_DIR, "Dockerfile"))) {
    assets.push(await upsertAsset({
      name: "backend/Dockerfile", type: "DockerImage", environment, criticality: "medium", owner,
      tags: ["docker"], metadata: {}
    }));
  }

  if (fs.existsSync(path.join(REPO_ROOT, "docker-compose.yml"))) {
    const compose = fs.readFileSync(path.join(REPO_ROOT, "docker-compose.yml"), "utf8");
    const serviceNames = [...compose.matchAll(/^\s{0,2}([a-zA-Z0-9_-]+):\s*$/gm)]
      .map((m) => m[1])
      .filter((n) => !["services", "volumes", "networks", "version"].includes(n));

    for (const service of serviceNames) {
      assets.push(await upsertAsset({
        name: `docker-compose:${service}`, type: "Container", environment, criticality: "medium", owner,
        tags: ["docker-compose"], metadata: { service }
      }));
    }

    if (/\bvolumes:\s*\n/.test(compose)) {
      assets.push(await upsertAsset({
        name: "docker-compose volumes", type: "Volume", environment, criticality: "low", owner, tags: ["docker-compose"]
      }));
    }
    if (/\bnetworks:\s*\n/.test(compose)) {
      assets.push(await upsertAsset({
        name: "docker-compose network", type: "Network", environment, criticality: "low", owner, tags: ["docker-compose"]
      }));
    }
  }

  // `app.set("trust proxy", 1)` in server.js only makes sense behind a reverse proxy/load balancer.
  assets.push(await upsertAsset({
    name: "Reverse Proxy / Trust Boundary", type: "ReverseProxy", environment, criticality: "medium", owner,
    tags: ["express-trust-proxy"], metadata: { trustProxy: true }
  }));

  return assets;
}
