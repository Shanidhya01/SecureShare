/**
 * Phase 11 (CSPM/ASM) - PART 4: certificate monitoring. Connects (via Node's built-in `tls`
 * module) to each configured HTTPS domain, reads the peer certificate, and upserts a Certificate
 * doc. `lastNotifiedTier` dedupes SIEM alerts so the 30/15/7/expired thresholds each fire at most
 * once per certificate until it's renewed. Domains come from `CLOUD_MONITORED_DOMAINS` (comma-
 * separated) plus the frontend origin (`WEBAUTHN_ORIGIN`/`FRONTEND_URL`) when it's HTTPS - this
 * project has no other externally reachable HTTPS endpoints to monitor.
 */
import tls from "tls";
import Certificate from "../../models/Certificate.js";
import { logSecurityEvent } from "../siem/siemLogger.js";

const DAY_MS = 24 * 60 * 60 * 1000;
const CONNECT_TIMEOUT_MS = 5000;

export function daysRemaining(validTo, now = new Date()) {
  return Math.ceil((new Date(validTo).getTime() - now.getTime()) / DAY_MS);
}

export function tierForDaysRemaining(days) {
  if (days <= 0) return "expired";
  if (days <= 7) return "7";
  if (days <= 15) return "15";
  if (days <= 30) return "30";
  return "none";
}

function fetchPeerCertificate(domain) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({ host: domain, port: 443, servername: domain, timeout: CONNECT_TIMEOUT_MS }, () => {
      const cert = socket.getPeerCertificate();
      const cipher = socket.getCipher();
      const protocol = socket.getProtocol();
      socket.end();
      if (!cert || !cert.valid_to) {
        reject(new Error("No certificate returned"));
        return;
      }
      resolve({
        issuer: cert.issuer?.O || cert.issuer?.CN || "Unknown",
        subject: cert.subject?.CN || domain,
        validFrom: new Date(cert.valid_from),
        validTo: new Date(cert.valid_to),
        algorithm: cert.pubkey?.asymmetricKeyType || cert.sigalg || "unknown",
        tlsVersion: protocol || "unknown",
        cipher: cipher?.name || "unknown"
      });
    });
    socket.on("error", reject);
    socket.on("timeout", () => {
      socket.destroy();
      reject(new Error("Connection timed out"));
    });
  });
}

export function resolveMonitoredDomains() {
  const domains = new Set();

  for (const raw of (process.env.CLOUD_MONITORED_DOMAINS || "").split(",")) {
    const domain = raw.trim();
    if (domain) domains.add(domain);
  }

  const origin = process.env.WEBAUTHN_ORIGIN || process.env.FRONTEND_URL || "";
  try {
    const url = new URL(origin);
    if (url.protocol === "https:") domains.add(url.hostname);
  } catch {
    // origin not a valid absolute URL (e.g. local dev http://localhost:3000) - nothing to monitor
  }

  return [...domains];
}

const WEAK_TLS_VERSIONS = new Set(["TLSv1", "TLSv1.1"]);

async function checkDomain({ owner, domain }) {
  let existing = await Certificate.findOne({ domain });

  let certInfo;
  try {
    certInfo = await fetchPeerCertificate(domain);
  } catch (err) {
    if (existing) {
      existing.status = "unreachable";
      existing.lastCheckedAt = new Date();
      await existing.save();
    }
    return existing;
  }

  const days = daysRemaining(certInfo.validTo);
  const tier = tierForDaysRemaining(days);
  const status = tier === "expired" ? "expired" : tier === "none" ? "valid" : "expiring";

  const cert = await Certificate.findOneAndUpdate(
    { domain },
    {
      ...certInfo,
      domain,
      status,
      daysRemaining: days,
      lastCheckedAt: new Date(),
      ...(tier !== existing?.lastNotifiedTier ? { lastNotifiedTier: tier } : {})
    },
    { upsert: true, new: true }
  );

  const alreadyNotifiedThisTier = existing?.lastNotifiedTier === tier;
  if (!alreadyNotifiedThisTier && tier !== "none") {
    await logSecurityEvent({
      owner,
      type: tier === "expired" ? "certificate_expired" : "certificate_expiring",
      message: tier === "expired"
        ? `Certificate for ${domain} has expired`
        : `Certificate for ${domain} expires in ${days} day(s) (${tier}-day threshold)`,
      metadata: { domain, daysRemaining: days, tier }
    }).catch(() => {});
  }

  if (WEAK_TLS_VERSIONS.has(certInfo.tlsVersion)) {
    await logSecurityEvent({
      owner,
      type: "weak_tls",
      message: `${domain} is negotiating a weak TLS version (${certInfo.tlsVersion})`,
      metadata: { domain, tlsVersion: certInfo.tlsVersion }
    }).catch(() => {});
  }

  return cert;
}

export async function runCertificateMonitor({ owner, domains } = {}) {
  const targets = domains || resolveMonitoredDomains();
  const results = [];
  for (const domain of targets) {
    results.push(await checkDomain({ owner, domain }));
  }
  return results.filter(Boolean);
}
