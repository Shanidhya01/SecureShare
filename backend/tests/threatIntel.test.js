/**
 * Sanity tests for the Phase 7 Threat Intelligence engine, using Node's built-in test runner
 * (same convention as backend/tests/dlp.test.js). These deliberately avoid a live MongoDB
 * connection - like dlp.test.js, they exercise the dependency-free/pure pieces (extraction,
 * MITRE mapping, YARA rule parsing, provider normalization/graceful-skip) rather than the
 * DB-backed IOC lookup, consistent with how this repo's test suite is scoped.
 * Run with: node --test backend/tests
 */
import test from "node:test";
import assert from "node:assert/strict";
import { extractIndicators } from "../services/threatIntel/extractors.js";
import { mapToMitre, getMitreCatalog } from "../services/threatIntel/mitreMapping.js";
import { parseRule, evaluateCondition } from "../services/threatIntel/yaraEngine.js";
import * as virusTotal from "../services/threatIntel/providers/virusTotalProvider.js";
import * as abuseIpdb from "../services/threatIntel/providers/abuseIpdbProvider.js";
import * as alienVaultOtx from "../services/threatIntel/providers/alienVaultOtxProvider.js";
import * as urlhaus from "../services/threatIntel/providers/urlhausProvider.js";
import * as openPhish from "../services/threatIntel/providers/openPhishProvider.js";
import * as circl from "../services/threatIntel/providers/circlProvider.js";

test("extractIndicators pulls URLs, domains, emails, and IPs from plaintext", () => {
  const text = "Beacon to http://evil.example.com/gate.php from 203.0.113.5, contact admin@example.com";
  const result = extractIndicators(text);
  assert.ok(result.urls.includes("http://evil.example.com/gate.php"));
  assert.ok(result.domains.includes("evil.example.com"));
  assert.ok(result.emails.includes("admin@example.com"));
  assert.ok(result.ips.includes("203.0.113.5"));
});

test("extractIndicators returns empty arrays for non-string/empty input", () => {
  assert.deepEqual(extractIndicators(""), { urls: [], domains: [], emails: [], ips: [] });
  assert.deepEqual(extractIndicators(null), { urls: [], domains: [], emails: [], ips: [] });
});

test("mapToMitre matches keywords to known techniques", () => {
  const matches = mapToMitre(["powershell encoded command", "ransomware"]);
  const ids = matches.map((m) => m.techniqueId);
  assert.ok(ids.includes("T1059"));
  assert.ok(ids.includes("T1486"));
});

test("mapToMitre returns empty array for no hints or unrecognized hints", () => {
  assert.deepEqual(mapToMitre([]), []);
  assert.deepEqual(mapToMitre(["totally_unrelated_benign_tag"]), []);
});

test("getMitreCatalog exposes a curated technique list", () => {
  const catalog = getMitreCatalog();
  assert.ok(catalog.length > 0);
  assert.ok(catalog.every((t) => t.techniqueId && t.name && t.tactic));
});

test("YARA parseRule extracts text and regex string patterns", () => {
  const { patterns, condition } = parseRule('strings:\n  $a = "-EncodedCommand"\n  $b = /shell\\(/i\ncondition:\n  any of them');
  assert.equal(patterns.length, 2);
  assert.equal(patterns[0].kind, "text");
  assert.equal(patterns[1].kind, "regex");
  assert.equal(condition, "any of them");
});

test("YARA evaluateCondition honors any/all/N-of-them semantics", () => {
  assert.equal(evaluateCondition("any of them", 1, 3), true);
  assert.equal(evaluateCondition("any of them", 0, 3), false);
  assert.equal(evaluateCondition("all of them", 2, 3), false);
  assert.equal(evaluateCondition("all of them", 3, 3), true);
  assert.equal(evaluateCondition("2 of them", 2, 3), true);
  assert.equal(evaluateCondition("2 of them", 1, 3), false);
});

test("VirusTotal provider skips gracefully when VIRUSTOTAL_API_KEY is unset", async () => {
  delete process.env.VIRUSTOTAL_API_KEY;
  const result = await virusTotal.lookup("sha256", "a".repeat(64));
  assert.equal(result.status, "skipped");
});

test("AbuseIPDB provider skips gracefully when ABUSEIPDB_API_KEY is unset", async () => {
  delete process.env.ABUSEIPDB_API_KEY;
  const result = await abuseIpdb.lookup("ip", "203.0.113.5");
  assert.equal(result.status, "skipped");
});

test("AlienVault OTX provider skips gracefully when OTX_API_KEY is unset", async () => {
  delete process.env.OTX_API_KEY;
  const result = await alienVaultOtx.lookup("domain", "example.com");
  assert.equal(result.status, "skipped");
});

test("URLHaus provider skips gracefully when explicitly disabled", async () => {
  process.env.THREAT_INTEL_ENABLE_URLHAUS = "false";
  const result = await urlhaus.lookup("url", "http://example.com/x");
  assert.equal(result.status, "skipped");
  delete process.env.THREAT_INTEL_ENABLE_URLHAUS;
});

test("OpenPhish provider skips gracefully when explicitly disabled", async () => {
  process.env.THREAT_INTEL_ENABLE_OPENPHISH = "false";
  const result = await openPhish.lookup("url", "http://example.com/x");
  assert.equal(result.status, "skipped");
  delete process.env.THREAT_INTEL_ENABLE_OPENPHISH;
});

test("CIRCL provider skips gracefully when explicitly disabled", async () => {
  process.env.THREAT_INTEL_ENABLE_CIRCL = "false";
  const result = await circl.lookup("sha256", "a".repeat(64));
  assert.equal(result.status, "skipped");
  delete process.env.THREAT_INTEL_ENABLE_CIRCL;
});

test("providers report 'skipped' (not a thrown error) for unsupported indicator types", async () => {
  const result = await abuseIpdb.lookup("domain", "example.com");
  assert.equal(result.status, "skipped");
});
