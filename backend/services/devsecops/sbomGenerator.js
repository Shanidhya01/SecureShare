/**
 * Phase 12 (DevSecOps/Supply Chain) - PART 7: generates a real SBOM from this repo's own
 * package-lock.json files (npm lockfile v3's `packages` map already carries resolved version,
 * SRI integrity hash, and license per dependency - no need to walk node_modules or fabricate data).
 */
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import SBOMDocument from "../../models/SBOMDocument.js";
import { logSecurityEvent } from "../siem/siemLogger.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.join(__dirname, "..", "..", "..");

function readJson(filePath) {
  try {
    return JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch {
    return null;
  }
}

/** Base64 SRI ("sha512-xxxx==") -> plain hex, for a PURL-style hash field. */
function sriToHex(integrity) {
  if (!integrity) return null;
  const match = /^sha(256|384|512)-(.+)$/.exec(integrity);
  if (!match) return null;
  return { algorithm: `SHA-${match[1]}`, hash: Buffer.from(match[2], "base64").toString("hex") };
}

/** Pure: builds a flat component list from one lockfile's `packages` map (lockfileVersion 3). */
export function extractComponents(lockfile, ecosystem = "npm") {
  if (!lockfile?.packages) return [];
  const components = [];

  for (const [key, pkg] of Object.entries(lockfile.packages)) {
    if (key === "" || !pkg.version) continue; // "" is the root project itself
    const name = key.replace(/^.*node_modules\//, "");
    const hashInfo = sriToHex(pkg.integrity);
    components.push({
      name,
      version: pkg.version,
      purl: `pkg:${ecosystem}/${name.replace("/", "%2F")}@${pkg.version}`,
      license: pkg.license || "UNKNOWN",
      hash: hashInfo,
      supplier: pkg.resolved ? new URL(pkg.resolved).hostname : "unknown"
    });
  }
  return components;
}

export function buildCycloneDx(components, { serialization = "JSON", metadata = {} } = {}) {
  const doc = {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    version: 1,
    metadata: { timestamp: new Date().toISOString(), component: { type: "application", name: "SecureShare", ...metadata } },
    components: components.map((c) => ({
      type: "library",
      name: c.name,
      version: c.version,
      purl: c.purl,
      licenses: c.license && c.license !== "UNKNOWN" ? [{ license: { id: c.license } }] : [],
      hashes: c.hash ? [{ alg: c.hash.algorithm, content: c.hash.hash }] : [],
      supplier: { name: c.supplier }
    }))
  };

  if (serialization === "JSON") return JSON.stringify(doc, null, 2);

  const xmlComponents = doc.components
    .map(
      (c) => `    <component type="library">
      <name>${c.name}</name>
      <version>${c.version}</version>
      <purl>${c.purl}</purl>
    </component>`
    )
    .join("\n");
  return `<?xml version="1.0" encoding="UTF-8"?>\n<bom xmlns="http://cyclonedx.org/schema/bom/1.5" version="1">\n  <components>\n${xmlComponents}\n  </components>\n</bom>`;
}

export function buildSpdx(components) {
  return {
    spdxVersion: "SPDX-2.3",
    dataLicense: "CC0-1.0",
    SPDXID: "SPDXRef-DOCUMENT",
    name: "SecureShare-SBOM",
    documentNamespace: `https://secureshare.local/sbom/${Date.now()}`,
    creationInfo: { created: new Date().toISOString(), creators: ["Tool: SecureShare-DevSecOps-SBOMGenerator"] },
    packages: components.map((c, i) => ({
      SPDXID: `SPDXRef-Package-${i}`,
      name: c.name,
      versionInfo: c.version,
      downloadLocation: "NOASSERTION",
      licenseConcluded: c.license || "NOASSERTION",
      externalRefs: [{ referenceCategory: "PACKAGE-MANAGER", referenceType: "purl", referenceLocator: c.purl }],
      checksums: c.hash ? [{ algorithm: c.hash.algorithm.replace("-", ""), checksumValue: c.hash.hash }] : []
    }))
  };
}

export async function generateSbom({ owner, format = "CycloneDX", serialization = "JSON" } = {}) {
  const backendLock = readJson(path.join(REPO_ROOT, "backend", "package-lock.json"));
  const frontendLock = readJson(path.join(REPO_ROOT, "frontend", "package-lock.json"));

  const components = [
    ...extractComponents(backendLock, "npm"),
    ...extractComponents(frontendLock, "npm")
  ];
  // De-dupe by name+version (both lockfiles commonly share transitive deps).
  const unique = [...new Map(components.map((c) => [`${c.name}@${c.version}`, c])).values()];

  const content = format === "SPDX" ? buildSpdx(unique) : JSON.parse(buildCycloneDx(unique, { serialization: "JSON" }));
  const rawSerialized = format === "CycloneDX" ? buildCycloneDx(unique, { serialization }) : JSON.stringify(content, null, 2);

  const filename = `sbom-${format.toLowerCase()}-${Date.now()}.${serialization.toLowerCase()}`;

  const doc = await SBOMDocument.create({
    format,
    serialization,
    componentCount: unique.length,
    generatedBy: owner,
    content: format === "CycloneDX" && serialization === "XML" ? { xml: rawSerialized } : content,
    filename
  });

  await logSecurityEvent({
    owner,
    type: "sbom_generated",
    message: `SBOM generated (${format}/${serialization}, ${unique.length} components)`,
    metadata: { sbomId: String(doc._id), format, serialization, componentCount: unique.length }
  }).catch(() => {});

  return doc;
}
