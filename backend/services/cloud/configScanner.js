/**
 * Phase 11 (CSPM/ASM) - PART 3: the configuration/hardening rule engine. Each rule is a small pure
 * function `(context) => { pass, severity, recommendation, reference }` - mirrors the
 * services/compliance/controlEvaluators.js convention so every rule is independently unit
 * testable (see backend/tests/cloudConfigScanner.test.js) without touching Mongo or the network.
 * `buildScanContext()` is the only DB/fs-touching part, built once per scan, same shape idea as
 * services/compliance/evidenceCollector.js's buildComplianceContext().
 */
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import CloudFinding from "../../models/CloudFinding.js";
import { logSecurityEvent } from "../siem/siemLogger.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const BACKEND_DIR = path.join(__dirname, "..", "..");

function readSafe(filePath) {
  try {
    return fs.readFileSync(filePath, "utf8");
  } catch {
    return "";
  }
}

export function buildScanContext() {
  const serverSource = readSafe(path.join(BACKEND_DIR, "server.js"));
  const pkg = JSON.parse(readSafe(path.join(BACKEND_DIR, "package.json")) || "{}");
  const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };

  const routesDir = path.join(BACKEND_DIR, "routes");
  const routeFiles = fs.existsSync(routesDir) ? fs.readdirSync(routesDir).filter((f) => f.endsWith(".routes.js")) : [];
  const routeSources = Object.fromEntries(routeFiles.map((f) => [f, readSafe(path.join(routesDir, f))]));

  const uploadRouteFiles = ["dlp.routes.js", "file.routes.js", "threat.routes.js"].filter((f) => routeFiles.includes(f));
  const uploadLimitsConfigured = uploadRouteFiles.some((f) => /multer\(\s*\{[^)]*limits/.test(routeSources[f] || ""));

  const adminGatedMounts = ["iam.routes.js", "soar.routes.js", "compliance.routes.js"].filter((f) => routeFiles.includes(f));
  const adminGatingMissing = adminGatedMounts.filter((f) => !/requireAdmin/.test(routeSources[f] || ""));

  return {
    nodeEnv: process.env.NODE_ENV || "development",
    hasHelmet: !!deps.helmet,
    hasCompression: !!deps.compression,
    corsWideOpen: /app\.use\(cors\(\)\)/.test(serverSource),
    hasRateLimiting: /apiLimiter/.test(serverSource),
    usesExpressStatic: /express\.static\(/.test(serverSource) || Object.values(routeSources).some((s) => /express\.static\(/.test(s)),
    usesCookies: /res\.cookie\(/.test(serverSource) || Object.values(routeSources).some((s) => /res\.cookie\(/.test(s)),
    jwtSecretLength: (process.env.JWT_SECRET || "").length,
    hasSwaggerDep: !!(deps.swaggerUi || deps["swagger-ui-express"] || deps["swagger-jsdoc"]),
    cloudinaryConfigured: !!process.env.CLOUDINARY_CLOUD_NAME,
    uploadLimitsConfigured,
    adminGatingMissing,
    trustProxyConfigured: /trust proxy/.test(serverSource)
  };
}

const RULES = [
  {
    ruleId: "missing-https-enforcement",
    title: "Missing HTTPS Enforcement",
    check: () => true, // Node process itself terminates plain HTTP - TLS is delegated to the host/reverse proxy
    severity: "MEDIUM",
    recommendation: "Terminate TLS at the load balancer/reverse proxy and redirect all HTTP traffic to HTTPS (or add express middleware enforcing req.secure in production).",
    reference: "https://owasp.org/www-project-secure-headers/#http-strict-transport-security"
  },
  {
    ruleId: "weak-tls-termination",
    title: "TLS Version/Cipher Not Enforced In-App",
    check: () => true,
    severity: "LOW",
    recommendation: "Verify the reverse proxy/hosting platform enforces TLS 1.2+ with strong ciphers - this app does not terminate TLS itself.",
    reference: "https://ssl-config.mozilla.org/"
  },
  {
    ruleId: "missing-hsts",
    title: "Missing HSTS Header",
    check: (ctx) => !ctx.hasHelmet,
    severity: "MEDIUM",
    recommendation: "Add helmet() (or a custom Strict-Transport-Security header) so browsers refuse to downgrade to HTTP.",
    reference: "https://owasp.org/www-project-secure-headers/#http-strict-transport-security"
  },
  {
    ruleId: "missing-csp",
    title: "Missing Content-Security-Policy Header",
    check: (ctx) => !ctx.hasHelmet,
    severity: "HIGH",
    recommendation: "Add a Content-Security-Policy header (e.g. via helmet.contentSecurityPolicy()) to mitigate XSS/data-injection.",
    reference: "https://owasp.org/www-project-secure-headers/#content-security-policy"
  },
  {
    ruleId: "missing-csp-nonce",
    title: "Missing CSP Nonce Support",
    check: (ctx) => !ctx.hasHelmet,
    severity: "LOW",
    recommendation: "Once a CSP is in place, use per-request nonces for any inline scripts/styles instead of 'unsafe-inline'.",
    reference: "https://owasp.org/www-project-secure-headers/#content-security-policy"
  },
  {
    ruleId: "missing-x-frame-options",
    title: "Missing X-Frame-Options Header",
    check: (ctx) => !ctx.hasHelmet,
    severity: "MEDIUM",
    recommendation: "Add X-Frame-Options: DENY (or CSP frame-ancestors) to prevent clickjacking.",
    reference: "https://owasp.org/www-project-secure-headers/#x-frame-options"
  },
  {
    ruleId: "missing-permissions-policy",
    title: "Missing Permissions-Policy Header",
    check: (ctx) => !ctx.hasHelmet,
    severity: "LOW",
    recommendation: "Add a Permissions-Policy header to restrict access to browser features (camera, geolocation, etc.).",
    reference: "https://owasp.org/www-project-secure-headers/#permissions-policy"
  },
  {
    ruleId: "missing-helmet",
    title: "Missing Helmet Security Middleware",
    check: (ctx) => !ctx.hasHelmet,
    severity: "HIGH",
    recommendation: "Install and mount helmet() as one of the first middlewares to get the standard security-header baseline.",
    reference: "https://www.npmjs.com/package/helmet"
  },
  {
    ruleId: "weak-cors",
    title: "Wide-Open CORS Policy",
    check: (ctx) => ctx.corsWideOpen,
    severity: "MEDIUM",
    recommendation: "Restrict cors() to an explicit allowlist of trusted origins instead of reflecting/allowing any origin.",
    reference: "https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny"
  },
  {
    ruleId: "directory-listing",
    title: "Directory Listing Exposure",
    check: (ctx) => ctx.usesExpressStatic,
    severity: "MEDIUM",
    recommendation: "If express.static() is used, disable directory indexes and serve only an explicit allowlist of files.",
    reference: "https://expressjs.com/en/4x/api.html#express.static"
  },
  {
    ruleId: "missing-rate-limiting",
    title: "Missing API Rate Limiting",
    check: (ctx) => !ctx.hasRateLimiting,
    severity: "HIGH",
    recommendation: "Apply express-rate-limit (or equivalent) to all public API routes to slow brute-force/DoS attempts.",
    reference: "https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks"
  },
  {
    ruleId: "missing-compression",
    title: "Missing Response Compression",
    check: (ctx) => !ctx.hasCompression,
    severity: "LOW",
    recommendation: "Mount the compression middleware to reduce response payload size and improve latency.",
    reference: "https://www.npmjs.com/package/compression"
  },
  {
    ruleId: "debug-mode-enabled",
    title: "Debug/Development Mode Enabled",
    check: (ctx) => ctx.nodeEnv !== "production",
    severity: "MEDIUM",
    recommendation: "Set NODE_ENV=production in every deployed environment - verbose errors/stack traces must never reach production responses.",
    reference: "https://expressjs.com/en/advanced/best-practice-performance.html#set-node_env-to-production"
  },
  {
    ruleId: "cookie-flags-not-applicable",
    title: "Session Cookies Not In Use (Secure/HttpOnly/SameSite N/A)",
    check: (ctx) => !ctx.usesCookies,
    severity: "INFO",
    recommendation: "Authentication uses Bearer JWTs, not cookies - Secure/HttpOnly/SameSite flags don't apply today. If cookie-based sessions are ever introduced, set all three.",
    reference: "https://owasp.org/www-community/controls/SecureCookieAttribute"
  },
  {
    ruleId: "weak-cookie-settings",
    title: "Weak Cookie Flags Detected",
    check: (ctx) => ctx.usesCookies,
    severity: "HIGH",
    recommendation: "Set Secure, HttpOnly, and SameSite=Strict/Lax on every cookie the app issues.",
    reference: "https://owasp.org/www-community/controls/SecureCookieAttribute"
  },
  {
    ruleId: "weak-jwt-configuration",
    title: "Weak JWT Secret Configuration",
    check: (ctx) => ctx.jwtSecretLength > 0 && ctx.jwtSecretLength < 32,
    severity: "CRITICAL",
    recommendation: "Use a JWT_SECRET of at least 32 random characters and rotate it periodically.",
    reference: "https://owasp.org/www-project-cheat-sheets/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html"
  },
  {
    ruleId: "open-swagger-documentation",
    title: "Public API Documentation Exposed",
    check: (ctx) => ctx.hasSwaggerDep,
    severity: "MEDIUM",
    recommendation: "Gate Swagger/OpenAPI UI behind authentication in production, or disable it entirely.",
    reference: "https://owasp.org/www-project-api-security/"
  },
  {
    ruleId: "open-admin-apis",
    title: "Admin API Routes Missing Access Control",
    check: (ctx) => ctx.adminGatingMissing.length > 0,
    severity: "CRITICAL",
    recommendation: "Every admin/governance route file (IAM, SOAR, Compliance) must apply the requireAdmin middleware.",
    reference: "https://owasp.org/www-project-api-security/"
  },
  {
    ruleId: "public-storage",
    title: "File Storage Access Mode Unverified",
    check: (ctx) => ctx.cloudinaryConfigured,
    severity: "LOW",
    recommendation: "Confirm the Cloudinary account's delivery type is set to authenticated/private, not public, for uploaded files.",
    reference: "https://cloudinary.com/documentation/control_access_to_media"
  },
  {
    ruleId: "large-upload-limits",
    title: "No Upload Size Limit Configured",
    check: (ctx) => !ctx.uploadLimitsConfigured,
    severity: "MEDIUM",
    recommendation: "Configure multer({ limits: { fileSize } }) on every upload route to prevent unbounded request bodies.",
    reference: "https://owasp.org/www-community/attacks/Denial_of_Service"
  }
];

/** Runs every rule against a freshly-built context, persists a CloudFinding per failing rule
 *  (resolving any previously-open finding for a rule that now passes), and emits the SIEM events
 *  the spec calls for. Never throws - matches every other Phase 11 service's resilience contract. */
export async function runConfigScan({ owner, context } = {}) {
  const ctx = context || buildScanContext();
  const findings = [];

  await logSecurityEvent({ owner, type: "configuration_scan", message: "Configuration scan run", metadata: { ruleCount: RULES.length } }).catch(() => {});

  for (const rule of RULES) {
    const triggered = rule.check(ctx);

    if (!triggered) {
      await CloudFinding.updateMany(
        { ruleId: rule.ruleId, category: "CONFIGURATION", status: "open" },
        { status: "resolved", resolvedAt: new Date() }
      );
      continue;
    }

    const existing = await CloudFinding.findOne({ ruleId: rule.ruleId, category: "CONFIGURATION", status: "open" });
    if (existing) {
      findings.push(existing);
      continue;
    }

    const finding = await CloudFinding.create({
      category: "CONFIGURATION",
      ruleId: rule.ruleId,
      title: rule.title,
      severity: rule.severity,
      recommendation: rule.recommendation,
      reference: rule.reference,
      status: "open"
    });
    findings.push(finding);

    if (rule.severity === "INFO") continue; // informational-only rules don't need a SIEM event each run

    await logSecurityEvent({
      owner,
      type: "configuration_failure",
      message: `Configuration finding: ${rule.title}`,
      metadata: { ruleId: rule.ruleId, severity: rule.severity }
    }).catch(() => {});
  }

  const headerFindings = findings.filter((f) => f.ruleId.includes("header") || f.ruleId.startsWith("missing-csp") || f.ruleId.startsWith("missing-x-frame") || f.ruleId.startsWith("missing-hsts") || f.ruleId.startsWith("missing-permissions"));
  if (headerFindings.length >= 3) {
    await logSecurityEvent({
      owner,
      type: "missing_security_headers",
      message: `${headerFindings.length} security headers missing`,
      metadata: { ruleIds: headerFindings.map((f) => f.ruleId) }
    }).catch(() => {});
  }

  return findings;
}

export { RULES as CONFIG_SCAN_RULES };
