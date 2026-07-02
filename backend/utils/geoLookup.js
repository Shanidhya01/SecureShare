/**
 * Best-effort country resolution from request headers set by common reverse proxies/CDNs
 * (Cloudflare, Vercel, etc.) that perform IP geolocation upstream. This app does not call any
 * external geo-IP API or ship a MaxMind-style database - if no such header is present (e.g.
 * local development, or a host that doesn't inject one), the country is reported as "Unknown"
 * and any policy `allowedCountries` restriction simply can't be satisfied for that request
 * (fails closed - see backend/services/policyEngine.js).
 *
 * Swap in a real geo-IP provider (MaxMind GeoLite2, ipapi, etc.) here for production deployments
 * that need accurate country resolution independent of the hosting platform.
 */
export function resolveCountry(req) {
  return (
    req.headers["cf-ipcountry"] ||
    req.headers["x-vercel-ip-country"] ||
    req.headers["x-country-code"] ||
    "Unknown"
  );
}
