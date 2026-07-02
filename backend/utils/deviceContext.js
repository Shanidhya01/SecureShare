/**
 * Dependency-free, best-effort User-Agent parsing for display purposes (Security Center device
 * list, session list, audit logs). Deliberately not exhaustive - this is metadata for humans to
 * recognize their own devices, not a security boundary (the deviceId fingerprint hash and the
 * policy engine's allowedDevices check are the actual access control).
 */
export function parseUserAgent(userAgent = "") {
  const ua = userAgent || "";

  let browser = "Unknown";
  if (/edg\//i.test(ua)) browser = "Edge";
  else if (/opr\/|opera/i.test(ua)) browser = "Opera";
  else if (/chrome|crios/i.test(ua)) browser = "Chrome";
  else if (/firefox|fxios/i.test(ua)) browser = "Firefox";
  else if (/safari/i.test(ua)) browser = "Safari";

  let operatingSystem = "Unknown";
  if (/windows/i.test(ua)) operatingSystem = "Windows";
  else if (/mac os x/i.test(ua)) operatingSystem = "macOS";
  else if (/android/i.test(ua)) operatingSystem = "Android";
  else if (/iphone|ipad|ipod|ios/i.test(ua)) operatingSystem = "iOS";
  else if (/linux/i.test(ua)) operatingSystem = "Linux";

  return { browser, operatingSystem };
}
