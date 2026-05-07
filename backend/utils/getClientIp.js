import os from "os";

/**
 * Get the local machine's actual IP address (not localhost)
 */
const getLocalMachineIp = () => {
  const interfaces = os.networkInterfaces();
  
  for (const name of Object.keys(interfaces)) {
    const iface = interfaces[name];
    if (!iface) continue;
    
    for (const addr of iface) {
      // Skip internal and non-IPv4 addresses
      if (addr.family === "IPv4" && !addr.internal) {
        return addr.address;
      }
    }
  }
  
  return null;
};

/**
 * Extract the real client IP address from the request
 * Checks multiple headers commonly set by proxies and CDNs
 * Also checks for custom client-ip header (set by frontend)
 */
export const getClientIp = (req) => {
  // Priority 1: Check custom x-client-ip header (set by frontend with detected IP)
  if (req.headers["x-client-ip"]) {
    const clientIp = req.headers["x-client-ip"];
    // If it's localhost/127.0.0.1/::1, try to get the real machine IP
    if (clientIp === "::1" || clientIp === "127.0.0.1") {
      const machineIp = getLocalMachineIp();
      if (machineIp) {
        console.log("✓ Using Local Machine IP:", machineIp);
        return machineIp;
      }
    }
    console.log("✓ Using X-Client-IP (from frontend):", clientIp);
    return clientIp;
  }

  // Priority 2: Check X-Forwarded-For header (set by proxies, load balancers)
  const forwarded = req.headers["x-forwarded-for"];
  if (forwarded) {
    const ip = forwarded.split(",")[0].trim();
    console.log("✓ Using X-Forwarded-For:", ip);
    return ip;
  }

  // Priority 3: Check X-Real-IP header (set by nginx)
  if (req.headers["x-real-ip"]) {
    console.log("✓ Using X-Real-IP:", req.headers["x-real-ip"]);
    return req.headers["x-real-ip"];
  }

  // Priority 4: Check CF-Connecting-IP (Cloudflare)
  if (req.headers["cf-connecting-ip"]) {
    console.log("✓ Using CF-Connecting-IP:", req.headers["cf-connecting-ip"]);
    return req.headers["cf-connecting-ip"];
  }

  // Priority 5: Check True-Client-IP (Cloudflare, Akamai)
  if (req.headers["true-client-ip"]) {
    console.log("✓ Using True-Client-IP:", req.headers["true-client-ip"]);
    return req.headers["true-client-ip"];
  }

  // Fallback to machine IP or req.socket.remoteAddress
  const machineIp = getLocalMachineIp();
  if (machineIp) {
    console.log("✓ Using Local Machine IP:", machineIp);
    return machineIp;
  }

  const ip = req.socket?.remoteAddress || req.ip || "unknown";
  console.log("✓ Using remoteAddress:", ip);
  return ip;
};
