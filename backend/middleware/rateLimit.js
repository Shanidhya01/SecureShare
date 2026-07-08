import rateLimit from "express-rate-limit";

export const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: {
    error: "Too many requests. Try again later."
  }
});

// AI Security Assistant: Gemini calls cost real latency/quota, so AI endpoints get a tighter,
// dedicated limiter on top of the global apiLimiter above (applied per-route in ai.routes.js,
// not mounted globally in server.js - same pattern as every other route-specific concern).
export const aiLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 20,
  message: {
    error: "Too many AI requests. Try again later."
  }
});
