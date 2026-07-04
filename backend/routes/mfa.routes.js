import express from "express";
import auth from "../middleware/auth.middleware.js";
import {
  setup,
  verify,
  disable,
  regenerateRecoveryCodes,
  status,
  verifyLogin
} from "../controllers/mfa.controller.js";

const router = express.Router();

// verify-login is intentionally NOT behind `auth` - it's the second step of logging in, before
// the caller has a real session token (only the short-lived mfaToken from POST /api/auth/login).
router.post("/verify-login", verifyLogin);

router.post("/setup", auth, setup);
router.post("/verify", auth, verify);
router.post("/disable", auth, disable);
router.post("/recovery/regenerate", auth, regenerateRecoveryCodes);
router.get("/status", auth, status);

export default router;
