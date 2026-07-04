import express from "express";
import auth from "../middleware/auth.middleware.js";
import {
  registerOptions,
  registerVerify,
  listPasskeys,
  removePasskey,
  loginOptions,
  loginVerify
} from "../controllers/passkey.controller.js";

const router = express.Router();

// Registration/management require an existing session.
router.post("/register/options", auth, registerOptions);
router.post("/register/verify", auth, registerVerify);
router.get("/", auth, listPasskeys);
router.delete("/:id", auth, removePasskey);

export default router;

// Login options/verify are public (pre-authentication) - mounted separately under /api/auth/passkey
// by server.js, exported here so both routers can share the same controller.
export const passkeyLoginRouter = express.Router();
passkeyLoginRouter.post("/options", loginOptions);
passkeyLoginRouter.post("/verify", loginVerify);
