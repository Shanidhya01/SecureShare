import express from "express";
import auth from "../middleware/auth.middleware.js";
import {
  updatePublicKey,
  getMyPublicKey,
  updateSigningKey,
  getMySigningKey
} from "../controllers/user.controller.js";

const router = express.Router();

router.patch("/publickey", auth, updatePublicKey);
router.get("/publickey", auth, getMyPublicKey);
router.patch("/signingkey", auth, updateSigningKey);
router.get("/signingkey", auth, getMySigningKey);

export default router;
