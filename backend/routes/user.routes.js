import express from "express";
import auth from "../middleware/auth.middleware.js";
import { updatePublicKey, getMyPublicKey } from "../controllers/user.controller.js";

const router = express.Router();

router.patch("/publickey", auth, updatePublicKey);
router.get("/publickey", auth, getMyPublicKey);

export default router;
