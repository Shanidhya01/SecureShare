import express from "express";
import auth from "../middleware/auth.middleware.js";
import { getMyDevices, removeDevice } from "../controllers/device.controller.js";

const router = express.Router();

router.get("/", auth, getMyDevices);
router.delete("/:deviceId", auth, removeDevice);

export default router;
