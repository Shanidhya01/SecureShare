/**
 * Registry of all Phase 8 SOAR response actions - mirrors the DETECTORS/PROVIDERS array-of-
 * modules convention used by backend/services/dlp/detectors/index.js and
 * backend/services/threatIntel/providers/index.js. Each handler is `async (params, event,
 * context) => ({success, detail})`. backend/services/soar/playbookRunner.js looks handlers up by
 * `type` string.
 */
import quarantineFile from "./quarantineFile.js";
import deleteFile from "./deleteFile.js";
import blockDownload from "./blockDownload.js";
import revokeSession from "./revokeSession.js";
import logoutUser from "./logoutUser.js";
import disableDevice from "./disableDevice.js";
import markFileHighRisk from "./markFileHighRisk.js";
import raiseIncident from "./raiseIncident.js";
import notifyUser from "./notifyUser.js";
import notifyAdmin from "./notifyAdmin.js";
import sendEmail from "./sendEmail.js";
import generateSiemEvent from "./generateSiemEvent.js";
import generateAuditLog from "./generateAuditLog.js";
import requireMfaStepUp from "./requireMfaStepUp.js";

export const ACTION_HANDLERS = {
  quarantineFile,
  deleteFile,
  blockDownload,
  revokeSession,
  logoutUser,
  disableDevice,
  markFileHighRisk,
  raiseIncident,
  notifyUser,
  notifyAdmin,
  sendEmail,
  generateSiemEvent,
  generateAuditLog,
  requireMfaStepUp
};

export const ACTION_TYPES = Object.keys(ACTION_HANDLERS);
