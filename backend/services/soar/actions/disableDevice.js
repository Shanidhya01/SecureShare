/**
 * Phase 8 (SOAR) action: disables the device tied to the triggering event, using the exact
 * `Device.revoked`/`trusted` fields Phase 3's device management already reads.
 */
import Device from "../../../models/Device.js";

export default async function disableDevice(params, event) {
  if (!event.deviceId) return { success: false, detail: "No device associated with triggering event" };

  const result = await Device.updateOne(
    { owner: event.owner, deviceId: event.deviceId },
    { revoked: true, trusted: false }
  );
  if (result.matchedCount === 0) return { success: false, detail: "Device not found" };

  return { success: true, detail: `Disabled device "${event.deviceId}"` };
}
