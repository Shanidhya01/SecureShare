import Device from "../models/Device.js";
import Session from "../models/Session.js";
import SecurityEvent from "../models/SecurityEvent.js";

/* List the caller's trusted devices (Security Center). */
export const getMyDevices = async (req, res) => {
  const [devices, currentSession] = await Promise.all([
    Device.find({ owner: req.user.id, revoked: false }).sort({ lastSeenAt: -1 }),
    req.user.sid ? Session.findOne({ sessionId: req.user.sid }) : null
  ]);

  res.json(
    devices.map((d) => ({
      deviceId: d.deviceId,
      label: d.label,
      browser: d.browser,
      operatingSystem: d.operatingSystem,
      firstSeenAt: d.firstSeenAt,
      lastSeenAt: d.lastSeenAt,
      lastIp: d.lastIp,
      trusted: d.trusted,
      isCurrent: !!currentSession && currentSession.deviceId === d.deviceId
    }))
  );
};

/* Remove (revoke) a trusted device. Also revokes any active sessions created from it, since a
   device the user no longer trusts shouldn't keep an active login either. */
export const removeDevice = async (req, res) => {
  const { deviceId } = req.params;
  const device = await Device.findOne({ owner: req.user.id, deviceId });
  if (!device) return res.sendStatus(404);

  device.revoked = true;
  device.trusted = false;
  await device.save();

  await Session.updateMany({ owner: req.user.id, deviceId, revoked: false }, { revoked: true });

  await SecurityEvent.create({
    owner: req.user.id,
    type: "device_removed",
    message: `Removed device: ${device.label || device.deviceId}`,
    deviceId
  });

  res.json({ message: "Device removed" });
};
