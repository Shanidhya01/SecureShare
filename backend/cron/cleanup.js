import cron from "node-cron";
import fs from "fs";
import File from "../models/File.js";

cron.schedule("0 * * * *", async () => {
  const expired = await File.find({ expiresAt: { $lt: new Date() } });

  expired.forEach(f => {
    if (fs.existsSync(`uploads/${f.filename}`))
      fs.unlinkSync(`uploads/${f.filename}`);
  });

  await File.deleteMany({ expiresAt: { $lt: new Date() } });
});
