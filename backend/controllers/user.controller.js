import User from "../models/User.js";

/* Set/update the caller's RSA public key (base64 SPKI), used for zero-knowledge E2E encryption. */
export const updatePublicKey = async (req, res) => {
  const { publicKey } = req.body;

  if (typeof publicKey !== "string" || publicKey.length === 0 || publicKey.length > 4000) {
    return res.status(400).json({ error: "A valid publicKey (base64 SPKI) is required" });
  }

  await User.findByIdAndUpdate(req.user.id, { publicKey });
  res.json({ message: "Public key updated" });
};

/* Return the caller's own public key, so the frontend can check whether a keypair is already set up. */
export const getMyPublicKey = async (req, res) => {
  const user = await User.findById(req.user.id).select("publicKey");
  res.json({ publicKey: user?.publicKey || null });
};
