// LEGACY: generates the global RSA keypair used only for encryptionVersion 1 (pre-E2E) file uploads.
// Not used by the client-side E2E flow (v2) — each user now generates their own per-account keypair
// in-browser (see frontend/lib/crypto.ts) and the private key never touches the server.
import crypto from "crypto";
import fs from "fs";

const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: {
    type: "spki",
    format: "pem"
  },
  privateKeyEncoding: {
    type: "pkcs8",
    format: "pem"
  }
});

fs.writeFileSync("public.pem", publicKey);
fs.writeFileSync("private.pem", privateKey);

console.log("RSA keys generated");
