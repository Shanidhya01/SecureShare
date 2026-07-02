"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import api from "@/lib/api";
import { downloadFileWithIpTracking } from "@/lib/ipTracking";
import { useCryptoKey } from "@/context/CryptoKeyContext";
import UnlockKeyModal from "@/components/UnlockKeyModal";
import {
  base64UrlToBuf,
  base64ToBuf,
  importAESKeyRaw,
  unwrapAESKey,
  unwrapAESKeyWithPassword,
  decryptFile,
  importSigningPublicKey,
  verifyEncryptedFileSignature,
} from "@/lib/crypto/cryptoHelpers";
import { AlertCircle, Lock, Download, Loader, ShieldCheck, ShieldAlert, ShieldQuestion, Clock, Ban } from "lucide-react";
import toast from "react-hot-toast";
import { getDeviceId } from "@/lib/security/fingerprint";

type FileMeta = {
  encryptionVersion: number;
  filename: string;
  mimeType: string | null;
  hasPassword: boolean;
  oneTime: boolean;
  maxDownloads: number;
  downloadCount: number;
  limitReached: boolean;
  iv?: string;
  algorithm?: string;
  originalFilename?: string;
  wrappedOwnerKey?: string;
  wrappedPasswordKey?: string | null;
  keySalt?: string | null;
  keyIterations?: number | null;
  passwordKeyIvHint?: string | null;
  // Phase 2: digital signature fields, all null on unsigned (legacy/Phase 1) v2 files.
  signature?: string | null;
  fileHash?: string | null;
  hashAlgorithm?: string | null;
  signatureAlgorithm?: string | null;
  signedAt?: string | null;
  ownerSigningPublicKey?: string | null;
  // Phase 3: whether this file has any Zero Trust access policy configured (never exposes the
  // actual rules to an anonymous requester - just whether extra checks will be evaluated).
  hasPolicy?: boolean;
};

type SignatureStatus = "idle" | "verifying" | "verified" | "unsigned" | "failed";

/** Distinguishable load-time failure states, driven by the backend's error codes
 *  (not_found / revoked / expired) so the UI can show a specific, meaningful message. */
type LoadErrorKind = "not_found" | "revoked" | "expired" | "network" | null;

export default function FileDownloadPage() {
  const params = useParams();
  const fileId = (params?.id as string) || "";
  const { isUnlocked, privateKey, checking: checkingKey } = useCryptoKey();

  const [meta, setMeta] = useState<FileMeta | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<LoadErrorKind>(null);
  const [passwordInput, setPasswordInput] = useState("");
  const [decryptError, setDecryptError] = useState("");
  const [decrypting, setDecrypting] = useState(false);
  const [showKeyModal, setShowKeyModal] = useState(false);
  const [signatureStatus, setSignatureStatus] = useState<SignatureStatus>("idle");

  const fragmentKey = typeof window !== "undefined" ? window.location.hash : "";
  const hasFragmentKey = fragmentKey.startsWith("#k=");

  useEffect(() => {
    if (!fileId) return;
    (async () => {
      try {
        const res = await api.get(`/files/file/${fileId}/meta`);
        setMeta(res.data);
      } catch (err: any) {
        const code = err?.response?.data?.error;
        if (code === "revoked") setLoadError("revoked");
        else if (code === "expired") setLoadError("expired");
        else if (code === "not_found") setLoadError("not_found");
        else setLoadError("network");
      } finally {
        setLoading(false);
      }
    })();
  }, [fileId]);

  const loadErrorMessage: Record<Exclude<LoadErrorKind, null>, string> = {
    not_found: "This link is invalid. Double-check the URL you were given.",
    revoked: "This file's access has been revoked by its owner.",
    expired: "This file has expired and is no longer available.",
    network: "Could not reach the server. Check your connection and try again.",
  };

  const triggerBlobDownload = (plaintext: ArrayBuffer, filename: string, mimeType: string | null) => {
    const blob = new Blob([plaintext], { type: mimeType || "application/octet-stream" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const fetchCiphertext = async (): Promise<ArrayBuffer> => {
    // Zero Trust (Phase 3): the device fingerprint travels as a header (never a raw file field)
    // so the backend's policy engine can evaluate allowedDevices/maxDevices rules. Authorization
    // is attached too, if the recipient happens to be logged in, so requireApproval can identify
    // them - the download route itself stays public and works fine without either.
    const headers: Record<string, string> = {};
    try {
      headers["x-device-id"] = await getDeviceId();
    } catch {
      // fingerprinting failures never block a download - just means device-based policy
      // checks (if any) will see no deviceId and evaluate accordingly.
    }
    const token = typeof window !== "undefined" ? localStorage.getItem("token") : null;
    if (token) headers["Authorization"] = `Bearer ${token}`;

    const res = await fetch(`${process.env.NEXT_PUBLIC_API || "http://localhost:5000/api"}/files/download/${fileId}`, {
      headers,
    });
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      if (body?.error === "download_limit_reached") throw new Error("LIMIT_REACHED");
      if (body?.error === "revoked") throw new Error("REVOKED");
      if (body?.error === "expired") throw new Error("EXPIRED");
      if (body?.error === "policy_denied") throw new Error(`POLICY_DENIED:${body.reason || "Access denied by security policy"}`);
      throw new Error("NETWORK");
    }
    return res.arrayBuffer();
  };

  /** Maps a caught error from the decrypt pipeline to a meaningful, user-facing message.
   *  `context` distinguishes password-derived failures (which mean "wrong password") from
   *  fragment/owner-key failures (which mean the ciphertext or key material was corrupted -
   *  an integrity verification failure, since AES-GCM authentication is what's failing either way). */
  const describeDecryptError = (err: unknown, context: "password" | "key"): string => {
    const message = err instanceof Error ? err.message : "";
    if (message === "LIMIT_REACHED") return "This file's download limit has already been reached.";
    if (message === "REVOKED") return "This file's access has been revoked.";
    if (message === "EXPIRED") return "This file has expired.";
    if (message === "NETWORK") return "Network error while fetching the encrypted file. Please try again.";
    if (message.startsWith("POLICY_DENIED:")) {
      return `🔒 Access denied by security policy: ${message.slice("POLICY_DENIED:".length)}`;
    }
    if (message === "TAMPERED") {
      return "⚠ Signature verification failed - this file may have been tampered with. Download blocked for your safety.";
    }
    return context === "password"
      ? "Wrong password. Please try again."
      : "Integrity verification failed - the file or key may be corrupted or tampered with.";
  };

  /** Phase 2: verifies the encrypted file's ECDSA signature (if present) against the uploader's
   *  public signing key BEFORE decrypting - a forged/tampered ciphertext must never reach
   *  decryptFile(). Files with no signature (legacy or pre-Phase-2 uploads) are treated as
   *  "unsigned" and allowed through unblocked, preserving compatibility. */
  const verifySignature = async (ciphertext: ArrayBuffer): Promise<void> => {
    if (!meta?.signature || !meta?.ownerSigningPublicKey) {
      setSignatureStatus("unsigned");
      return;
    }
    setSignatureStatus("verifying");
    const publicKey = await importSigningPublicKey(meta.ownerSigningPublicKey);
    const valid = await verifyEncryptedFileSignature(ciphertext, meta.signature, publicKey);
    if (!valid) {
      setSignatureStatus("failed");
      throw new Error("TAMPERED");
    }
    setSignatureStatus("verified");
  };

  const handleDecryptWithFragment = async () => {
    if (!meta) return;
    setDecrypting(true);
    setDecryptError("");
    setSignatureStatus("idle");
    try {
      const rawKey = base64UrlToBuf(fragmentKey.slice(3));
      const aesKey = await importAESKeyRaw(rawKey);
      const ciphertext = await fetchCiphertext();
      await verifySignature(ciphertext); // throws before any decryption if tampered
      const plaintext = await decryptFile(ciphertext, aesKey, base64ToBuf(meta.iv!));
      triggerBlobDownload(plaintext, meta.originalFilename || meta.filename, meta.mimeType);
    } catch (err) {
      console.error("Decryption failed"); // never log key material or ciphertext, only that it failed
      setDecryptError(describeDecryptError(err, "key"));
    } finally {
      setDecrypting(false);
    }
  };

  const handleDecryptWithPassword = async () => {
    if (!meta) return;
    if (!passwordInput) {
      setDecryptError("Please enter the password");
      return;
    }
    setDecrypting(true);
    setDecryptError("");
    setSignatureStatus("idle");
    try {
      const aesKey = await unwrapAESKeyWithPassword(
        meta.wrappedPasswordKey!,
        passwordInput,
        meta.keySalt!,
        meta.passwordKeyIvHint!,
        meta.keyIterations!
      );
      const ciphertext = await fetchCiphertext();
      await verifySignature(ciphertext);
      const plaintext = await decryptFile(ciphertext, aesKey, base64ToBuf(meta.iv!));
      triggerBlobDownload(plaintext, meta.originalFilename || meta.filename, meta.mimeType);
    } catch (err) {
      console.error("Decryption failed");
      setDecryptError(describeDecryptError(err, "password"));
    } finally {
      setDecrypting(false);
    }
  };

  const handleDecryptAsOwner = async () => {
    if (!meta) return;
    if (!isUnlocked || !privateKey) {
      setShowKeyModal(true);
      return;
    }
    setDecrypting(true);
    setDecryptError("");
    setSignatureStatus("idle");
    try {
      const aesKey = await unwrapAESKey(meta.wrappedOwnerKey!, privateKey);
      const ciphertext = await fetchCiphertext();
      await verifySignature(ciphertext);
      const plaintext = await decryptFile(ciphertext, aesKey, base64ToBuf(meta.iv!));
      triggerBlobDownload(plaintext, meta.originalFilename || meta.filename, meta.mimeType);
    } catch (err) {
      console.error("Decryption failed");
      setDecryptError(describeDecryptError(err, "key"));
      toast.error("Decryption failed");
    } finally {
      setDecrypting(false);
    }
  };

  const handleLegacyDownload = async () => {
    setDecrypting(true);
    setDecryptError("");
    try {
      await downloadFileWithIpTracking(fileId, undefined, meta?.hasPassword ? passwordInput : undefined);
    } catch (err) {
      console.error("Download failed:", err);
      const message = err instanceof Error ? err.message : "";
      if (message.startsWith("Access denied by security policy")) {
        setDecryptError(`🔒 ${message}`);
      } else {
        setDecryptError(meta?.hasPassword ? "Wrong password or download failed." : "Download failed.");
      }
    } finally {
      setDecrypting(false);
    }
  };

  const loggedIn = typeof window !== "undefined" && !!localStorage.getItem("token");

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 flex items-center justify-center px-4 py-8">
      <div className="w-full max-w-lg">
        <div className="bg-slate-800 bg-opacity-80 backdrop-blur-xl border border-slate-700 rounded-2xl shadow-2xl overflow-hidden">
          <div className="relative h-28 bg-gradient-to-r from-blue-600 to-cyan-600 flex items-center justify-center">
            <div className="bg-white bg-opacity-20 p-3 rounded-full backdrop-blur-md">
              <ShieldCheck size={28} className="text-white" />
            </div>
          </div>

          <div className="p-8">
            {loading || checkingKey ? (
              <div className="flex flex-col items-center gap-3 py-8">
                <Loader size={28} className="text-blue-400 animate-spin" />
                <p className="text-slate-400 text-sm">Loading file details...</p>
              </div>
            ) : loadError ? (
              <div className="p-4 bg-red-500 bg-opacity-20 border border-red-500 border-opacity-50 rounded-lg flex items-start gap-3">
                {loadError === "expired" ? (
                  <Clock size={20} className="text-red-400 flex-shrink-0 mt-0.5" />
                ) : loadError === "revoked" ? (
                  <Ban size={20} className="text-red-400 flex-shrink-0 mt-0.5" />
                ) : (
                  <AlertCircle size={20} className="text-red-400 flex-shrink-0 mt-0.5" />
                )}
                <p className="text-red-200 text-sm">{loadErrorMessage[loadError]}</p>
              </div>
            ) : meta ? (
              <>
                <h1 className="text-2xl font-bold text-white mb-1 text-center break-all">
                  {meta.originalFilename || meta.filename}
                </h1>
                <p className={`text-slate-400 text-sm text-center ${meta.hasPolicy ? "mb-2" : "mb-6"}`}>
                  {meta.encryptionVersion === 2
                    ? "This file is end-to-end encrypted. Decryption happens locally in your browser."
                    : "Secure file download"}
                </p>
                {meta.hasPolicy && (
                  <p className="text-slate-500 text-xs text-center mb-6 flex items-center justify-center gap-1">
                    <Lock size={12} />
                    This file has additional access restrictions set by its owner.
                  </p>
                )}

                {meta.limitReached ? (
                  <div className="p-4 bg-orange-500 bg-opacity-20 border border-orange-500 border-opacity-50 rounded-lg text-center">
                    <p className="text-orange-200 text-sm font-semibold">Download limit reached</p>
                  </div>
                ) : decryptError ? (
                  <div className="mb-4 p-4 bg-red-500 bg-opacity-20 border border-red-500 border-opacity-50 rounded-lg flex items-start gap-3">
                    <AlertCircle size={20} className="text-red-400 flex-shrink-0 mt-0.5" />
                    <p className="text-red-200 text-sm">{decryptError}</p>
                  </div>
                ) : null}

                {!meta.limitReached && meta.encryptionVersion === 1 && (
                  <div className="space-y-4">
                    {meta.hasPassword && (
                      <div className="relative">
                        <Lock size={16} className="absolute left-3 top-3.5 text-slate-400" />
                        <input
                          type="password"
                          value={passwordInput}
                          onChange={(e) => setPasswordInput(e.target.value)}
                          placeholder="Enter the download password"
                          className="w-full pl-10 pr-4 py-3 bg-slate-700 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500 focus:ring-opacity-50 transition-all"
                        />
                      </div>
                    )}
                    <button
                      onClick={handleLegacyDownload}
                      disabled={decrypting}
                      className="w-full py-3 bg-gradient-to-r from-blue-500 to-cyan-500 text-white font-bold rounded-lg flex items-center justify-center gap-2 disabled:opacity-50"
                    >
                      {decrypting ? <Loader size={20} className="animate-spin" /> : <Download size={20} />}
                      {decrypting ? "Downloading..." : "Download File"}
                    </button>
                  </div>
                )}

                {!meta.limitReached && meta.encryptionVersion === 2 && (
                  <div className="space-y-4">
                    {decrypting && (
                      <p className="text-center text-blue-300 text-sm">
                        {signatureStatus === "verifying"
                          ? "Verifying digital signature..."
                          : "Decrypting file locally in your browser..."}
                      </p>
                    )}

                    {!decrypting && signatureStatus === "verified" && (
                      <div className="flex items-center justify-center gap-2 text-green-300 text-xs">
                        <ShieldCheck size={14} />
                        <span>Signature verified - this file is authentic and unmodified.</span>
                      </div>
                    )}
                    {!decrypting && signatureStatus === "unsigned" && (
                      <div className="flex items-center justify-center gap-2 text-yellow-300 text-xs">
                        <ShieldQuestion size={14} />
                        <span>This file is unsigned (uploaded before signing was available) - integrity was not cryptographically verified.</span>
                      </div>
                    )}
                    {signatureStatus === "failed" && (
                      <div className="p-3 bg-red-600 bg-opacity-30 border border-red-500 rounded-lg flex items-start gap-2">
                        <ShieldAlert size={18} className="text-red-300 flex-shrink-0 mt-0.5" />
                        <p className="text-red-100 text-xs font-semibold">
                          Tampering detected. This file's signature does not match its content - download blocked.
                        </p>
                      </div>
                    )}

                    {hasFragmentKey && (
                      <button
                        onClick={handleDecryptWithFragment}
                        disabled={decrypting}
                        className="w-full py-3 bg-gradient-to-r from-blue-500 to-cyan-500 text-white font-bold rounded-lg flex items-center justify-center gap-2 disabled:opacity-50"
                      >
                        {decrypting ? <Loader size={20} className="animate-spin" /> : <Download size={20} />}
                        {decrypting ? "Decrypting..." : "Decrypt & Download"}
                      </button>
                    )}

                    {!hasFragmentKey && meta.hasPassword && (
                      <>
                        <div className="relative">
                          <Lock size={16} className="absolute left-3 top-3.5 text-slate-400" />
                          <input
                            type="password"
                            value={passwordInput}
                            onChange={(e) => setPasswordInput(e.target.value)}
                            onKeyDown={(e) => e.key === "Enter" && handleDecryptWithPassword()}
                            placeholder="Enter the share password"
                            className="w-full pl-10 pr-4 py-3 bg-slate-700 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500 focus:ring-opacity-50 transition-all"
                          />
                        </div>
                        <button
                          onClick={handleDecryptWithPassword}
                          disabled={decrypting}
                          className="w-full py-3 bg-gradient-to-r from-blue-500 to-cyan-500 text-white font-bold rounded-lg flex items-center justify-center gap-2 disabled:opacity-50"
                        >
                          {decrypting ? <Loader size={20} className="animate-spin" /> : <Download size={20} />}
                          {decrypting ? "Decrypting..." : "Decrypt & Download"}
                        </button>
                      </>
                    )}

                    {!hasFragmentKey && !meta.hasPassword && loggedIn && (
                      <button
                        onClick={handleDecryptAsOwner}
                        disabled={decrypting}
                        className="w-full py-3 bg-gradient-to-r from-blue-500 to-cyan-500 text-white font-bold rounded-lg flex items-center justify-center gap-2 disabled:opacity-50"
                      >
                        {decrypting ? <Loader size={20} className="animate-spin" /> : <Download size={20} />}
                        {decrypting ? "Decrypting..." : "Decrypt & Download (as owner)"}
                      </button>
                    )}

                    {!hasFragmentKey && !meta.hasPassword && !loggedIn && (
                      <div className="p-4 bg-red-500 bg-opacity-20 border border-red-500 border-opacity-50 rounded-lg text-center">
                        <p className="text-red-200 text-sm">
                          This link is missing its decryption key. Please request a new link from the sender.
                        </p>
                      </div>
                    )}
                  </div>
                )}
              </>
            ) : null}
          </div>
        </div>
      </div>

      <UnlockKeyModal
        open={showKeyModal}
        onClose={() => setShowKeyModal(false)}
        onSuccess={() => {
          setShowKeyModal(false);
          handleDecryptAsOwner();
        }}
      />
    </div>
  );
}
