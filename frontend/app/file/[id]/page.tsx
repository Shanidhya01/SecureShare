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
import { AlertCircle, Lock, Download, Loader, ShieldCheck, Clock, Ban, Bug } from "lucide-react";
import toast from "react-hot-toast";
import { getDeviceId } from "@/lib/security/fingerprint";
import { apiErrorCode } from "@/lib/errors";
import ProgressTimeline, { type TimelineStep, type TimelineStepState } from "@/components/design/ProgressTimeline";
import ExplainWithAIButton from "@/components/ai/ExplainWithAIButton";

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
  signature?: string | null;
  fileHash?: string | null;
  hashAlgorithm?: string | null;
  signatureAlgorithm?: string | null;
  signedAt?: string | null;
  ownerSigningPublicKey?: string | null;
  hasPolicy?: boolean;
  scanStatus?: string;
  riskLevel?: string | null;
  quarantined?: boolean;
};

type SignatureStatus = "idle" | "verifying" | "verified" | "unsigned" | "failed";
type LoadErrorKind = "not_found" | "revoked" | "expired" | "network" | null;
type DownloadStage = "idle" | "policy" | "signature" | "threat" | "decrypting" | "preparing" | "done" | "error";

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
  const [downloadStage, setDownloadStage] = useState<DownloadStage>("idle");

  const fragmentKey = typeof window !== "undefined" ? window.location.hash : "";
  const hasFragmentKey = fragmentKey.startsWith("#k=");

  useEffect(() => {
    if (!fileId) return;
    (async () => {
      try {
        const res = await api.get(`/files/file/${fileId}/meta`);
        setMeta(res.data);
      } catch (err: unknown) {
        const code = apiErrorCode(err);
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
    setDownloadStage("policy");
    const headers: Record<string, string> = {};
    try {
      headers["x-device-id"] = await getDeviceId();
    } catch {
      // fingerprinting failures never block a download
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
      if (body?.error === "quarantined") throw new Error(`QUARANTINED:${body.riskLevel || ""}`);
      throw new Error("NETWORK");
    }
    setDownloadStage("threat");
    return res.arrayBuffer();
  };

  const describeDecryptError = (err: unknown, context: "password" | "key"): string => {
    const message = err instanceof Error ? err.message : "";
    if (message === "LIMIT_REACHED") return "This file's download limit has already been reached.";
    if (message === "REVOKED") return "This file's access has been revoked.";
    if (message === "EXPIRED") return "This file has expired.";
    if (message === "NETWORK") return "Network error while fetching the encrypted file. Please try again.";
    if (message.startsWith("POLICY_DENIED:")) {
      return `Access denied by security policy: ${message.slice("POLICY_DENIED:".length)}`;
    }
    if (message.startsWith("QUARANTINED:")) {
      return `This file is quarantined (${message.slice("QUARANTINED:".length) || "flagged"} risk) and cannot be downloaded.`;
    }
    if (message === "TAMPERED") {
      return "Signature verification failed - this file may have been tampered with. Download blocked for your safety.";
    }
    return context === "password" ? "Wrong password. Please try again." : "Integrity verification failed - the file or key may be corrupted or tampered with.";
  };

  // Phase 6 (SIEM): signature verification happens entirely client-side (zero-knowledge design -
  // the server never sees plaintext or performs the ECDSA check itself), so the outcome is
  // reported here for the SIEM's event feed. Fire-and-forget and non-blocking - reporting must
  // never affect the download flow, and no crypto logic below is touched.
  const reportSignatureEvent = (result: "verified" | "invalid") => {
    api.post("/siem/events/signature", { fileId, result }).catch(() => {});
  };

  const verifySignature = async (ciphertext: ArrayBuffer): Promise<void> => {
    setDownloadStage("signature");
    if (!meta?.signature || !meta?.ownerSigningPublicKey) {
      setSignatureStatus("unsigned");
      return;
    }
    setSignatureStatus("verifying");
    const publicKey = await importSigningPublicKey(meta.ownerSigningPublicKey);
    const valid = await verifyEncryptedFileSignature(ciphertext, meta.signature, publicKey);
    if (!valid) {
      setSignatureStatus("failed");
      reportSignatureEvent("invalid");
      throw new Error("TAMPERED");
    }
    setSignatureStatus("verified");
    reportSignatureEvent("verified");
  };

  const handleDecryptWithFragment = async () => {
    if (!meta) return;
    setDecrypting(true);
    setDecryptError("");
    setSignatureStatus("idle");
    setDownloadStage("policy");
    try {
      const rawKey = base64UrlToBuf(fragmentKey.slice(3));
      const aesKey = await importAESKeyRaw(rawKey);
      const ciphertext = await fetchCiphertext();
      await verifySignature(ciphertext);
      setDownloadStage("decrypting");
      const plaintext = await decryptFile(ciphertext, aesKey, base64ToBuf(meta.iv!));
      setDownloadStage("preparing");
      triggerBlobDownload(plaintext, meta.originalFilename || meta.filename, meta.mimeType);
      setDownloadStage("done");
    } catch (err) {
      console.error("Decryption failed");
      setDownloadStage("error");
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
    setDownloadStage("policy");
    try {
      const aesKey = await unwrapAESKeyWithPassword(meta.wrappedPasswordKey!, passwordInput, meta.keySalt!, meta.passwordKeyIvHint!, meta.keyIterations!);
      const ciphertext = await fetchCiphertext();
      await verifySignature(ciphertext);
      setDownloadStage("decrypting");
      const plaintext = await decryptFile(ciphertext, aesKey, base64ToBuf(meta.iv!));
      setDownloadStage("preparing");
      triggerBlobDownload(plaintext, meta.originalFilename || meta.filename, meta.mimeType);
      setDownloadStage("done");
    } catch (err) {
      console.error("Decryption failed");
      setDownloadStage("error");
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
    setDownloadStage("policy");
    try {
      const aesKey = await unwrapAESKey(meta.wrappedOwnerKey!, privateKey);
      const ciphertext = await fetchCiphertext();
      await verifySignature(ciphertext);
      setDownloadStage("decrypting");
      const plaintext = await decryptFile(ciphertext, aesKey, base64ToBuf(meta.iv!));
      setDownloadStage("preparing");
      triggerBlobDownload(plaintext, meta.originalFilename || meta.filename, meta.mimeType);
      setDownloadStage("done");
    } catch (err) {
      console.error("Decryption failed");
      setDownloadStage("error");
      setDecryptError(describeDecryptError(err, "key"));
      toast.error("Decryption failed");
    } finally {
      setDecrypting(false);
    }
  };

  const handleLegacyDownload = async () => {
    setDecrypting(true);
    setDecryptError("");
    setDownloadStage("policy");
    try {
      await downloadFileWithIpTracking(fileId, undefined, meta?.hasPassword ? passwordInput : undefined);
      setDownloadStage("done");
    } catch (err) {
      console.error("Download failed:", err);
      setDownloadStage("error");
      const message = err instanceof Error ? err.message : "";
      if (message.startsWith("Access denied by security policy")) {
        setDecryptError(message);
      } else {
        setDecryptError(meta?.hasPassword ? "Wrong password or download failed." : "Download failed.");
      }
    } finally {
      setDecrypting(false);
    }
  };

  const loggedIn = typeof window !== "undefined" && !!localStorage.getItem("token");

  const stepState = (_key: DownloadStage, order: number, currentOrder: number, hasError: boolean): TimelineStepState => {
    if (hasError && currentOrder === order) return "error";
    if (currentOrder > order || downloadStage === "done") return "done";
    if (currentOrder === order) return "active";
    return "pending";
  };

  const stageOrder: Record<DownloadStage, number> = {
    idle: -1,
    policy: 0,
    signature: 1,
    threat: 2,
    decrypting: 3,
    preparing: 4,
    done: 5,
    error: -1,
  };

  const timelineSteps: TimelineStep[] =
    downloadStage !== "idle"
      ? [
          { key: "policy", label: "Checking Policies", state: stepState("policy", 0, stageOrder[downloadStage], downloadStage === "error" && stageOrder.policy === 0) },
          {
            key: "signature",
            label: "Verifying Signature",
            state: stepState("signature", 1, stageOrder[downloadStage], false),
            detail: signatureStatus === "verified" ? "Verified" : signatureStatus === "unsigned" ? "Unsigned file" : signatureStatus === "failed" ? "Tampering detected" : undefined,
          },
          { key: "threat", label: "Threat Check", state: stepState("threat", 2, stageOrder[downloadStage], false) },
          { key: "decrypt", label: "Decrypting", state: stepState("decrypting", 3, stageOrder[downloadStage], false) },
          { key: "prepare", label: "Preparing Download", state: stepState("preparing", 4, stageOrder[downloadStage], false) },
          { key: "done", label: "Downloaded", state: downloadStage === "done" ? "done" : downloadStage === "error" ? "pending" : "pending" },
        ]
      : [];

  return (
    <div className="min-h-screen bg-background flex items-center justify-center px-4 py-8">
      <div className="w-full max-w-2xl grid grid-cols-1 md:grid-cols-5 gap-6">
        <div className="md:col-span-3 bg-card border border-border rounded-2xl shadow-2xl overflow-hidden h-fit">
          <div className="relative h-24 bg-linear-to-r from-primary to-cyan-500 flex items-center justify-center">
            <div className="bg-white/20 p-3 rounded-full backdrop-blur-md">
              <ShieldCheck size={26} className="text-white" />
            </div>
          </div>

          <div className="p-8">
            {loading || checkingKey ? (
              <div className="flex flex-col items-center gap-3 py-8">
                <Loader size={28} className="text-primary animate-spin" />
                <p className="text-muted-foreground text-sm">Loading file details...</p>
              </div>
            ) : loadError ? (
              <div className="p-4 bg-destructive/10 border border-destructive/30 rounded-lg flex items-start gap-3">
                {loadError === "expired" ? (
                  <Clock size={20} className="text-destructive shrink-0 mt-0.5" />
                ) : loadError === "revoked" ? (
                  <Ban size={20} className="text-destructive shrink-0 mt-0.5" />
                ) : (
                  <AlertCircle size={20} className="text-destructive shrink-0 mt-0.5" />
                )}
                <p className="text-destructive text-sm">{loadErrorMessage[loadError]}</p>
              </div>
            ) : meta ? (
              <>
                <h1 className="text-2xl font-bold text-foreground mb-1 text-center break-all">{meta.originalFilename || meta.filename}</h1>
                <p className={`text-muted-foreground text-sm text-center ${meta.hasPolicy ? "mb-2" : "mb-6"}`}>
                  {meta.encryptionVersion === 2
                    ? "This file is end-to-end encrypted. Decryption happens locally in your browser."
                    : "Secure file download"}
                </p>
                {meta.hasPolicy && (
                  <p className="text-muted-foreground/80 text-xs text-center mb-6 flex items-center justify-center gap-1">
                    <Lock size={12} />
                    This file has additional access restrictions set by its owner.
                  </p>
                )}

                {meta.quarantined ? (
                  <div className="p-4 bg-destructive/15 border border-destructive/40 rounded-lg flex items-start gap-3">
                    <Bug size={20} className="text-destructive shrink-0 mt-0.5" />
                    <div className="min-w-0">
                      <p className="text-destructive text-sm font-semibold">This file is quarantined</p>
                      <p className="text-destructive/80 text-xs mt-1">
                        SecureShare&apos;s threat scanner flagged this upload as {meta.riskLevel || "high"} risk. Download has
                        been disabled to protect you. Contact the file&apos;s owner if you believe this is a mistake.
                      </p>
                      {loggedIn && (
                        <div className="mt-3">
                          <ExplainWithAIButton sourceType="File" sourceId={fileId} />
                        </div>
                      )}
                    </div>
                  </div>
                ) : meta.limitReached ? (
                  <div className="p-4 bg-warning/10 border border-warning/30 rounded-lg text-center">
                    <p className="text-warning text-sm font-semibold">Download limit reached</p>
                  </div>
                ) : decryptError ? (
                  <div className="mb-4 p-4 bg-destructive/10 border border-destructive/30 rounded-lg flex items-start gap-3">
                    <AlertCircle size={20} className="text-destructive shrink-0 mt-0.5" />
                    <div className="min-w-0">
                      <p className="text-destructive text-sm">{decryptError}</p>
                      {loggedIn && decryptError.toLowerCase().includes("tamper") && (
                        <div className="mt-3">
                          <ExplainWithAIButton sourceType="File" sourceId={fileId} />
                        </div>
                      )}
                    </div>
                  </div>
                ) : null}

                {!meta.quarantined && !meta.limitReached && meta.encryptionVersion === 1 && (
                  <div className="space-y-4">
                    {meta.hasPassword && (
                      <div className="relative">
                        <Lock size={16} className="absolute left-3 top-3.5 text-muted-foreground" />
                        <input
                          type="password"
                          value={passwordInput}
                          onChange={(e) => setPasswordInput(e.target.value)}
                          placeholder="Enter the download password"
                          className="w-full pl-10 pr-4 py-3 bg-background border border-border rounded-lg text-foreground placeholder-muted-foreground focus:outline-none focus-visible:ring-2 focus-visible:ring-primary/60 transition-all"
                        />
                      </div>
                    )}
                    <button
                      type="button"
                      onClick={handleLegacyDownload}
                      disabled={decrypting}
                      className="w-full py-3 bg-primary text-white font-bold rounded-lg flex items-center justify-center gap-2 disabled:opacity-50"
                    >
                      {decrypting ? <Loader size={20} className="animate-spin" /> : <Download size={20} />}
                      {decrypting ? "Downloading..." : "Download File"}
                    </button>
                  </div>
                )}

                {!meta.quarantined && !meta.limitReached && meta.encryptionVersion === 2 && (
                  <div className="space-y-4">
                    {hasFragmentKey && (
                      <button
                        type="button"
                        onClick={handleDecryptWithFragment}
                        disabled={decrypting}
                        className="w-full py-3 bg-primary text-white font-bold rounded-lg flex items-center justify-center gap-2 disabled:opacity-50"
                      >
                        {decrypting ? <Loader size={20} className="animate-spin" /> : <Download size={20} />}
                        {decrypting ? "Decrypting..." : "Decrypt & Download"}
                      </button>
                    )}

                    {!hasFragmentKey && meta.hasPassword && (
                      <>
                        <div className="relative">
                          <Lock size={16} className="absolute left-3 top-3.5 text-muted-foreground" />
                          <input
                            type="password"
                            value={passwordInput}
                            onChange={(e) => setPasswordInput(e.target.value)}
                            onKeyDown={(e) => e.key === "Enter" && handleDecryptWithPassword()}
                            placeholder="Enter the share password"
                            className="w-full pl-10 pr-4 py-3 bg-background border border-border rounded-lg text-foreground placeholder-muted-foreground focus:outline-none focus-visible:ring-2 focus-visible:ring-primary/60 transition-all"
                          />
                        </div>
                        <button
                          type="button"
                          onClick={handleDecryptWithPassword}
                          disabled={decrypting}
                          className="w-full py-3 bg-primary text-white font-bold rounded-lg flex items-center justify-center gap-2 disabled:opacity-50"
                        >
                          {decrypting ? <Loader size={20} className="animate-spin" /> : <Download size={20} />}
                          {decrypting ? "Decrypting..." : "Decrypt & Download"}
                        </button>
                      </>
                    )}

                    {!hasFragmentKey && !meta.hasPassword && loggedIn && (
                      <button
                        type="button"
                        onClick={handleDecryptAsOwner}
                        disabled={decrypting}
                        className="w-full py-3 bg-primary text-white font-bold rounded-lg flex items-center justify-center gap-2 disabled:opacity-50"
                      >
                        {decrypting ? <Loader size={20} className="animate-spin" /> : <Download size={20} />}
                        {decrypting ? "Decrypting..." : "Decrypt & Download (as owner)"}
                      </button>
                    )}

                    {!hasFragmentKey && !meta.hasPassword && !loggedIn && (
                      <div className="p-4 bg-destructive/10 border border-destructive/30 rounded-lg text-center">
                        <p className="text-destructive text-sm">
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

        {meta && !loadError && (
          <div className="md:col-span-2 rounded-2xl border border-border bg-card p-6 h-fit">
            <h3 className="text-sm font-semibold text-foreground mb-5">Download Verification</h3>
            {timelineSteps.length === 0 ? (
              <p className="text-sm text-muted-foreground">Start the download to see live verification progress here.</p>
            ) : (
              <ProgressTimeline steps={timelineSteps} />
            )}
          </div>
        )}
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
