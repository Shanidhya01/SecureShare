"use client";
import { useEffect, useState, useRef } from "react";
import api from "@/lib/api";
import { useRouter } from "next/navigation";
import { Upload, AlertCircle, CheckCircle, Loader, X, FileIcon, Lock, Copy, Check, ChevronDown, ChevronUp, Globe2, Eye } from "lucide-react";
import toast from "react-hot-toast";
import { motion } from "framer-motion";
import {
  generateAESKey,
  encryptFile,
  wrapAESKey,
  wrapAESKeyWithPassword,
  exportAESKeyRaw,
  importPublicKey,
  bufToBase64,
  bufToBase64Url,
  signEncryptedFile,
} from "@/lib/crypto/cryptoHelpers";
import { useCryptoKey } from "@/context/CryptoKeyContext";
import { apiErrorMessage } from "@/lib/errors";
import UnlockKeyModal from "@/components/UnlockKeyModal";
import PageHeader from "@/components/design/PageHeader";
import ProgressTimeline, { type TimelineStep, type TimelineStepState } from "@/components/design/ProgressTimeline";
import StatusBadge from "@/components/design/StatusBadge";

type ThreatScanResult = {
  scanId: string;
  riskLevel: "Low" | "Medium" | "High" | "Critical";
  quarantined: boolean;
  clamav?: { status: string };
};

type DLPScanResult = {
  dlpScanId: string;
  decision: "allow" | "warn" | "require_approval" | "block";
  severity: "None" | "Low" | "Medium" | "High" | "Critical";
  supported: boolean;
  matchedPatterns?: string[];
};

export default function UploadFile() {
  const [file, setFile] = useState<File | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState(false);
  const [password, setPassword] = useState("");
  const [usePassword, setUsePassword] = useState(false);
  const [maxDownloads, setMaxDownloads] = useState("1");
  const [expiryHours, setExpiryHours] = useState("24");
  const [shareLink, setShareLink] = useState("");
  const [linkCopied, setLinkCopied] = useState(false);
  const [showKeyModal, setShowKeyModal] = useState(false);
  const [signingStatus, setSigningStatus] = useState<"idle" | "signing" | "signed" | "unsigned">("idle");
  // Phase 4: malware/threat scan, run against the plaintext file before it's ever encrypted -
  // see backend/controllers/threat.controller.js for why this is the one deliberate moment the
  // server sees unencrypted bytes (scoped to this single request, never persisted).
  const [scanStatus, setScanStatus] = useState<"idle" | "scanning" | "clean" | "flagged" | "blocked">("idle");
  const [scanResult, setScanResult] = useState<ThreatScanResult | null>(null);
  // Phase 5: DLP scan, run right after the malware scan and before encryption - see
  // backend/controllers/dlp.controller.js for why this is also a deliberate, scoped exception
  // to the zero-knowledge model. Only supported (text-based) files are actually inspected;
  // binary files are skipped gracefully and always come back as "allow".
  const [dlpStatus, setDlpStatus] = useState<"idle" | "scanning" | "clean" | "warned" | "pending_approval" | "blocked">("idle");
  const [dlpResult, setDlpResult] = useState<DLPScanResult | null>(null);
  const [showDlpApprovalModal, setShowDlpApprovalModal] = useState(false);
  const [dlpApproving, setDlpApproving] = useState(false);
  // Track encryption/upload network stages, purely for the ProgressTimeline UI below - doesn't
  // change any upload behavior.
  const [encryptStatus, setEncryptStatus] = useState<"idle" | "active" | "done" | "error">("idle");
  const [uploadStatus, setUploadStatus] = useState<"idle" | "active" | "done" | "error">("idle");
  // Holds the in-flight upload continuation while we wait for the user to respond to a
  // "require_approval" DLP finding via the modal above.
  const pendingUploadRef = useRef<null | (() => Promise<void>)>(null);
  // Phase 3: optional Zero Trust access policy, collapsed by default since most uploads don't need it.
  const [showPolicy, setShowPolicy] = useState(false);
  const [allowedCountries, setAllowedCountries] = useState("");
  const [allowedIPs, setAllowedIPs] = useState("");
  const [businessHoursEnabled, setBusinessHoursEnabled] = useState(false);
  const [businessStartHour, setBusinessStartHour] = useState("9");
  const [businessEndHour, setBusinessEndHour] = useState("17");
  const [maxDevices, setMaxDevices] = useState("");
  const [requireApproval, setRequireApproval] = useState(false);
  const router = useRouter();
  const token = typeof window !== "undefined" ? localStorage.getItem("token") : null;
  const { needsSetup, isUnlocked, signingPrivateKey, checking: checkingKey } = useCryptoKey();

  useEffect(() => {
    if (!token) {
      setError("Please log in to upload files.");
      const t = setTimeout(() => router.push("/login"), 1000);
      return () => clearTimeout(t);
    }
  }, [router, token]);

  const MAX_FILE_SIZE = 100 * 1024 * 1024; // 100MB
  const ALLOWED_TYPES = [
    "application/pdf",
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.ms-excel",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "image/jpeg",
    "image/png",
    "image/gif",
    "text/plain",
    "application/zip",
    "application/x-rar-compressed",
  ];

  const formatFileSize = (bytes: number): string => {
    if (bytes === 0) return "0 Bytes";
    const k = 1024;
    const sizes = ["Bytes", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + " " + sizes[i];
  };

  const validateFile = (selectedFile: File): string | null => {
    if (!selectedFile) return "Please select a file";

    if (selectedFile.size > MAX_FILE_SIZE) {
      return `File size exceeds 100MB limit. Your file is ${formatFileSize(selectedFile.size)}`;
    }

    if (!ALLOWED_TYPES.includes(selectedFile.type)) {
      return `File type not allowed. Please upload: PDF, DOC, XLS, Images, TXT, or ZIP`;
    }

    return null;
  };

  const handleFileSelect = (selectedFile: File | null) => {
    setError("");
    setSuccess(false);

    if (!selectedFile) return;

    const validationError = validateFile(selectedFile);
    if (validationError) {
      setError(validationError);
      setFile(null);
      return;
    }

    setFile(selectedFile);
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);

    const droppedFile = e.dataTransfer.files?.[0] ?? null;
    handleFileSelect(droppedFile);
  };

  /** Builds the Phase 3 Zero Trust access-policy payload from the advanced-section inputs.
   *  Returns null if nothing was actually configured, so the upload proceeds with no policy
   *  at all (the default, unrestricted behavior) rather than sending an empty-but-present one. */
  const buildPolicyPayload = () => {
    const countries = allowedCountries
      .split(",")
      .map((s) => s.trim().toUpperCase())
      .filter(Boolean);
    const ips = allowedIPs
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    const maxDev = parseInt(maxDevices) || 0;

    const hasAnyRestriction = countries.length > 0 || ips.length > 0 || businessHoursEnabled || maxDev > 0 || requireApproval;
    if (!hasAnyRestriction) return null;

    return {
      allowedCountries: countries,
      allowedIPs: ips,
      businessHours: {
        enabled: businessHoursEnabled,
        startHour: parseInt(businessStartHour) || 0,
        endHour: parseInt(businessEndHour) || 24,
      },
      maxDevices: maxDev,
      requireApproval,
    };
  };

  const uploadFile = async () => {
    if (!file) {
      setError("Please select a file");
      return;
    }

    const token = localStorage.getItem("token");
    if (!token) {
      setError("Session expired. Please log in again.");
      setTimeout(() => router.push("/login"), 1500);
      return;
    }

    // The file's owner-wrap requires the user's unwrapped RSA keypair. If it isn't set up or
    // unlocked yet for this session, prompt for the account password and retry once resolved.
    if (needsSetup || !isUnlocked) {
      setShowKeyModal(true);
      return;
    }

    const currentFile = file;

    setUploading(true);
    setError("");
    setSigningStatus("idle");
    setEncryptStatus("idle");
    setUploadStatus("idle");
    setScanStatus("scanning");
    setScanResult(null);
    setDlpStatus("scanning");
    setDlpResult(null);

    // --- 0a. Phase 4: scan the plaintext file for malware/threats BEFORE any encryption. This
    // is the one deliberate exception to "the server never sees plaintext" - the buffer is
    // scanned in memory for the duration of this single request and never persisted. A file
    // flagged Critical/High risk is refused here so nothing gets encrypted/uploaded/stored at
    // all; the server also independently blocks quarantined files from being downloaded even
    // if this client-side gate were somehow bypassed.
    let scanId: string;
    try {
      const scanFormData = new FormData();
      scanFormData.append("file", currentFile);
      const scanRes = await api.post("/threats/scan", scanFormData, {
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "multipart/form-data" },
      });
      setScanResult(scanRes.data);

      if (scanRes.data.quarantined) {
        setScanStatus("blocked");
        setError(
          `Upload blocked: this file was flagged as ${scanRes.data.riskLevel} risk by the threat scanner and will not be uploaded.`
        );
        toast.error("File blocked by threat scan");
        setUploading(false);
        return;
      }

      setScanStatus(scanRes.data.riskLevel === "Low" ? "clean" : "flagged");
      scanId = scanRes.data.scanId;
    } catch (scanErr: unknown) {
      setScanStatus("idle");
      const msg = apiErrorMessage(scanErr, "Threat scan failed. Please try again.");
      setError(msg);
      toast.error("Threat scan failed");
      setUploading(false);
      return;
    }

    // --- 0b. Phase 5: scan the same plaintext buffer for embedded secrets/PII (DLP), also
    // before any encryption. Only text-based files are actually inspected; binary files are
    // skipped gracefully and always resolve to "allow". Four possible outcomes:
    //   allow/warn            -> proceed straight to encryption + upload
    //   require_approval      -> pause and ask the uploader to explicitly confirm via a modal
    //   block                 -> refuse the upload outright, nothing is encrypted/stored
    let dlpScanId: string;
    try {
      const dlpFormData = new FormData();
      dlpFormData.append("file", currentFile);
      const dlpRes = await api.post("/dlp/scan", dlpFormData, {
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "multipart/form-data" },
      });
      setDlpResult(dlpRes.data);
      dlpScanId = dlpRes.data.dlpScanId;

      if (dlpRes.data.decision === "block") {
        setDlpStatus("blocked");
        setError(
          `Upload blocked: sensitive data (${(dlpRes.data.matchedPatterns || []).join(", ") || "policy violation"}) was detected by the DLP scanner.`
        );
        toast.error("File blocked by DLP scan");
        setUploading(false);
        return;
      }

      if (dlpRes.data.decision === "require_approval") {
        setDlpStatus("pending_approval");
        pendingUploadRef.current = async () => {
          setDlpApproving(true);
          try {
            await api.post(
              `/dlp/scans/${dlpScanId}/acknowledge`,
              {},
              { headers: { Authorization: `Bearer ${token}` } }
            );
            setShowDlpApprovalModal(false);
            await finishUpload(currentFile, token, scanId, dlpScanId);
          } catch (ackErr: unknown) {
            toast.error(apiErrorMessage(ackErr, "Failed to confirm - please try again"));
            setUploading(false);
          } finally {
            setDlpApproving(false);
          }
        };
        setShowDlpApprovalModal(true);
        return;
      }

      setDlpStatus(dlpRes.data.decision === "warn" ? "warned" : "clean");
      if (dlpRes.data.decision === "warn") toast("Sensitive data detected - review before sharing", { icon: "⚠️" });
    } catch (dlpErr: unknown) {
      setDlpStatus("idle");
      const msg = apiErrorMessage(dlpErr, "DLP scan failed. Please try again.");
      setError(msg);
      toast.error("DLP scan failed");
      setUploading(false);
      return;
    }

    await finishUpload(currentFile, token, scanId, dlpScanId);
  };

  const cancelDlpApproval = () => {
    pendingUploadRef.current = null;
    setShowDlpApprovalModal(false);
    setDlpStatus("blocked");
    setError("Upload cancelled - sensitive data findings were not acknowledged.");
    setUploading(false);
  };

  /** Steps 1-2 of the upload: client-side encryption + the actual POST /files/upload. Split out
   *  from uploadFile() so it can be invoked either immediately (DLP decision allow/warn) or
   *  later, once the user has explicitly confirmed a "require_approval" DLP finding via the modal. */
  const finishUpload = async (currentFile: File, token: string, scanId: string, dlpScanId: string) => {
    try {
      // --- 1. Encrypt the file entirely in the browser before any network request ---
      let ciphertext: ArrayBuffer;
      let iv: Uint8Array;
      let wrappedOwnerKey: string;
      let passwordWrap: { wrapped: string; salt: string; iv: string; iterations: number } | null = null;
      let fragmentKeyBase64Url: string | null = null;
      let fileSignature: Awaited<ReturnType<typeof signEncryptedFile>> | null = null;

      setEncryptStatus("active");
      try {
        const aesKey = await generateAESKey();
        const encrypted = await encryptFile(currentFile, aesKey);
        ciphertext = encrypted.ciphertext;
        iv = encrypted.iv;

        // Owner-wrap: lets the uploader always re-access this file from their dashboard.
        const publicKeyRes = await api.get("/users/publickey", {
          headers: { Authorization: `Bearer ${token}` },
        });
        if (!publicKeyRes.data?.publicKey) {
          throw new Error("No public key found for your account. Please try logging in again.");
        }
        const ownPublicKey = await importPublicKey(publicKeyRes.data.publicKey);
        wrappedOwnerKey = await wrapAESKey(aesKey, ownPublicKey);

        // Sharing path: either a password-derived wrap, or a raw key in the URL fragment
        // (never sent to the server - fragments are stripped before the request leaves the browser).
        if (usePassword && password.trim().length > 0) {
          passwordWrap = await wrapAESKeyWithPassword(aesKey, password.trim());
        } else {
          const raw = await exportAESKeyRaw(aesKey);
          fragmentKeyBase64Url = bufToBase64Url(raw);
        }
        setEncryptStatus("done");

        // Phase 2: sign the encrypted file (hash + ECDSA signature) so downloaders can verify
        // authenticity/integrity before decrypting. Signing key may be missing for accounts
        // mid-upgrade (see CryptoKeyContext's lazy backfill) - upload still proceeds unsigned
        // rather than blocking, preserving compatibility with the Phase 1 flow.
        if (signingPrivateKey) {
          setSigningStatus("signing");
          fileSignature = await signEncryptedFile(ciphertext, signingPrivateKey);
          setSigningStatus("signed");
        } else {
          setSigningStatus("unsigned");
        }
      } catch (cryptoErr: unknown) {
        setEncryptStatus("error");
        console.error("Client-side encryption failed:", cryptoErr);
        setError("Failed to encrypt file locally. Please try again or use a different browser.");
        toast.error("Encryption failed");
        setUploading(false);
        return;
      }

      // --- 2. Upload only ciphertext + wrapped keys + signature + metadata; raw key never included ---
      const formData = new FormData();
      formData.append("file", new Blob([ciphertext]), currentFile.name);
      formData.append("encryptionVersion", "2");
      formData.append("algorithm", "AES-256-GCM");
      formData.append("iv", bufToBase64(iv));
      formData.append("mimeType", currentFile.type);
      formData.append("wrappedOwnerKey", wrappedOwnerKey);
      formData.append("scanId", scanId);
      formData.append("dlpScanId", dlpScanId);
      if (passwordWrap) {
        formData.append("wrappedPasswordKey", passwordWrap.wrapped);
        formData.append("keySalt", passwordWrap.salt);
        formData.append("passwordKeyIvHint", passwordWrap.iv);
        formData.append("keyIterations", String(passwordWrap.iterations));
      }
      if (fileSignature) {
        formData.append("signature", fileSignature.signature);
        formData.append("fileHash", fileSignature.fileHash);
        formData.append("hashAlgorithm", fileSignature.hashAlgorithm);
        formData.append("signatureAlgorithm", fileSignature.signatureAlgorithm);
        formData.append("signedAt", fileSignature.signedAt);
      }
      formData.append("maxDownloads", maxDownloads);
      formData.append("expiryHours", expiryHours);

      const policyPayload = buildPolicyPayload();
      if (policyPayload) {
        formData.append("policy", JSON.stringify(policyPayload));
      }

      setUploadStatus("active");
      const request = api.post("/files/upload", formData, {
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "multipart/form-data",
        },
      });

      const response = await toast.promise(
        request,
        {
          loading: "Uploading encrypted file...",
          success: "File uploaded successfully",
          error: (err: unknown) => apiErrorMessage(err, "Upload failed. Please try again."),
        },
        { id: "upload" }
      );

      setUploadStatus("done");
      setSuccess(true);
      setFile(null);

      const fileId = response.data?.fileId;
      if (fileId) {
        const origin = window.location.origin;
        const link = fragmentKeyBase64Url
          ? `${origin}/file/${fileId}#k=${fragmentKeyBase64Url}`
          : `${origin}/file/${fileId}`;
        setShareLink(link);
      }
    } catch (err: unknown) {
      setUploadStatus("error");
      setError(apiErrorMessage(err, "Upload failed. Please try again."));
      // toast handled by toast.promise
      if (process.env.NODE_ENV !== "production") {
        // Helpful debug info during development
        console.error("Upload failed:", err);
      }
    } finally {
      setUploading(false);
    }
  };

  const handleCopyShareLink = async () => {
    try {
      await navigator.clipboard.writeText(shareLink);
      setLinkCopied(true);
      toast.success("Share link copied");
      setTimeout(() => setLinkCopied(false), 2000);
    } catch {
      toast.error("Failed to copy link");
    }
  };

  const handleRemoveFile = () => {
    setFile(null);
    setError("");
  };

  const stepState = (
    achieved: TimelineStepState,
    active: boolean,
    errored: boolean,
    reachedYet: boolean
  ): TimelineStepState => {
    if (errored) return "error";
    if (active) return "active";
    if (reachedYet) return achieved;
    return "pending";
  };

  const timelineSteps: TimelineStep[] = uploading || success || error
    ? [
        {
          key: "scan",
          label: "Threat Scan",
          state: stepState("done", scanStatus === "scanning", scanStatus === "blocked", scanStatus !== "idle"),
          detail: scanResult ? `${scanResult.riskLevel} risk` : undefined,
        },
        {
          key: "dlp",
          label: "DLP Scan",
          state: stepState(
            "done",
            dlpStatus === "scanning" || dlpStatus === "pending_approval",
            dlpStatus === "blocked",
            dlpStatus !== "idle"
          ),
          detail: dlpResult ? (dlpResult.supported === false ? "skipped (binary)" : `${dlpResult.severity} severity`) : undefined,
        },
        {
          key: "encrypt",
          label: "Encryption",
          state: stepState("done", encryptStatus === "active", encryptStatus === "error", encryptStatus !== "idle"),
          detail: "AES-256-GCM, client-side",
        },
        {
          key: "sign",
          label: "Signing",
          state: stepState(
            signingStatus === "unsigned" ? "done" : "done",
            signingStatus === "signing",
            false,
            signingStatus !== "idle"
          ),
          detail: signingStatus === "unsigned" ? "unsigned (no signing key)" : signingStatus === "signed" ? "ECDSA P-256" : undefined,
        },
        {
          key: "upload",
          label: "Uploading",
          state: stepState("done", uploadStatus === "active", uploadStatus === "error", uploadStatus !== "idle"),
        },
        {
          key: "complete",
          label: "Completed",
          state: success ? "done" : "pending",
        },
      ]
    : [];

  return (
    <div className="max-w-5xl mx-auto">
      <PageHeader icon={Upload} title="Upload File" description="Encrypt, scan, sign, and share a file securely." />

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 bg-card border border-border rounded-2xl p-6 sm:p-8">
          {error && (
            <div className="mb-6 p-4 bg-destructive/10 border border-destructive/30 rounded-lg flex items-start gap-3">
              <AlertCircle size={20} className="text-destructive shrink-0 mt-0.5" />
              <p className="text-destructive text-sm">{error}</p>
            </div>
          )}

          {success && (
            <div className="mb-6 p-4 bg-success/10 border border-success/30 rounded-lg">
              <div className="flex items-start gap-3">
                <CheckCircle size={20} className="text-success shrink-0 mt-0.5" />
                <div className="flex-1 min-w-0">
                  <p className="text-success font-semibold text-sm">File encrypted &amp; uploaded successfully!</p>
                  <p className="text-success/80 text-xs mt-1">
                    This link contains the only copy of the decryption key outside your account - save it now.
                  </p>
                </div>
              </div>
              {shareLink && (
                <div className="mt-3 flex items-center gap-2">
                  <code className="flex-1 min-w-0 text-xs text-foreground bg-background/60 rounded-lg px-3 py-2 break-all">
                    {shareLink}
                  </code>
                  <button type="button" onClick={handleCopyShareLink} className="shrink-0 p-2 bg-success hover:bg-success/90 text-white rounded-lg" title="Copy link">
                    {linkCopied ? <Check size={16} /> : <Copy size={16} />}
                  </button>
                </div>
              )}
              <div className="mt-3 flex flex-wrap gap-2">
                {scanResult && <StatusBadge label={`Threat: ${scanResult.riskLevel}`} tone={scanStatus === "clean" ? "success" : "warning"} />}
                {dlpResult && (
                  <StatusBadge
                    label={dlpResult.supported === false ? "DLP: skipped" : `DLP: ${dlpResult.severity}`}
                    tone={dlpStatus === "clean" ? "success" : "warning"}
                  />
                )}
                {signingStatus === "signed" ? (
                  <StatusBadge label="Digitally Signed" tone="success" />
                ) : signingStatus === "unsigned" ? (
                  <StatusBadge label="Unsigned" tone="warning" />
                ) : null}
              </div>
              <button type="button" onClick={() => router.push("/files")} className="mt-4 text-success text-xs font-semibold hover:text-success/80 transition-colors">
                Go to files →
              </button>
            </div>
          )}

          <div
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onDrop={handleDrop}
            onClick={() => !uploading && document.getElementById("fileInput")?.click()}
            className={`border-2 border-dashed rounded-xl p-12 text-center cursor-pointer transition-all mb-6 ${
              isDragging ? "border-primary bg-primary/10" : "border-border hover:border-primary/60 hover:bg-primary/5"
            } ${uploading ? "opacity-50 cursor-not-allowed" : ""}`}
          >
            <div className="flex flex-col items-center gap-3">
              <motion.div animate={isDragging ? { scale: 1.1 } : { scale: 1 }}>
                <Upload size={48} className="text-primary" />
              </motion.div>
              <div>
                <h3 className="text-xl font-bold text-foreground mb-1">{file ? "File selected" : "Drag and drop your file"}</h3>
                <p className="text-muted-foreground text-sm">{file ? "Click to change file" : "or click to select from your device"}</p>
                <p className="text-muted-foreground/70 text-xs mt-2">Max file size: 100MB</p>
              </div>
            </div>

            <input
              id="fileInput"
              type="file"
              hidden
              onChange={(e) => {
                const selected = e.currentTarget.files?.[0] ?? null;
                handleFileSelect(selected);
              }}
              disabled={uploading}
              accept={ALLOWED_TYPES.join(",")}
            />
          </div>

          {file && (
            <div className="mb-6 p-4 bg-muted/40 border border-border rounded-lg">
              <div className="flex items-center justify-between gap-3">
                <div className="flex items-center gap-3 flex-1 min-w-0">
                  <FileIcon size={24} className="text-primary shrink-0" />
                  <div className="min-w-0">
                    <p className="font-semibold text-foreground truncate">{file.name}</p>
                    <p className="text-muted-foreground text-sm">{formatFileSize(file.size)}</p>
                  </div>
                </div>
                <button type="button" onClick={handleRemoveFile} disabled={uploading} aria-label="Remove file" className="text-muted-foreground hover:text-destructive transition-colors shrink-0 disabled:opacity-50">
                  <X size={20} />
                </button>
              </div>

              <div className="mt-4 grid grid-cols-1 gap-3">
                <label className="flex items-center gap-2 text-foreground text-sm">
                  <input type="checkbox" checked={usePassword} onChange={(e) => setUsePassword(e.target.checked)} disabled={uploading} />
                  Protect with password
                </label>
                {usePassword && (
                  <div className="relative">
                    <Lock size={16} className="absolute left-3 top-3.5 text-muted-foreground" />
                    <input
                      type="text"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      placeholder="Enter a download password"
                      className="w-full pl-10 pr-4 py-3 bg-background border border-border rounded-lg text-foreground placeholder-muted-foreground focus:outline-none focus-visible:ring-2 focus-visible:ring-primary/60 transition-all"
                      disabled={uploading}
                    />
                    <p className="text-muted-foreground text-xs mt-2">Recipients must provide this password to download.</p>
                  </div>
                )}
              </div>

              <div className="mt-4 grid grid-cols-2 gap-3">
                <div>
                  <label htmlFor="maxDownloads" className="block text-foreground text-xs font-semibold mb-2">Max Downloads</label>
                  <input
                    id="maxDownloads"
                    type="number"
                    min="1"
                    max="100"
                    value={maxDownloads}
                    onChange={(e) => setMaxDownloads(e.target.value)}
                    className="w-full px-3 py-2 bg-background border border-border rounded-lg text-foreground focus:outline-none focus-visible:ring-2 focus-visible:ring-primary/60 transition-all"
                    disabled={uploading}
                  />
                  <p className="text-muted-foreground text-xs mt-1">1-100 downloads</p>
                </div>
                <div>
                  <label htmlFor="expiryHours" className="block text-foreground text-xs font-semibold mb-2">Expiry (hours)</label>
                  <input
                    id="expiryHours"
                    type="number"
                    min="1"
                    max="720"
                    value={expiryHours}
                    onChange={(e) => setExpiryHours(e.target.value)}
                    className="w-full px-3 py-2 bg-background border border-border rounded-lg text-foreground focus:outline-none focus-visible:ring-2 focus-visible:ring-primary/60 transition-all"
                    disabled={uploading}
                  />
                  <p className="text-muted-foreground text-xs mt-1">Up to 30 days</p>
                </div>
              </div>

              <div className="mt-4 border-t border-border pt-4">
                <button
                  type="button"
                  onClick={() => setShowPolicy(!showPolicy)}
                  disabled={uploading}
                  className="w-full flex items-center justify-between text-foreground text-xs font-semibold"
                >
                  <span className="flex items-center gap-2">
                    <Globe2 size={14} />
                    Advanced Security Policy (Zero Trust)
                  </span>
                  {showPolicy ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
                </button>

                {showPolicy && (
                  <div className="mt-3 space-y-3">
                    <p className="text-muted-foreground text-xs">
                      Every rule below is optional. Leave everything blank for an unrestricted file - this only
                      applies extra checks the file&apos;s recipients must pass before downloading.
                    </p>

                    <div>
                      <label className="block text-foreground text-xs font-semibold mb-1">Allowed countries</label>
                      <input
                        type="text"
                        value={allowedCountries}
                        onChange={(e) => setAllowedCountries(e.target.value)}
                        placeholder="US, IN, GB (comma-separated ISO codes)"
                        className="w-full px-3 py-2 bg-background border border-border rounded-lg text-foreground text-sm placeholder-muted-foreground focus:outline-none focus:border-primary"
                        disabled={uploading}
                      />
                    </div>

                    <div>
                      <label className="block text-foreground text-xs font-semibold mb-1">Allowed IP addresses</label>
                      <input
                        type="text"
                        value={allowedIPs}
                        onChange={(e) => setAllowedIPs(e.target.value)}
                        placeholder="203.0.113.5, 198.51.100.2 (comma-separated)"
                        className="w-full px-3 py-2 bg-background border border-border rounded-lg text-foreground text-sm placeholder-muted-foreground focus:outline-none focus:border-primary"
                        disabled={uploading}
                      />
                    </div>

                    <div>
                      <label className="flex items-center gap-2 text-foreground text-xs font-semibold mb-2">
                        <input type="checkbox" checked={businessHoursEnabled} onChange={(e) => setBusinessHoursEnabled(e.target.checked)} disabled={uploading} />
                        Restrict to specific hours (UTC)
                      </label>
                      {businessHoursEnabled && (
                        <div className="grid grid-cols-2 gap-3">
                          <input
                            type="number"
                            min="0"
                            max="23"
                            value={businessStartHour}
                            onChange={(e) => setBusinessStartHour(e.target.value)}
                            placeholder="Start hour"
                            className="w-full px-3 py-2 bg-background border border-border rounded-lg text-foreground text-sm focus:outline-none focus:border-primary"
                            disabled={uploading}
                          />
                          <input
                            type="number"
                            min="0"
                            max="24"
                            value={businessEndHour}
                            onChange={(e) => setBusinessEndHour(e.target.value)}
                            placeholder="End hour"
                            className="w-full px-3 py-2 bg-background border border-border rounded-lg text-foreground text-sm focus:outline-none focus:border-primary"
                            disabled={uploading}
                          />
                        </div>
                      )}
                    </div>

                    <div>
                      <label className="block text-foreground text-xs font-semibold mb-1">Max distinct devices</label>
                      <input
                        type="number"
                        min="0"
                        value={maxDevices}
                        onChange={(e) => setMaxDevices(e.target.value)}
                        placeholder="0 = unlimited"
                        className="w-full px-3 py-2 bg-background border border-border rounded-lg text-foreground text-sm placeholder-muted-foreground focus:outline-none focus:border-primary"
                        disabled={uploading}
                      />
                    </div>

                    <label className="flex items-center gap-2 text-foreground text-xs font-semibold">
                      <input type="checkbox" checked={requireApproval} onChange={(e) => setRequireApproval(e.target.checked)} disabled={uploading} />
                      Require an authenticated, trusted-device recipient
                    </label>
                  </div>
                )}
              </div>
            </div>
          )}

          {!file && (
            <div className="mb-6 p-4 bg-primary/5 border border-primary/20 rounded-lg flex items-start gap-3">
              <Lock size={18} className="text-primary shrink-0 mt-0.5" />
              <div>
                <p className="text-foreground font-semibold text-sm">Your file is protected</p>
                <p className="text-muted-foreground text-xs mt-1">
                  All files are encrypted with AES-256 and can be shared with time-limited links
                </p>
              </div>
            </div>
          )}

          <motion.button
            onClick={uploadFile}
            disabled={!file || uploading || success || checkingKey}
            whileTap={{ scale: 0.98 }}
            className="w-full py-3 bg-primary text-white font-bold rounded-lg hover:bg-primary/90 disabled:bg-muted transition-all shadow-lg shadow-primary/20 disabled:shadow-none flex items-center justify-center gap-2"
          >
            {uploading ? (
              <>
                <Loader size={20} className="animate-spin" />
                Uploading...
              </>
            ) : success ? (
              <>
                <CheckCircle size={20} />
                Upload Complete
              </>
            ) : file ? (
              <>
                <Upload size={20} />
                Upload File
              </>
            ) : (
              <>
                <Upload size={20} />
                Select a File First
              </>
            )}
          </motion.button>

          <div className="mt-6 pt-6 border-t border-border">
            <p className="text-muted-foreground text-xs font-semibold mb-2">Supported formats:</p>
            <div className="grid grid-cols-3 sm:grid-cols-5 gap-2">
              {["PDF", "DOC", "XLS", "JPG", "PNG", "TXT", "ZIP", "GIF", "DOCX"].map((format) => (
                <div key={format} className="bg-muted/40 rounded px-2 py-1 text-center">
                  <p className="text-muted-foreground text-xs font-medium">{format}</p>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Progress timeline sidebar */}
        <div className="rounded-2xl border border-border bg-card p-6 h-fit lg:sticky lg:top-24">
          <h3 className="text-sm font-semibold text-foreground mb-5">Security Pipeline</h3>
          {timelineSteps.length === 0 ? (
            <p className="text-sm text-muted-foreground">Select a file and start the upload to see live progress here.</p>
          ) : (
            <ProgressTimeline steps={timelineSteps} />
          )}
        </div>
      </div>

      <UnlockKeyModal
        open={showKeyModal}
        onClose={() => setShowKeyModal(false)}
        onSuccess={() => {
          setShowKeyModal(false);
          uploadFile();
        }}
      />

      {/* Phase 5: DLP "require_approval" confirmation - shown when the scanner found sensitive
          data that isn't outright blocked, but needs the uploader's explicit sign-off before
          the file is encrypted and uploaded. Only category/pattern names are shown here, never
          the actual matched values. */}
      {showDlpApprovalModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm px-4">
          <div className="w-full max-w-md bg-card border border-border rounded-2xl shadow-2xl p-6">
            <div className="flex items-center gap-3 mb-4">
              <div className="inline-flex h-10 w-10 items-center justify-center rounded-xl bg-warning/10 text-warning ring-1 ring-warning/30">
                <Eye size={20} />
              </div>
              <h2 className="text-lg font-bold text-foreground">Sensitive data detected</h2>
            </div>
            <p className="text-foreground/90 text-sm mb-3">
              This file appears to contain:{" "}
              <span className="font-semibold text-warning">{(dlpResult?.matchedPatterns || []).join(", ") || "sensitive information"}</span>.
              Do you want to continue uploading it anyway?
            </p>
            <p className="text-muted-foreground text-xs mb-5">
              Your choice is recorded in the DLP Center audit log. The file will still be encrypted end-to-end before it leaves your browser.
            </p>
            <div className="flex gap-3 justify-end">
              <button type="button" onClick={cancelDlpApproval} disabled={dlpApproving} className="px-4 py-2 text-sm font-semibold text-muted-foreground hover:text-foreground hover:bg-white/5 rounded-lg disabled:opacity-50">
                Cancel
              </button>
              <button
                onClick={() => pendingUploadRef.current?.()}
                disabled={dlpApproving}
                className="px-4 py-2 text-sm font-semibold text-white bg-warning hover:bg-warning/90 rounded-lg disabled:opacity-50 flex items-center gap-2"
              >
                {dlpApproving && <Loader size={14} className="animate-spin" />}
                Continue Anyway
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
