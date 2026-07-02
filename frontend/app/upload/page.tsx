"use client";
import { useEffect, useState } from "react";
import api from "@/lib/api";
import { useRouter } from "next/navigation";
import { Upload, AlertCircle, CheckCircle, Loader, X, FileIcon, Lock, Copy, Check, ShieldCheck, ShieldAlert, ChevronDown, ChevronUp, Globe2 } from "lucide-react";
import toast from "react-hot-toast";
import Navbar from "@/components/Navbar";
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
import UnlockKeyModal from "@/components/UnlockKeyModal";

export default function UploadFile() {
  const [file, setFile] = useState<File | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
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

    setUploading(true);
    setError("");
    setUploadProgress(0);
    setSigningStatus("idle");

    // Simulate progress for better UX (actual progress can be tracked with axios)
    const progressInterval = setInterval(() => {
      setUploadProgress((prev) => {
        if (prev >= 90) {
          clearInterval(progressInterval);
          return prev;
        }
        return prev + Math.random() * 30;
      });
    }, 300);

    try {
      // --- 1. Encrypt the file entirely in the browser before any network request ---
      let ciphertext: ArrayBuffer;
      let iv: Uint8Array;
      let wrappedOwnerKey: string;
      let passwordWrap: { wrapped: string; salt: string; iv: string; iterations: number } | null = null;
      let fragmentKeyBase64Url: string | null = null;
      let fileSignature: Awaited<ReturnType<typeof signEncryptedFile>> | null = null;

      try {
        const aesKey = await generateAESKey();
        const encrypted = await encryptFile(file, aesKey);
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
      } catch (cryptoErr: any) {
        clearInterval(progressInterval);
        console.error("Client-side encryption failed:", cryptoErr);
        setError("Failed to encrypt file locally. Please try again or use a different browser.");
        toast.error("Encryption failed");
        setUploading(false);
        return;
      }

      // --- 2. Upload only ciphertext + wrapped keys + signature + metadata; raw key never included ---
      const formData = new FormData();
      formData.append("file", new Blob([ciphertext]), file.name);
      formData.append("encryptionVersion", "2");
      formData.append("algorithm", "AES-256-GCM");
      formData.append("iv", bufToBase64(iv));
      formData.append("mimeType", file.type);
      formData.append("wrappedOwnerKey", wrappedOwnerKey);
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
          error: (err: any) =>
            err?.response?.data?.error || err?.response?.data?.message || "Upload failed. Please try again.",
        },
        { id: "upload" }
      );

      clearInterval(progressInterval);
      setUploadProgress(100);
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
    } catch (err: any) {
      clearInterval(progressInterval);
      const serverError = err?.response?.data?.error || err?.response?.data?.message;
      const errorMessage = serverError || err.message || "Upload failed. Please try again.";
      setError(errorMessage);
      // toast handled by toast.promise
      if (process.env.NODE_ENV !== "production") {
        // Helpful debug info during development
        console.error("Upload failed:", err?.response?.data || err);
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
    setUploadProgress(0);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 flex items-center justify-center px-4 py-8">
      {/* Animated background blobs */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-20 right-10 w-72 h-72 bg-blue-500 rounded-full mix-blend-multiply filter blur-3xl opacity-20 animate-pulse"></div>
        <div className="absolute -bottom-8 left-20 w-72 h-72 bg-purple-500 rounded-full mix-blend-multiply filter blur-3xl opacity-20 animate-pulse" style={{ animationDelay: "2s" }}></div>
      </div>

      <div className="w-full max-w-2xl relative z-10">
        {/* Card */}
        <div className="bg-slate-800 bg-opacity-80 backdrop-blur-xl border border-slate-700 rounded-2xl shadow-2xl overflow-hidden">
          {/* Header */}
          <div className="relative h-32 bg-gradient-to-r from-blue-600 to-cyan-600 flex items-center justify-center overflow-hidden">
            <div className="absolute inset-0 opacity-20">
              <div className="absolute top-0 left-0 w-40 h-40 bg-white rounded-full mix-blend-multiply filter blur-2xl"></div>
              <div className="absolute bottom-0 right-0 w-40 h-40 bg-white rounded-full mix-blend-multiply filter blur-2xl"></div>
            </div>
            <div className="relative">
              <div className="bg-white bg-opacity-20 p-3 rounded-full backdrop-blur-md">
                <Upload size={32} className="text-white" />
              </div>
            </div>
          </div>

          {/* Content */}
          <div className="p-8">
            <h1 className="text-3xl font-bold text-white mb-2 text-center">Upload File</h1>
            <p className="text-slate-400 text-center mb-8">
              Securely upload files with encryption protection
            </p>

            {/* Error Alert */}
            {error && (
              <div className="mb-6 p-4 bg-red-500 bg-opacity-20 border border-red-500 border-opacity-50 rounded-lg flex items-start gap-3">
                <AlertCircle size={20} className="text-red-400 flex-shrink-0 mt-0.5" />
                <p className="text-red-200 text-sm">{error}</p>
              </div>
            )}

            {/* Success Alert */}
            {success && (
              <div className="mb-6 p-4 bg-green-500 bg-opacity-20 border border-green-500 border-opacity-50 rounded-lg">
                <div className="flex items-start gap-3">
                  <CheckCircle size={20} className="text-green-400 flex-shrink-0 mt-0.5" />
                  <div className="flex-1 min-w-0">
                    <p className="text-green-200 font-semibold text-sm">File encrypted &amp; uploaded successfully!</p>
                    <p className="text-green-200 text-xs mt-1">
                      This link contains the only copy of the decryption key outside your account — save it now.
                    </p>
                  </div>
                </div>
                {shareLink && (
                  <div className="mt-3 flex items-center gap-2">
                    <code className="flex-1 min-w-0 text-xs text-slate-200 bg-slate-900 bg-opacity-60 rounded-lg px-3 py-2 break-all">
                      {shareLink}
                    </code>
                    <button
                      onClick={handleCopyShareLink}
                      className="flex-shrink-0 p-2 bg-green-600 hover:bg-green-700 text-white rounded-lg"
                      title="Copy link"
                    >
                      {linkCopied ? <Check size={16} /> : <Copy size={16} />}
                    </button>
                  </div>
                )}
                {signingStatus === "signed" ? (
                  <div className="mt-3 flex items-center gap-2 text-green-300 text-xs">
                    <ShieldCheck size={14} />
                    <span>Digitally signed (ECDSA P-256) - recipients can verify this file wasn&apos;t tampered with.</span>
                  </div>
                ) : signingStatus === "unsigned" ? (
                  <div className="mt-3 flex items-center gap-2 text-yellow-300 text-xs">
                    <ShieldAlert size={14} />
                    <span>Uploaded without a digital signature - your signing key isn&apos;t set up on this device yet.</span>
                  </div>
                ) : null}
                <button
                  onClick={() => router.push("/dashboard")}
                  className="mt-3 text-green-300 text-xs font-semibold hover:text-green-200 transition-colors"
                >
                  Go to dashboard →
                </button>
              </div>
            )}

            {/* Drag & Drop Area */}
            <div
              onDragOver={handleDragOver}
              onDragLeave={handleDragLeave}
              onDrop={handleDrop}
              onClick={() => !uploading && document.getElementById("fileInput")?.click()}
              className={`border-2 border-dashed rounded-xl p-12 text-center cursor-pointer transition-all mb-6 ${
                isDragging
                  ? "border-blue-400 bg-blue-500 bg-opacity-20"
                  : "border-slate-600 hover:border-blue-500 hover:bg-blue-500 hover:bg-opacity-10"
              } ${uploading ? "opacity-50 cursor-not-allowed" : ""}`}
            >
              <div className="flex flex-col items-center gap-3">
                <div className={`transition-transform ${isDragging ? "scale-110" : ""}`}>
                  <Upload size={48} className="text-blue-400" />
                </div>
                <div>
                  <h3 className="text-xl font-bold text-white mb-1">
                    {file ? "File selected" : "Drag and drop your file"}
                  </h3>
                  <p className="text-slate-400 text-sm">
                    {file ? "Click to change file" : "or click to select from your device"}
                  </p>
                  <p className="text-slate-500 text-xs mt-2">Max file size: 100MB</p>
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

            {/* Selected File Info */}
            {file && (
              <div className="mb-6 p-4 bg-slate-700 bg-opacity-50 border border-slate-600 rounded-lg">
                <div className="flex items-center justify-between gap-3">
                  <div className="flex items-center gap-3 flex-1 min-w-0">
                    <FileIcon size={24} className="text-blue-400 flex-shrink-0" />
                    <div className="min-w-0">
                      <p className="font-semibold text-white truncate">{file.name}</p>
                      <p className="text-slate-400 text-sm">{formatFileSize(file.size)}</p>
                    </div>
                  </div>
                  <button
                    onClick={handleRemoveFile}
                    disabled={uploading}
                    className="text-slate-400 hover:text-red-400 transition-colors flex-shrink-0 disabled:opacity-50"
                  >
                    <X size={20} />
                  </button>
                </div>
                {/* Optional Password */}
                <div className="mt-4 grid grid-cols-1 gap-3">
                  <label className="flex items-center gap-2 text-slate-300 text-sm">
                    <input
                      type="checkbox"
                      checked={usePassword}
                      onChange={(e) => setUsePassword(e.target.checked)}
                      disabled={uploading}
                    />
                    Protect with password
                  </label>
                  {usePassword && (
                    <div className="relative">
                      <Lock size={16} className="absolute left-3 top-3.5 text-slate-400" />
                      <input
                        type="text"
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        placeholder="Enter a download password"
                        className="w-full pl-10 pr-4 py-3 bg-slate-700 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500 focus:ring-opacity-50 transition-all"
                        disabled={uploading}
                      />
                      <p className="text-slate-500 text-xs mt-2">Recipients must provide this password to download.</p>
                    </div>
                  )}
                </div>

                {/* Download Limits & Expiry */}
                <div className="mt-4 grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-slate-300 text-xs font-semibold mb-2">Max Downloads</label>
                    <input
                      type="number"
                      min="1"
                      max="100"
                      value={maxDownloads}
                      onChange={(e) => setMaxDownloads(e.target.value)}
                      className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white focus:outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500 focus:ring-opacity-50 transition-all"
                      disabled={uploading}
                    />
                    <p className="text-slate-500 text-xs mt-1">1-100 downloads</p>
                  </div>
                  <div>
                    <label className="block text-slate-300 text-xs font-semibold mb-2">Expiry (hours)</label>
                    <input
                      type="number"
                      min="1"
                      max="720"
                      value={expiryHours}
                      onChange={(e) => setExpiryHours(e.target.value)}
                      className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white focus:outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500 focus:ring-opacity-50 transition-all"
                      disabled={uploading}
                    />
                    <p className="text-slate-500 text-xs mt-1">Up to 30 days</p>
                  </div>
                </div>

                {/* Phase 3: Zero Trust access policy (optional, collapsed by default) */}
                <div className="mt-4 border-t border-slate-600 pt-4">
                  <button
                    type="button"
                    onClick={() => setShowPolicy(!showPolicy)}
                    disabled={uploading}
                    className="w-full flex items-center justify-between text-slate-300 text-xs font-semibold"
                  >
                    <span className="flex items-center gap-2">
                      <Globe2 size={14} />
                      Advanced Security Policy (Zero Trust)
                    </span>
                    {showPolicy ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
                  </button>

                  {showPolicy && (
                    <div className="mt-3 space-y-3">
                      <p className="text-slate-500 text-xs">
                        Every rule below is optional. Leave everything blank for an unrestricted file - this only
                        applies extra checks the file's recipients must pass before downloading.
                      </p>

                      <div>
                        <label className="block text-slate-300 text-xs font-semibold mb-1">Allowed countries</label>
                        <input
                          type="text"
                          value={allowedCountries}
                          onChange={(e) => setAllowedCountries(e.target.value)}
                          placeholder="US, IN, GB (comma-separated ISO codes)"
                          className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white text-sm placeholder-slate-500 focus:outline-none focus:border-blue-500"
                          disabled={uploading}
                        />
                      </div>

                      <div>
                        <label className="block text-slate-300 text-xs font-semibold mb-1">Allowed IP addresses</label>
                        <input
                          type="text"
                          value={allowedIPs}
                          onChange={(e) => setAllowedIPs(e.target.value)}
                          placeholder="203.0.113.5, 198.51.100.2 (comma-separated)"
                          className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white text-sm placeholder-slate-500 focus:outline-none focus:border-blue-500"
                          disabled={uploading}
                        />
                      </div>

                      <div>
                        <label className="flex items-center gap-2 text-slate-300 text-xs font-semibold mb-2">
                          <input
                            type="checkbox"
                            checked={businessHoursEnabled}
                            onChange={(e) => setBusinessHoursEnabled(e.target.checked)}
                            disabled={uploading}
                          />
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
                              className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white text-sm focus:outline-none focus:border-blue-500"
                              disabled={uploading}
                            />
                            <input
                              type="number"
                              min="0"
                              max="24"
                              value={businessEndHour}
                              onChange={(e) => setBusinessEndHour(e.target.value)}
                              placeholder="End hour"
                              className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white text-sm focus:outline-none focus:border-blue-500"
                              disabled={uploading}
                            />
                          </div>
                        )}
                      </div>

                      <div>
                        <label className="block text-slate-300 text-xs font-semibold mb-1">Max distinct devices</label>
                        <input
                          type="number"
                          min="0"
                          value={maxDevices}
                          onChange={(e) => setMaxDevices(e.target.value)}
                          placeholder="0 = unlimited"
                          className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white text-sm placeholder-slate-500 focus:outline-none focus:border-blue-500"
                          disabled={uploading}
                        />
                      </div>

                      <label className="flex items-center gap-2 text-slate-300 text-xs font-semibold">
                        <input
                          type="checkbox"
                          checked={requireApproval}
                          onChange={(e) => setRequireApproval(e.target.checked)}
                          disabled={uploading}
                        />
                        Require an authenticated, trusted-device recipient
                      </label>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Upload Progress */}
            {uploading && (
              <div className="mb-6">
                <div className="flex items-center justify-between mb-2">
                  <p className="text-slate-300 font-semibold text-sm">
                    {signingStatus === "signing" ? "Signing file (ECDSA P-256)..." : "Uploading..."}
                  </p>
                  <p className="text-blue-400 font-semibold text-sm">{Math.round(uploadProgress)}%</p>
                </div>
                <div className="w-full bg-slate-700 rounded-full h-2 overflow-hidden">
                  <div
                    className="bg-gradient-to-r from-blue-500 to-cyan-500 h-full transition-all duration-300"
                    style={{ width: `${uploadProgress}%` }}
                  ></div>
                </div>
              </div>
            )}

            {/* File Info Box */}
            {!file && (
              <div className="mb-6 p-4 bg-blue-500 bg-opacity-10 border border-blue-500 border-opacity-30 rounded-lg flex items-start gap-3">
                <Lock size={18} className="text-blue-400 flex-shrink-0 mt-0.5" />
                <div>
                  <p className="text-blue-200 font-semibold text-sm">Your file is protected</p>
                  <p className="text-blue-200 text-xs mt-1">
                    All files are encrypted with AES-256 and can be shared with time-limited links
                  </p>
                </div>
              </div>
            )}

            {/* Upload Button */}
            <button
              onClick={uploadFile}
              disabled={!file || uploading || success || checkingKey}
              className="w-full py-3 bg-gradient-to-r from-blue-500 to-cyan-500 text-white font-bold rounded-lg hover:from-blue-600 hover:to-cyan-600 disabled:from-slate-600 disabled:to-slate-600 transition-all shadow-lg hover:shadow-blue-500/50 disabled:shadow-none flex items-center justify-center gap-2"
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
            </button>

            {/* Supported Formats */}
            <div className="mt-6 pt-6 border-t border-slate-700">
              <p className="text-slate-400 text-xs font-semibold mb-2">Supported formats:</p>
              <div className="grid grid-cols-3 gap-2">
                {["PDF", "DOC", "XLS", "JPG", "PNG", "TXT", "ZIP", "GIF", "DOCX"].map((format) => (
                  <div key={format} className="bg-slate-700 bg-opacity-50 rounded px-2 py-1 text-center">
                    <p className="text-slate-300 text-xs font-medium">{format}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="mt-6 text-center text-slate-400 text-sm">
          <p>🔐 Military-grade AES-256 encryption • Zero-knowledge storage</p>
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
    </div>
  );
}