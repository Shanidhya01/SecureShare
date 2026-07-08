"use client";

import { useState } from "react";
import { motion } from "framer-motion";
import { useRouter } from "next/navigation";
import {
  Copy,
  Check,
  Lock,
  Clock,
  AlertCircle,
  Share2,
  Trash2,
  Eye,
  EyeOff,
  List,
  X,
  FileText,
  User,
} from "lucide-react";
import toast from "react-hot-toast";
import api from "@/lib/api";
import { downloadFileWithIpTracking } from "@/lib/ipTracking";
import StatusBadge, { decisionTone, riskTone } from "@/components/design/StatusBadge";
import RiskExplainButton from "@/components/ai/RiskExplainButton";
import { fadeInUp } from "@/lib/motion";
import { hasZeroTrustPolicy, type FilePolicy } from "@/lib/types";

type FileDoc = {
  expiresAt: string | number | Date;
  oneTime: boolean;
  maxDownloads?: number;
  downloadCount: number;
  _id: string;
  filename: string;
  passwordHash?: string;
  wrappedPasswordKey?: string;
  encryptionVersion?: number;
  revoked?: boolean;
  owner?: { email?: string; name?: string };
  mimeType?: string | null;
  createdAt?: string;
  signature?: string | null;
  riskLevel?: "Low" | "Medium" | "High" | "Critical" | null;
  quarantined?: boolean;
  scanStatus?: string;
  dlpRisk?: "None" | "Low" | "Medium" | "High" | "Critical" | null;
  dlpDecision?: "allow" | "warn" | "require_approval" | "block" | null;
  threatScore?: number;
  policy?: FilePolicy;
};

export default function FileCard({
  file,
  onDelete,
  onPermanentDelete,
  canManage,
  selectable,
  selected,
  onToggleSelect,
}: {
  file: FileDoc;
  onDelete?: (fileId: string) => void;
  onPermanentDelete?: (fileId: string) => void;
  canManage?: boolean;
  /** Bulk-selection mode (Files page) - shows a checkbox and highlights the card when selected. */
  selectable?: boolean;
  selected?: boolean;
  onToggleSelect?: (fileId: string) => void;
}) {
  const router = useRouter();
  const [copied, setCopied] = useState(false);
  const [showLink, setShowLink] = useState(false);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [showPermanentDeleteConfirm, setShowPermanentDeleteConfirm] = useState(false);
  const [loading, setLoading] = useState(false);
  const [showPwdModal, setShowPwdModal] = useState(false);
  const [pwdInput, setPwdInput] = useState("");

  const expiresDate = new Date(file.expiresAt);
  const now = new Date();
  const expired = expiresDate < now;
  const maxDownloads = file.maxDownloads || 1;
  const limitReached = file.downloadCount >= maxDownloads;
  const used = limitReached;
  const revoked = !!file.revoked;

  const timeUntilExpiry = expiresDate.getTime() - now.getTime();
  const daysLeft = Math.floor(timeUntilExpiry / (1000 * 60 * 60 * 24));
  const hoursLeft = Math.floor((timeUntilExpiry % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));

  const isE2E = file.encryptionVersion === 2;

  const e2eLink = typeof window !== "undefined" ? `${window.location.origin}/file/${file._id}` : `/file/${file._id}`;

  const baseLink = `${process.env.NEXT_PUBLIC_API || "http://localhost:5000/api"}/files/download/${file._id}`;

  const getTrackedLink = (password?: string) => {
    try {
      const url = new URL(baseLink);
      if (typeof window !== "undefined") {
        const rawUser = localStorage.getItem("user");
        if (rawUser) {
          const parsed = JSON.parse(rawUser);
          if (parsed?.email) url.searchParams.set("email", parsed.email as string);
        }
      }
      if (password && password.trim()) url.searchParams.set("password", password.trim());
      return url.toString();
    } catch {
      return baseLink;
    }
  };

  const handleDirectDownload = async () => {
    if (isE2E) {
      router.push(`/file/${file._id}`);
      return;
    }
    try {
      setLoading(true);
      if (file.passwordHash) {
        setShowPwdModal(true);
        return;
      }
      const userEmail = typeof window !== "undefined" ? JSON.parse(localStorage.getItem("user") || "{}").email : undefined;
      await downloadFileWithIpTracking(file._id, userEmail);
      toast.success("Download started with IP tracking");
    } catch (error) {
      console.error("Download error:", error);
      toast.error("Download failed. Try the copy link option.");
    } finally {
      setLoading(false);
    }
  };

  const handleDirectDownloadWithPassword = async () => {
    try {
      setLoading(true);
      const pwd = pwdInput.trim();
      const userEmail = typeof window !== "undefined" ? JSON.parse(localStorage.getItem("user") || "{}").email : undefined;
      await downloadFileWithIpTracking(file._id, userEmail, pwd);
      toast.success("Download started with IP tracking");
      setShowPwdModal(false);
      setPwdInput("");
    } catch (error) {
      console.error("Download error:", error);
      toast.error("Download failed");
    } finally {
      setLoading(false);
    }
  };

  const getExpiryStatus = () => {
    if (revoked) return { label: "Revoked", tone: "danger" as const };
    if (expired) return { label: "Expired", tone: "danger" as const };
    if (used) return { label: "Limit Reached", tone: "warning" as const };
    if (daysLeft === 0 && hoursLeft < 24) return { label: "Expiring Soon", tone: "warning" as const };
    return { label: "Active", tone: "success" as const };
  };

  const status = getExpiryStatus();

  const handleCopyLink = async () => {
    try {
      if (isE2E) {
        await navigator.clipboard.writeText(e2eLink);
        toast.success("File page link copied (decrypts using your account key)");
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
        return;
      }
      if (file.passwordHash) {
        setShowPwdModal(true);
        return;
      }
      const link = getTrackedLink();
      await navigator.clipboard.writeText(link);
      toast.success("Download link copied");
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      toast.error("Failed to copy link");
    }
  };

  const confirmCopyWithPassword = async () => {
    try {
      const pwd = pwdInput.trim();
      const finalLink = getTrackedLink(pwd);
      await navigator.clipboard.writeText(finalLink);
      toast.success("Download link copied");
      setCopied(true);
      setShowPwdModal(false);
      setPwdInput("");
      setTimeout(() => setCopied(false), 2000);
    } catch {
      toast.error("Failed to copy link");
    }
  };

  const handleDelete = async () => {
    if (!onDelete) return;
    setLoading(true);
    try {
      await onDelete(file._id);
      toast.success("File revoked successfully");
      setShowDeleteConfirm(false);
    } catch {
      toast.error("Failed to revoke file");
    } finally {
      setLoading(false);
    }
  };

  const handlePermanentDelete = async () => {
    setLoading(true);
    try {
      const token = localStorage.getItem("token");
      await api.delete(`/files/file/${file._id}/permanent`, { headers: { Authorization: `Bearer ${token}` } });
      toast.success("File deleted permanently");
      if (onPermanentDelete) onPermanentDelete(file._id);
    } catch {
      toast.error("Failed to delete file");
    } finally {
      setLoading(false);
      setShowPermanentDeleteConfirm(false);
    }
  };

  const handleViewLogs = () => router.push(`/file/${file._id}/logs`);

  const getTimeRemaining = () => {
    if (expired) return "Expired";
    if (used) return "Used";
    if (daysLeft > 0) return `${daysLeft}d ${hoursLeft}h left`;
    return `${hoursLeft}h left`;
  };

  const zeroTrustPolicyActive = hasZeroTrustPolicy(file.policy);

  return (
    <motion.div
      variants={fadeInUp}
      className={`group relative bg-card border rounded-xl p-6 transition-all hover:shadow-lg hover:shadow-primary/10 ${
        selected ? "border-primary ring-2 ring-primary/40" : "border-border hover:border-primary/40"
      }`}
    >
      {selectable && (
        <label className="absolute top-5 left-5 z-10 inline-flex h-5 w-5 cursor-pointer items-center justify-center">
          <span className="sr-only">Select {file.filename}</span>
          <input
            type="checkbox"
            checked={!!selected}
            onChange={() => onToggleSelect?.(file._id)}
            className="h-5 w-5 rounded border-border text-primary focus-visible:ring-2 focus-visible:ring-primary/60"
          />
        </label>
      )}
      {showPwdModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm px-4">
          <div className="bg-card border border-border rounded-xl w-full max-w-sm p-6 shadow-xl">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-foreground font-bold">Include Password</h2>
              <button
                onClick={() => {
                  setShowPwdModal(false);
                  setPwdInput("");
                }}
                className="text-muted-foreground hover:text-foreground"
                aria-label="Close"
              >
                <X size={18} />
              </button>
            </div>
            <p className="text-muted-foreground text-sm mb-3">
              Add the file password to the copied link so recipients can download directly.
            </p>
            <div className="relative mb-4">
              <Lock size={16} className="absolute left-3 top-3.5 text-muted-foreground" />
              <input
                type="text"
                value={pwdInput}
                onChange={(e) => setPwdInput(e.target.value)}
                placeholder="Enter password (optional)"
                className="w-full pl-10 pr-4 py-3 bg-background border border-border rounded-lg text-foreground placeholder-muted-foreground focus:outline-none focus-visible:ring-2 focus-visible:ring-primary/60 transition-all"
              />
            </div>
            <div className="flex gap-2">
              <button onClick={confirmCopyWithPassword} className="flex-1 px-4 py-2 bg-primary hover:bg-primary/90 text-white rounded-lg text-sm font-semibold">
                Copy Link
              </button>
              <button
                onClick={handleDirectDownloadWithPassword}
                disabled={loading}
                className="flex-1 px-4 py-2 bg-success hover:bg-success/90 text-white rounded-lg disabled:opacity-50 text-sm font-semibold"
              >
                Download
              </button>
              <button
                onClick={() => {
                  setShowPwdModal(false);
                  setPwdInput("");
                }}
                className="flex-1 px-4 py-2 bg-muted text-foreground rounded-lg text-sm font-semibold"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Header */}
      <div className={`flex items-start justify-between mb-3 gap-2 ${selectable ? "pl-7" : ""}`}>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <FileText size={18} className="text-primary shrink-0" />
            <h3 className="font-bold text-base text-foreground truncate">{file.filename}</h3>
          </div>
          <p className="text-xs text-muted-foreground truncate">
            {file.mimeType || "Unknown type"}
            {file.createdAt && ` · Uploaded ${new Date(file.createdAt).toLocaleDateString()}`}
          </p>
          {file.owner?.email && (
            <p className="text-xs text-muted-foreground truncate flex items-center gap-1 mt-0.5">
              <User size={11} />
              {file.owner.name || file.owner.email}
            </p>
          )}
        </div>
        <StatusBadge label={status.label} tone={status.tone} />
      </div>

      {/* Security badges - only rendered when backed by real per-file data */}
      <div className="flex flex-wrap gap-1.5 mb-4">
        <StatusBadge label={isE2E ? "Encrypted" : "Legacy Encryption"} tone={isE2E ? "success" : "neutral"} />
        {file.signature ? (
          <StatusBadge label="Signed" tone="success" />
        ) : (
          <StatusBadge label="Unsigned" tone="neutral" />
        )}
        {file.quarantined ? (
          <StatusBadge label="Quarantined" tone="danger" />
        ) : file.riskLevel ? (
          <StatusBadge label={file.riskLevel === "Low" ? "Threat Clean" : `Threat: ${file.riskLevel}`} tone={riskTone[file.riskLevel] ?? "neutral"} />
        ) : null}
        {file.dlpDecision && file.dlpDecision !== "allow" ? (
          <StatusBadge label={`DLP: ${file.dlpRisk || "flagged"}`} tone={decisionTone[file.dlpDecision] ?? "warning"} />
        ) : file.dlpDecision === "allow" ? (
          <StatusBadge label="DLP Safe" tone="success" />
        ) : null}
        {zeroTrustPolicyActive && <StatusBadge label="Zero Trust" tone="info" />}
      </div>

      {/* AI Security Assistant - Feature 4 (AI Risk Explanation). Only rendered once Threat
          Intelligence enrichment has actually produced a score for this file (threatScore > 0) -
          most files never reach that path, so this stays invisible rather than showing a
          misleading "0/100" for everything. */}
      {typeof file.threatScore === "number" && file.threatScore > 0 && (
        <div className="flex items-center justify-between gap-2 mb-4 rounded-lg border border-border bg-background/40 px-3 py-2">
          <span className="text-xs text-muted-foreground">
            Risk Score: <span className="font-semibold text-foreground">{file.threatScore}/100</span>
          </span>
          <RiskExplainButton sourceType="File" sourceId={file._id} />
        </div>
      )}

      {/* Info */}
      <div className="space-y-2 mb-4 text-sm">
        <div className="flex items-center gap-2 text-muted-foreground">
          <Clock size={16} />
          <span>
            Expires: <span className="text-foreground font-medium">{expiresDate.toLocaleDateString()}</span>
          </span>
        </div>

        {!expired && !used && (
          <div className="flex items-center gap-2 text-primary font-semibold">
            <Clock size={16} />
            <span>{getTimeRemaining()}</span>
          </div>
        )}

        {file.oneTime && (
          <div className="flex items-center gap-2 text-warning">
            <AlertCircle size={16} />
            <span>One-time download</span>
          </div>
        )}

        <div className="flex items-center gap-2 text-muted-foreground">
          <Share2 size={16} />
          <span>
            Downloads: <span className="text-foreground font-medium">{file.downloadCount}</span>
          </span>
        </div>
      </div>

      {/* Actions */}
      <div className="space-y-2">
        {!expired && !used && !revoked && (
          <>
            <button
              onClick={handleCopyLink}
              className="w-full flex items-center justify-center gap-2 px-4 py-2 bg-primary hover:bg-primary/90 text-white font-semibold rounded-lg text-sm transition-colors"
            >
              {copied ? <Check size={18} /> : <Copy size={18} />}
              {copied ? "Copied!" : "Copy Link"}
            </button>

            <button
              onClick={handleDirectDownload}
              disabled={loading}
              className="w-full flex items-center justify-center gap-2 px-4 py-2 bg-success hover:bg-success/90 text-white font-semibold rounded-lg disabled:opacity-50 text-sm transition-colors"
            >
              {loading ? "Downloading..." : "Direct Download"}
            </button>

            <button
              onClick={() => setShowLink(!showLink)}
              className="w-full flex items-center justify-center gap-2 px-4 py-2 bg-muted hover:bg-muted/70 text-foreground font-semibold rounded-lg text-sm transition-colors"
            >
              {showLink ? <EyeOff size={18} /> : <Eye size={18} />}
              {showLink ? "Hide Link" : "Show Link"}
            </button>

            {showLink && (
              <div className="bg-muted/50 rounded-lg p-3 border border-border">
                <div className="space-y-2">
                  <code className="text-xs text-muted-foreground break-all">{isE2E ? e2eLink : getTrackedLink()}</code>
                  {isE2E ? (
                    <p className="text-muted-foreground text-xs">
                      This is your account-access page. The original share link containing the decryption key was
                      only shown once, right after upload - if you lost it, you can still decrypt here while logged in.
                    </p>
                  ) : (
                    file.passwordHash && (
                      <p className="text-muted-foreground text-xs">
                        This file is password protected. Append{" "}
                        <span className="text-foreground">?password=YOUR_PASSWORD</span> to the link when sharing.
                      </p>
                    )
                  )}
                </div>
              </div>
            )}
          </>
        )}

        {(expired || used || revoked) && (
          <div className="p-3 bg-destructive/10 border border-destructive/30 rounded-lg text-center">
            <p className="text-destructive text-sm font-semibold">
              {revoked ? "This link was revoked" : expired ? "This link has expired" : "This link was used"}
            </p>
          </div>
        )}

        {canManage && (
          <button
            onClick={handleViewLogs}
            className="w-full flex items-center justify-center gap-2 px-4 py-2 bg-muted hover:bg-muted/70 text-foreground font-semibold rounded-lg text-sm transition-colors"
          >
            <List size={18} />
            View Logs
          </button>
        )}

        {canManage && onDelete && !(expired || used || revoked) && (
          <div className="pt-2 border-t border-border">
            {!showDeleteConfirm ? (
              <button
                onClick={() => setShowDeleteConfirm(true)}
                className="w-full flex items-center justify-center gap-2 px-4 py-2 bg-destructive/10 hover:bg-destructive/20 text-destructive font-semibold rounded-lg text-sm transition-colors"
              >
                <Trash2 size={18} />
                Revoke File
              </button>
            ) : (
              <div className="flex gap-2">
                <button onClick={handleDelete} disabled={loading} className="flex-1 px-3 py-2 bg-destructive text-white rounded-lg text-sm font-semibold">
                  Revoke
                </button>
                <button onClick={() => setShowDeleteConfirm(false)} className="flex-1 px-3 py-2 bg-muted text-foreground rounded-lg text-sm font-semibold">
                  Cancel
                </button>
              </div>
            )}
          </div>
        )}

        {canManage && onPermanentDelete && (
          <div className={!(expired || used || revoked) ? "" : "pt-2 border-t border-border"}>
            {!showPermanentDeleteConfirm ? (
              <button
                onClick={() => setShowPermanentDeleteConfirm(true)}
                className="w-full flex items-center justify-center gap-2 px-4 py-2 bg-destructive/5 hover:bg-destructive/15 text-destructive/90 font-semibold rounded-lg border border-destructive/30 text-sm transition-colors"
              >
                <Trash2 size={18} />
                Delete Permanently
              </button>
            ) : (
              <div className="space-y-2">
                <p className="text-destructive text-xs text-center font-semibold">This cannot be undone!</p>
                <div className="flex gap-2">
                  <button
                    onClick={handlePermanentDelete}
                    disabled={loading}
                    className="flex-1 px-3 py-2 bg-destructive text-white rounded-lg font-semibold disabled:opacity-50 text-sm"
                  >
                    {loading ? "Deleting..." : "Delete Forever"}
                  </button>
                  <button onClick={() => setShowPermanentDeleteConfirm(false)} disabled={loading} className="flex-1 px-3 py-2 bg-muted text-foreground rounded-lg text-sm font-semibold">
                    Cancel
                  </button>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </motion.div>
  );
}
