"use client";

import { useState } from "react";
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
  X
} from "lucide-react";
import toast from "react-hot-toast";
import api from "@/lib/api";

export default function FileCard({
  file,
  onDelete
}: {
  file: {
    expiresAt: string | number | Date;
    oneTime: boolean;
    downloadCount: number;
    _id: string;
    filename: string;
    passwordHash?: string;
    revoked?: boolean;
  };
  onDelete?: (fileId: string) => void;
}) {
  const router = useRouter();
  const [copied, setCopied] = useState(false);
  const [showLink, setShowLink] = useState(false);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [loading, setLoading] = useState(false);
  const [showPwdModal, setShowPwdModal] = useState(false);
  const [pwdInput, setPwdInput] = useState("");

  const expiresDate = new Date(file.expiresAt);
  const now = new Date();
  const expired = expiresDate < now;
  const used = file.oneTime && file.downloadCount > 0;
  const revoked = !!file.revoked;

  const timeUntilExpiry = expiresDate.getTime() - now.getTime();
  const daysLeft = Math.floor(timeUntilExpiry / (1000 * 60 * 60 * 24));
  const hoursLeft = Math.floor(
    (timeUntilExpiry % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60)
  );

  const baseLink = `${
    process.env.NEXT_PUBLIC_API || "http://localhost:5000/api"
  }/files/download/${file._id}`;

  const getExpiryStatus = () => {
    if (revoked)
      return {
        label: "Revoked",
        color: "bg-red-600",
        textColor: "text-red-400",
        icon: AlertCircle
      };
    if (expired)
      return {
        label: "Expired",
        color: "bg-red-500",
        textColor: "text-red-400",
        icon: AlertCircle
      };
    if (used)
      return {
        label: "Used (One-time)",
        color: "bg-orange-500",
        textColor: "text-orange-400",
        icon: AlertCircle
      };
    if (daysLeft === 0 && hoursLeft < 24)
      return {
        label: "Expiring Soon",
        color: "bg-yellow-500",
        textColor: "text-yellow-400",
        icon: Clock
      };
    return {
      label: "Active",
      color: "bg-green-500",
      textColor: "text-green-400",
      icon: Check
    };
  };

  const status = getExpiryStatus();
  const StatusIcon = status.icon;

  const handleCopyLink = async () => {
    try {
      if (file.passwordHash) {
        setShowPwdModal(true);
        return;
      }
      await navigator.clipboard.writeText(baseLink);
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
      const finalLink = pwd ? `${baseLink}?${new URLSearchParams({ password: pwd }).toString()}` : baseLink;
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

  const handleViewLogs = () => {
    router.push(`/file/${file._id}/logs`);
  };

  const getTimeRemaining = () => {
    if (expired) return "Expired";
    if (used) return "Used";
    if (daysLeft > 0) return `${daysLeft}d ${hoursLeft}h left`;
    return `${hoursLeft}h left`;
  };

  return (
    <div className="group bg-slate-800 border border-slate-700 rounded-xl p-6 hover:border-blue-500 transition-all hover:shadow-lg hover:shadow-blue-500/20">
      {showPwdModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
          <div className="bg-slate-800 border border-slate-700 rounded-xl w-full max-w-sm p-6 shadow-xl">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-white font-bold">Include Password</h2>
              <button
                onClick={() => { setShowPwdModal(false); setPwdInput(""); }}
                className="text-slate-400 hover:text-slate-200"
              >
                <X size={18} />
              </button>
            </div>
            <p className="text-slate-400 text-sm mb-3">Add the file password to the copied link so recipients can download directly.</p>
            <div className="relative mb-4">
              <Lock size={16} className="absolute left-3 top-3.5 text-slate-400" />
              <input
                type="text"
                value={pwdInput}
                onChange={(e) => setPwdInput(e.target.value)}
                placeholder="Enter password (optional)"
                className="w-full pl-10 pr-4 py-3 bg-slate-700 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500 focus:ring-opacity-50 transition-all"
              />
            </div>
            <div className="flex gap-2">
              <button
                onClick={confirmCopyWithPassword}
                className="flex-1 px-4 py-2 bg-blue-500 hover:bg-blue-600 text-white rounded-lg"
              >
                Copy Link
              </button>
              <button
                onClick={() => { setShowPwdModal(false); setPwdInput(""); }}
                className="flex-1 px-4 py-2 bg-slate-700 text-white rounded-lg"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
      {/* Header */}
      <div className="flex items-start justify-between mb-4">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-2">
            <Lock size={18} className="text-blue-400 flex-shrink-0" />
            <h3 className="font-bold text-lg text-white truncate">
              {file.filename}
            </h3>
          </div>
        </div>

        {/* Status */}
        <div
          className={`flex items-center gap-1 px-3 py-1 rounded-full ${status.color} bg-opacity-20 border ${status.color} border-opacity-30`}
        >
          <StatusIcon size={14} className={status.textColor} />
          <span className={`text-xs font-semibold ${status.textColor}`}>
            {status.label}
          </span>
        </div>
      </div>

      {/* Info */}
      <div className="space-y-2 mb-4 text-sm">
        <div className="flex items-center gap-2 text-slate-400">
          <Clock size={16} />
          <span>
            Expires:{" "}
            <span className="text-slate-300 font-medium">
              {expiresDate.toLocaleDateString()}
            </span>
          </span>
        </div>

        {!expired && !used && (
          <div className="flex items-center gap-2 text-blue-400 font-semibold">
            <Clock size={16} />
            <span>{getTimeRemaining()}</span>
          </div>
        )}

        {file.oneTime && (
          <div className="flex items-center gap-2 text-yellow-400">
            <AlertCircle size={16} />
            <span>One-time download</span>
          </div>
        )}

        <div className="flex items-center gap-2 text-slate-400">
          <Share2 size={16} />
          <span>
            Downloads:{" "}
            <span className="text-slate-300 font-medium">
              {file.downloadCount}
            </span>
          </span>
        </div>
      </div>

      {/* Actions */}
      <div className="space-y-2">
        {!expired && !used && !revoked && (
          <>
            <button
              onClick={handleCopyLink}
              className="w-full flex items-center justify-center gap-2 px-4 py-2 bg-blue-500 hover:bg-blue-600 text-white font-semibold rounded-lg"
            >
              {copied ? <Check size={18} /> : <Copy size={18} />}
              {copied ? "Copied!" : "Copy Link"}
            </button>

            <button
              onClick={() => setShowLink(!showLink)}
              className="w-full flex items-center justify-center gap-2 px-4 py-2 bg-slate-700 hover:bg-slate-600 text-slate-200 font-semibold rounded-lg"
            >
              {showLink ? <EyeOff size={18} /> : <Eye size={18} />}
              {showLink ? "Hide Link" : "Show Link"}
            </button>

            {showLink && (
              <div className="bg-slate-700 rounded-lg p-3 border border-slate-600">
                <div className="space-y-2">
                  <code className="text-xs text-slate-300 break-all">
                    {baseLink}
                  </code>
                  {file.passwordHash && (
                    <p className="text-slate-400 text-xs">
                      This file is password protected. Append <span className="text-slate-200">?password=YOUR_PASSWORD</span> to the link when sharing.
                    </p>
                  )}
                </div>
              </div>
            )}
          </>
        )}

        {(expired || used || revoked) && (
          <div className="p-3 bg-red-500 bg-opacity-20 border border-red-500 border-opacity-30 rounded-lg text-center">
            <p className="text-red-300 text-sm font-semibold">
              {revoked ? "This link was revoked" : expired ? "This link has expired" : "This link was used"}
            </p>
          </div>
        )}

        {/* Logs */}
        <button
          onClick={handleViewLogs}
          className="w-full flex items-center justify-center gap-2 px-4 py-2 bg-slate-700 hover:bg-slate-600 text-slate-200 font-semibold rounded-lg"
        >
          <List size={18} />
          View Logs
        </button>

        {/* Delete */}
        {onDelete && !(expired || used || revoked) && (
          <div className="pt-2 border-t border-slate-700">
            {!showDeleteConfirm ? (
              <button
                onClick={() => setShowDeleteConfirm(true)}
                className="w-full flex items-center justify-center gap-2 px-4 py-2 bg-red-500 bg-opacity-20 hover:bg-opacity-30 text-red-400 font-semibold rounded-lg"
              >
                <Trash2 size={18} />
                Revoke File
              </button>
            ) : (
              <div className="flex gap-2">
                <button
                  onClick={handleDelete}
                  disabled={loading}
                  className="flex-1 px-3 py-2 bg-red-600 text-white rounded-lg"
                >
                  Delete
                </button>
                <button
                  onClick={() => setShowDeleteConfirm(false)}
                  className="flex-1 px-3 py-2 bg-slate-700 text-white rounded-lg"
                >
                  Cancel
                </button>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
