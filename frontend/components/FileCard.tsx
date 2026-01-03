import { useState } from "react";
import { Copy, Check, Lock, Clock, AlertCircle, Share2, Trash2, Eye, EyeOff } from "lucide-react";

import toast from "react-hot-toast";

export default function FileCard({
  file,
  onDelete,
}: {
  file: {
    expiresAt: string | number | Date;
    oneTime: boolean;
    downloadCount: number;
    _id: string;
    filename: string;
  };
  onDelete?: (fileId: string) => void;
}) {
  const [copied, setCopied] = useState(false);
  const [showLink, setShowLink] = useState(false);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);

  const expiresDate = new Date(file.expiresAt);
  const now = new Date();
  const expired = expiresDate < now;
  const used = file.oneTime && file.downloadCount > 0;

  const timeUntilExpiry = expiresDate.getTime() - now.getTime();
  const daysLeft = Math.floor(timeUntilExpiry / (1000 * 60 * 60 * 24));
  const hoursLeft = Math.floor((timeUntilExpiry % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));

  const link = `${process.env.NEXT_PUBLIC_API_URL || "http://localhost:5000"}/api/files/download/${file._id}`;

  const getExpiryStatus = () => {
    if (expired) return { label: "Expired", color: "bg-red-500", textColor: "text-red-400", icon: AlertCircle };
    if (used) return { label: "Used (One-time)", color: "bg-orange-500", textColor: "text-orange-400", icon: AlertCircle };
    if (daysLeft === 0 && hoursLeft < 24) return { label: "Expiring Soon", color: "bg-yellow-500", textColor: "text-yellow-400", icon: Clock };
    return { label: "Active", color: "bg-green-500", textColor: "text-green-400", icon: Check };
  };

  const status = getExpiryStatus();
  const StatusIcon = status.icon;

  const handleCopyLink = () => {
    navigator.clipboard.writeText(link).then(() => {
      toast.success("Download link copied");
    });
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDelete = async () => {
    if (onDelete) {
      onDelete(file._id);
      setShowDeleteConfirm(false);
    }
  };

  const getTimeRemaining = () => {
    if (expired) return "Expired";
    if (used) return "Used";
    if (daysLeft > 0) return `${daysLeft}d ${hoursLeft}h left`;
    return `${hoursLeft}h left`;
  };

  return (
    <div className="group bg-slate-800 border border-slate-700 rounded-xl p-6 hover:border-blue-500 transition-all hover:shadow-lg hover:shadow-blue-500/20">
      {/* Header */}
      <div className="flex items-start justify-between mb-4">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-2">
            <Lock size={18} className="text-blue-400 flex-shrink-0" />
            <h3 className="font-bold text-lg text-white truncate">{file.filename}</h3>
          </div>
        </div>

        {/* Status Badge */}
        <div className={`flex items-center gap-1 px-3 py-1 rounded-full flex-shrink-0 ml-2 ${status.color} bg-opacity-20 border ${status.color} border-opacity-30`}>
          <StatusIcon size={14} className={status.textColor} />
          <span className={`text-xs font-semibold ${status.textColor}`}>{status.label}</span>
        </div>
      </div>

      {/* Details */}
      <div className="space-y-2 mb-4">
        {/* Expiry Info */}
        <div className="flex items-center gap-2 text-slate-400 text-sm">
          <Clock size={16} className="flex-shrink-0" />
          <span>
            Expires: <span className="text-slate-300 font-medium">{expiresDate.toLocaleDateString()}</span>
          </span>
        </div>

        {/* Time Remaining */}
        {!expired && !used && (
          <div className="flex items-center gap-2 text-blue-400 text-sm font-semibold">
            <Clock size={16} className="flex-shrink-0" />
            <span>{getTimeRemaining()}</span>
          </div>
        )}

        {/* One-time Info */}
        {file.oneTime && (
          <div className="flex items-center gap-2 text-yellow-400 text-sm">
            <AlertCircle size={16} className="flex-shrink-0" />
            <span>One-time download link</span>
          </div>
        )}

        {/* Download Count */}
        <div className="flex items-center gap-2 text-slate-400 text-sm">
          <Share2 size={16} className="flex-shrink-0" />
          <span>
            Downloads: <span className="text-slate-300 font-medium">{file.downloadCount}</span>
          </span>
        </div>
      </div>

      {/* Action Buttons */}
      <div className="space-y-2">
        {!expired && !used && (
          <>
            {/* Copy Link Button */}
            <button
              onClick={handleCopyLink}
              className="w-full flex items-center justify-center gap-2 px-4 py-2 bg-blue-500 hover:bg-blue-600 text-white font-semibold rounded-lg transition-colors"
            >
              {copied ? (
                <>
                  <Check size={18} />
                  Copied!
                </>
              ) : (
                <>
                  <Copy size={18} />
                  Copy Link
                </>
              )}
            </button>

            {/* Show/Hide Link */}
            <button
              onClick={() => setShowLink(!showLink)}
              className="w-full flex items-center justify-center gap-2 px-4 py-2 bg-slate-700 hover:bg-slate-600 text-slate-200 font-semibold rounded-lg transition-colors"
            >
              {showLink ? (
                <>
                  <EyeOff size={18} />
                  Hide Link
                </>
              ) : (
                <>
                  <Eye size={18} />
                  Show Link
                </>
              )}
            </button>

            {/* Link Display */}
            {showLink && (
              <div className="bg-slate-700 rounded-lg p-3 mt-2 border border-slate-600">
                <p className="text-xs text-slate-400 font-semibold mb-1">Download Link:</p>
                <code className="text-xs text-slate-300 break-all font-mono">{link}</code>
              </div>
            )}
          </>
        )}

        {/* Expired/Used Message */}
        {(expired || used) && (
          <div className="w-full p-3 bg-red-500 bg-opacity-20 border border-red-500 border-opacity-30 rounded-lg text-center">
            <p className="text-red-300 text-sm font-semibold">
              {expired ? "This link has expired" : "This one-time link has been used"}
            </p>
          </div>
        )}

        {/* Delete Button */}
        {onDelete && (
          <div className="pt-2 border-t border-slate-700">
            {!showDeleteConfirm ? (
              <button
                onClick={() => setShowDeleteConfirm(true)}
                className="w-full flex items-center justify-center gap-2 px-4 py-2 bg-red-500 bg-opacity-20 hover:bg-opacity-30 text-red-400 font-semibold rounded-lg transition-colors"
              >
                <Trash2 size={18} />
                Delete File
              </button>
            ) : (
              <div className="space-y-2">
                <p className="text-red-300 text-sm text-center font-semibold">Are you sure?</p>
                <div className="flex gap-2">
                  <button
                    onClick={handleDelete}
                    className="flex-1 px-3 py-2 bg-red-500 hover:bg-red-600 text-white font-semibold rounded-lg transition-colors text-sm"
                  >
                    Delete
                  </button>
                  <button
                    onClick={() => setShowDeleteConfirm(false)}
                    className="flex-1 px-3 py-2 bg-slate-700 hover:bg-slate-600 text-white font-semibold rounded-lg transition-colors text-sm"
                  >
                    Cancel
                  </button>
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Hover Info */}
      <div className="mt-3 pt-3 border-t border-slate-700 opacity-0 group-hover:opacity-100 transition-opacity">
        <p className="text-xs text-slate-500">
          File ID: <span className="text-slate-400 font-mono">{file._id.slice(0, 8)}...</span>
        </p>
      </div>
    </div>
  );
}