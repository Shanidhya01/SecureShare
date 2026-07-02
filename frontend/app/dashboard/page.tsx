"use client";
import { useEffect, useState } from "react";
import api from "@/lib/api";
import FileCard from "@/components/FileCard";
import { useRouter } from "next/navigation";
import {
  Loader,
  AlertCircle,
  Upload,
  FileText,
  Clock,
  Download
} from "lucide-react";
import toast from "react-hot-toast";

export default function Dashboard() {
  type FileMeta = {
    _id: string;
    filename: string;
    expiresAt: string;
    oneTime: boolean;
    downloadCount: number;
    revoked?: boolean;
    owner?: { email?: string; name?: string };
    passwordHash?: string;
    wrappedPasswordKey?: string;
    encryptionVersion?: number;
    mimeType?: string;
  };

  const [files, setFiles] = useState<FileMeta[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [sortBy, setSortBy] =
    useState<"date" | "name" | "downloads">("date");
  const [filterOneTime, setFilterOneTime] = useState(false);
  const router = useRouter();

  const userRaw =
    typeof window !== "undefined" ? localStorage.getItem("user") : null;
  const user = userRaw ? JSON.parse(userRaw) : null;

  const token =
    typeof window !== "undefined" ? localStorage.getItem("token") : null;

  useEffect(() => {
    if (!token) {
      router.push("/login");
      return;
    }

    const fetchFiles = async () => {
      try {
        setLoading(true);
        const res = await api.get<FileMeta[]>("/files/my-files", {
          headers: { Authorization: `Bearer ${token}` }
        });
        setFiles(res.data || []);
      } catch (err: any) {
        const status = err.response?.status;
        if (status === 401 || status === 403) {
          localStorage.removeItem("token");
          localStorage.removeItem("user");
          router.push("/login");
          return;
        }

        setError("Failed to load files");
      } finally {
        setLoading(false);
      }
    };

    fetchFiles();
  }, [router, token]);

  /* ---------- DELETE / REVOKE ---------- */
  const handleDelete = async (fileId: string) => {
    try {
      await api.delete(`/files/file/${fileId}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setFiles((prev) => prev.map((f) => f._id === fileId ? { ...f, revoked: true } : f));
      toast.success("File revoked successfully");
    } catch {
      toast.error("Failed to revoke file");
    }
  };

  const handlePermanentDelete = (fileId: string) => {
    // Backend permanent delete is already done in FileCard; just remove locally
    setFiles((prev) => prev.filter((f) => f._id !== fileId));
  };

  /* ---------- SORT / FILTER ---------- */
  const getSortedAndFilteredFiles = () => {
    let filtered = [...files];
    if (filterOneTime) filtered = filtered.filter((f) => f.oneTime);

    return filtered.sort((a, b) => {
      switch (sortBy) {
        case "name":
          return a.filename.localeCompare(b.filename);
        case "downloads":
          return b.downloadCount - a.downloadCount;
        default:
          return (
            new Date(b.expiresAt).getTime() -
            new Date(a.expiresAt).getTime()
          );
      }
    });
  };

  const sortedFiles = getSortedAndFilteredFiles();
  const totalDownloads = files.reduce((sum, f) => sum + f.downloadCount, 0);
  const expiringFiles = files.filter(
    (f) => new Date(f.expiresAt).getTime() - Date.now() < 24 * 60 * 60 * 1000
  ).length;

  return (
    <div className="min-h-screen bg-linear-to-br from-slate-900 via-slate-800 to-slate-900 text-white">
      <div className="max-w-6xl mx-auto px-4 py-12">

        {/* HEADER */}
        <div className="mb-12 flex flex-col md:flex-row md:items-end md:justify-between gap-6">
          <div>
            <h1 className="text-4xl font-black text-transparent bg-clip-text bg-linear-to-r from-blue-400 to-cyan-400">
              My Files
            </h1>
            <p className="text-slate-400">
              Manage and share your encrypted files
            </p>
          </div>
          <a
            href="/upload"
            className="inline-flex items-center gap-2 px-6 py-3 bg-linear-to-r from-blue-500 to-cyan-500 rounded-lg font-bold hover:opacity-90"
          >
            <Upload size={20} />
            Upload File
          </a>
        </div>

        {/* STATS */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
          <Stat label="Total Files" value={files.length} icon={FileText} />
          <Stat label="Total Downloads" value={totalDownloads} icon={Download} />
          <Stat label="Expiring Soon" value={expiringFiles} icon={Clock} />
        </div>

        {/* CONTROLS */}
        {files.length > 0 && (
          <div className="mb-8 flex flex-col md:flex-row gap-4">
            <select
              aria-label="Sort files"
              value={sortBy}
              onChange={(e) =>
                setSortBy(e.target.value as "date" | "name" | "downloads")
              }
              className="px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg"
            >
              <option value="date">Newest</option>
              <option value="name">Name</option>
              <option value="downloads">Most Downloaded</option>
            </select>

            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={filterOneTime}
                onChange={(e) => setFilterOneTime(e.target.checked)}
              />
              One-time only
            </label>
          </div>
        )}

        {/* ERROR */}
        {error && (
          <div className="mb-6 p-4 bg-red-500/20 border border-red-500/40 rounded-lg flex gap-2">
            <AlertCircle className="text-red-400" />
            <p>{error}</p>
          </div>
        )}

        {/* CONTENT */}
        {loading ? (
          <div className="flex flex-col items-center py-20">
            <Loader className="animate-spin text-blue-400" size={48} />
            <p className="mt-4 text-slate-400">Loading files…</p>
          </div>
        ) : sortedFiles.length === 0 ? (
          <EmptyState />
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {sortedFiles.map((file) => {
              const ownerEmail = file.owner?.email;
              const currentEmail = user?.email as string | undefined;
              const isOwner = !!(ownerEmail && currentEmail && ownerEmail === currentEmail);

              return (
                <FileCard
                  key={file._id}
                  file={file}
                  canManage={isOwner}
                  onDelete={isOwner ? handleDelete : undefined}
                  onPermanentDelete={isOwner ? handlePermanentDelete : undefined}
                />
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}

/* ---------- SMALL UI HELPERS ---------- */

function Stat({
  label,
  value,
  icon: Icon
}: {
  label: string;
  value: number;
  icon: any;
}) {
  return (
    <div className="bg-slate-800 border border-slate-700 rounded-lg p-6">
      <div className="flex justify-between mb-2">
        <p className="text-slate-400 text-sm">{label}</p>
        <Icon size={20} className="text-blue-400" />
      </div>
      <p className="text-3xl font-bold">{value}</p>
    </div>
  );
}

function EmptyState() {
  return (
    <div className="text-center py-20 text-slate-400">
      <p className="text-xl font-semibold">No files uploaded yet</p>
      <a
        href="/upload"
        className="inline-block mt-4 px-6 py-3 bg-blue-500 rounded-lg text-white font-bold"
      >
        Upload your first file
      </a>
    </div>
  );
}
