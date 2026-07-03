"use client";
import { useEffect, useState } from "react";
import api from "@/lib/api";
import { apiErrorStatus } from "@/lib/errors";
import FileCard from "@/components/FileCard";
import { useRouter } from "next/navigation";
import { Files as FilesIcon, AlertCircle, Upload } from "lucide-react";
import { motion } from "framer-motion";
import toast from "react-hot-toast";
import PageHeader from "@/components/design/PageHeader";
import EmptyState from "@/components/design/EmptyState";
import { CardsSkeleton } from "@/components/design/Skeletons";
import { staggerContainer } from "@/lib/motion";
import type { FilePolicy } from "@/lib/types";

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
  createdAt?: string;
  signature?: string | null;
  riskLevel?: "Low" | "Medium" | "High" | "Critical" | null;
  quarantined?: boolean;
  dlpRisk?: "None" | "Low" | "Medium" | "High" | "Critical" | null;
  dlpDecision?: "allow" | "warn" | "require_approval" | "block" | null;
  policy?: FilePolicy;
};

export default function FilesPage() {
  const [files, setFiles] = useState<FileMeta[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [sortBy, setSortBy] = useState<"date" | "name" | "downloads">("date");
  const [filterOneTime, setFilterOneTime] = useState(false);
  const router = useRouter();

  const userRaw = typeof window !== "undefined" ? localStorage.getItem("user") : null;
  const user = userRaw ? JSON.parse(userRaw) : null;
  const token = typeof window !== "undefined" ? localStorage.getItem("token") : null;

  useEffect(() => {
    if (!token) {
      router.push("/login");
      return;
    }

    const fetchFiles = async () => {
      try {
        setLoading(true);
        const res = await api.get<FileMeta[]>("/files/my-files", { headers: { Authorization: `Bearer ${token}` } });
        setFiles(res.data || []);
      } catch (err: unknown) {
        const status = apiErrorStatus(err);
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

  const handleDelete = async (fileId: string) => {
    try {
      await api.delete(`/files/file/${fileId}`, { headers: { Authorization: `Bearer ${token}` } });
      setFiles((prev) => prev.map((f) => (f._id === fileId ? { ...f, revoked: true } : f)));
      toast.success("File revoked successfully");
    } catch {
      toast.error("Failed to revoke file");
    }
  };

  const handlePermanentDelete = (fileId: string) => {
    setFiles((prev) => prev.filter((f) => f._id !== fileId));
  };

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
          return new Date(b.expiresAt).getTime() - new Date(a.expiresAt).getTime();
      }
    });
  };

  const sortedFiles = getSortedAndFilteredFiles();

  return (
    <div>
      <PageHeader
        icon={FilesIcon}
        title="Files"
        description="Manage, share, and monitor every encrypted file you've uploaded."
        actions={
          <a
            href="/upload"
            className="inline-flex items-center gap-2 px-4 py-2.5 bg-primary hover:bg-primary/90 text-white font-semibold rounded-lg text-sm transition-colors shadow-lg shadow-primary/20"
          >
            <Upload size={16} />
            Upload File
          </a>
        }
      />

      {files.length > 0 && (
        <div className="mb-6 flex flex-col md:flex-row gap-4">
          <select
            aria-label="Sort files"
            value={sortBy}
            onChange={(e) => setSortBy(e.target.value as "date" | "name" | "downloads")}
            className="px-4 py-2 bg-card border border-border rounded-lg text-sm text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/60"
          >
            <option value="date">Newest</option>
            <option value="name">Name</option>
            <option value="downloads">Most Downloaded</option>
          </select>

          <label className="flex items-center gap-2 text-sm text-muted-foreground">
            <input type="checkbox" checked={filterOneTime} onChange={(e) => setFilterOneTime(e.target.checked)} />
            One-time only
          </label>
        </div>
      )}

      {error && (
        <div className="mb-6 p-4 bg-destructive/10 border border-destructive/30 rounded-lg flex gap-2">
          <AlertCircle className="text-destructive" size={18} />
          <p className="text-destructive text-sm">{error}</p>
        </div>
      )}

      {loading ? (
        <CardsSkeleton count={6} />
      ) : sortedFiles.length === 0 ? (
        <EmptyState
          icon={FilesIcon}
          title="No files uploaded yet"
          description="Once you upload a file, it'll show up here with its encryption, signature, and security status."
          actionLabel="Upload your first file"
          actionHref="/upload"
        />
      ) : (
        <motion.div
          variants={staggerContainer}
          initial="hidden"
          animate="show"
          className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6"
        >
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
        </motion.div>
      )}
    </div>
  );
}
