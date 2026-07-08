"use client";
import { useEffect, useState, useMemo } from "react";
import api from "@/lib/api";
import { apiErrorStatus } from "@/lib/errors";
import { downloadFileWithIpTracking } from "@/lib/ipTracking";
import FileCard from "@/components/FileCard";
import { useRouter } from "next/navigation";
import { Files as FilesIcon, AlertCircle, Upload, Search, Download, Trash2, X } from "lucide-react";
import { motion } from "framer-motion";
import toast from "react-hot-toast";
import PageHeader from "@/components/design/PageHeader";
import EmptyState from "@/components/design/EmptyState";
import Pagination from "@/components/design/Pagination";
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
  threatScore?: number;
  policy?: FilePolicy;
};

type StatusFilter = "all" | "active" | "expired" | "revoked" | "oneTime";

const PAGE_SIZE = 9;

export default function FilesPage() {
  const [files, setFiles] = useState<FileMeta[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [sortBy, setSortBy] = useState<"date" | "name" | "downloads">("date");
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(1);
  const [selectMode, setSelectMode] = useState(false);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [bulkBusy, setBulkBusy] = useState(false);
  const router = useRouter();

  const userRaw = typeof window !== "undefined" ? localStorage.getItem("user") : null;
  const user = userRaw ? JSON.parse(userRaw) : null;
  const token = typeof window !== "undefined" ? localStorage.getItem("token") : null;

  const isOwner = (file: FileMeta) => {
    const ownerEmail = file.owner?.email;
    const currentEmail = user?.email as string | undefined;
    return !!(ownerEmail && currentEmail && ownerEmail === currentEmail);
  };

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

  const getFileStatus = (file: FileMeta): "active" | "expired" | "revoked" => {
    if (file.revoked) return "revoked";
    if (new Date(file.expiresAt).getTime() < Date.now()) return "expired";
    return "active";
  };

  const filteredFiles = useMemo(() => {
    let result = [...files];
    if (statusFilter === "oneTime") result = result.filter((f) => f.oneTime);
    else if (statusFilter !== "all") result = result.filter((f) => getFileStatus(f) === statusFilter);
    if (search.trim()) {
      const q = search.trim().toLowerCase();
      result = result.filter((f) => f.filename.toLowerCase().includes(q));
    }
    return result.sort((a, b) => {
      switch (sortBy) {
        case "name":
          return a.filename.localeCompare(b.filename);
        case "downloads":
          return b.downloadCount - a.downloadCount;
        default:
          return new Date(b.expiresAt).getTime() - new Date(a.expiresAt).getTime();
      }
    });
  }, [files, statusFilter, search, sortBy]);

  const totalPages = Math.max(1, Math.ceil(filteredFiles.length / PAGE_SIZE));
  const pageFiles = filteredFiles.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);
  const ownedPageFiles = pageFiles.filter(isOwner);

  const toggleSelect = (fileId: string) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(fileId)) next.delete(fileId);
      else next.add(fileId);
      return next;
    });
  };

  const toggleSelectAllOnPage = () => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      const allSelected = ownedPageFiles.every((f) => next.has(f._id));
      for (const f of ownedPageFiles) {
        if (allSelected) next.delete(f._id);
        else next.add(f._id);
      }
      return next;
    });
  };

  const exitSelectMode = () => {
    setSelectMode(false);
    setSelectedIds(new Set());
  };

  const handleBulkDelete = async () => {
    const ids = Array.from(selectedIds).filter((id) => files.some((f) => f._id === id && isOwner(f) && !f.revoked));
    if (ids.length === 0) return;
    setBulkBusy(true);
    const results = await Promise.allSettled(ids.map((id) => api.delete(`/files/file/${id}`, { headers: { Authorization: `Bearer ${token}` } })));
    const succeeded = results.filter((r) => r.status === "fulfilled").length;
    setFiles((prev) => prev.map((f) => (ids.includes(f._id) && results[ids.indexOf(f._id)]?.status === "fulfilled" ? { ...f, revoked: true } : f)));
    if (succeeded > 0) toast.success(`Revoked ${succeeded} file(s)`);
    if (succeeded < ids.length) toast.error(`Failed to revoke ${ids.length - succeeded} file(s)`);
    setBulkBusy(false);
    exitSelectMode();
  };

  const handleBulkDownload = async () => {
    const selected = files.filter((f) => selectedIds.has(f._id));
    if (selected.length === 0) return;
    setBulkBusy(true);
    const legacyFiles = selected.filter((f) => f.encryptionVersion !== 2);
    const e2eFiles = selected.filter((f) => f.encryptionVersion === 2);

    let downloaded = 0;
    for (const f of legacyFiles) {
      try {
        await downloadFileWithIpTracking(f._id, user?.email);
        downloaded++;
      } catch {
        toast.error(`Failed to download ${f.filename}`);
      }
    }
    if (downloaded > 0) toast.success(`Downloaded ${downloaded} file(s)`);

    if (e2eFiles.length > 0) {
      e2eFiles.forEach((f) => window.open(`/file/${f._id}`, "_blank", "noopener,noreferrer"));
      toast(`${e2eFiles.length} end-to-end encrypted file(s) opened in new tabs - decrypt each individually.`, { icon: "🔐" });
    }
    setBulkBusy(false);
  };

  return (
    <div>
      <PageHeader
        icon={FilesIcon}
        title="Files"
        description="Manage, share, and monitor every encrypted file you've uploaded."
        actions={
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => (selectMode ? exitSelectMode() : setSelectMode(true))}
              className="inline-flex items-center gap-2 px-4 py-2.5 bg-card hover:bg-white/5 text-foreground font-semibold rounded-lg text-sm ring-1 ring-border transition-colors"
            >
              {selectMode ? <X size={16} /> : null}
              {selectMode ? "Cancel Selection" : "Select"}
            </button>
            <a
              href="/upload"
              className="inline-flex items-center gap-2 px-4 py-2.5 bg-primary hover:bg-primary/90 text-white font-semibold rounded-lg text-sm transition-colors shadow-lg shadow-primary/20"
            >
              <Upload size={16} />
              Upload File
            </a>
          </div>
        }
      />

      {files.length > 0 && (
        <div className="mb-6 flex flex-col lg:flex-row gap-3">
          <div className="relative flex-1">
            <Search size={16} className="absolute left-3 top-3 text-muted-foreground" />
            <input
              value={search}
              onChange={(e) => {
                setSearch(e.target.value);
                setPage(1);
              }}
              placeholder="Search by filename..."
              className="w-full pl-9 pr-4 py-2.5 bg-card border border-border rounded-lg text-sm text-foreground placeholder-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/60"
            />
          </div>
          <select
            aria-label="Filter by status"
            value={statusFilter}
            onChange={(e) => {
              setStatusFilter(e.target.value as StatusFilter);
              setPage(1);
            }}
            className="px-4 py-2.5 bg-card border border-border rounded-lg text-sm text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/60"
          >
            <option value="all">All statuses</option>
            <option value="active">Active</option>
            <option value="expired">Expired</option>
            <option value="revoked">Revoked</option>
            <option value="oneTime">One-time only</option>
          </select>
          <select
            aria-label="Sort files"
            value={sortBy}
            onChange={(e) => setSortBy(e.target.value as "date" | "name" | "downloads")}
            className="px-4 py-2.5 bg-card border border-border rounded-lg text-sm text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/60"
          >
            <option value="date">Newest</option>
            <option value="name">Name</option>
            <option value="downloads">Most Downloaded</option>
          </select>
        </div>
      )}

      {selectMode && (
        <div className="mb-6 flex flex-wrap items-center gap-3 rounded-xl border border-primary/30 bg-primary/5 px-4 py-3">
          <label className="flex items-center gap-2 text-sm text-foreground">
            <input
              type="checkbox"
              checked={ownedPageFiles.length > 0 && ownedPageFiles.every((f) => selectedIds.has(f._id))}
              onChange={toggleSelectAllOnPage}
              disabled={ownedPageFiles.length === 0}
            />
            Select all on page
          </label>
          <span className="text-sm text-muted-foreground">{selectedIds.size} selected</span>
          <div className="ml-auto flex gap-2">
            <button
              type="button"
              onClick={handleBulkDownload}
              disabled={selectedIds.size === 0 || bulkBusy}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-foreground bg-card ring-1 ring-border rounded-lg hover:bg-white/5 disabled:opacity-50"
            >
              <Download size={14} />
              Download
            </button>
            <button
              type="button"
              onClick={handleBulkDelete}
              disabled={selectedIds.size === 0 || bulkBusy}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-destructive bg-destructive/10 rounded-lg hover:bg-destructive/20 disabled:opacity-50"
            >
              <Trash2 size={14} />
              Revoke
            </button>
          </div>
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
      ) : filteredFiles.length === 0 ? (
        <EmptyState
          icon={FilesIcon}
          title={files.length === 0 ? "No files uploaded yet" : "No files match your filters"}
          description={
            files.length === 0
              ? "Once you upload a file, it'll show up here with its encryption, signature, and security status."
              : "Try a different search term or clear your filters."
          }
          actionLabel={files.length === 0 ? "Upload your first file" : undefined}
          actionHref={files.length === 0 ? "/upload" : undefined}
        />
      ) : (
        <>
          <motion.div
            variants={staggerContainer}
            initial="hidden"
            animate="show"
            className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6"
          >
            {pageFiles.map((file) => {
              const owner = isOwner(file);
              return (
                <FileCard
                  key={file._id}
                  file={file}
                  canManage={owner}
                  onDelete={owner ? handleDelete : undefined}
                  onPermanentDelete={owner ? handlePermanentDelete : undefined}
                  selectable={selectMode && owner}
                  selected={selectedIds.has(file._id)}
                  onToggleSelect={toggleSelect}
                />
              );
            })}
          </motion.div>
          <Pagination page={page} totalPages={totalPages} totalItems={filteredFiles.length} pageSize={PAGE_SIZE} onPageChange={setPage} />
        </>
      )}
    </div>
  );
}
