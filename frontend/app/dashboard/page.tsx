"use client";
import { useEffect, useState } from "react";
import api from "@/lib/api";
import FileCard from "@/components/FileCard";
import { useRouter } from "next/navigation";
import { Loader, AlertCircle, Upload, FileText, Clock, Download } from "lucide-react";

export default function Dashboard() {
  type FileMeta = {
    _id: string;
    filename: string;
    expiresAt: string;
    oneTime: boolean;
    downloadCount: number;
  };

  const [files, setFiles] = useState<FileMeta[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [sortBy, setSortBy] = useState<"date" | "name" | "downloads">("date");
  const [filterOneTime, setFilterOneTime] = useState(false);
  const router = useRouter();

  useEffect(() => {
    const fetchFiles = async () => {
      const token = localStorage.getItem("token");
      if (!token) {
        router.push("/login");
        return;
      }

      try {
        setLoading(true);
        setError("");
        const res = await api.get<FileMeta[]>("/files/my-files", {
          headers: { Authorization: `Bearer ${token}` },
        });
        setFiles(res.data || []);
      } catch (err: any) {
        const errorMessage = err.response?.data?.message || "Failed to load files";
        setError(errorMessage);
        if (err.response?.status === 401) {
          router.push("/login");
        }
      } finally {
        setLoading(false);
      }
    };

    fetchFiles();
  }, [router]);

  const getSortedAndFilteredFiles = () => {
    let filtered = files;

    if (filterOneTime) {
      filtered = filtered.filter((f) => f.oneTime);
    }

    return filtered.sort((a, b) => {
      switch (sortBy) {
        case "name":
          return a.filename.localeCompare(b.filename);
        case "downloads":
          return b.downloadCount - a.downloadCount;
        case "date":
        default:
          return new Date(b.expiresAt).getTime() - new Date(a.expiresAt).getTime();
      }
    });
  };

  const sortedFiles = getSortedAndFilteredFiles();
  const totalDownloads = files.reduce((sum, f) => sum + f.downloadCount, 0);
  const expiringFiles = files.filter(
    (f) => new Date(f.expiresAt).getTime() - Date.now() < 24 * 60 * 60 * 1000
  ).length;

  return (
    <>
      <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 text-white">
        <div className="max-w-6xl mx-auto px-4 py-12">
          {/* Header */}
          <div className="mb-12">
            <div className="flex flex-col md:flex-row md:items-end md:justify-between gap-6 mb-8">
              <div>
                <h1 className="text-4xl md:text-5xl font-black mb-2 bg-clip-text text-transparent bg-gradient-to-r from-blue-400 via-cyan-300 to-blue-400">
                  My Files
                </h1>
                <p className="text-slate-400">Manage and share your encrypted files</p>
              </div>
              <a
                href="/upload"
                className="inline-flex items-center gap-2 px-6 py-3 bg-gradient-to-r from-blue-500 to-cyan-500 text-white font-bold rounded-lg hover:from-blue-600 hover:to-cyan-600 transition-all shadow-lg hover:shadow-blue-500/50"
              >
                <Upload size={20} />
                Upload New File
              </a>
            </div>

            {/* Stats Grid */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="bg-slate-800 border border-slate-700 rounded-lg p-6 hover:border-blue-500 transition-colors">
                <div className="flex items-center justify-between mb-2">
                  <p className="text-slate-400 text-sm font-semibold">Total Files</p>
                  <FileText size={20} className="text-blue-400" />
                </div>
                <p className="text-3xl font-bold text-white">{files.length}</p>
              </div>

              <div className="bg-slate-800 border border-slate-700 rounded-lg p-6 hover:border-blue-500 transition-colors">
                <div className="flex items-center justify-between mb-2">
                  <p className="text-slate-400 text-sm font-semibold">Total Downloads</p>
                  <Download size={20} className="text-cyan-400" />
                </div>
                <p className="text-3xl font-bold text-white">{totalDownloads}</p>
              </div>

              <div className="bg-slate-800 border border-slate-700 rounded-lg p-6 hover:border-blue-500 transition-colors">
                <div className="flex items-center justify-between mb-2">
                  <p className="text-slate-400 text-sm font-semibold">Expiring Soon</p>
                  <Clock size={20} className="text-yellow-400" />
                </div>
                <p className="text-3xl font-bold text-white">{expiringFiles}</p>
              </div>
            </div>
          </div>

          {/* Controls */}
          {files.length > 0 && (
            <div className="mb-8 flex flex-col md:flex-row gap-4 items-start md:items-center justify-between">
              <div className="flex flex-col md:flex-row gap-3 w-full md:w-auto">
                <div>
                  <label htmlFor="sortBy" className="block text-slate-400 text-sm font-semibold mb-2">
                    Sort By
                  </label>
                  <select
                    id="sortBy"
                    value={sortBy}
                    onChange={(e) => setSortBy(e.target.value as "date" | "name" | "downloads")}
                    className="px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white focus:outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500 focus:ring-opacity-50 transition-all"
                  >
                    <option value="date">Newest First</option>
                    <option value="name">Name (A-Z)</option>
                    <option value="downloads">Most Downloaded</option>
                  </select>
                </div>

                <div className="flex items-end">
                  <label className="flex items-center gap-2 px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white cursor-pointer hover:border-blue-500 transition-colors">
                    <input
                      type="checkbox"
                      checked={filterOneTime}
                      onChange={(e) => setFilterOneTime(e.target.checked)}
                      className="w-4 h-4 rounded cursor-pointer"
                    />
                    <span className="text-sm font-semibold">One-Time Links Only</span>
                  </label>
                </div>
              </div>

              {sortedFiles.length > 0 && (
                <p className="text-slate-400 text-sm">
                  Showing <span className="text-blue-400 font-semibold">{sortedFiles.length}</span> of{" "}
                  <span className="text-blue-400 font-semibold">{files.length}</span> files
                </p>
              )}
            </div>
          )}

          {/* Error Alert */}
          {error && (
            <div className="mb-8 p-4 bg-red-500 bg-opacity-20 border border-red-500 border-opacity-50 rounded-lg flex items-start gap-3">
              <AlertCircle size={20} className="text-red-400 flex-shrink-0 mt-0.5" />
              <div>
                <p className="text-red-200 font-semibold">Failed to load files</p>
                <p className="text-red-200 text-sm mt-1">{error}</p>
              </div>
            </div>
          )}

          {/* Loading State */}
          {loading ? (
            <div className="flex flex-col items-center justify-center py-20">
              <Loader size={48} className="text-blue-400 animate-spin mb-4" />
              <p className="text-slate-400 font-semibold">Loading your files...</p>
            </div>
          ) : sortedFiles.length === 0 ? (
            <div className="text-center py-20">
              <div className="bg-slate-800 border-2 border-dashed border-slate-700 rounded-2xl p-12 max-w-md mx-auto">
                <div className="flex justify-center mb-4">
                  <div className="bg-blue-500 bg-opacity-20 p-4 rounded-full">
                    <FileText size={48} className="text-blue-400" />
                  </div>
                </div>
                <h3 className="text-2xl font-bold text-white mb-2">No Files Yet</h3>
                <p className="text-slate-400 mb-6">
                  {filterOneTime
                    ? "No one-time link files found"
                    : "You haven't uploaded any files yet. Start by uploading your first file!"}
                </p>
                <a
                  href="/upload"
                  className="inline-flex items-center gap-2 px-6 py-3 bg-gradient-to-r from-blue-500 to-cyan-500 text-white font-bold rounded-lg hover:from-blue-600 hover:to-cyan-600 transition-all shadow-lg hover:shadow-blue-500/50"
                >
                  <Upload size={20} />
                  Upload Your First File
                </a>
              </div>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {sortedFiles.map((file) => (
                <FileCard key={file._id} file={file} />
              ))}
            </div>
          )}
        </div>
      </div>
    </>
  );
}