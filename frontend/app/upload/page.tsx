"use client";
import { useState } from "react";
import api from "@/lib/api";
import { useRouter } from "next/navigation";
import { Upload, AlertCircle, CheckCircle, Loader, X, FileIcon, Lock } from "lucide-react";
import toast from "react-hot-toast";
import Navbar from "@/components/Navbar";

export default function UploadFile() {
  const [file, setFile] = useState<File | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState(false);
  const router = useRouter();

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

    setUploading(true);
    setError("");
    setUploadProgress(0);

    try {
      const formData = new FormData();
      formData.append("file", file);

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

      const response = await api.post("/files/upload", formData, {
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "multipart/form-data",
        },
      });

      clearInterval(progressInterval);
      setUploadProgress(100);
      setSuccess(true);
      setFile(null);
      toast.success("File uploaded successfully");

      // Redirect to dashboard after 2 seconds
      setTimeout(() => {
        router.push("/dashboard");
      }, 2000);
    } catch (err: any) {
      const errorMessage =
        err.response?.data?.message ||
        err.message ||
        "Upload failed. Please try again.";
      setError(errorMessage);
      toast.error(errorMessage);
    } finally {
      setUploading(false);
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
              <div className="mb-6 p-4 bg-green-500 bg-opacity-20 border border-green-500 border-opacity-50 rounded-lg flex items-start gap-3">
                <CheckCircle size={20} className="text-green-400 flex-shrink-0 mt-0.5" />
                <div>
                  <p className="text-green-200 font-semibold text-sm">File uploaded successfully!</p>
                  <p className="text-green-200 text-sm mt-1">Redirecting to dashboard...</p>
                </div>
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
              </div>
            )}

            {/* Upload Progress */}
            {uploading && (
              <div className="mb-6">
                <div className="flex items-center justify-between mb-2">
                  <p className="text-slate-300 font-semibold text-sm">Uploading...</p>
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
              disabled={!file || uploading || success}
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
    </div>
  );
}