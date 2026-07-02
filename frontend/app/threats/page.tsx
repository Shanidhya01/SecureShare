"use client";

import { useEffect, useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import api from "@/lib/api";
import {
  ShieldAlert,
  Bug,
  Ban,
  ScanSearch,
  Loader,
  AlertCircle,
  CheckCircle,
  Fingerprint,
  RotateCcw,
} from "lucide-react";
import toast from "react-hot-toast";

type RiskLevel = "Low" | "Medium" | "High" | "Critical";

type ScanEntry = {
  _id: string;
  originalFilename?: string;
  fileSizeBytes?: number;
  claimedMimeType?: string | null;
  detectedMimeType?: string;
  mimeMismatch?: boolean;
  dangerousExtension?: boolean;
  dangerousDetectedType?: boolean;
  hasMacros?: boolean;
  isEncryptedArchive?: boolean;
  hashes?: { sha256?: string; sha1?: string; md5?: string };
  clamav?: { status: string; threatNames: string[] };
  virusTotal?: { status: string; maliciousCount: number; totalEngines: number; threatNames: string[] };
  riskLevel: RiskLevel;
  quarantined: boolean;
  scanStatus: string;
  createdAt: string;
};

type QuarantinedFile = {
  _id: string;
  filename: string;
  riskLevel: RiskLevel | null;
  scanId?: ScanEntry;
  createdAt: string;
};

type ThreatStats = {
  totalScans: number;
  quarantinedFiles: number;
  byRiskLevel: Record<RiskLevel, number>;
  malwareDetections: number;
  clamavUnavailableCount: number;
};

const riskBadgeClass: Record<RiskLevel, string> = {
  Low: "text-green-300 bg-green-500/10 ring-green-500/30",
  Medium: "text-yellow-300 bg-yellow-500/10 ring-yellow-500/30",
  High: "text-orange-300 bg-orange-500/10 ring-orange-500/30",
  Critical: "text-red-300 bg-red-500/10 ring-red-500/30",
};

function RiskBadge({ level }: { level: RiskLevel | null | undefined }) {
  const lvl = level || "Low";
  return (
    <span className={`text-[10px] font-bold uppercase tracking-wide rounded-full px-2 py-0.5 ring-1 ${riskBadgeClass[lvl]}`}>
      {lvl}
    </span>
  );
}

export default function ThreatCenterPage() {
  const router = useRouter();
  const [scans, setScans] = useState<ScanEntry[]>([]);
  const [quarantined, setQuarantined] = useState<QuarantinedFile[]>([]);
  const [stats, setStats] = useState<ThreatStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [busyId, setBusyId] = useState<string | null>(null);

  const fetchAll = useCallback(
    async (token: string) => {
      try {
        setLoading(true);
        const [scansRes, quarantinedRes, statsRes] = await Promise.all([
          api.get<ScanEntry[]>("/threats/scans", { headers: { Authorization: `Bearer ${token}` } }),
          api.get<QuarantinedFile[]>("/threats/quarantined", { headers: { Authorization: `Bearer ${token}` } }),
          api.get<ThreatStats>("/threats/stats", { headers: { Authorization: `Bearer ${token}` } }),
        ]);
        setScans(scansRes.data || []);
        setQuarantined(quarantinedRes.data || []);
        setStats(statsRes.data || null);
      } catch (err: any) {
        if (err?.response?.status === 401 || err?.response?.status === 403) {
          router.push("/login");
          return;
        }
        setError("Failed to load threat data");
      } finally {
        setLoading(false);
      }
    },
    [router]
  );

  useEffect(() => {
    const token = localStorage.getItem("token");
    if (!token) {
      router.push("/login");
      return;
    }
    fetchAll(token);
  }, [fetchAll, router]);

  const handleRelease = async (fileId: string) => {
    const token = localStorage.getItem("token");
    if (!token) return;
    setBusyId(fileId);
    try {
      await api.post(`/threats/quarantine/${fileId}/release`, {}, { headers: { Authorization: `Bearer ${token}` } });
      setQuarantined((prev) => prev.filter((f) => f._id !== fileId));
      toast.success("File released from quarantine");
    } catch {
      toast.error("Failed to release file");
    } finally {
      setBusyId(null);
    }
  };

  const malwareDetections = scans.filter(
    (s) => s.clamav?.status === "infected" || s.virusTotal?.status === "malicious"
  );

  const formatDate = (d: string) => new Date(d).toLocaleString();
  const formatBytes = (n?: number) => {
    if (!n) return "-";
    if (n < 1024) return `${n} B`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
    return `${(n / (1024 * 1024)).toFixed(1)} MB`;
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 text-white">
      <div className="max-w-5xl mx-auto px-4 py-12">
        <div className="mb-10 flex items-center gap-3">
          <div className="inline-flex h-11 w-11 items-center justify-center rounded-xl bg-red-500/10 text-red-300 ring-1 ring-red-500/30">
            <ScanSearch size={22} />
          </div>
          <div>
            <h1 className="text-3xl font-black text-transparent bg-clip-text bg-gradient-to-r from-red-400 to-orange-400">
              Threat Center
            </h1>
            <p className="text-slate-400 text-sm">Malware scanning, quarantine, and threat intelligence for your uploads.</p>
          </div>
        </div>

        {error && (
          <div className="mb-6 p-4 bg-red-500/20 border border-red-500/40 rounded-lg flex items-center gap-2">
            <AlertCircle className="text-red-400" size={18} />
            <p className="text-red-200 text-sm">{error}</p>
          </div>
        )}

        {loading ? (
          <div className="flex flex-col items-center py-20">
            <Loader className="animate-spin text-red-400" size={40} />
            <p className="mt-4 text-slate-400">Loading threat data…</p>
          </div>
        ) : (
          <div className="space-y-10">
            {/* Stats */}
            {stats && (
              <section className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="bg-slate-800 border border-slate-700 rounded-xl p-4">
                  <p className="text-slate-400 text-xs">Total Scans</p>
                  <p className="text-2xl font-bold mt-1">{stats.totalScans}</p>
                </div>
                <div className="bg-slate-800 border border-slate-700 rounded-xl p-4">
                  <p className="text-slate-400 text-xs">Quarantined Files</p>
                  <p className="text-2xl font-bold mt-1 text-red-300">{stats.quarantinedFiles}</p>
                </div>
                <div className="bg-slate-800 border border-slate-700 rounded-xl p-4">
                  <p className="text-slate-400 text-xs">Malware Detections</p>
                  <p className="text-2xl font-bold mt-1 text-orange-300">{stats.malwareDetections}</p>
                </div>
                <div className="bg-slate-800 border border-slate-700 rounded-xl p-4">
                  <p className="text-slate-400 text-xs">Risk Breakdown</p>
                  <div className="flex gap-1.5 mt-2 flex-wrap">
                    {(Object.keys(stats.byRiskLevel) as RiskLevel[]).map((lvl) => (
                      <span key={lvl} className={`text-[10px] font-bold rounded-full px-2 py-0.5 ring-1 ${riskBadgeClass[lvl]}`}>
                        {lvl}: {stats.byRiskLevel[lvl]}
                      </span>
                    ))}
                  </div>
                </div>
                {stats.clamavUnavailableCount > 0 && (
                  <div className="col-span-2 md:col-span-4 flex items-center gap-2 text-slate-500 text-xs">
                    <AlertCircle size={12} />
                    ClamAV was unavailable for {stats.clamavUnavailableCount} scan(s) in this environment - those scans
                    still ran magic-byte, MIME-mismatch, and VirusTotal checks.
                  </div>
                )}
              </section>
            )}

            {/* Quarantined Files */}
            <section>
              <h2 className="flex items-center gap-2 text-lg font-bold text-white mb-4">
                <Ban size={20} className="text-red-300" />
                Quarantined Files
              </h2>
              {quarantined.length === 0 ? (
                <p className="text-slate-500 text-sm">No quarantined files. Nothing you've uploaded has been blocked.</p>
              ) : (
                <div className="space-y-2">
                  {quarantined.map((f) => (
                    <div key={f._id} className="flex items-start justify-between gap-3 rounded-xl border border-red-500/30 bg-red-500/5 px-4 py-3">
                      <div className="flex items-start gap-3 min-w-0">
                        <Bug size={16} className="text-red-400 shrink-0 mt-0.5" />
                        <div className="min-w-0">
                          <p className="text-red-100 text-sm font-semibold truncate">{f.filename}</p>
                          <p className="text-slate-500 text-xs mt-1">
                            Quarantined {formatDate(f.createdAt)}
                            {f.scanId?.clamav?.threatNames?.length ? ` · ${f.scanId.clamav.threatNames.join(", ")}` : ""}
                          </p>
                        </div>
                      </div>
                      <div className="flex items-center gap-2 shrink-0">
                        <RiskBadge level={f.riskLevel} />
                        <button
                          onClick={() => handleRelease(f._id)}
                          disabled={busyId === f._id}
                          className="flex items-center gap-1 px-3 py-1.5 text-xs font-semibold text-slate-300 hover:text-white hover:bg-slate-700 rounded-lg disabled:opacity-50"
                          title="Release from quarantine (owner override)"
                        >
                          <RotateCcw size={12} />
                          Release
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </section>

            {/* Malware Detections */}
            <section>
              <h2 className="flex items-center gap-2 text-lg font-bold text-white mb-4">
                <ShieldAlert size={20} className="text-orange-300" />
                Malware Detections
              </h2>
              {malwareDetections.length === 0 ? (
                <p className="text-slate-500 text-sm">No malware has been detected in your uploads.</p>
              ) : (
                <div className="space-y-2">
                  {malwareDetections.map((s) => (
                    <div key={s._id} className="rounded-xl border border-orange-500/30 bg-orange-500/5 px-4 py-3">
                      <div className="flex items-center justify-between gap-2">
                        <p className="text-orange-100 text-sm font-semibold truncate">{s.originalFilename}</p>
                        <RiskBadge level={s.riskLevel} />
                      </div>
                      <p className="text-slate-400 text-xs mt-1">
                        {s.clamav?.status === "infected" && `ClamAV: ${s.clamav.threatNames.join(", ")}`}
                        {s.clamav?.status === "infected" && s.virusTotal?.status === "malicious" && " · "}
                        {s.virusTotal?.status === "malicious" &&
                          `VirusTotal: ${s.virusTotal.maliciousCount}/${s.virusTotal.totalEngines} engines flagged`}
                      </p>
                    </div>
                  ))}
                </div>
              )}
            </section>

            {/* Scan History */}
            <section>
              <h2 className="flex items-center gap-2 text-lg font-bold text-white mb-4">
                <Fingerprint size={20} className="text-blue-300" />
                Scan History
              </h2>
              {scans.length === 0 ? (
                <p className="text-slate-500 text-sm">No scans yet - files are scanned automatically before upload.</p>
              ) : (
                <div className="rounded-2xl border border-slate-800/80 bg-slate-900/80 overflow-hidden">
                  <div className="overflow-x-auto">
                    <table className="min-w-full w-full text-sm">
                      <thead className="bg-slate-900 text-xs uppercase tracking-wide text-slate-400">
                        <tr>
                          <th className="px-4 py-3 text-left">File</th>
                          <th className="px-4 py-3 text-left">Size</th>
                          <th className="px-4 py-3 text-left">SHA-256</th>
                          <th className="px-4 py-3 text-left">ClamAV</th>
                          <th className="px-4 py-3 text-left">VirusTotal</th>
                          <th className="px-4 py-3 text-left">Risk</th>
                          <th className="px-4 py-3 text-left">Scanned</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/80">
                        {scans.map((s) => (
                          <tr key={s._id} className="hover:bg-slate-900/70">
                            <td className="px-4 py-3 max-w-[180px] truncate" title={s.originalFilename}>
                              {s.originalFilename}
                              {s.mimeMismatch && (
                                <span title="Claimed type didn't match detected content" className="ml-1 text-yellow-400">
                                  ⚠
                                </span>
                              )}
                            </td>
                            <td className="px-4 py-3 text-slate-300">{formatBytes(s.fileSizeBytes)}</td>
                            <td className="px-4 py-3 font-mono text-xs text-slate-400 max-w-[140px] truncate" title={s.hashes?.sha256}>
                              {s.hashes?.sha256?.slice(0, 16)}…
                            </td>
                            <td className="px-4 py-3 text-slate-300">
                              {s.clamav?.status === "clean" && <span className="text-green-300">Clean</span>}
                              {s.clamav?.status === "infected" && <span className="text-red-300">Infected</span>}
                              {s.clamav?.status === "unavailable" && <span className="text-slate-500">Unavailable</span>}
                              {s.clamav?.status === "error" && <span className="text-yellow-400">Error</span>}
                            </td>
                            <td className="px-4 py-3 text-slate-300">
                              {s.virusTotal?.status === "skipped" && <span className="text-slate-500">Skipped</span>}
                              {s.virusTotal?.status === "clean" && <span className="text-green-300">Clean</span>}
                              {s.virusTotal?.status === "unknown" && <span className="text-slate-500">Unknown</span>}
                              {s.virusTotal?.status === "suspicious" && <span className="text-yellow-400">Suspicious</span>}
                              {s.virusTotal?.status === "malicious" && <span className="text-red-300">Malicious</span>}
                              {s.virusTotal?.status === "error" && <span className="text-yellow-400">Error</span>}
                            </td>
                            <td className="px-4 py-3">
                              <RiskBadge level={s.riskLevel} />
                            </td>
                            <td className="px-4 py-3 text-slate-400 text-xs whitespace-nowrap">{formatDate(s.createdAt)}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </section>
          </div>
        )}
      </div>
    </div>
  );
}
