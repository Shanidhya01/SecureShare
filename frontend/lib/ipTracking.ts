/**
 * Utility to download files with IP tracking
 * The backend handles IP detection
 */
import { getDeviceId } from "@/lib/security/fingerprint";

const API_URL = process.env.NEXT_PUBLIC_API || "http://localhost:5000/api";

/**
 * Download a file with IP tracking
 * Backend will detect the real IP from the request
 */
export const downloadFileWithIpTracking = async (
  fileId: string,
  email?: string,
  password?: string
) => {
  try {
    // Build the download URL
    const url = new URL(`${API_URL}/files/download/${fileId}`);
    if (email) url.searchParams.set("email", email);
    if (password) url.searchParams.set("password", password);

    console.log("📥 Starting download:", {
      fileId,
      email,
      url: url.toString(),
    });

    // Zero Trust (Phase 3): attach the device fingerprint so any allowedDevices/maxDevices
    // policy on this file can be evaluated. Never blocks the download if fingerprinting fails.
    const headers: Record<string, string> = {};
    try {
      headers["x-device-id"] = await getDeviceId();
    } catch {
      // ignore - policy checks that need a deviceId will simply see none
    }
    const token = typeof window !== "undefined" ? localStorage.getItem("token") : null;
    if (token) headers["Authorization"] = `Bearer ${token}`;

    // Make the fetch request - backend will detect real IP
    const response = await fetch(url.toString(), {
      method: "GET",
      headers,
    });

    if (!response.ok) {
      const body = await response.json().catch(() => ({} as { error?: string; reason?: string }));
      if (body?.error === "policy_denied") {
        throw new Error(`Access denied by security policy: ${body.reason || "restricted"}`);
      }
      console.error("Download error response:", body);
      throw new Error(`Download failed with status ${response.status}`);
    }

    // Get the blob and download it
    const blob = await response.blob();
    const downloadUrl = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = downloadUrl;
    
    // Extract filename from Content-Disposition header if available
    const contentDisposition = response.headers.get("content-disposition");
    let filename = "download";
    if (contentDisposition) {
      const filenameMatch = contentDisposition.match(/filename="?([^"]*)"?/);
      if (filenameMatch) filename = filenameMatch[1];
    }
    
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    
    console.log("✅ Download completed:", filename);
    
    // Cleanup
    window.URL.revokeObjectURL(downloadUrl);
    document.body.removeChild(a);
    
    return true;
  } catch (error) {
    console.error("Error downloading file:", error);
    throw error;
  }
};
