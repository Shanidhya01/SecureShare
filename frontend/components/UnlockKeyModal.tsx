"use client";

import { useState } from "react";
import { Lock, X, AlertCircle } from "lucide-react";
import { useCryptoKey } from "@/context/CryptoKeyContext";

/**
 * Shared modal that either sets up a brand-new local encryption keypair (no local record found -
 * e.g. first upload after registering pre-migration, or a cleared browser) or unlocks an existing
 * one (local record exists but the private key isn't in memory for this session yet). Re-collects
 * the user's login password once, uses it in-memory only, and never sends it to the server.
 */
export default function UnlockKeyModal({
  open,
  onClose,
  onSuccess,
}: {
  open: boolean;
  onClose: () => void;
  onSuccess: () => void;
}) {
  const { needsSetup, unlock, setup } = useCryptoKey();
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  if (!open) return null;

  const handleSubmit = async () => {
    if (!password) {
      setError("Please enter your password");
      return;
    }
    setBusy(true);
    setError("");
    try {
      if (needsSetup) {
        await setup(password);
      } else {
        await unlock(password);
      }
      setPassword("");
      onSuccess();
    } catch (err) {
      console.error("Key unlock/setup failed:", err);
      setError(
        needsSetup
          ? "Failed to set up encryption. Please try again."
          : "Incorrect password, or no local key found on this device."
      );
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
      <div className="bg-slate-800 border border-slate-700 rounded-xl w-full max-w-sm p-6 shadow-xl">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-white font-bold">
            {needsSetup ? "Set Up Encryption" : "Unlock Your Encryption Key"}
          </h2>
          <button onClick={onClose} className="text-slate-400 hover:text-slate-200" disabled={busy}>
            <X size={18} />
          </button>
        </div>
        <p className="text-slate-400 text-sm mb-3">
          {needsSetup
            ? "Confirm your account password to set up file encryption for this device."
            : "Enter your account password to unlock your encryption key for this session."}
        </p>

        {error && (
          <div className="mb-3 p-3 bg-red-500 bg-opacity-20 border border-red-500 border-opacity-50 rounded-lg flex items-start gap-2">
            <AlertCircle size={16} className="text-red-400 flex-shrink-0 mt-0.5" />
            <p className="text-red-200 text-xs">{error}</p>
          </div>
        )}

        <div className="relative mb-4">
          <Lock size={16} className="absolute left-3 top-3.5 text-slate-400" />
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleSubmit()}
            placeholder="Your account password"
            className="w-full pl-10 pr-4 py-3 bg-slate-700 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500 focus:ring-opacity-50 transition-all"
            disabled={busy}
            autoFocus
          />
        </div>

        <div className="flex gap-2">
          <button
            onClick={handleSubmit}
            disabled={busy}
            className="flex-1 px-4 py-2 bg-blue-500 hover:bg-blue-600 text-white rounded-lg disabled:opacity-50"
          >
            {busy ? "Please wait..." : needsSetup ? "Set Up" : "Unlock"}
          </button>
          <button
            onClick={onClose}
            disabled={busy}
            className="flex-1 px-4 py-2 bg-slate-700 text-white rounded-lg disabled:opacity-50"
          >
            Cancel
          </button>
        </div>
      </div>
    </div>
  );
}
