"use client";

import { useState } from "react";
import { Lock, AlertCircle } from "lucide-react";
import { useCryptoKey } from "@/context/CryptoKeyContext";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from "@/components/ui/dialog";

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
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (!next && !busy) onClose();
      }}
    >
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{needsSetup ? "Set Up Encryption" : "Unlock Your Encryption Key"}</DialogTitle>
          <DialogDescription>
            {needsSetup
              ? "Confirm your account password to set up file encryption for this device."
              : "Enter your account password to unlock your encryption key for this session."}
          </DialogDescription>
        </DialogHeader>

        {error && (
          <div className="p-3 bg-destructive/10 border border-destructive/30 rounded-lg flex items-start gap-2" role="alert">
            <AlertCircle size={16} className="text-destructive shrink-0 mt-0.5" />
            <p className="text-destructive text-xs">{error}</p>
          </div>
        )}

        <div className="relative">
          <Lock size={16} className="absolute left-3 top-3.5 text-muted-foreground" />
          <label htmlFor="unlock-key-password" className="sr-only">
            Account password
          </label>
          <input
            id="unlock-key-password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleSubmit()}
            placeholder="Your account password"
            className="w-full pl-10 pr-4 py-3 bg-background border border-border rounded-lg text-foreground placeholder-muted-foreground focus:outline-none focus-visible:ring-2 focus-visible:ring-primary/60 transition-all"
            disabled={busy}
            autoFocus
          />
        </div>

        <div className="flex gap-2">
          <button
            type="button"
            onClick={handleSubmit}
            disabled={busy}
            className="flex-1 px-4 py-2 bg-primary text-primary-foreground rounded-lg text-sm font-semibold disabled:opacity-50"
          >
            {busy ? "Please wait..." : needsSetup ? "Set Up" : "Unlock"}
          </button>
          <button
            type="button"
            onClick={onClose}
            disabled={busy}
            className="flex-1 px-4 py-2 bg-card border border-border rounded-lg text-sm hover:bg-muted disabled:opacity-50"
          >
            Cancel
          </button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
