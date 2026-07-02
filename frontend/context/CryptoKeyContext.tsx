"use client";

import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import api from "@/lib/api";
import {
  decryptPrivateKey,
  encryptPrivateKey,
  exportPublicKey,
  generateRSAKeyPair,
  loadPrivateKeyIndexedDB,
  hasLocalKeypair,
  savePrivateKeyIndexedDB,
} from "@/lib/crypto/cryptoHelpers";

type CryptoKeyContextValue = {
  privateKey: CryptoKey | null;
  isUnlocked: boolean;
  needsSetup: boolean;
  checking: boolean;
  refreshNeedsSetup: () => Promise<void>;
  /** Unlocks the current user's already-provisioned local keypair using their login password. */
  unlock: (password: string) => Promise<void>;
  /** Generates a brand-new keypair for the current user (lazy-setup fallback) and uploads the
   *  public key to the server, using the password only in-memory to wrap the private key. */
  setup: (password: string) => Promise<void>;
  lock: () => void;
};

const CryptoKeyContext = createContext<CryptoKeyContextValue | null>(null);

function getCurrentUserEmail(): string | null {
  if (typeof window === "undefined") return null;
  const raw = localStorage.getItem("user");
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw);
    return typeof parsed?.email === "string" ? parsed.email.toLowerCase().trim() : null;
  } catch {
    return null;
  }
}

export function CryptoKeyProvider({ children }: { children: React.ReactNode }) {
  const [privateKey, setPrivateKey] = useState<CryptoKey | null>(null);
  const [needsSetup, setNeedsSetup] = useState(false);
  const [checking, setChecking] = useState(true);

  const refreshNeedsSetup = useCallback(async () => {
    const email = getCurrentUserEmail();
    const token = typeof window !== "undefined" ? localStorage.getItem("token") : null;
    if (!email || !token) {
      setNeedsSetup(false);
      setChecking(false);
      return;
    }
    setChecking(true);
    try {
      const [hasLocal, res] = await Promise.all([
        hasLocalKeypair(email),
        api.get("/users/publickey", { headers: { Authorization: `Bearer ${token}` } }),
      ]);
      setNeedsSetup(!hasLocal || !res.data?.publicKey);
    } catch {
      setNeedsSetup(true);
    } finally {
      setChecking(false);
    }
  }, []);

  useEffect(() => {
    refreshNeedsSetup();
  }, [refreshNeedsSetup]);

  const unlock = useCallback(async (password: string) => {
    const email = getCurrentUserEmail();
    if (!email) throw new Error("Not logged in");

    const record = await loadPrivateKeyIndexedDB(email);
    if (!record) throw new Error("No local encryption key found for this device");

    const key = await decryptPrivateKey(
      record.wrappedPrivateKey,
      password,
      record.salt,
      record.iv,
      record.iterations
    );
    setPrivateKey(key);
  }, []);

  const setup = useCallback(async (password: string) => {
    const email = getCurrentUserEmail();
    const token = typeof window !== "undefined" ? localStorage.getItem("token") : null;
    if (!email || !token) throw new Error("Not logged in");

    const keyPair = await generateRSAKeyPair();
    const publicKeyBase64 = await exportPublicKey(keyPair.publicKey);
    const { wrappedPrivateKey, salt, iv, iterations } = await encryptPrivateKey(
      keyPair.privateKey,
      password
    );

    await api.patch(
      "/users/publickey",
      { publicKey: publicKeyBase64 },
      { headers: { Authorization: `Bearer ${token}` } }
    );

    await savePrivateKeyIndexedDB(email, {
      wrappedPrivateKey,
      salt,
      iv,
      iterations,
      publicKeyBase64,
      createdAt: Date.now(),
    });

    setPrivateKey(keyPair.privateKey);
    setNeedsSetup(false);
  }, []);

  const lock = useCallback(() => setPrivateKey(null), []);

  const value = useMemo<CryptoKeyContextValue>(
    () => ({
      privateKey,
      isUnlocked: privateKey !== null,
      needsSetup,
      checking,
      refreshNeedsSetup,
      unlock,
      setup,
      lock,
    }),
    [privateKey, needsSetup, checking, refreshNeedsSetup, unlock, setup, lock]
  );

  return <CryptoKeyContext.Provider value={value}>{children}</CryptoKeyContext.Provider>;
}

export function useCryptoKey(): CryptoKeyContextValue {
  const ctx = useContext(CryptoKeyContext);
  if (!ctx) throw new Error("useCryptoKey must be used within a CryptoKeyProvider");
  return ctx;
}
