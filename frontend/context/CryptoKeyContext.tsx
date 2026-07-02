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
  generateSigningKeyPair,
  exportSigningPublicKey,
  decryptSigningPrivateKey,
} from "@/lib/crypto/cryptoHelpers";

type CryptoKeyContextValue = {
  privateKey: CryptoKey | null;
  /** ECDSA P-256 signing private key (Phase 2), unlocked alongside the RSA key. Null if this
   *  account hasn't set up signing yet (e.g. mid-upgrade, or setup partially failed). */
  signingPrivateKey: CryptoKey | null;
  isUnlocked: boolean;
  needsSetup: boolean;
  checking: boolean;
  refreshNeedsSetup: () => Promise<void>;
  /** Unlocks the current user's already-provisioned local keypair(s) using their login password.
   *  Also transparently backfills a signing keypair for accounts created before Phase 2. */
  unlock: (password: string) => Promise<void>;
  /** Generates brand-new RSA + ECDSA keypairs for the current user (lazy-setup fallback) and
   *  uploads both public keys to the server, using the password only in-memory to wrap them. */
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
  const [signingPrivateKey, setSigningPrivateKey] = useState<CryptoKey | null>(null);
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

  /** Generates a signing keypair for an account that only has an RSA keypair so far (either a
   *  brand-new setup, or an account created before Phase 2 shipped), uploads the public part,
   *  and persists the wrapped private part into the given IndexedDB record. Never throws - a
   *  user should still be able to encrypt/decrypt files even if signing setup has a hiccup;
   *  they'll just upload unsigned until it succeeds on a later unlock. */
  const backfillSigningKey = useCallback(
    async (email: string, token: string, password: string): Promise<CryptoKey | null> => {
      try {
        const signingKeyPair = await generateSigningKeyPair();
        const signingPublicKeyBase64 = await exportSigningPublicKey(signingKeyPair.publicKey);
        const wrapped = await encryptPrivateKey(signingKeyPair.privateKey, password);

        await api.patch(
          "/users/signingkey",
          { signingPublicKey: signingPublicKeyBase64 },
          { headers: { Authorization: `Bearer ${token}` } }
        );

        const existing = await loadPrivateKeyIndexedDB(email);
        if (existing) {
          await savePrivateKeyIndexedDB(email, {
            ...existing,
            wrappedSigningPrivateKey: wrapped.wrappedPrivateKey,
            signingSalt: wrapped.salt,
            signingIv: wrapped.iv,
            signingIterations: wrapped.iterations,
            signingPublicKeyBase64,
          });
        }

        return signingKeyPair.privateKey;
      } catch (err) {
        console.error("Signing key backfill failed:", err);
        return null;
      }
    },
    []
  );

  const unlock = useCallback(
    async (password: string) => {
      const email = getCurrentUserEmail();
      if (!email) throw new Error("Not logged in");
      const token = typeof window !== "undefined" ? localStorage.getItem("token") : null;

      const record = await loadPrivateKeyIndexedDB(email);
      if (!record) throw new Error("No local encryption key found for this device");

      const key = await decryptPrivateKey(record.wrappedPrivateKey, password, record.salt, record.iv, record.iterations);
      setPrivateKey(key);

      if (record.wrappedSigningPrivateKey && record.signingSalt && record.signingIv && record.signingIterations) {
        try {
          const signingKey = await decryptSigningPrivateKey(
            record.wrappedSigningPrivateKey,
            password,
            record.signingSalt,
            record.signingIv,
            record.signingIterations
          );
          setSigningPrivateKey(signingKey);
        } catch (err) {
          console.error("Failed to unlock signing key:", err);
          setSigningPrivateKey(null);
        }
      } else if (token) {
        // Pre-Phase-2 account: transparently provision a signing keypair now.
        const backfilled = await backfillSigningKey(email, token, password);
        setSigningPrivateKey(backfilled);
      }
    },
    [backfillSigningKey]
  );

  const setup = useCallback(async (password: string) => {
    const email = getCurrentUserEmail();
    const token = typeof window !== "undefined" ? localStorage.getItem("token") : null;
    if (!email || !token) throw new Error("Not logged in");

    const keyPair = await generateRSAKeyPair();
    const publicKeyBase64 = await exportPublicKey(keyPair.publicKey);
    const { wrappedPrivateKey, salt, iv, iterations } = await encryptPrivateKey(keyPair.privateKey, password);

    await api.patch(
      "/users/publickey",
      { publicKey: publicKeyBase64 },
      { headers: { Authorization: `Bearer ${token}` } }
    );

    const signingKeyPair = await generateSigningKeyPair();
    const signingPublicKeyBase64 = await exportSigningPublicKey(signingKeyPair.publicKey);
    const wrappedSigning = await encryptPrivateKey(signingKeyPair.privateKey, password);

    await api.patch(
      "/users/signingkey",
      { signingPublicKey: signingPublicKeyBase64 },
      { headers: { Authorization: `Bearer ${token}` } }
    );

    await savePrivateKeyIndexedDB(email, {
      wrappedPrivateKey,
      salt,
      iv,
      iterations,
      publicKeyBase64,
      wrappedSigningPrivateKey: wrappedSigning.wrappedPrivateKey,
      signingSalt: wrappedSigning.salt,
      signingIv: wrappedSigning.iv,
      signingIterations: wrappedSigning.iterations,
      signingPublicKeyBase64,
      createdAt: Date.now(),
    });

    setPrivateKey(keyPair.privateKey);
    setSigningPrivateKey(signingKeyPair.privateKey);
    setNeedsSetup(false);
  }, []);

  const lock = useCallback(() => {
    setPrivateKey(null);
    setSigningPrivateKey(null);
  }, []);

  const value = useMemo<CryptoKeyContextValue>(
    () => ({
      privateKey,
      signingPrivateKey,
      isUnlocked: privateKey !== null,
      needsSetup,
      checking,
      refreshNeedsSetup,
      unlock,
      setup,
      lock,
    }),
    [privateKey, signingPrivateKey, needsSetup, checking, refreshNeedsSetup, unlock, setup, lock]
  );

  return <CryptoKeyContext.Provider value={value}>{children}</CryptoKeyContext.Provider>;
}

export function useCryptoKey(): CryptoKeyContextValue {
  const ctx = useContext(CryptoKeyContext);
  if (!ctx) throw new Error("useCryptoKey must be used within a CryptoKeyProvider");
  return ctx;
}
