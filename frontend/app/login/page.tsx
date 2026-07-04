"use client";
import { useState } from "react";
import Link from "next/link";
import api from "@/lib/api";
import { useRouter } from "next/navigation";
import { motion } from "framer-motion";
import { Eye, EyeOff, Lock, Mail, AlertCircle, Loader, ShieldCheck, ScanSearch, FileCheck2, KeyRound, Fingerprint } from "lucide-react";
import toast from "react-hot-toast";
import { getDeviceId } from "@/lib/security/fingerprint";
import { apiErrorMessage } from "@/lib/errors";
import { fadeInUp } from "@/lib/motion";
import { loginWithPasskey } from "@/lib/webauthn";

const highlights = [
  { icon: Lock, text: "Zero-knowledge AES-256 encryption" },
  { icon: FileCheck2, text: "ECDSA digital signatures on every file" },
  { icon: ScanSearch, text: "Malware & DLP scanning before upload" },
  { icon: ShieldCheck, text: "Zero Trust device & session controls" },
];

export default function Login() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [passkeyLoading, setPasskeyLoading] = useState(false);

  // Phase 9 (IAM): set once the backend responds 202 {mfaRequired:true} - the login form is
  // replaced with a code-entry step until this resolves.
  const [mfaToken, setMfaToken] = useState<string | null>(null);
  const [mfaCode, setMfaCode] = useState("");
  const [trustDevice, setTrustDevice] = useState(false);

  const router = useRouter();

  const completeLogin = (token: string, userInfo: { email: string; name?: string }) => {
    localStorage.setItem("token", token);
    localStorage.setItem("user", JSON.stringify(userInfo));
    try { window.dispatchEvent(new Event("auth:changed")); } catch {}
    toast.success("Signed in successfully");
    router.push("/dashboard");
  };

  const submitMfaCode = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!mfaToken || !mfaCode.trim()) return;
    setLoading(true);
    setError("");
    try {
      const res = await api.post("/mfa/verify-login", { mfaToken, code: mfaCode.trim(), trustDevice });
      completeLogin(res.data.token, res.data.user ?? { email });
    } catch (err: unknown) {
      setError(apiErrorMessage(err, "Invalid code. Please try again."));
    } finally {
      setLoading(false);
    }
  };

  const handlePasskeyLogin = async () => {
    if (!email.trim()) {
      setError("Enter your email above, then use the passkey option");
      return;
    }
    setPasskeyLoading(true);
    setError("");
    try {
      let deviceId: string | undefined;
      try {
        deviceId = await getDeviceId();
      } catch {}
      const data = await loginWithPasskey(email, deviceId);
      completeLogin(data.token, data.user ?? { email });
    } catch (err: unknown) {
      setError(apiErrorMessage(err, "Passkey sign-in failed."));
    } finally {
      setPasskeyLoading(false);
    }
  };

  const validateForm = () => {
    if (!email.trim()) {
      setError("Email is required");
      return false;
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      setError("Please enter a valid email address");
      return false;
    }
    if (!password) {
      setError("Password is required");
      return false;
    }
    if (password.length < 6) {
      setError("Password must be at least 6 characters");
      return false;
    }
    return true;
  };

  const login = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");

    if (!validateForm()) return;

    setLoading(true);
    try {
      // Zero Trust (Phase 3): a stable, privacy-preserving device fingerprint hash accompanies
      // login so the backend can recognize this device on future requests (Security Center
      // device list, trusted-device access policies). Never blocks login if it fails.
      let deviceId: string | undefined;
      try {
        deviceId = await getDeviceId();
      } catch (fingerprintErr) {
        console.error("Device fingerprinting failed:", fingerprintErr);
      }

      const res = await api.post("/auth/login", { email, password, deviceId });

      if (res.data?.mfaRequired) {
        // Phase 9: password check passed but MFA is required - swap to the code-entry step
        // instead of completing login.
        setMfaToken(res.data.mfaToken);
        return;
      }

      if (res.data?.token) {
        completeLogin(res.data.token, res.data.user ?? { email });
        if (res.data.mfaSetupRequired) toast("Your organization requires MFA - set it up from /identity", { icon: "🔐" });
        if (res.data.stepUpRecommended) toast("Unusual login detected - consider enabling MFA", { icon: "⚠️" });
      } else {
        setError("Invalid response from server");
      }
    } catch (err: unknown) {
      setError(apiErrorMessage(err, "Login failed. Please try again."));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-background flex">
      {/* Brand panel */}
      <div className="hidden lg:flex lg:w-1/2 relative overflow-hidden bg-linear-to-br from-slate-950 via-slate-900 to-slate-950 items-center justify-center p-12">
        <div className="absolute inset-0 overflow-hidden pointer-events-none">
          <div className="absolute top-10 right-10 w-80 h-80 bg-primary rounded-full mix-blend-screen filter blur-3xl opacity-20 animate-pulse" />
          <div className="absolute bottom-10 left-10 w-80 h-80 bg-purple-500 rounded-full mix-blend-screen filter blur-3xl opacity-20 animate-pulse" style={{ animationDelay: "2s" }} />
        </div>
        <motion.div initial="hidden" animate="show" variants={fadeInUp} className="relative z-10 max-w-md">
          <div className="inline-flex h-14 w-14 items-center justify-center rounded-2xl bg-primary/10 ring-1 ring-primary/30 mb-6">
            <ShieldCheck size={28} className="text-primary" />
          </div>
          <h2 className="text-3xl font-black text-white mb-3">Enterprise-grade security, by default</h2>
          <p className="text-slate-400 mb-8">
            Every file uploaded to SecureShare is encrypted, signed, scanned, and access-controlled - before it ever leaves your device.
          </p>
          <ul className="space-y-3">
            {highlights.map((h) => (
              <li key={h.text} className="flex items-center gap-3 text-sm text-slate-300">
                <span className="inline-flex h-8 w-8 items-center justify-center rounded-lg bg-white/5 ring-1 ring-white/10 shrink-0">
                  <h.icon size={16} className="text-primary" />
                </span>
                {h.text}
              </li>
            ))}
          </ul>
        </motion.div>
      </div>

      {/* Form panel */}
      <div className="flex w-full lg:w-1/2 items-center justify-center px-4 py-12">
        <motion.div initial="hidden" animate="show" variants={fadeInUp} className="w-full max-w-md">
          <div className="mb-8 text-center lg:text-left">
            <div className="inline-flex h-12 w-12 items-center justify-center rounded-xl bg-primary/10 ring-1 ring-primary/30 mb-4 lg:hidden">
              <Lock size={22} className="text-primary" />
            </div>
            <h1 className="text-3xl font-bold text-foreground mb-1">Welcome back</h1>
            <p className="text-muted-foreground">Secure access to your files</p>
          </div>

          {error && (
            <div className="mb-6 p-4 bg-destructive/10 border border-destructive/30 rounded-lg flex items-start gap-3">
              <AlertCircle size={20} className="text-destructive shrink-0 mt-0.5" />
              <p className="text-destructive text-sm">{error}</p>
            </div>
          )}

          {mfaToken ? (
            // Phase 9 (IAM): second step of an MFA-gated login - a TOTP code or a recovery code.
            <form onSubmit={submitMfaCode} className="space-y-4">
              <div>
                <label htmlFor="mfaCode" className="block text-foreground font-medium text-sm mb-2">Authentication code</label>
                <div className="relative">
                  <KeyRound size={18} className="absolute left-3 top-3.5 text-muted-foreground" />
                  <input
                    id="mfaCode"
                    type="text"
                    inputMode="text"
                    autoFocus
                    value={mfaCode}
                    onChange={(e) => setMfaCode(e.target.value)}
                    placeholder="6-digit code or recovery code"
                    className="w-full pl-10 pr-4 py-3 bg-card border border-border rounded-lg text-foreground placeholder-muted-foreground focus:outline-none focus-visible:ring-2 focus-visible:ring-primary/60 focus:border-primary transition-all"
                    disabled={loading}
                  />
                </div>
              </div>
              <label className="flex items-center gap-2 text-sm text-muted-foreground">
                <input type="checkbox" checked={trustDevice} onChange={(e) => setTrustDevice(e.target.checked)} className="rounded border-border" />
                Trust this device for 30 days
              </label>
              <motion.button
                type="submit"
                disabled={loading}
                whileTap={{ scale: 0.98 }}
                className="w-full py-3 mt-2 bg-primary text-white font-bold rounded-lg hover:bg-primary/90 disabled:bg-muted transition-all shadow-lg shadow-primary/20 disabled:shadow-none flex items-center justify-center gap-2 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/60"
              >
                {loading ? <Loader size={20} className="animate-spin" /> : "Verify"}
              </motion.button>
              <button type="button" onClick={() => { setMfaToken(null); setMfaCode(""); }} className="w-full text-center text-sm text-muted-foreground hover:text-foreground">
                Back to login
              </button>
            </form>
          ) : (
            <>
              <form onSubmit={login} className="space-y-4">
                <div>
                  <label htmlFor="email" className="block text-foreground font-medium text-sm mb-2">Email address</label>
                  <div className="relative">
                    <Mail size={18} className="absolute left-3 top-3.5 text-muted-foreground" />
                    <input
                      id="email"
                      type="email"
                      value={email}
                      onChange={(e) => {
                        setEmail(e.target.value);
                        setError("");
                      }}
                      placeholder="you@example.com"
                      className="w-full pl-10 pr-4 py-3 bg-card border border-border rounded-lg text-foreground placeholder-muted-foreground focus:outline-none focus-visible:ring-2 focus-visible:ring-primary/60 focus:border-primary transition-all"
                      disabled={loading}
                    />
                  </div>
                </div>

                <div>
                  <label htmlFor="password" className="block text-foreground font-medium text-sm mb-2">Password</label>
                  <div className="relative">
                    <Lock size={18} className="absolute left-3 top-3.5 text-muted-foreground" />
                    <input
                      id="password"
                      type={showPassword ? "text" : "password"}
                      value={password}
                      onChange={(e) => {
                        setPassword(e.target.value);
                        setError("");
                      }}
                      placeholder="••••••••"
                      className="w-full pl-10 pr-11 py-3 bg-card border border-border rounded-lg text-foreground placeholder-muted-foreground focus:outline-none focus-visible:ring-2 focus-visible:ring-primary/60 focus:border-primary transition-all"
                      disabled={loading}
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      aria-label={showPassword ? "Hide password" : "Show password"}
                      className="absolute right-3 top-3.5 text-muted-foreground hover:text-primary transition-colors disabled:opacity-50"
                      disabled={loading}
                    >
                      {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                    </button>
                  </div>
                </div>

                <motion.button
                  type="submit"
                  disabled={loading}
                  whileTap={{ scale: 0.98 }}
                  className="w-full py-3 mt-2 bg-primary text-white font-bold rounded-lg hover:bg-primary/90 disabled:bg-muted transition-all shadow-lg shadow-primary/20 disabled:shadow-none flex items-center justify-center gap-2 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/60"
                >
                  {loading ? (
                    <>
                      <Loader size={20} className="animate-spin" />
                      Signing in...
                    </>
                  ) : (
                    "Sign In"
                  )}
                </motion.button>
              </form>

              <div className="my-4 flex items-center gap-3">
                <div className="flex-1 h-px bg-border" />
                <span className="text-muted-foreground text-xs">or</span>
                <div className="flex-1 h-px bg-border" />
              </div>

              <button
                type="button"
                onClick={handlePasskeyLogin}
                disabled={passkeyLoading}
                className="w-full py-3 bg-card border border-border text-foreground font-semibold rounded-lg hover:bg-muted transition-all flex items-center justify-center gap-2 disabled:opacity-50"
              >
                {passkeyLoading ? <Loader size={18} className="animate-spin" /> : <Fingerprint size={18} className="text-primary" />}
                Sign in with a passkey
              </button>
            </>
          )}

          <div className="my-6 flex items-center gap-3">
            <div className="flex-1 h-px bg-border" />
            <span className="text-muted-foreground text-sm">New to SecureShare?</span>
            <div className="flex-1 h-px bg-border" />
          </div>

          <div className="text-center">
            <p className="text-muted-foreground">
              Don&apos;t have an account?{" "}
              <Link href="/register" className="text-primary hover:text-primary/80 font-semibold transition-colors">
                Create one
              </Link>
            </p>
          </div>
        </motion.div>
      </div>
    </div>
  );
}
