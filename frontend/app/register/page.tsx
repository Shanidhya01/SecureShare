"use client";
import { useState } from "react";
import Link from "next/link";
import api from "@/lib/api";
import { useRouter } from "next/navigation";
import { motion } from "framer-motion";
import { Eye, EyeOff, Lock, Mail, User, AlertCircle, CheckCircle, Loader, ArrowRight, ShieldCheck, ScanSearch, FileCheck2, Eye as EyeIcon } from "lucide-react";
import toast from "react-hot-toast";
import {
  encryptPrivateKey,
  exportPublicKey,
  generateRSAKeyPair,
  savePrivateKeyIndexedDB,
  generateSigningKeyPair,
  exportSigningPublicKey,
} from "@/lib/crypto/cryptoHelpers";
import { apiErrorMessage } from "@/lib/errors";
import { fadeInUp } from "@/lib/motion";

const highlights = [
  { icon: Lock, text: "Zero-knowledge AES-256 encryption" },
  { icon: FileCheck2, text: "ECDSA digital signatures on every file" },
  { icon: ScanSearch, text: "Malware & DLP scanning before upload" },
  { icon: ShieldCheck, text: "Zero Trust device & session controls" },
];

export default function Register() {
  const [form, setForm] = useState({
    name: "",
    email: "",
    password: "",
    confirmPassword: "",
  });
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState(false);
  const router = useRouter();

  const validateForm = () => {
    const newErrors: Record<string, string> = {};

    if (!form.name?.trim()) {
      newErrors.name = "Name is required";
    } else if (form.name.length < 2) {
      newErrors.name = "Name must be at least 2 characters";
    }

    if (!form.email?.trim()) {
      newErrors.email = "Email is required";
    } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(form.email)) {
      newErrors.email = "Please enter a valid email address";
    }

    if (!form.password) {
      newErrors.password = "Password is required";
    } else if (form.password.length < 8) {
      newErrors.password = "Password must be at least 8 characters";
    } else if (!/(?=.*[a-z])/.test(form.password)) {
      newErrors.password = "Password must contain lowercase letters";
    } else if (!/(?=.*[A-Z])/.test(form.password)) {
      newErrors.password = "Password must contain uppercase letters";
    } else if (!/(?=.*\d)/.test(form.password)) {
      newErrors.password = "Password must contain numbers";
    } else if (!/(?=.*[@$!%*?&])/.test(form.password)) {
      newErrors.password = "Password must contain special characters (@$!%*?&)";
    }

    if (!form.confirmPassword) {
      newErrors.confirmPassword = "Please confirm your password";
    } else if (form.password !== form.confirmPassword) {
      newErrors.confirmPassword = "Passwords do not match";
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleInputChange = (field: string, value: string) => {
    setForm({ ...form, [field]: value });
    if (errors[field]) {
      setErrors({ ...errors, [field]: "" });
    }
  };

  const register = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrors({});

    if (!validateForm()) return;

    setLoading(true);
    try {
      const registerData = { name: form.name, email: form.email, password: form.password };

      // Generate this account's E2E encryption keypair (RSA-OAEP) AND its digital-signing
      // keypair (ECDSA P-256, Phase 2) while the plaintext password is still available in
      // memory - this is the only point after account creation where we have it without
      // asking the user to re-enter it. Both private keys are wrapped with this password and
      // only ever leave this function to be stored locally (IndexedDB); both public keys are
      // submitted alongside registration.
      let keyPair: CryptoKeyPair;
      let publicKeyBase64: string;
      let wrappedPrivateKey: { wrappedPrivateKey: string; salt: string; iv: string; iterations: number };
      let signingKeyPair: CryptoKeyPair;
      let signingPublicKeyBase64: string;
      let wrappedSigningPrivateKey: { wrappedPrivateKey: string; salt: string; iv: string; iterations: number };
      try {
        keyPair = await generateRSAKeyPair();
        publicKeyBase64 = await exportPublicKey(keyPair.publicKey);
        wrappedPrivateKey = await encryptPrivateKey(keyPair.privateKey, form.password);

        signingKeyPair = await generateSigningKeyPair();
        signingPublicKeyBase64 = await exportSigningPublicKey(signingKeyPair.publicKey);
        wrappedSigningPrivateKey = await encryptPrivateKey(signingKeyPair.privateKey, form.password);
      } catch (cryptoErr) {
        console.error("Encryption setup failed:", cryptoErr);
        setErrors({ submit: "Failed to set up encryption on this device. Please try again." });
        setLoading(false);
        return;
      }

      await api.post("/auth/register", {
        ...registerData,
        publicKey: publicKeyBase64,
        signingPublicKey: signingPublicKeyBase64,
      });

      // Only persist the wrapped private keys locally after registration succeeded, to avoid
      // orphaning a local keypair for an account that was never actually created.
      await savePrivateKeyIndexedDB(form.email.toLowerCase().trim(), {
        ...wrappedPrivateKey,
        publicKeyBase64,
        wrappedSigningPrivateKey: wrappedSigningPrivateKey.wrappedPrivateKey,
        signingSalt: wrappedSigningPrivateKey.salt,
        signingIv: wrappedSigningPrivateKey.iv,
        signingIterations: wrappedSigningPrivateKey.iterations,
        signingPublicKeyBase64,
        createdAt: Date.now(),
      });

      setSuccess(true);
      toast.success("Account created successfully");

      setTimeout(() => {
        toast.success("Redirecting to login");
        router.push("/login");
      }, 2000);
    } catch (err: unknown) {
      setErrors({ submit: apiErrorMessage(err, "Registration failed. Please try again.") });
    } finally {
      setLoading(false);
    }
  };

  const getPasswordStrength = () => {
    let strength = 0;
    if (form.password?.length >= 8) strength++;
    if (/(?=.*[a-z])/.test(form.password)) strength++;
    if (/(?=.*[A-Z])/.test(form.password)) strength++;
    if (/(?=.*\d)/.test(form.password)) strength++;
    if (/(?=.*[@$!%*?&])/.test(form.password)) strength++;
    return strength;
  };

  const passwordStrength = getPasswordStrength();
  const strengthColors = ["bg-destructive", "bg-orange-500", "bg-warning", "bg-lime-500", "bg-success"];
  const strengthLabels = ["Weak", "Weak", "Fair", "Good", "Strong"];

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
            <EyeIcon size={28} className="text-primary" />
          </div>
          <h2 className="text-3xl font-black text-white mb-3">Your keys, your data</h2>
          <p className="text-slate-400 mb-8">
            Registration generates your personal encryption and signing keypairs locally in your browser - your
            private keys never leave this device unencrypted.
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
              <User size={22} className="text-primary" />
            </div>
            <h1 className="text-3xl font-bold text-foreground mb-1">Create your account</h1>
            <p className="text-muted-foreground">Join SecureShare and secure your files</p>
          </div>

          {success && (
            <div className="mb-6 p-4 bg-success/10 border border-success/30 rounded-lg flex items-start gap-3">
              <CheckCircle size={20} className="text-success shrink-0 mt-0.5" />
              <div>
                <p className="text-success font-semibold text-sm">Registration successful!</p>
                <p className="text-success/80 text-sm mt-1">Redirecting to login...</p>
              </div>
            </div>
          )}

          {errors.submit && (
            <div className="mb-6 p-4 bg-destructive/10 border border-destructive/30 rounded-lg flex items-start gap-3">
              <AlertCircle size={20} className="text-destructive shrink-0 mt-0.5" />
              <p className="text-destructive text-sm">{errors.submit}</p>
            </div>
          )}

          <form onSubmit={register} className="space-y-4">
            <div>
              <label htmlFor="name" className="block text-foreground font-medium text-sm mb-2">Full name</label>
              <div className="relative">
                <User size={18} className="absolute left-3 top-3.5 text-muted-foreground" />
                <input
                  id="name"
                  type="text"
                  value={form.name}
                  onChange={(e) => handleInputChange("name", e.target.value)}
                  placeholder="John Doe"
                  className={`w-full pl-10 pr-4 py-3 bg-card border rounded-lg text-foreground placeholder-muted-foreground focus:outline-none focus-visible:ring-2 transition-all ${
                    errors.name ? "border-destructive focus-visible:ring-destructive/40" : "border-border focus:border-primary focus-visible:ring-primary/60"
                  }`}
                  disabled={loading}
                />
              </div>
              {errors.name && <p className="text-destructive text-sm mt-1">{errors.name}</p>}
            </div>

            <div>
              <label htmlFor="reg-email" className="block text-foreground font-medium text-sm mb-2">Email address</label>
              <div className="relative">
                <Mail size={18} className="absolute left-3 top-3.5 text-muted-foreground" />
                <input
                  id="reg-email"
                  type="email"
                  value={form.email}
                  onChange={(e) => handleInputChange("email", e.target.value)}
                  placeholder="you@example.com"
                  className={`w-full pl-10 pr-4 py-3 bg-card border rounded-lg text-foreground placeholder-muted-foreground focus:outline-none focus-visible:ring-2 transition-all ${
                    errors.email ? "border-destructive focus-visible:ring-destructive/40" : "border-border focus:border-primary focus-visible:ring-primary/60"
                  }`}
                  disabled={loading}
                />
              </div>
              {errors.email && <p className="text-destructive text-sm mt-1">{errors.email}</p>}
            </div>

            <div>
              <label htmlFor="reg-password" className="block text-foreground font-medium text-sm mb-2">Password</label>
              <div className="relative">
                <Lock size={18} className="absolute left-3 top-3.5 text-primary" />
                <input
                  id="reg-password"
                  type={showPassword ? "text" : "password"}
                  value={form.password}
                  onChange={(e) => handleInputChange("password", e.target.value)}
                  placeholder="••••••••"
                  className={`w-full pl-10 pr-11 py-3 bg-card border rounded-lg text-foreground placeholder-muted-foreground focus:outline-none focus-visible:ring-2 transition-all ${
                    errors.password ? "border-destructive focus-visible:ring-destructive/40" : "border-border focus:border-primary focus-visible:ring-primary/60"
                  }`}
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

              {form.password && (
                <div className="mt-2">
                  <div className="flex gap-1 mb-1.5">
                    {[...Array(5)].map((_, i) => (
                      <div
                        key={i}
                        className={`h-1.5 flex-1 rounded-full transition-colors ${
                          i < passwordStrength ? strengthColors[passwordStrength - 1] : "bg-muted"
                        }`}
                      />
                    ))}
                  </div>
                  <p className="text-muted-foreground text-xs">{strengthLabels[Math.max(0, passwordStrength - 1)]} password</p>
                </div>
              )}

              {errors.password && <p className="text-destructive text-sm mt-1">{errors.password}</p>}
            </div>

            <div>
              <label htmlFor="confirm-password" className="block text-foreground font-medium text-sm mb-2">Confirm password</label>
              <div className="relative">
                <Lock size={18} className="absolute left-3 top-3.5 text-primary" />
                <input
                  id="confirm-password"
                  type={showConfirmPassword ? "text" : "password"}
                  value={form.confirmPassword}
                  onChange={(e) => handleInputChange("confirmPassword", e.target.value)}
                  placeholder="••••••••"
                  className={`w-full pl-10 pr-11 py-3 bg-card border rounded-lg text-foreground placeholder-muted-foreground focus:outline-none focus-visible:ring-2 transition-all ${
                    errors.confirmPassword ? "border-destructive focus-visible:ring-destructive/40" : "border-border focus:border-primary focus-visible:ring-primary/60"
                  }`}
                  disabled={loading}
                />
                <button
                  type="button"
                  onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                  aria-label={showConfirmPassword ? "Hide password" : "Show password"}
                  className="absolute right-3 top-3.5 text-muted-foreground hover:text-primary transition-colors disabled:opacity-50"
                  disabled={loading}
                >
                  {showConfirmPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                </button>
              </div>
              {errors.confirmPassword && <p className="text-destructive text-sm mt-1">{errors.confirmPassword}</p>}
            </div>

            <motion.button
              type="submit"
              disabled={loading || success}
              whileTap={{ scale: 0.98 }}
              className="w-full py-3 mt-2 bg-primary text-white font-bold rounded-lg hover:bg-primary/90 disabled:bg-muted transition-all shadow-lg shadow-primary/20 disabled:shadow-none flex items-center justify-center gap-2 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/60"
            >
              {loading ? (
                <>
                  <Loader size={20} className="animate-spin" />
                  Creating account...
                </>
              ) : success ? (
                <>
                  <CheckCircle size={20} />
                  Account created!
                </>
              ) : (
                <>
                  Create Account
                  <ArrowRight size={20} />
                </>
              )}
            </motion.button>

            {form.password && (
              <div className="mt-2 p-4 bg-muted/50 rounded-lg">
                <p className="text-foreground text-xs font-semibold mb-2">Password requirements:</p>
                <ul className="space-y-1 text-xs text-muted-foreground">
                  <li className={form.password.length >= 8 ? "text-success" : ""}>✓ At least 8 characters</li>
                  <li className={/(?=.*[a-z])/.test(form.password) ? "text-success" : ""}>✓ Lowercase letters</li>
                  <li className={/(?=.*[A-Z])/.test(form.password) ? "text-success" : ""}>✓ Uppercase letters</li>
                  <li className={/(?=.*\d)/.test(form.password) ? "text-success" : ""}>✓ Numbers</li>
                  <li className={/(?=.*[@$!%*?&])/.test(form.password) ? "text-success" : ""}>✓ Special characters (@$!%*?&)</li>
                </ul>
              </div>
            )}
          </form>

          <div className="my-6 flex items-center gap-3">
            <div className="flex-1 h-px bg-border" />
            <span className="text-muted-foreground text-sm">Already registered?</span>
            <div className="flex-1 h-px bg-border" />
          </div>

          <div className="text-center">
            <p className="text-muted-foreground">
              Have an account?{" "}
              <Link href="/login" className="text-primary hover:text-primary/80 font-semibold transition-colors">
                Sign in here
              </Link>
            </p>
          </div>
        </motion.div>
      </div>
    </div>
  );
}
