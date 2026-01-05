"use client";
import { useState } from "react";
import api from "@/lib/api";
import { useRouter } from "next/navigation";
import { Eye, EyeOff, Lock, Mail, User, AlertCircle, CheckCircle, Loader, ArrowRight } from "lucide-react";
import toast from "react-hot-toast";

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
      const { confirmPassword, ...registerData } = form;
      await api.post("/auth/register", registerData);
      setSuccess(true);
      toast.success("Account created successfully");
      
      setTimeout(() => {
        toast.success("Redirecting to login");
        router.push("/login");
      }, 2000);
    } catch (err: any) {
      const errorMessage = err.response?.data?.message || "Registration failed. Please try again.";
      setErrors({ submit: errorMessage });
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
  const strengthColors = ["bg-red-500", "bg-orange-500", "bg-yellow-500", "bg-lime-500", "bg-green-500"];

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 flex items-center justify-center px-4 py-8">
      {/* Animated background blobs */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-20 right-10 w-72 h-72 bg-blue-500 rounded-full mix-blend-multiply filter blur-3xl opacity-20 animate-pulse"></div>
        <div className="absolute -bottom-8 left-20 w-72 h-72 bg-purple-500 rounded-full mix-blend-multiply filter blur-3xl opacity-20 animate-pulse" style={{ animationDelay: '2s' }}></div>
      </div>

      <div className="w-full max-w-md relative z-10">
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
                <User size={32} className="text-white" />
              </div>
            </div>
          </div>

          {/* Content */}
          <div className="p-8">
            <h1 className="text-3xl font-bold text-white mb-2 text-center">Create Account</h1>
            <p className="text-slate-400 text-center mb-8">Join SecureShare today and secure your files</p>

            {/* Success Alert */}
            {success && (
              <div className="mb-6 p-4 bg-green-500 bg-opacity-20 border border-green-500 border-opacity-50 rounded-lg flex items-start gap-3">
                <CheckCircle size={20} className="text-green-400 flex-shrink-0 mt-0.5" />
                <div>
                  <p className="text-green-200 font-semibold text-sm">Registration successful!</p>
                  <p className="text-green-200 text-sm mt-1">Redirecting to login...</p>
                </div>
              </div>
            )}

            {/* Error Alert */}
            {errors.submit && (
              <div className="mb-6 p-4 bg-red-500 bg-opacity-20 border border-red-500 border-opacity-50 rounded-lg flex items-start gap-3">
                <AlertCircle size={20} className="text-red-400 flex-shrink-0 mt-0.5" />
                <p className="text-red-200 text-sm">{errors.submit}</p>
              </div>
            )}

            {/* Form */}
            <div className="space-y-4">
              {/* Name Input */}
              <div>
                <label className="block text-slate-300 font-semibold mb-2">Full Name</label>
                <div className="relative">
                  <User size={18} className="absolute left-3 top-3.5 text-slate-400" />
                  <input
                    type="text"
                    value={form.name}
                    onChange={(e) => handleInputChange("name", e.target.value)}
                    placeholder="John Doe"
                    className={`w-full pl-10 pr-4 py-3 bg-slate-700 border rounded-lg text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-opacity-50 transition-all ${
                      errors.name ? "border-red-500 focus:ring-red-500" : "border-slate-600 focus:border-blue-500 focus:ring-blue-500"
                    }`}
                    disabled={loading}
                  />
                </div>
                {errors.name && <p className="text-red-400 text-sm mt-1">{errors.name}</p>}
              </div>

              {/* Email Input */}
              <div>
                <label className="block text-slate-300 font-semibold mb-2">Email Address</label>
                <div className="relative">
                  <Mail size={18} className="absolute left-3 top-3.5 text-slate-400" />
                  <input
                    type="email"
                    value={form.email}
                    onChange={(e) => handleInputChange("email", e.target.value)}
                    placeholder="you@example.com"
                    className={`w-full pl-10 pr-4 py-3 bg-slate-700 border rounded-lg text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-opacity-50 transition-all ${
                      errors.email ? "border-red-500 focus:ring-red-500" : "border-slate-600 focus:border-blue-500 focus:ring-blue-500"
                    }`}
                    disabled={loading}
                  />
                </div>
                {errors.email && <p className="text-red-400 text-sm mt-1">{errors.email}</p>}
              </div>

              {/* Password Input */}
              <div>
                <label className="block text-slate-300 font-semibold mb-2">Password</label>
                <div className="relative">
                  <Lock size={18} className="absolute left-3 top-3.5 text-blue-400" />
                  <input
                    type={showPassword ? "text" : "password"}
                    value={form.password}
                    onChange={(e) => handleInputChange("password", e.target.value)}
                    placeholder="••••••••"
                    className={`w-full pl-10 pr-11 py-3 bg-slate-700 border rounded-lg text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-opacity-50 transition-all ${
                      errors.password ? "border-red-500 focus:ring-red-500" : "border-slate-600 focus:border-blue-500 focus:ring-blue-500"
                    }`}
                    disabled={loading}
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-3 top-3.5 text-slate-400 hover:text-blue-400 transition-colors disabled:opacity-50"
                    disabled={loading}
                  >
                    {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                  </button>
                </div>

                {/* Password Strength Indicator */}
                {form.password && (
                  <div className="mt-2">
                    <div className="flex gap-1 mb-2">
                      {[...Array(5)].map((_, i) => (
                        <div
                          key={i}
                          className={`h-2 flex-1 rounded-full transition-colors ${
                            i < passwordStrength ? strengthColors[passwordStrength - 1] : "bg-slate-600"
                          }`}
                        ></div>
                      ))}
                    </div>
                    <p className="text-slate-400 text-xs">
                      {passwordStrength <= 2 && "Weak password"}
                      {passwordStrength === 3 && "Fair password"}
                      {passwordStrength === 4 && "Good password"}
                      {passwordStrength === 5 && "Strong password"}
                    </p>
                  </div>
                )}

                {errors.password && <p className="text-red-400 text-sm mt-1">{errors.password}</p>}
              </div>

              {/* Confirm Password Input */}
              <div>
                <label className="block text-slate-300 font-semibold mb-2">Confirm Password</label>
                <div className="relative">
                  <Lock size={18} className="absolute left-3 top-3.5 text-blue-400" />
                  <input
                    type={showConfirmPassword ? "text" : "password"}
                    value={form.confirmPassword}
                    onChange={(e) => handleInputChange("confirmPassword", e.target.value)}
                    placeholder="••••••••"
                    className={`w-full pl-10 pr-11 py-3 bg-slate-700 border rounded-lg text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-opacity-50 transition-all ${
                      errors.confirmPassword ? "border-red-500 focus:ring-red-500" : "border-slate-600 focus:border-blue-500 focus:ring-blue-500"
                    }`}
                    disabled={loading}
                  />
                  <button
                    type="button"
                    onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                    className="absolute right-3 top-3.5 text-slate-400 hover:text-blue-400 transition-colors disabled:opacity-50"
                    disabled={loading}
                  >
                    {showConfirmPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                  </button>
                </div>
                {errors.confirmPassword && <p className="text-red-400 text-sm mt-1">{errors.confirmPassword}</p>}
              </div>

              {/* Register Button */}
              <button
                onClick={register}
                disabled={loading || success}
                className="w-full py-3 mt-6 bg-gradient-to-r from-blue-500 to-cyan-500 text-white font-bold rounded-lg hover:from-blue-600 hover:to-cyan-600 disabled:from-slate-600 disabled:to-slate-600 transition-all shadow-lg hover:shadow-blue-500/50 disabled:shadow-none flex items-center justify-center gap-2"
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
              </button>

              {/* Password Requirements */}
              {form.password && (
                <div className="mt-4 p-4 bg-slate-700 bg-opacity-50 rounded-lg">
                  <p className="text-slate-300 text-xs font-semibold mb-2">Password requirements:</p>
                  <ul className="space-y-1 text-xs text-slate-400">
                    <li className={form.password.length >= 8 ? "text-green-400" : ""}>
                      ✓ At least 8 characters
                    </li>
                    <li className={/(?=.*[a-z])/.test(form.password) ? "text-green-400" : ""}>
                      ✓ Lowercase letters
                    </li>
                    <li className={/(?=.*[A-Z])/.test(form.password) ? "text-green-400" : ""}>
                      ✓ Uppercase letters
                    </li>
                    <li className={/(?=.*\d)/.test(form.password) ? "text-green-400" : ""}>
                      ✓ Numbers
                    </li>
                    <li className={/(?=.*[@$!%*?&])/.test(form.password) ? "text-green-400" : ""}>
                      ✓ Special characters (@$!%*?&)
                    </li>
                  </ul>
                </div>
              )}
            </div>

            {/* Divider */}
            <div className="my-6 flex items-center gap-3">
              <div className="flex-1 h-px bg-slate-700"></div>
              <span className="text-slate-400 text-sm">Already registered?</span>
              <div className="flex-1 h-px bg-slate-700"></div>
            </div>

            {/* Login Link */}
            <div className="text-center">
              <p className="text-slate-400">
                Have an account?{" "}
                <a
                  href="/login"
                  className="text-blue-400 hover:text-blue-300 font-semibold transition-colors"
                >
                  Sign in here
                </a>
              </p>
            </div>
          </div>
        </div>

        {/* Footer Text */}
        <div className="mt-6 text-center text-slate-400 text-sm">
          <p>🔐 Your data is protected with military-grade encryption</p>
        </div>
      </div>
    </div>
  );
}