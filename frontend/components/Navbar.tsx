"use client";
import { useEffect, useState } from "react";
import { useRouter, usePathname } from "next/navigation";
import { Upload, LogOut, Lock, LogIn, UserPlus } from "lucide-react";
import toast from "react-hot-toast";

export default function Navbar() {
  const router = useRouter();
  const pathname = usePathname();
  const [isAuthed, setIsAuthed] = useState(false);

  useEffect(() => {
    const hasToken = !!localStorage.getItem("token");
    setIsAuthed(hasToken);

    const onStorage = (e: StorageEvent) => {
      if (e.key === "token") setIsAuthed(!!(e.newValue));
    };
    const onAuthChanged = () => setIsAuthed(!!localStorage.getItem("token"));
    const onFocus = () => setIsAuthed(!!localStorage.getItem("token"));
    window.addEventListener("storage", onStorage);
    window.addEventListener("auth:changed", onAuthChanged as EventListener);
    window.addEventListener("focus", onFocus);
    return () => window.removeEventListener("storage", onStorage);
  }, []);

  // Re-evaluate auth when route changes
  useEffect(() => {
    setIsAuthed(!!localStorage.getItem("token"));
  }, [pathname]);

  const logout = () => {
    localStorage.removeItem("token");
    localStorage.removeItem("user");
    setIsAuthed(false);
    try { window.dispatchEvent(new Event("auth:changed")); } catch {}
    toast.success("Logged out");
    router.push("/");
  };

  return (
    <nav className="sticky top-0 z-50 bg-gradient-to-r from-slate-900 via-slate-800 to-slate-900 border-b border-slate-700 backdrop-blur-sm">
      <div className="max-w-6xl mx-auto px-4">
        <div className="flex justify-between items-center h-16">
          {/* Logo */}
          <button
            onClick={() => router.push(isAuthed ? "/dashboard" : "/")}
            className="flex items-center gap-2 hover:opacity-80 transition-opacity"
          >
            <div className="bg-gradient-to-r from-blue-500 to-cyan-500 p-2 rounded-lg">
              <Lock size={20} className="text-white" />
            </div>
            <span className="text-xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-blue-400 to-cyan-400">
              SecureShare
            </span>
          </button>

          {/* Navigation */}
          <div className="flex items-center gap-4">
            {isAuthed ? (
              <>
                <button
                  onClick={() => router.push("/upload")}
                  className="flex items-center gap-2 px-4 py-2 text-slate-300 hover:text-white hover:bg-slate-700 rounded-lg transition-all"
                >
                  <Upload size={18} />
                  Upload
                </button>
                <button
                  onClick={() => router.push("/dashboard")}
                  className="flex items-center gap-2 px-4 py-2 text-slate-300 hover:text-white hover:bg-slate-700 rounded-lg transition-all"
                >
                  DashBoard
                </button>
                <button
                  onClick={logout}
                  className="flex items-center gap-2 px-4 py-2 text-red-400 hover:text-red-300 hover:bg-red-500 hover:bg-opacity-10 rounded-lg transition-all"
                >
                  <LogOut size={18} />
                  Logout
                </button>
              </>
            ) : (
              <>
                <button
                  onClick={() => router.push("/login")}
                  className="flex items-center gap-2 px-4 py-2 text-slate-300 hover:text-white hover:bg-slate-700 rounded-lg transition-all"
                >
                  <LogIn size={18} />
                  Login
                </button>
                <button
                  onClick={() => router.push("/register")}
                  className="flex items-center gap-2 px-4 py-2 text-blue-300 hover:text-white hover:bg-blue-600/20 rounded-lg transition-all"
                >
                  <UserPlus size={18} />
                  Register
                </button>
              </>
            )}
          </div>
        </div>
      </div>
    </nav>
  );
}