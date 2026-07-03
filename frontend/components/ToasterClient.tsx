"use client";
import { Toaster, ToastBar, toast, type Toast } from "react-hot-toast";
import { CheckCircle2, XCircle, Loader2, Info, X as Close } from "lucide-react";
import { useEffect, useState } from "react";

export default function ToasterClient() {
  return (
    <Toaster
      position="top-center"
      gutter={12}
      containerClassName=""
      containerStyle={{
        top: 20,
        right: 20,
      }}
      toastOptions={{
        duration: 3500,
        className: "",
        style: {
          background: "transparent",
          boxShadow: "none",
          padding: 0,
        },
        success: {
          duration: 3000,
        },
        error: {
          duration: 5000,
        },
        loading: {
          duration: Infinity,
        },
      }}
    >
      {(t) => (
        <EnhancedToast
          toast={t}
          onDismiss={() => toast.dismiss(t.id)}
        />
      )}
    </Toaster>
  );
}

interface EnhancedToastProps {
  toast: Toast;
  onDismiss: () => void;
}

function EnhancedToast({ toast: t, onDismiss }: EnhancedToastProps) {
  const [progress, setProgress] = useState(100);
  const [isHovered, setIsHovered] = useState(false);

  // Progress bar animation
  useEffect(() => {
    if (t.type === "loading" || !t.duration || t.pauseDuration > 0) return;

    const startTime = Date.now();
    const duration = t.duration;

    const interval = setInterval(() => {
      if (isHovered) return; // Pause on hover

      const elapsed = Date.now() - startTime;
      const remaining = Math.max(0, 100 - (elapsed / duration) * 100);
      setProgress(remaining);

      if (remaining === 0) {
        clearInterval(interval);
      }
    }, 16); // ~60fps

    return () => clearInterval(interval);
  }, [t.duration, t.type, t.pauseDuration, isHovered]);

  const getTypeStyles = () => {
    switch (t.type) {
      case "success":
        return {
          border: "border-l-4 border-l-cyan-400",
          icon: <CheckCircle2 className="h-5 w-5 text-cyan-400 animate-in zoom-in-50 duration-200" />,
          progress: "bg-gradient-to-r from-cyan-500 to-cyan-400",
          glow: "shadow-cyan-500/20",
        };
      case "error":
        return {
          border: "border-l-4 border-l-rose-400",
          icon: <XCircle className="h-5 w-5 text-rose-400 animate-in zoom-in-50 duration-200" />,
          progress: "bg-gradient-to-r from-rose-500 to-rose-400",
          glow: "shadow-rose-500/20",
        };
      case "loading":
        return {
          border: "border-l-4 border-l-blue-400",
          icon: <Loader2 className="h-5 w-5 text-blue-400 animate-spin" />,
          progress: "bg-gradient-to-r from-blue-500 to-blue-400",
          glow: "shadow-blue-500/20",
        };
      default:
        return {
          border: "border-l-4 border-l-slate-400",
          icon: <Info className="h-5 w-5 text-slate-300 animate-in zoom-in-50 duration-200" />,
          progress: "bg-gradient-to-r from-slate-500 to-slate-400",
          glow: "shadow-slate-500/20",
        };
    }
  };

  const styles = getTypeStyles();

  return (
    <ToastBar toast={t}>
      {({ message }) => (
        <div
          className={`
            group relative overflow-hidden
            bg-slate-900/95 backdrop-blur-xl
            border border-slate-700/80 ${styles.border}
            rounded-xl shadow-2xl ${styles.glow}
            transition-all duration-300 ease-out
            ${t.visible ? "animate-in slide-in-from-right-full" : "animate-out slide-out-to-right-full"}
            hover:scale-[1.02] hover:shadow-3xl
            min-w-[320px] max-w-md
          `}
          onMouseEnter={() => setIsHovered(true)}
          onMouseLeave={() => setIsHovered(false)}
          role="alert"
          aria-atomic="true"
        >
          {/* Background gradient effect */}
          <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/[0.02] to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500" />
          
          {/* Content */}
          <div className="relative flex items-center gap-3 px-4 py-3">
            {/* Icon with pulse effect */}
            <div className="shrink-0 relative">
              <div className={`absolute inset-0 ${t.type === 'success' ? 'bg-cyan-400/20' : t.type === 'error' ? 'bg-rose-400/20' : 'bg-blue-400/20'} rounded-full blur-md animate-pulse`} />
              <div className="relative">{styles.icon}</div>
            </div>

            {/* Message */}
            <div className="flex-1 min-w-0">
              <div className="text-sm font-medium text-slate-100 leading-relaxed break-words">
                {message}
              </div>
            </div>

            {/* Close button with enhanced hover */}
            {t.type !== "loading" && (
              <button
                onClick={onDismiss}
                aria-label="Dismiss notification"
                className="
                  shrink-0 p-1 rounded-md
                  text-slate-400 hover:text-slate-100
                  hover:bg-slate-700/50
                  transition-all duration-200
                  focus:outline-none focus:ring-2 focus:ring-cyan-400/50
                  active:scale-95
                "
              >
                <Close className="h-4 w-4" />
              </button>
            )}
          </div>

          {/* Progress bar */}
          {t.type !== "loading" && t.duration && (
            <div className="absolute bottom-0 left-0 right-0 h-1 bg-slate-800/50 overflow-hidden">
              <div
                className={`h-full transition-all duration-100 ease-linear ${styles.progress}`}
                style={{
                  width: `${progress}%`,
                  opacity: isHovered ? 0.5 : 1,
                }}
              />
            </div>
          )}

          {/* Animated shine effect on success */}
          {t.type === "success" && (
            <div className="absolute inset-0 pointer-events-none overflow-hidden">
              <div className="absolute inset-0 translate-x-[-100%] group-hover:translate-x-[100%] bg-gradient-to-r from-transparent via-white/10 to-transparent transition-transform duration-1000" />
            </div>
          )}
        </div>
      )}
    </ToastBar>
  );
}
