"use client";

import { useEffect, useState } from "react";
import { useRouter, usePathname } from "next/navigation";
import Link from "next/link";
import { Bell, ChevronRight, LogOut, Menu, Settings, ShieldCheck, User as UserIcon } from "lucide-react";
import toast from "react-hot-toast";
import api from "@/lib/api";
import { navItems } from "./navItems";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Sheet, SheetContent, SheetTitle } from "@/components/ui/sheet";
import SidebarNav from "./SidebarNav";

type SecurityEventEntry = {
  id: string;
  type: string;
  message: string;
  createdAt: string;
};

export default function Topbar() {
  const router = useRouter();
  const pathname = usePathname();
  const [mobileOpen, setMobileOpen] = useState(false);
  const [events, setEvents] = useState<SecurityEventEntry[]>([]);
  const [user, setUser] = useState<{ email?: string; name?: string } | null>(() => {
    if (typeof window === "undefined") return null;
    try {
      const raw = localStorage.getItem("user");
      return raw ? JSON.parse(raw) : null;
    } catch {
      return null;
    }
  });

  useEffect(() => {
    const refreshUser = () => {
      try {
        const raw = localStorage.getItem("user");
        setUser(raw ? JSON.parse(raw) : null);
      } catch {
        setUser(null);
      }
    };
    window.addEventListener("auth:changed", refreshUser);
    window.addEventListener("storage", refreshUser);
    return () => {
      window.removeEventListener("auth:changed", refreshUser);
      window.removeEventListener("storage", refreshUser);
    };
  }, []);

  // Fetch notifications once per session rather than on every route change - each page already
  // fetches whatever data it needs, and refetching here on every nav needlessly multiplies
  // requests against the backend's shared rate limiter.
  useEffect(() => {
    const token = localStorage.getItem("token");
    if (!token) return;
    api
      .get<SecurityEventEntry[]>("/security/events", { headers: { Authorization: `Bearer ${token}` } })
      .then((res) => setEvents((res.data || []).slice(0, 5)))
      .catch(() => {});
  }, []);

  const activeItem = navItems.find((item) => pathname === item.href || pathname.startsWith(item.href + "/"));

  const logout = () => {
    localStorage.removeItem("token");
    localStorage.removeItem("user");
    try {
      window.dispatchEvent(new Event("auth:changed"));
    } catch {}
    toast.success("Logged out");
    router.push("/");
  };

  return (
    <header className="sticky top-0 z-40 flex h-16 items-center gap-3 border-b border-border bg-background/80 backdrop-blur-xl px-4 sm:px-6">
      <button
        type="button"
        onClick={() => setMobileOpen(true)}
        aria-label="Open navigation menu"
        className="md:hidden inline-flex h-9 w-9 items-center justify-center rounded-lg text-muted-foreground hover:bg-white/5 hover:text-foreground"
      >
        <Menu size={20} />
      </button>

      <nav aria-label="Breadcrumb" className="hidden sm:flex items-center gap-1.5 text-sm text-muted-foreground">
        <Link href="/dashboard" className="hover:text-foreground transition-colors">
          SecureShare
        </Link>
        {activeItem && (
          <>
            <ChevronRight size={14} />
            <span className="font-medium text-foreground">{activeItem.label}</span>
          </>
        )}
      </nav>

      <div className="ml-auto flex items-center gap-2">
        <DropdownMenu>
          <DropdownMenuTrigger
            aria-label="Notifications"
            className="relative inline-flex h-9 w-9 items-center justify-center rounded-lg text-muted-foreground hover:bg-white/5 hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/60"
          >
            <Bell size={18} />
            {events.length > 0 && (
              <span className="absolute top-1.5 right-1.5 h-2 w-2 rounded-full bg-destructive ring-2 ring-background" />
            )}
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-80">
            <DropdownMenuGroup>
              <DropdownMenuLabel>Recent security events</DropdownMenuLabel>
              <DropdownMenuSeparator />
              {events.length === 0 ? (
                <p className="px-2 py-3 text-sm text-muted-foreground">No recent activity.</p>
              ) : (
                events.map((e) => (
                  <DropdownMenuItem key={e.id} className="flex-col items-start gap-0.5 whitespace-normal">
                    <span className="text-xs text-foreground">{e.message}</span>
                    <span className="text-[11px] text-muted-foreground">{new Date(e.createdAt).toLocaleString()}</span>
                  </DropdownMenuItem>
                ))
              )}
              <DropdownMenuSeparator />
              <DropdownMenuItem onClick={() => router.push("/audit")}>View all in Audit Logs</DropdownMenuItem>
            </DropdownMenuGroup>
          </DropdownMenuContent>
        </DropdownMenu>

        <DropdownMenu>
          <DropdownMenuTrigger
            aria-label="Account menu"
            className="inline-flex items-center gap-2 rounded-lg px-2 py-1.5 hover:bg-white/5 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/60"
          >
            <span className="inline-flex h-7 w-7 items-center justify-center rounded-full bg-primary/15 text-primary ring-1 ring-primary/30">
              <UserIcon size={15} />
            </span>
            <span className="hidden sm:block text-sm font-medium text-foreground max-w-[140px] truncate">
              {user?.name || user?.email || "Account"}
            </span>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-56">
            <DropdownMenuGroup>
              <DropdownMenuLabel>{user?.email || "Signed in"}</DropdownMenuLabel>
              <DropdownMenuSeparator />
              <DropdownMenuItem onClick={() => router.push("/settings")}>
                <Settings size={14} /> Settings
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => router.push("/security")}>
                <ShieldCheck size={14} /> Security Center
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem variant="destructive" onClick={logout}>
                <LogOut size={14} /> Logout
              </DropdownMenuItem>
            </DropdownMenuGroup>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>

      <Sheet open={mobileOpen} onOpenChange={setMobileOpen}>
        <SheetContent side="left" className="w-72 p-0 bg-sidebar">
          <SheetTitle className="sr-only">Navigation</SheetTitle>
          <SidebarNav onNavigate={() => setMobileOpen(false)} />
        </SheetContent>
      </Sheet>
    </header>
  );
}
