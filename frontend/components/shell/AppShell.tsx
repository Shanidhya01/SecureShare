"use client";

import { useEffect, useState } from "react";
import { usePathname } from "next/navigation";
import { AnimatePresence, motion } from "framer-motion";
import SidebarNav from "./SidebarNav";
import Topbar from "./Topbar";
import { pageTransition } from "@/lib/motion";

const STANDALONE_ROUTES = ["/", "/login", "/register"];

function isStandaloneRoute(pathname: string): boolean {
  if (STANDALONE_ROUTES.includes(pathname)) return true;
  // Public share-link download page (/file/:id) - not /file/:id/logs, which is an owner-only
  // management view and does belong inside the authenticated app shell.
  if (/^\/file\/[^/]+$/.test(pathname)) return true;
  return false;
}

export default function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const [isAuthed, setIsAuthed] = useState(false);

  useEffect(() => {
    const check = () => setIsAuthed(!!localStorage.getItem("token"));
    check();
    window.addEventListener("storage", check);
    window.addEventListener("auth:changed", check);
    window.addEventListener("focus", check);
    return () => {
      window.removeEventListener("storage", check);
      window.removeEventListener("auth:changed", check);
      window.removeEventListener("focus", check);
    };
  }, [pathname]);

  const standalone = isStandaloneRoute(pathname) || !isAuthed;

  if (standalone) {
    return (
      <AnimatePresence mode="wait">
        <motion.div key={pathname} variants={pageTransition} initial="hidden" animate="show" exit="exit">
          {children}
        </motion.div>
      </AnimatePresence>
    );
  }

  return (
    <div className="min-h-screen bg-background">
      <div className="hidden md:fixed md:inset-y-0 md:left-0 md:z-30 md:flex md:w-64 md:flex-col md:border-r md:border-border md:bg-sidebar">
        <SidebarNav />
      </div>
      <div className="md:pl-64">
        <Topbar />
        <main className="px-4 py-6 sm:px-6 lg:px-8">
          <AnimatePresence mode="wait">
            <motion.div key={pathname} variants={pageTransition} initial="hidden" animate="show" exit="exit">
              {children}
            </motion.div>
          </AnimatePresence>
        </main>
      </div>
    </div>
  );
}
