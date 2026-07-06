"use client";

import { useCallback, useEffect, useMemo, useRef, useState, type KeyboardEvent as ReactKeyboardEvent } from "react";
import { useRouter } from "next/navigation";
import { Cloud, Files, Fingerprint, ClipboardCheck, ScanSearch, Radar, Clock, type LucideIcon } from "lucide-react";
import api from "@/lib/api";
import { Dialog, DialogContent, DialogTitle } from "@/components/ui/dialog";
import SearchInput from "@/components/design/SearchInput";
import { Spinner } from "@/components/design/Loader";
import { cn } from "@/lib/utils";
import { useRole } from "@/hooks/useRole";

type ResultItem = {
  id: string;
  title: string;
  subtitle?: string;
  href: string;
};

type Category = {
  id: string;
  label: string;
  icon: LucideIcon;
  href: string;
  fetch: (token: string) => Promise<ResultItem[]>;
  match: (item: ResultItem, query: string) => boolean;
  /** Backed by an admin-only endpoint (see backend/routes/{iam,compliance,cloud}.routes.js) -
   *  excluded from non-admin searches so it never fires a needless 403 or surfaces org-wide data. */
  adminOnly?: boolean;
};

const authHeaders = (token: string) => ({ headers: { Authorization: `Bearer ${token}` } });

const CATEGORIES: Category[] = [
  {
    id: "files",
    label: "Files",
    icon: Files,
    href: "/files",
    fetch: async (token) => {
      const res = await api.get<{ _id: string; filename: string }[]>("/files/my-files", authHeaders(token));
      return (res.data || []).map((f) => ({ id: f._id, title: f.filename, href: "/files" }));
    },
    match: (item, q) => item.title.toLowerCase().includes(q),
  },
  {
    id: "threats",
    label: "Threats",
    icon: ScanSearch,
    href: "/threats",
    fetch: async (token) => {
      const res = await api.get<{ _id: string; originalFilename?: string; riskLevel?: string }[]>(
        "/threats/scans",
        authHeaders(token)
      );
      return (res.data || []).map((s) => ({
        id: s._id,
        title: s.originalFilename || "Untitled scan",
        subtitle: s.riskLevel ? `Risk: ${s.riskLevel}` : undefined,
        href: "/threats",
      }));
    },
    match: (item, q) => item.title.toLowerCase().includes(q),
  },
  {
    id: "incidents",
    label: "Incidents",
    icon: Radar,
    href: "/soc",
    fetch: async (token) => {
      const res = await api.get<{ id: string; title: string; summary?: string }[]>("/siem/incidents", authHeaders(token));
      return (res.data || []).map((i) => ({ id: i.id, title: i.title, subtitle: i.summary, href: "/soc" }));
    },
    match: (item, q) => item.title.toLowerCase().includes(q) || (item.subtitle || "").toLowerCase().includes(q),
  },
  {
    id: "users",
    label: "Users",
    icon: Fingerprint,
    href: "/identity",
    adminOnly: true,
    fetch: async (token) => {
      const res = await api.get<{ _id: string; name?: string; email: string }[]>("/iam/users", authHeaders(token));
      return (res.data || []).map((u) => ({ id: u._id, title: u.name || u.email, subtitle: u.email, href: "/identity" }));
    },
    match: (item, q) => item.title.toLowerCase().includes(q) || (item.subtitle || "").toLowerCase().includes(q),
  },
  {
    id: "compliance",
    label: "Compliance",
    icon: ClipboardCheck,
    href: "/compliance",
    adminOnly: true,
    fetch: async (token) => {
      const res = await api.get<{ _id: string; summary: string; control: { title: string } | null }[]>(
        "/compliance/evidence",
        authHeaders(token)
      );
      return (res.data || []).map((e) => ({
        id: e._id,
        title: e.control?.title || "Compliance evidence",
        subtitle: e.summary,
        href: "/compliance",
      }));
    },
    match: (item, q) => item.title.toLowerCase().includes(q) || (item.subtitle || "").toLowerCase().includes(q),
  },
  {
    id: "cloud-assets",
    label: "Cloud Assets",
    icon: Cloud,
    href: "/cloud-security/assets",
    adminOnly: true,
    fetch: async (token) => {
      const res = await api.get<{ _id: string; name: string; type?: string }[]>("/cloud/assets", authHeaders(token));
      return (res.data || []).map((a) => ({ id: a._id, title: a.name, subtitle: a.type, href: "/cloud-security/assets" }));
    },
    match: (item, q) => item.title.toLowerCase().includes(q),
  },
];

const RESULTS_PER_CATEGORY = 5;
const RECENT_KEY = "secureshare:quicksearch:recent";
const MAX_RECENT = 5;

function loadRecent(): string[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = localStorage.getItem(RECENT_KEY);
    const parsed = raw ? JSON.parse(raw) : [];
    return Array.isArray(parsed) ? parsed.filter((v) => typeof v === "string") : [];
  } catch {
    return [];
  }
}

function saveRecent(terms: string[]) {
  try {
    localStorage.setItem(RECENT_KEY, JSON.stringify(terms));
  } catch {}
}

type FlatEntry =
  | { kind: "recent"; term: string }
  | { kind: "result"; item: ResultItem; icon: LucideIcon };

/** Global Ctrl/Cmd+K command palette. Searches across the domains already exposed by existing
 *  list endpoints (files, threats, incidents, users, compliance evidence, cloud assets) - fetched
 *  once per open and filtered client-side, the same pattern individual pages already use. */
export default function QuickSearch() {
  const router = useRouter();
  const { isAdmin } = useRole();
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [loading, setLoading] = useState(false);
  const [resultsByCategory, setResultsByCategory] = useState<Record<string, ResultItem[]>>({});
  const [recent, setRecent] = useState<string[]>([]);
  const [highlightedIndex, setHighlightedIndex] = useState(0);
  const listRef = useRef<HTMLDivElement>(null);

  const categories = useMemo(() => CATEGORIES.filter((cat) => !cat.adminOnly || isAdmin), [isAdmin]);

  const loadAll = useCallback(async () => {
    const token = localStorage.getItem("token");
    if (!token) return;
    setLoading(true);
    try {
      const entries = await Promise.all(
        categories.map(async (cat) => {
          try {
            return [cat.id, await cat.fetch(token)] as const;
          } catch {
            return [cat.id, []] as const;
          }
        })
      );
      setResultsByCategory(Object.fromEntries(entries));
    } finally {
      setLoading(false);
    }
  }, [categories]);

  useEffect(() => {
    const openPalette = () => setOpen(true);
    const onKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setOpen((prev) => !prev);
      }
    };
    window.addEventListener("quicksearch:open", openPalette);
    window.addEventListener("keydown", onKeyDown);
    return () => {
      window.removeEventListener("quicksearch:open", openPalette);
      window.removeEventListener("keydown", onKeyDown);
    };
  }, []);

  useEffect(() => {
    if (open) {
      setQuery("");
      setRecent(loadRecent());
      loadAll();
    }
  }, [open, loadAll]);

  const grouped = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return [];
    return categories
      .map((cat) => ({
        category: cat,
        items: (resultsByCategory[cat.id] || []).filter((item) => cat.match(item, q)).slice(0, RESULTS_PER_CATEGORY),
      }))
      .filter((group) => group.items.length > 0);
  }, [query, resultsByCategory, categories]);

  const flatList: FlatEntry[] = useMemo(() => {
    if (!query.trim()) return recent.map((term) => ({ kind: "recent", term }) as const);
    return grouped.flatMap(({ category, items }) => items.map((item) => ({ kind: "result", item, icon: category.icon }) as const));
  }, [query, recent, grouped]);

  useEffect(() => {
    setHighlightedIndex(0);
  }, [flatList.length, query]);

  const rememberSearch = (term: string) => {
    const trimmed = term.trim();
    if (!trimmed) return;
    const next = [trimmed, ...recent.filter((t) => t.toLowerCase() !== trimmed.toLowerCase())].slice(0, MAX_RECENT);
    setRecent(next);
    saveRecent(next);
  };

  const goTo = (href: string) => {
    rememberSearch(query);
    setOpen(false);
    router.push(href);
  };

  const selectEntry = (entry: FlatEntry) => {
    if (entry.kind === "recent") {
      setQuery(entry.term);
    } else {
      goTo(entry.item.href);
    }
  };

  const onListKeyDown = (e: ReactKeyboardEvent) => {
    if (flatList.length === 0) return;
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setHighlightedIndex((i) => Math.min(i + 1, flatList.length - 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setHighlightedIndex((i) => Math.max(i - 1, 0));
    } else if (e.key === "Enter") {
      e.preventDefault();
      selectEntry(flatList[highlightedIndex]);
    }
  };

  let flatIndex = -1;

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogContent className="top-[20%] max-w-lg translate-y-0 p-0 sm:max-w-lg" showCloseButton={false}>
        <DialogTitle className="sr-only">Quick search</DialogTitle>
        <div className="p-3" onKeyDown={onListKeyDown}>
          <SearchInput value={query} onChange={setQuery} placeholder="Search files, threats, incidents, users…" autoFocus />
        </div>
        <div ref={listRef} className="max-h-[60vh] overflow-y-auto border-t border-border" onKeyDown={onListKeyDown}>
          {loading ? (
            <div className="flex items-center justify-center gap-2 py-8 text-sm text-muted-foreground">
              <Spinner size={14} /> Loading…
            </div>
          ) : !query.trim() ? (
            recent.length === 0 ? (
              <p className="px-4 py-8 text-center text-sm text-muted-foreground">
                Start typing to search across files, threats, incidents, users, compliance, and cloud assets.
              </p>
            ) : (
              <div className="py-2">
                <p className="px-4 py-1 text-xs font-medium uppercase tracking-wide text-muted-foreground">Recent searches</p>
                {recent.map((term) => {
                  flatIndex += 1;
                  const idx = flatIndex;
                  return (
                    <button
                      key={term}
                      type="button"
                      onClick={() => selectEntry({ kind: "recent", term })}
                      onMouseEnter={() => setHighlightedIndex(idx)}
                      className={cn(
                        "flex w-full items-center gap-3 px-4 py-2 text-left text-sm",
                        idx === highlightedIndex ? "bg-white/5 text-foreground" : "hover:bg-white/5"
                      )}
                    >
                      <Clock size={15} className="shrink-0 text-muted-foreground" />
                      <span className="min-w-0 flex-1 truncate text-foreground">{term}</span>
                    </button>
                  );
                })}
              </div>
            )
          ) : grouped.length === 0 ? (
            <p className="px-4 py-8 text-center text-sm text-muted-foreground">No results for &ldquo;{query}&rdquo;.</p>
          ) : (
            grouped.map(({ category, items }) => (
              <div key={category.id} className="border-b border-border py-2 last:border-b-0">
                <p className="px-4 py-1 text-xs font-medium uppercase tracking-wide text-muted-foreground">
                  {category.label}
                </p>
                {items.map((item) => {
                  flatIndex += 1;
                  const idx = flatIndex;
                  return (
                    <button
                      key={item.id}
                      type="button"
                      onClick={() => goTo(item.href)}
                      onMouseEnter={() => setHighlightedIndex(idx)}
                      className={cn(
                        "flex w-full items-center gap-3 px-4 py-2 text-left text-sm",
                        idx === highlightedIndex ? "bg-white/5 text-foreground" : "hover:bg-white/5"
                      )}
                    >
                      <category.icon size={15} className="shrink-0 text-muted-foreground" />
                      <span className="min-w-0 flex-1">
                        <span className="block truncate text-foreground">{item.title}</span>
                        {item.subtitle && <span className="block truncate text-xs text-muted-foreground">{item.subtitle}</span>}
                      </span>
                    </button>
                  );
                })}
              </div>
            ))
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}
