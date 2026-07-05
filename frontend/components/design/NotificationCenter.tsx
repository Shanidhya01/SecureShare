"use client";

import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { Archive, Bell, CheckCheck } from "lucide-react";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import StatusBadge from "@/components/design/StatusBadge";
import { securityEventTypeLabel, securityEventTypeTone, type SecurityEventEntry } from "@/lib/securityEvents";
import { cn } from "@/lib/utils";

const STORAGE_KEY = "secureshare:notifications:state";

type NotificationState = { read: string[]; archived: string[] };

function loadState(): NotificationState {
  if (typeof window === "undefined") return { read: [], archived: [] };
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return { read: [], archived: [] };
    const parsed = JSON.parse(raw);
    return { read: Array.isArray(parsed.read) ? parsed.read : [], archived: Array.isArray(parsed.archived) ? parsed.archived : [] };
  } catch {
    return { read: [], archived: [] };
  }
}

function saveState(state: NotificationState) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
  } catch {}
}

const FILTERS = ["all", "unread"] as const;
type Filter = (typeof FILTERS)[number];

/** Notification center backed by the same /security/events feed Topbar already fetches - there's
 *  no backend read/archived-state endpoint, so unread/archived status is tracked client-side in
 *  localStorage (same pattern as the display-only preferences in app/settings/page.tsx). */
export default function NotificationCenter({ events }: { events: SecurityEventEntry[] }) {
  const router = useRouter();
  const [state, setState] = useState<NotificationState>({ read: [], archived: [] });
  const [filter, setFilter] = useState<Filter>("all");

  useEffect(() => {
    const syncState = () => setState(loadState());
    syncState();
  }, []);

  const visible = useMemo(
    () => events.filter((e) => !state.archived.includes(e.id) && (filter === "all" || !state.read.includes(e.id))),
    [events, state, filter]
  );
  const unreadCount = useMemo(
    () => events.filter((e) => !state.archived.includes(e.id) && !state.read.includes(e.id)).length,
    [events, state]
  );

  const markRead = (id: string) => {
    setState((prev) => {
      if (prev.read.includes(id)) return prev;
      const next = { ...prev, read: [...prev.read, id] };
      saveState(next);
      return next;
    });
  };

  const archive = (id: string) => {
    setState((prev) => {
      if (prev.archived.includes(id)) return prev;
      const next = { ...prev, archived: [...prev.archived, id] };
      saveState(next);
      return next;
    });
  };

  const markAllRead = () => {
    setState((prev) => {
      const next = { ...prev, read: Array.from(new Set([...prev.read, ...events.map((e) => e.id)])) };
      saveState(next);
      return next;
    });
  };

  return (
    <DropdownMenu>
      <DropdownMenuTrigger
        aria-label={unreadCount > 0 ? `Notifications, ${unreadCount} unread` : "Notifications"}
        className="relative inline-flex h-9 w-9 items-center justify-center rounded-lg text-muted-foreground hover:bg-white/5 hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/60"
      >
        <Bell size={18} />
        {unreadCount > 0 && (
          <span className="absolute top-1 right-1 inline-flex h-4 min-w-4 items-center justify-center rounded-full bg-destructive px-1 text-[9px] font-bold text-white ring-2 ring-background">
            {unreadCount > 9 ? "9+" : unreadCount}
          </span>
        )}
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-96">
        <DropdownMenuGroup>
          <div className="flex items-center justify-between gap-2 px-2 py-1.5">
            <DropdownMenuLabel className="p-0">Notifications</DropdownMenuLabel>
            <div className="flex items-center gap-1">
              {FILTERS.map((f) => (
                <button
                  key={f}
                  type="button"
                  onClick={(e) => {
                    e.preventDefault();
                    setFilter(f);
                  }}
                  className={cn(
                    "rounded-md px-2 py-0.5 text-[11px] font-medium capitalize transition-colors",
                    filter === f ? "bg-primary/15 text-primary" : "text-muted-foreground hover:text-foreground"
                  )}
                >
                  {f}
                </button>
              ))}
            </div>
          </div>
          <DropdownMenuSeparator />
          <div className="max-h-80 overflow-y-auto">
            {visible.length === 0 ? (
              <p className="px-2 py-6 text-center text-sm text-muted-foreground">
                {filter === "unread" ? "No unread notifications." : "No recent activity."}
              </p>
            ) : (
              visible.map((e) => {
                const isRead = state.read.includes(e.id);
                return (
                  <DropdownMenuItem
                    key={e.id}
                    onSelect={(evt) => {
                      evt.preventDefault();
                      markRead(e.id);
                    }}
                    className="flex-col items-start gap-1 whitespace-normal"
                  >
                    <div className="flex w-full items-start justify-between gap-2">
                      <div className="flex items-center gap-1.5">
                        {!isRead && <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-primary" />}
                        <StatusBadge label={securityEventTypeLabel[e.type]} tone={securityEventTypeTone[e.type]} />
                      </div>
                      <button
                        type="button"
                        onClick={(evt) => {
                          evt.stopPropagation();
                          archive(e.id);
                        }}
                        aria-label="Archive notification"
                        className="shrink-0 rounded p-0.5 text-muted-foreground hover:text-foreground"
                      >
                        <Archive size={13} />
                      </button>
                    </div>
                    <span className="text-xs text-foreground">{e.message}</span>
                    <span className="text-[11px] text-muted-foreground">{new Date(e.createdAt).toLocaleString()}</span>
                  </DropdownMenuItem>
                );
              })
            )}
          </div>
          <DropdownMenuSeparator />
          <DropdownMenuItem onClick={markAllRead} disabled={unreadCount === 0}>
            <CheckCheck size={14} /> Mark all as read
          </DropdownMenuItem>
          <DropdownMenuItem onClick={() => router.push("/audit")}>View all in Audit Logs</DropdownMenuItem>
        </DropdownMenuGroup>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
