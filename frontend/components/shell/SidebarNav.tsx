"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Lock } from "lucide-react";
import { navItems } from "./navItems";
import { cn } from "@/lib/utils";
import { useRole } from "@/hooks/useRole";

function groupItems(items: typeof navItems) {
  const groups: { name: string; items: typeof navItems }[] = [];
  for (const item of items) {
    const last = groups[groups.length - 1];
    if (last && last.name === item.group) {
      last.items.push(item);
    } else {
      groups.push({ name: item.group, items: [item] });
    }
  }
  return groups;
}

export default function SidebarNav({ onNavigate }: { onNavigate?: () => void }) {
  const pathname = usePathname();
  const { isAdmin } = useRole();
  const visibleItems = navItems.filter((item) => !item.adminOnly || isAdmin);
  const groups = groupItems(visibleItems);

  return (
    <div className="flex h-full flex-col">
      <div className="flex items-center gap-2 px-5 py-5">
        <div className="bg-linear-to-br from-primary to-cyan-500 p-2 rounded-lg shadow-(--shadow-sm)">
          <Lock size={18} className="text-white" />
        </div>
        <span className="text-lg font-bold tracking-tight text-foreground">SecureShare</span>
      </div>

      <nav className="flex-1 space-y-4 overflow-y-auto px-3 py-2 scrollbar-thin" aria-label="Primary">
        {groups.map((group) => (
          <div key={group.name}>
            <p className="px-3 pb-1 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground/70">
              {group.name}
            </p>
            <div className="space-y-1">
              {group.items.map((item) => {
                const active = pathname === item.href || pathname.startsWith(item.href + "/");
                const Icon = item.icon;
                return (
                  <Link
                    key={item.href}
                    href={item.href}
                    onClick={onNavigate}
                    aria-current={active ? "page" : undefined}
                    className={cn(
                      "group relative flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/60",
                      active
                        ? "bg-primary/10 text-primary ring-1 ring-primary/25 shadow-(--shadow-sm)"
                        : "text-muted-foreground hover:bg-white/5 hover:text-foreground"
                    )}
                  >
                    {active && <span className="absolute left-0 top-1.5 bottom-1.5 w-0.5 rounded-full bg-primary" />}
                    <Icon size={18} className={cn(active ? "text-primary" : "text-muted-foreground group-hover:text-foreground")} />
                    {item.label}
                  </Link>
                );
              })}
            </div>
          </div>
        ))}
      </nav>

      <div className="px-5 py-4 text-[11px] text-muted-foreground border-t border-border">
        Zero-Trust Secure File Platform
      </div>
    </div>
  );
}
