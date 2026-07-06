"use client";

import { useEffect, type ReactNode } from "react";
import { useRouter } from "next/navigation";
import { useRole, type RoleState } from "@/hooks/useRole";
import { Spinner } from "@/components/design/Loader";

/** "admin" covers the isAdmin flag plus the administrator/org_owner roles (see lib/auth.ts::getIsAdminFromToken). */
export type RoleRequirement = "admin" | "org_owner";

function isAuthorized(requirement: RoleRequirement, state: RoleState): boolean {
  return requirement === "org_owner" ? state.isOrgOwner : state.isAdmin;
}

/**
 * Hides `children` from the DOM entirely (not just disabled) unless the current user meets
 * `role`. Use for nav items, dashboard cards, buttons, and any other UI that must not be visible
 * to non-admins - never render admin affordances and disable them, since that still leaks their
 * existence.
 */
export function RoleGuard({
  role,
  children,
  fallback = null,
}: {
  role: RoleRequirement;
  children: ReactNode;
  fallback?: ReactNode;
}) {
  const state = useRole();
  if (!state.ready || !isAuthorized(role, state)) return <>{fallback}</>;
  return <>{children}</>;
}

/** Convenience wrapper for the common "hide unless admin" case. */
export function AdminOnly({ children, fallback = null }: { children: ReactNode; fallback?: ReactNode }) {
  return (
    <RoleGuard role="admin" fallback={fallback}>
      {children}
    </RoleGuard>
  );
}

/**
 * Full route protection for admin-only pages: blocks rendering of `children` and redirects
 * unauthorized/unauthenticated visitors to /403 (or /login), so manually typing an admin URL
 * never flashes real data before bouncing. The backend's requireAdmin/requireRole middleware is
 * the actual security boundary - this only prevents a confusing or broken screen client-side.
 */
export function RequireRole({ role, children }: { role: RoleRequirement; children: ReactNode }) {
  const state = useRole();
  const router = useRouter();
  const authorized = isAuthorized(role, state);

  useEffect(() => {
    if (!state.ready) return;
    if (!state.isAuthenticated) {
      router.push("/login");
    } else if (!authorized) {
      router.push("/403");
    }
  }, [state.ready, state.isAuthenticated, authorized, router]);

  if (!state.ready || !state.isAuthenticated || !authorized) {
    return (
      <div className="flex h-64 items-center justify-center">
        <Spinner size={20} />
      </div>
    );
  }

  return <>{children}</>;
}
