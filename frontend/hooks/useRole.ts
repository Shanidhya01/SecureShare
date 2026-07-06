"use client";

import { useEffect, useState } from "react";
import { getIsAdminFromToken, getIsOrgOwnerFromToken, getRoleFromToken } from "@/lib/auth";

export type Role = "user" | "moderator" | "security_analyst" | "administrator" | "org_owner";

export type RoleState = {
  /** True once the token has been read at least once (avoids a flash of admin-only UI on first paint). */
  ready: boolean;
  role: Role;
  isAdmin: boolean;
  isOrgOwner: boolean;
  isAuthenticated: boolean;
};

/**
 * Single source of truth for "what can this user see" on the frontend. Reads the same JWT
 * already used by lib/auth.ts - no new storage, no duplicated decode logic. Every RBAC helper
 * component in components/rbac builds on this hook.
 */
export function useRole(): RoleState {
  const [state, setState] = useState<RoleState>({
    ready: false,
    role: "user",
    isAdmin: false,
    isOrgOwner: false,
    isAuthenticated: false,
  });

  useEffect(() => {
    const sync = () => {
      const token = localStorage.getItem("token");
      setState({
        ready: true,
        role: (getRoleFromToken(token) as Role) || "user",
        isAdmin: getIsAdminFromToken(token),
        isOrgOwner: getIsOrgOwnerFromToken(token),
        isAuthenticated: !!token,
      });
    };
    sync();
    window.addEventListener("auth:changed", sync);
    window.addEventListener("storage", sync);
    return () => {
      window.removeEventListener("auth:changed", sync);
      window.removeEventListener("storage", sync);
    };
  }, []);

  return state;
}

/** Alias kept for readability at call sites that are checking "can I do X" rather than "who am I". */
export const usePermissions = useRole;
