import {
  LayoutDashboard,
  Files,
  UploadCloud,
  ScanSearch,
  Eye,
  ShieldCheck,
  ScrollText,
  BarChart3,
  Radar,
  Settings,
  type LucideIcon,
} from "lucide-react";

export type NavItem = {
  label: string;
  href: string;
  icon: LucideIcon;
};

export const navItems: NavItem[] = [
  { label: "Dashboard", href: "/dashboard", icon: LayoutDashboard },
  { label: "Files", href: "/files", icon: Files },
  { label: "Upload", href: "/upload", icon: UploadCloud },
  { label: "Threat Center", href: "/threats", icon: ScanSearch },
  { label: "DLP Center", href: "/dlp", icon: Eye },
  { label: "Security Center", href: "/security", icon: ShieldCheck },
  { label: "Security Operations", href: "/soc", icon: Radar },
  { label: "Analytics", href: "/analytics", icon: BarChart3 },
  { label: "Audit Logs", href: "/audit", icon: ScrollText },
  { label: "Settings", href: "/settings", icon: Settings },
];
