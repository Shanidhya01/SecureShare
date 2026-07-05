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
  Crosshair,
  Bot,
  Fingerprint,
  ClipboardCheck,
  Cloud,
  ShieldHalf,
  Activity,
  type LucideIcon,
} from "lucide-react";

export type NavItem = {
  label: string;
  href: string;
  icon: LucideIcon;
  group: string;
};

export const navItems: NavItem[] = [
  { label: "Dashboard", href: "/dashboard", icon: LayoutDashboard, group: "Overview" },
  { label: "Files", href: "/files", icon: Files, group: "Files" },
  { label: "Upload", href: "/upload", icon: UploadCloud, group: "Files" },
  { label: "Threat Center", href: "/threats", icon: ScanSearch, group: "Security Operations" },
  { label: "DLP Center", href: "/dlp", icon: Eye, group: "Security Operations" },
  { label: "Threat Intelligence", href: "/threat-intelligence", icon: Crosshair, group: "Security Operations" },
  { label: "SOAR", href: "/soar", icon: Bot, group: "Security Operations" },
  { label: "Security Center", href: "/security", icon: ShieldCheck, group: "Security Operations" },
  { label: "Security Operations", href: "/soc", icon: Radar, group: "Security Operations" },
  { label: "Identity & Access", href: "/identity", icon: Fingerprint, group: "Identity & Governance" },
  { label: "Compliance", href: "/compliance", icon: ClipboardCheck, group: "Identity & Governance" },
  { label: "Cloud Security", href: "/cloud-security", icon: Cloud, group: "Platform" },
  { label: "DevSecOps", href: "/devsecops", icon: ShieldHalf, group: "Platform" },
  { label: "Platform", href: "/platform", icon: Activity, group: "Platform" },
  { label: "Analytics", href: "/analytics", icon: BarChart3, group: "Insights" },
  { label: "Audit Logs", href: "/audit", icon: ScrollText, group: "Insights" },
  { label: "Settings", href: "/settings", icon: Settings, group: "Account" },
];
