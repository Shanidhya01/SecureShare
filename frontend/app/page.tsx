"use client";

import Link from "next/link";
import { motion } from "framer-motion";
import {
  Lock,
  ShieldCheck,
  ScanSearch,
  Eye,
  FileCheck2,
  LogIn,
  ArrowRight,
  Fingerprint,
  Globe2,
} from "lucide-react";
import { fadeInUp, staggerContainer } from "@/lib/motion";

const stats = [
  { label: "Protected Files", value: "E2E Encrypted", icon: Lock },
  { label: "Threats Blocked", value: "Real-time Scanning", icon: ScanSearch },
  { label: "Trusted Devices", value: "Zero Trust Enforced", icon: Fingerprint },
  { label: "Risk Score", value: "Continuously Assessed", icon: ShieldCheck },
  { label: "Zero Trust", value: "Enabled by Default", icon: Globe2 },
];

const features = [
  {
    icon: Lock,
    title: "Zero-Knowledge Encryption",
    desc: "AES-256-GCM end-to-end encryption. Files are encrypted in your browser - the server never sees plaintext.",
  },
  {
    icon: FileCheck2,
    title: "Digital Signatures",
    desc: "Every upload is signed with ECDSA P-256 so recipients can cryptographically verify authenticity and integrity.",
  },
  {
    icon: ShieldCheck,
    title: "Zero Trust Access Control",
    desc: "Per-file policies for allowed countries, IPs, business hours, device limits, and approval requirements.",
  },
  {
    icon: ScanSearch,
    title: "Malware & Threat Detection",
    desc: "Every upload is scanned for malware and dangerous content before it's ever encrypted or stored.",
  },
  {
    icon: Eye,
    title: "Data Loss Prevention",
    desc: "Automatic detection of sensitive data - emails, credit cards, API keys, and private keys - before it leaves your device.",
  },
  {
    icon: Fingerprint,
    title: "Full Audit Trail",
    desc: "Every access, download, and security event is logged so you always know who touched your files.",
  },
];

export default function LandingPage() {
  return (
    <div className="min-h-screen bg-background text-foreground relative overflow-hidden">
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-20 right-10 w-96 h-96 bg-primary rounded-full mix-blend-screen filter blur-3xl opacity-10 animate-pulse" />
        <div
          className="absolute -bottom-8 left-20 w-96 h-96 bg-purple-500 rounded-full mix-blend-screen filter blur-3xl opacity-10 animate-pulse"
          style={{ animationDelay: "2s" }}
        />
        <div
          className="absolute top-1/2 left-1/2 w-96 h-96 bg-cyan-500 rounded-full mix-blend-screen filter blur-3xl opacity-10 animate-pulse"
          style={{ animationDelay: "4s" }}
        />
      </div>

      <header className="relative z-10 max-w-6xl mx-auto px-4 pt-6 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <div className="bg-linear-to-br from-primary to-cyan-500 p-2 rounded-lg">
            <Lock size={18} className="text-white" />
          </div>
          <span className="text-lg font-bold">SecureShare</span>
        </div>
        <div className="flex items-center gap-3">
          <Link href="/login" className="text-sm font-medium text-muted-foreground hover:text-foreground transition-colors">
            Sign in
          </Link>
          <Link
            href="/register"
            className="text-sm font-semibold text-white bg-primary hover:bg-primary/90 rounded-lg px-4 py-2 transition-colors"
          >
            Get Started
          </Link>
        </div>
      </header>

      <section className="relative z-10 max-w-4xl mx-auto px-4 pt-16 pb-20 text-center">
        <motion.div initial="hidden" animate="show" variants={staggerContainer}>
          <motion.div variants={fadeInUp} className="mb-8 flex justify-center">
            <div className="relative">
              <div className="absolute inset-0 bg-linear-to-r from-primary to-cyan-500 rounded-full blur-lg opacity-60" />
              <div className="relative bg-card p-5 rounded-full ring-1 ring-border">
                <ShieldCheck size={52} className="text-primary" />
              </div>
            </div>
          </motion.div>

          <motion.h1 variants={fadeInUp} className="text-4xl md:text-6xl font-black mb-5 tracking-tight">
            Enterprise Zero-Trust <br className="hidden md:block" />
            <span className="text-transparent bg-clip-text bg-linear-to-r from-primary via-cyan-300 to-primary">
              Secure File Platform
            </span>
          </motion.h1>

          <motion.p variants={fadeInUp} className="text-muted-foreground text-lg leading-relaxed max-w-2xl mx-auto">
            Share files with confidence: zero-knowledge <strong className="text-foreground">encryption</strong>,{" "}
            <strong className="text-foreground">digital signatures</strong>, real-time{" "}
            <strong className="text-foreground">threat detection</strong>,{" "}
            <strong className="text-foreground">data loss prevention</strong>, and{" "}
            <strong className="text-foreground">Zero Trust</strong> access control - all built in.
          </motion.p>

          <motion.div variants={fadeInUp} className="mt-10 flex flex-wrap items-center justify-center gap-3">
            <Link
              href="/register"
              className="inline-flex items-center gap-2 px-6 py-3 bg-primary hover:bg-primary/90 text-white font-semibold rounded-xl shadow-lg shadow-primary/20 transition-all"
            >
              Get Started
              <ArrowRight size={18} />
            </Link>
            <Link
              href="/login"
              className="inline-flex items-center gap-2 px-6 py-3 bg-card hover:bg-white/5 text-foreground font-semibold rounded-xl ring-1 ring-border transition-all"
            >
              <LogIn size={18} />
              Sign In
            </Link>
          </motion.div>
        </motion.div>

        <motion.div
          variants={staggerContainer}
          initial="hidden"
          animate="show"
          className="mt-16 grid grid-cols-2 md:grid-cols-5 gap-3"
        >
          {stats.map((s) => (
            <motion.div
              key={s.label}
              variants={fadeInUp}
              className="rounded-xl border border-border bg-card p-4 text-left"
            >
              <s.icon size={18} className="text-primary mb-2" />
              <p className="text-xs text-muted-foreground">{s.label}</p>
              <p className="text-sm font-semibold text-foreground mt-0.5">{s.value}</p>
            </motion.div>
          ))}
        </motion.div>
      </section>

      <section className="relative z-10 max-w-6xl mx-auto px-4 pb-24">
        <motion.div
          variants={staggerContainer}
          initial="hidden"
          whileInView="show"
          viewport={{ once: true, amount: 0.2 }}
          className="grid md:grid-cols-3 gap-6"
        >
          {features.map((f) => (
            <motion.div
              key={f.title}
              variants={fadeInUp}
              whileHover={{ y: -4 }}
              className="bg-card ring-1 ring-border rounded-xl p-6 hover:ring-primary/40 transition-all"
            >
              <div className="inline-flex h-11 w-11 items-center justify-center rounded-lg bg-primary/10 text-primary ring-1 ring-primary/25 mb-4">
                <f.icon size={22} />
              </div>
              <h3 className="text-lg font-bold mb-2 text-foreground">{f.title}</h3>
              <p className="text-muted-foreground text-sm leading-relaxed">{f.desc}</p>
            </motion.div>
          ))}
        </motion.div>
      </section>

      <footer className="relative z-10 border-t border-border">
        <div className="max-w-6xl mx-auto px-4 py-10 flex flex-col md:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <Lock size={16} className="text-primary" />
            <span className="text-sm font-semibold text-foreground">SecureShare</span>
          </div>
          <p className="text-xs text-muted-foreground text-center">
            Zero-knowledge encryption &middot; Digital signatures &middot; Threat detection &middot; DLP &middot; Zero Trust
          </p>
          <div className="flex items-center gap-4 text-xs text-muted-foreground">
            <Link href="/login" className="hover:text-foreground transition-colors">Sign in</Link>
            <Link href="/register" className="hover:text-foreground transition-colors">Register</Link>
          </div>
        </div>
      </footer>
    </div>
  );
}
