import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import AppShell from "@/components/shell/AppShell";
import ToasterClient from "@/components/ToasterClient";
import { CryptoKeyProvider } from "@/context/CryptoKeyContext";
import { TooltipProvider } from "@/components/ui/tooltip";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "SecureShare",
  description: "A full-stack secure file sharing web application that allows users to upload files, encrypt them on the server, and share them using time-limited or one-time download links. The system ensures confidentiality, controlled access, and traceability of file downloads.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body
        className={`dark ${geistSans.variable} ${geistMono.variable} antialiased`}
      >
        <CryptoKeyProvider>
          <TooltipProvider>
            <AppShell>{children}</AppShell>
            <ToasterClient />
          </TooltipProvider>
        </CryptoKeyProvider>
      </body>
    </html>
  );
}
