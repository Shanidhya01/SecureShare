"use client";
import React, { useState } from 'react';
import { Lock, Upload, Share2, Clock, Eye, EyeOff, LogOut, Trash2, Copy, Check } from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import { useRouter } from 'next/navigation';

export default function SecureFileSharing() {
  type FileItem = {
    id: number;
    name: string;
    size: string; // MB as string per UI
    date: string; // localized date string per UI
  };

  type ShareLink = {
    id: number;
    filename: string;
    url: string;
    created: string;
    expiry: string;
    downloads: number;
    password: string;
  };

  const router = useRouter();
  const [currentPage, setCurrentPage] = useState<'home' | 'login' | 'register' | 'dashboard'>('home');
  const [isLoggedIn, setIsLoggedIn] = useState<boolean>(false);
  const [email, setEmail] = useState<string>('');
  const [password, setPassword] = useState<string>('');
  const [showPassword, setShowPassword] = useState<boolean>(false);
  const [files, setFiles] = useState<FileItem[]>([]);
  const [selectedFile, setSelectedFile] = useState<FileItem | null>(null);
  const [shareLinks, setShareLinks] = useState<ShareLink[]>([]);
  const [copiedId, setCopiedId] = useState<number | null>(null);
  const [expiryTime, setExpiryTime] = useState<string>('24 hours');
  const [sharePassword, setSharePassword] = useState<string>('');

  // Home Page
  const HomePage = () => (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 text-white relative overflow-hidden">
      {/* Animated background elements */}
      <div className="absolute inset-0 overflow-hidden">
        <div className="absolute top-20 right-10 w-72 h-72 bg-blue-500 rounded-full mix-blend-multiply filter blur-3xl opacity-20 animate-pulse"></div>
        <div className="absolute -bottom-8 left-20 w-72 h-72 bg-purple-500 rounded-full mix-blend-multiply filter blur-3xl opacity-20 animate-pulse" style={{animationDelay: '2s'}}></div>
        <div className="absolute top-1/2 left-1/2 w-72 h-72 bg-cyan-500 rounded-full mix-blend-multiply filter blur-3xl opacity-20 animate-pulse" style={{animationDelay: '4s'}}></div>
      </div>

      {/* Content */}
      <div className="relative z-10 min-h-screen flex flex-col items-center justify-center px-4">
        <div className="text-center max-w-2xl mx-auto">
          <div className="mb-8 flex justify-center">
            <div className="relative">
              <div className="absolute inset-0 bg-gradient-to-r from-blue-500 to-cyan-500 rounded-full blur-lg opacity-75"></div>
              <div className="relative bg-slate-900 p-4 rounded-full">
                <Lock size={56} className="text-blue-400" />
              </div>
            </div>
          </div>

          <h1 className="text-5xl md:text-6xl font-black mb-4 bg-clip-text text-transparent bg-gradient-to-r from-blue-400 via-cyan-300 to-blue-400">
            SecureShare
          </h1>

          <p className="text-xl md:text-2xl text-slate-300 mb-2 font-light">
            Enterprise-Grade File Sharing
          </p>

          <p className="text-slate-400 text-lg mb-12 leading-relaxed">
            Share files with confidence. Military-grade encryption, time-limited access, and complete audit trails.
          </p>
          {/* Features */}
          <div className="grid md:grid-cols-3 gap-6 mt-16">
            {([
              { icon: Lock, title: 'AES-256 Encryption', desc: 'End-to-end encrypted file transfers' },
              { icon: Clock, title: 'Time-Limited Links', desc: 'Automatic expiration control' },
              { icon: Eye, title: 'Full Audit Trail', desc: 'Track every download access' }
            ] as { icon: LucideIcon; title: string; desc: string }[]).map((feature, i) => (
              <div key={i} className="bg-slate-800 bg-opacity-50 backdrop-blur border border-slate-700 rounded-xl p-6 hover:border-blue-500 transition-colors">
                <feature.icon size={32} className="text-blue-400 mb-4" />
                <h3 className="text-lg font-bold mb-2">{feature.title}</h3>
                <p className="text-slate-400">{feature.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );



  return (
    <>
      {currentPage === 'home' && <HomePage />}
    </>
  );
}