"use client";

import { useEffect, useState, useCallback } from "react";
import { Bell, X, AlertTriangle, ShieldAlert, Activity, Check } from "lucide-react";

const API = "https://fyp-backend-production-944f.up.railway.app";

type Notification = {
  id: number;
  severity: "Critical" | "High" | "Medium" | "Low" | "Info";
  title: string;
  message: string;
  src_ip: string | null;
  category: string | null;
  email_sent: boolean;
  read: boolean;
  created_at: string;
};

function authHeader(): HeadersInit {
  const token =
    typeof window !== "undefined" ? localStorage.getItem("token") : null;
  return token ? { Authorization: `Bearer ${token}` } : {};
}

function sevColor(s: string) {
  if (s === "Critical") return "#ff006e";
  if (s === "High")     return "#f59e0b";
  if (s === "Medium")   return "#fbbf24";
  if (s === "Low")      return "#00d4ff";
  return "#94a3b8";
}

function sevIcon(s: string) {
  if (s === "Critical") return ShieldAlert;
  if (s === "High")     return AlertTriangle;
  return Activity;
}

function timeAgo(iso: string): string {
  const d = new Date(iso);
  const diff = (Date.now() - d.getTime()) / 1000;
  if (diff < 60) return `${Math.floor(diff)}s ago`;
  if (diff < 3600) return `${Math.floor(diff/60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff/3600)}h ago`;
  return d.toLocaleDateString();
}

export default function NotificationBell() {
  const [open, setOpen]         = useState(false);
  const [unread, setUnread]     = useState(0);
  const [items, setItems]       = useState<Notification[]>([]);
  const [loading, setLoading]   = useState(false);
  const [showToast, setShowToast] = useState<Notification | null>(null);

  // Fetch unread count
  const fetchCount = useCallback(async () => {
    try {
      const res = await fetch(`${API}/api/notifications/unread-count`, { headers: authHeader() });
      if (!res.ok) return;
      const data = await res.json();
      setUnread((prev) => {
        // Show toast if a new Critical notification arrived
        if (data.count > prev && prev > 0) {
          // Fetch the latest critical one and toast it
          fetch(`${API}/api/notifications?limit=1&only_unread=true`, { headers: authHeader() })
            .then(r => r.json())
            .then(d => {
              const top = d.notifications?.[0];
              if (top && top.severity === "Critical") {
                setShowToast(top);
                setTimeout(() => setShowToast(null), 5000);
              }
            }).catch(() => {});
        }
        return data.count;
      });
    } catch {}
  }, []);

  // Fetch full list when drawer opens
  const fetchList = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API}/api/notifications?limit=30`, { headers: authHeader() });
      if (res.ok) {
        const data = await res.json();
        setItems(data.notifications || []);
      }
    } catch {}
    setLoading(false);
  }, []);

  // Poll every 10s
  useEffect(() => {
    fetchCount();
    const id = setInterval(fetchCount, 10000);
    return () => clearInterval(id);
  }, [fetchCount]);

  // Refresh list when opened
  useEffect(() => {
    if (open) fetchList();
  }, [open, fetchList]);

  const markRead = async (id: number) => {
    try {
      await fetch(`${API}/api/notifications/${id}/read`, {
        method: "POST",
        headers: authHeader(),
      });
      setItems((prev) => prev.map((n) => (n.id === id ? { ...n, read: true } : n)));
      setUnread((c) => Math.max(0, c - 1));
    } catch {}
  };

  const markAllRead = async () => {
    try {
      await fetch(`${API}/api/notifications/mark-all-read`, {
        method: "POST",
        headers: authHeader(),
      });
      setItems((prev) => prev.map((n) => ({ ...n, read: true })));
      setUnread(0);
    } catch {}
  };

  return (
    <>
      {/* Bell button */}
      <button
        onClick={() => setOpen(true)}
        className="relative p-2 rounded transition-colors hover:bg-cyan-400/10"
        style={{ border: "1px solid rgba(0,212,255,0.15)" }}
        title="Notifications"
      >
        <Bell size={14} className="text-cyan-400" />
        {unread > 0 && (
          <span
            className="absolute -top-1 -right-1 min-w-[18px] h-[18px] flex items-center justify-center text-[9px] font-bold rounded-full text-white px-1 animate-pulse"
            style={{ background: "#ff006e", boxShadow: "0 0 8px rgba(255,0,110,0.6)" }}
          >
            {unread > 99 ? "99+" : unread}
          </span>
        )}
      </button>

      {/* Drawer */}
      {open && (
        <div
          className="fixed inset-0 z-[9999]"
          onClick={() => setOpen(false)}
          style={{ height: "100vh" }}
        >
          <div
            className="absolute inset-0"
            style={{ background: "rgba(0,0,0,0.6)", backdropFilter: "blur(6px)" }}
          />
          <div
            onClick={(e) => e.stopPropagation()}
            className="absolute top-0 right-0 w-full max-w-md flex flex-col"
            style={{
              height: "100vh",
              background: "rgba(10,15,30,1)",
              borderLeft: "1px solid rgba(0,212,255,0.3)",
              boxShadow: "-20px 0 60px rgba(0,212,255,0.15)",
              animation: "slideInRight 0.25s ease-out",
            }}
          >
            <style>{`
              @keyframes slideInRight {
                from { transform: translateX(100%); }
                to   { transform: translateX(0); }
              }
            `}</style>

            {/* Drawer header */}
            <div
              className="px-5 py-4 flex items-center justify-between"
              style={{ borderBottom: "1px solid rgba(0,212,255,0.15)" }}
            >
              <div className="flex items-center gap-3">
                <Bell size={16} className="text-cyan-400" />
                <h2
                  className="text-[13px] font-bold text-cyan-400 tracking-widest"
                  style={{ fontFamily: "'Orbitron', monospace" }}
                >
                  NOTIFICATIONS
                </h2>
                {unread > 0 && (
                  <span className="text-[10px] font-mono text-slate-500">
                    {unread} unread
                  </span>
                )}
              </div>
              <div className="flex items-center gap-2">
                {unread > 0 && (
                  <button
                    onClick={markAllRead}
                    className="text-[10px] font-mono text-slate-500 hover:text-cyan-400 transition-colors px-2 py-1 rounded"
                    style={{ border: "1px solid rgba(148,163,184,0.15)" }}
                  >
                    MARK ALL READ
                  </button>
                )}
                <button
                  onClick={() => setOpen(false)}
                  className="text-slate-500 hover:text-cyan-400 transition-colors"
                >
                  <X size={16} />
                </button>
              </div>
            </div>

            {/* List */}
            <div className="flex-1 overflow-y-auto px-3 py-3 space-y-2">
              {loading && (
                <div className="text-center text-[11px] font-mono text-slate-500 py-8">
                  Loading...
                </div>
              )}
              {!loading && items.length === 0 && (
                <div className="text-center text-[11px] font-mono text-slate-500 py-12">
                  <Bell size={28} className="mx-auto mb-2 opacity-20" />
                  No notifications yet
                </div>
              )}
              {items.map((n) => {
                const Icon = sevIcon(n.severity);
                const color = sevColor(n.severity);
                return (
                  <div
                    key={n.id}
                    onClick={() => !n.read && markRead(n.id)}
                    className="px-4 py-3 rounded cursor-pointer transition-all hover:bg-cyan-400/5"
                    style={{
                      background: n.read ? "rgba(3,7,18,0.4)" : "rgba(0,212,255,0.03)",
                      border: `1px solid ${n.read ? "rgba(148,163,184,0.08)" : "rgba(0,212,255,0.2)"}`,
                      opacity: n.read ? 0.65 : 1,
                    }}
                  >
                    <div className="flex items-start gap-3">
                      <div
                        className="flex-shrink-0 w-7 h-7 rounded flex items-center justify-center"
                        style={{ background: `${color}15`, border: `1px solid ${color}40` }}
                      >
                        <Icon size={13} style={{ color }} />
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-start justify-between gap-2">
                          <div
                            className="text-[11px] font-mono font-bold truncate"
                            style={{ color }}
                          >
                            {n.severity.toUpperCase()}
                            {n.category && (
                              <span className="text-slate-500 font-normal ml-1.5">
                                · {n.category}
                              </span>
                            )}
                          </div>
                          {!n.read && (
                            <div
                              className="w-1.5 h-1.5 rounded-full flex-shrink-0 mt-1"
                              style={{ background: "#00d4ff", boxShadow: "0 0 4px #00d4ff" }}
                            />
                          )}
                        </div>
                        <div className="text-[11px] font-mono text-slate-300 mt-0.5 truncate">
                          {n.title}
                        </div>
                        <div className="text-[10px] font-mono text-slate-500 mt-1 line-clamp-2">
                          {n.message}
                        </div>
                        <div className="flex items-center gap-3 mt-1.5">
                          <span className="text-[9px] font-mono text-slate-600">
                            {timeAgo(n.created_at)}
                          </span>
                          {n.email_sent && (
                            <span className="text-[9px] font-mono text-cyan-400/60 flex items-center gap-1">
                              <Check size={9} /> Email sent
                            </span>
                          )}
                        </div>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>

            {/* Footer */}
            <div
              className="px-5 py-3 text-center text-[9px] font-mono text-slate-700"
              style={{ borderTop: "1px solid rgba(148,163,184,0.08)" }}
            >
              {items.length > 0 ? `Showing ${items.length} most recent` : "All clear"}
            </div>
          </div>
        </div>
      )}

      {/* Toast for new Critical */}
      {showToast && (
        <div
          className="fixed top-20 right-4 z-[200] max-w-sm p-4 rounded-lg"
          style={{
            background: "rgba(10,15,30,0.98)",
            border: "1px solid #ff006e",
            boxShadow: "0 0 30px rgba(255,0,110,0.3)",
            animation: "slideInRight 0.3s ease-out",
          }}
        >
          <div className="flex items-start gap-3">
            <ShieldAlert size={20} style={{ color: "#ff006e" }} />
            <div className="flex-1">
              <div
                className="text-[11px] font-mono font-bold"
                style={{ color: "#ff006e" }}
              >
                CRITICAL THREAT DETECTED
              </div>
              <div className="text-[11px] font-mono text-slate-300 mt-1">
                {showToast.title}
              </div>
            </div>
            <button
              onClick={() => setShowToast(null)}
              className="text-slate-500 hover:text-slate-300"
            >
              <X size={14} />
            </button>
          </div>
        </div>
      )}
    </>
  );
}
