"use client";
import NotificationBell from "../../components/NotificationBell";

import { useState, useEffect, useRef } from "react";
import {
  Shield, Activity, AlertTriangle, Settings, FileText, LogOut,
  Radio, Menu, X, BarChart2, AlertCircle, Lock, Eye, UserCheck,
  CheckCircle, XCircle, ChevronUp, ChevronDown, Search, Download,
  ChevronLeft, ChevronRight, RotateCcw, Layers,
  Bot,
} from "lucide-react";

// ══════════════════════════════════════════════
// CONFIG
// ══════════════════════════════════════════════
const API_INC = "fyp-backend-production-944f.up.railway.app/api/incidents";
const API_REP = "fyp-backend-production-944f.up.railway.app/api/reports";

function getToken(): string {
  return (
    localStorage.getItem("token") ||
    localStorage.getItem("access_token") ||
    ""
  );
}

function authHeaders(extra?: HeadersInit): HeadersInit {
  const token = getToken();
  return {
    "Content-Type": "application/json",
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...(extra || {}),
  };
}

async function apiFetch<T>(path: string, opts?: RequestInit): Promise<T | null> {
  try {
    const res = await fetch(`${API_INC}${path}`, {
      headers: authHeaders(),
      ...opts,
    });
    if (!res.ok) return null;
    return await res.json() as T;
  } catch {
    return null;
  }
}

// ══════════════════════════════════════════════
// TYPES
// ══════════════════════════════════════════════
type Severity = "Info" | "Low" | "Medium" | "High" | "Critical";
type IncidentStatus = "Open" | "In Progress" | "Resolved" | "Closed";
type DetectionType = "Anomaly" | "Signature" | "Ransomware" | "DDoS" | "Brute Force";
type Classification = "Normal" | "Suspicious" | "Malicious";

interface Incident {
  id: string;
  desc: string;
  type: DetectionType;
  severity: Severity;
  status: IncidentStatus;
  analyst: string;
  updated: string;
  srcIp: string;
  dstIp: string;
  protocol: string;
  port: number;
  timestamp: string;
}

interface Detection {
  id: number;
  timestamp: string;
  srcIp: string;
  dstIp: string;
  protocol: string;
  port: number;
  detType: "Anomaly" | "Signature" | "Ransomware";
  severity: Severity;
  classification: Classification;
  explanation: string;
}

interface StatCard {
  label: string;
  value: number;
  sub: string;
  color: string;
  pulse: boolean;
}
interface DonutItem {
  label: string;
  value: number;
  color: string;
}
interface BarItem {
  label: string;
  value: number;
  color: string;
}

// ══════════════════════════════════════════════
// NORMALIZERS
// ══════════════════════════════════════════════
function normalizeIncident(i: any): Incident {
  return {
    id: i.id,
    desc: i.desc,
    type: i.type,
    severity: i.severity,
    status: i.status,
    analyst: i.analyst,
    updated: i.updated ?? i.updated_at ?? i.timestamp ?? "",
    srcIp: i.srcIp ?? i.src_ip ?? "",
    dstIp: i.dstIp ?? i.dst_ip ?? "",
    protocol: i.protocol,
    port: i.port,
    timestamp: i.timestamp ?? "",
  };
}

function normalizeDetection(d: any): Detection {
  return {
    id: d.id,
    timestamp: d.timestamp,
    srcIp: d.srcIp ?? d.src_ip ?? "",
    dstIp: d.dstIp ?? d.dst_ip ?? "",
    protocol: d.protocol,
    port: d.port,
    detType: d.detType ?? d.det_type,
    severity: d.severity,
    classification: d.classification,
    explanation: d.explanation,
  };
}

// ══════════════════════════════════════════════
// COLOR HELPERS
// ══════════════════════════════════════════════
const SEV_COLOR: Record<string, string> = {
  Info: "#94a3b8",
  Low: "#00ff9f",
  Medium: "#ffbe0b",
  High: "#f97316",
  Critical: "#ff006e",
};

const SEV_BG: Record<string, string> = {
  Info: "rgba(148,163,184,0.1)",
  Low: "rgba(0,255,159,0.1)",
  Medium: "rgba(255,190,11,0.1)",
  High: "rgba(249,115,22,0.1)",
  Critical: "rgba(255,0,110,0.1)",
};

const STAT_COLOR: Record<string, string> = {
  Open: "#ff006e",
  "In Progress": "#ffbe0b",
  Resolved: "#00ff9f",
  Closed: "#94a3b8",
};

const STAT_BG: Record<string, string> = {
  Open: "rgba(255,0,110,0.1)",
  "In Progress": "rgba(255,190,11,0.1)",
  Resolved: "rgba(0,255,159,0.1)",
  Closed: "rgba(148,163,184,0.08)",
};

const DET_COLOR: Record<string, string> = {
  Anomaly: "#ffbe0b",
  Signature: "#00d4ff",
  Ransomware: "#f97316",
};

const CLASS_COLOR: Record<string, string> = {
  Normal: "#00ff9f",
  Suspicious: "#ffbe0b",
  Malicious: "#ff006e",
};

function SevBadge({ s }: { s: string }) {
  return (
    <span
      className="px-2 py-0.5 rounded-full text-[9px] font-mono font-bold whitespace-nowrap"
      style={{
        color: SEV_COLOR[s] || "#94a3b8",
        background: SEV_BG[s] || "rgba(148,163,184,0.1)",
        border: `1px solid ${(SEV_COLOR[s] || "#94a3b8")}40`,
        boxShadow: s === "Critical" ? `0 0 8px ${SEV_COLOR[s]}50` : "none",
      }}
    >
      {s}
    </span>
  );
}

function StatBadge({ s }: { s: string }) {
  return (
    <span
      className="px-2 py-0.5 rounded-full text-[9px] font-mono font-bold whitespace-nowrap"
      style={{
        color: STAT_COLOR[s] || "#94a3b8",
        background: STAT_BG[s] || "rgba(148,163,184,0.08)",
        border: `1px solid ${(STAT_COLOR[s] || "#94a3b8")}40`,
      }}
    >
      {s}
    </span>
  );
}

function Skeleton({ className = "" }: { className?: string }) {
  return (
    <div
      className={`rounded animate-pulse ${className}`}
      style={{ background: "rgba(0,212,255,0.06)" }}
    />
  );
}

// ══════════════════════════════���═══════════════
// NAVBAR
// ══════════════════════════════════════════════
const NAV_LINKS = [
  { label: "Dashboard", href: "/dashboard", icon: BarChart2 },
  { label: "Network Monitoring", href: "/network", icon: Radio },
  { label: "Incidents", href: "/incidents", icon: AlertTriangle },
  { label: "Configuration", href: "/configuration", icon: Settings },
  { label: "Audits", href: "/audits", icon: FileText },
  { label: "Agents", href: "/agents", icon: Bot },
];

function Navbar() {
  const [menuOpen, setMenuOpen] = useState(false);
  const [time, setTime] = useState("");

  useEffect(() => {
    const tick = () => setTime(new Date().toUTCString().slice(5, 25) + " UTC");
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, []);

  return (
    <nav
      className="sticky top-0 z-50 w-full"
      style={{
        background: "rgba(6,10,20,0.98)",
        borderBottom: "1px solid rgba(0,212,255,0.15)",
        backdropFilter: "blur(12px)",
      }}
    >
      <div className="flex items-center justify-between px-6 h-14">
        <div className="flex items-center gap-3 shrink-0">
          <div className="relative">
            <Shield size={20} className="text-cyan-400" />
            <div
              className="absolute -top-0.5 -right-0.5 w-2 h-2 rounded-full bg-green-400"
              style={{ boxShadow: "0 0 6px #00ff9f" }}
            />
          </div>
          <span
            style={{ fontFamily: "'Orbitron',monospace" }}
            className="text-cyan-400 font-bold tracking-widest text-sm hidden sm:block"
          >
            CyGuardian-X
          </span>
        </div>

        <div className="hidden lg:flex items-center">
          {NAV_LINKS.map(({ label, href, icon: Icon }) => (
            <a
              key={label}
              href={href}
              className={`flex items-center gap-1.5 px-3 py-4 text-[11px] font-mono tracking-wider border-b-2 transition-all duration-200 ${
                label === "Incidents"
                  ? "text-cyan-400 border-cyan-400"
                  : "text-slate-500 border-transparent hover:text-slate-300 hover:border-slate-700"
              }`}
            >
              <Icon size={12} />
              {label.toUpperCase()}
            </a>
          ))}
        </div>

        <div className="flex items-center gap-3">
          <span className="text-[10px] font-mono text-slate-600 hidden md:block">
            {time}
          </span>
          <div
            className="flex items-center gap-2 px-3 py-1 rounded"
            style={{
              background: "rgba(0,212,255,0.06)",
              border: "1px solid rgba(0,212,255,0.15)",
            }}
          >
            <div
              className="w-6 h-6 rounded-full flex items-center justify-center text-[10px] font-bold text-cyan-400"
              style={{ background: "rgba(0,212,255,0.2)" }}
            >
              A
            </div>
            <span className="text-[11px] font-mono text-slate-400 hidden sm:block">
              ADMIN
            </span>
          </div>
          <NotificationBell />
          <a
            href="/logout"
            className="flex items-center gap-1.5 text-[10px] font-mono text-slate-600 hover:text-red-400 transition-colors"
          >
            <LogOut size={13} />
            <span className="hidden sm:block">LOGOUT</span>
          </a>
          <button className="lg:hidden text-slate-400" onClick={() => setMenuOpen(!menuOpen)}>
            {menuOpen ? <X size={18} /> : <Menu size={18} />}
          </button>
        </div>
      </div>

      {menuOpen && (
        <div
          className="lg:hidden px-4 pb-3 space-y-1 border-t"
          style={{ borderColor: "rgba(0,212,255,0.1)" }}
        >
          {NAV_LINKS.map(({ label, href, icon: Icon }) => (
            <a
              key={label}
              href={href}
              className={`flex items-center gap-2 px-3 py-2 text-[11px] font-mono rounded ${
                label === "Incidents"
                  ? "text-cyan-400 bg-cyan-400/10"
                  : "text-slate-500"
              }`}
            >
              <Icon size={12} />
              {label}
            </a>
          ))}
        </div>
      )}
    </nav>
  );
}

// ══════════════════════════════════════════════
// SHARED UI
// ══════════════════════════════════════════════
function Toast({
  msg,
  type,
  onClose,
}: {
  msg: string;
  type: "success" | "error";
  onClose: () => void;
}) {
  useEffect(() => {
    const t = setTimeout(onClose, 3000);
    return () => clearTimeout(t);
  }, [onClose]);

  return (
    <div
      className="fixed top-20 right-4 z-50 px-4 py-3 rounded flex items-center gap-2 text-[11px] font-mono shadow-lg"
      style={{
        background:
          type === "success"
            ? "rgba(0,255,159,0.15)"
            : "rgba(255,0,110,0.15)",
        border: `1px solid ${
          type === "success"
            ? "rgba(0,255,159,0.4)"
            : "rgba(255,0,110,0.4)"
        }`,
        color: type === "success" ? "#00ff9f" : "#ff006e",
      }}
    >
      {type === "success" ? <CheckCircle size={13} /> : <XCircle size={13} />}
      {msg}
    </div>
  );
}

function Modal({
  msg,
  onConfirm,
  onCancel,
}: {
  msg: string;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center"
      style={{ background: "rgba(0,0,0,0.75)" }}
    >
      <div
        className="p-6 rounded max-w-sm w-full mx-4"
        style={{
          background: "rgba(10,15,30,0.98)",
          border: "1px solid rgba(255,0,110,0.4)",
        }}
      >
        <AlertTriangle size={22} className="text-red-400 mb-3" />
        <div className="text-sm font-mono text-slate-200 mb-2 font-bold">
          Confirm Action
        </div>
        <div className="text-[11px] font-mono text-slate-400 mb-4">{msg}</div>
        <div className="flex gap-3">
          <button
            onClick={onCancel}
            className="flex-1 py-2 rounded text-[11px] font-mono text-slate-400 hover:text-slate-200 transition-colors"
            style={{ border: "1px solid rgba(100,116,139,0.3)" }}
          >
            Cancel
          </button>
          <button
            onClick={onConfirm}
            className="flex-1 py-2 rounded text-[11px] font-mono text-red-400 hover:bg-red-400/10 transition-colors"
            style={{ border: "1px solid rgba(255,0,110,0.4)" }}
          >
            Confirm
          </button>
        </div>
      </div>
    </div>
  );
}

function useCountUp(target: number, duration = 1400) {
  const [count, setCount] = useState(0);
  useEffect(() => {
    if (!target) return;
    let s = 0;
    const step = target / (duration / 16);
    const t = setInterval(() => {
      s += step;
      if (s >= target) {
        setCount(target);
        clearInterval(t);
      } else setCount(Math.floor(s));
    }, 16);
    return () => clearInterval(t);
  }, [target, duration]);
  return count;
}

// ══════════════════════════════════════════════
// STAT CARDS
// ══════════════════════════════════════════════
function StatCardComp({ s }: { s: StatCard }) {
  const count = useCountUp(s.value);
  const Icon =
    s.label === "Total Detections"
      ? Activity
      : s.label === "Anomaly"
      ? AlertCircle
      : s.label === "Signature"
      ? Shield
      : s.label === "Ransomware"
      ? Lock
      : AlertTriangle;

  return (
    <div
      className="relative p-4 rounded overflow-hidden group transition-all duration-300 hover:-translate-y-0.5"
      style={{
        background: "rgba(10,15,30,0.95)",
        border: `1px solid ${s.color}30`,
        boxShadow: s.pulse
          ? `0 0 20px ${s.color}30,0 0 40px ${s.color}10`
          : `0 0 16px ${s.color}10`,
        animation: s.pulse ? "critPulse 2s ease-in-out infinite" : "none",
      }}
    >
      <div
        className="absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none"
        style={{
          background: `radial-gradient(ellipse at top left,${s.color}08,transparent)`,
        }}
      />
      <Icon size={14} style={{ color: s.color }} className="mb-2" />
      <div
        className="text-xl font-bold mb-0.5"
        style={{ color: s.color, fontFamily: "'Orbitron',monospace" }}
      >
        {count.toLocaleString()}
      </div>
      <div className="text-[10px] font-mono text-slate-400 uppercase tracking-wider">
        {s.label}
      </div>
      <div className="text-[9px] font-mono text-slate-600">{s.sub}</div>
    </div>
  );
}

function StatCards({ stats }: { stats: StatCard[] }) {
  if (!stats.length)
    return (
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-3">
        {[0, 1, 2, 3, 4].map((i) => (
          <Skeleton key={i} className="h-24" />
        ))}
      </div>
    );
  return (
    <div className="grid grid-cols-2 lg:grid-cols-5 gap-3">
      {stats.map((s) => (
        <StatCardComp key={s.label} s={s} />
      ))}
    </div>
  );
}

// ══════════════════════════════════════════════
// DETAIL MODAL
// ════════════════════════════════════════════���═
function DetailModal({
  inc,
  timeline,
  onClose,
  onAssign,
  onResolve,
}: {
  inc: Incident;
  timeline: { time: string; event: string }[];
  onClose: () => void;
  onAssign: () => void;
  onResolve: () => void;
}) {
  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      style={{ background: "rgba(0,0,0,0.8)" }}
    >
      <div
        className="w-full max-w-2xl rounded overflow-hidden"
        style={{
          background: "rgba(10,15,30,0.99)",
          border: "1px solid rgba(0,212,255,0.2)",
        }}
      >
        <div
          className="flex items-center justify-between px-5 py-4 border-b"
          style={{ borderColor: "rgba(0,212,255,0.1)" }}
        >
          <div className="flex items-center gap-3">
            <Shield size={16} className="text-cyan-400" />
            <span className="text-[13px] font-mono font-bold text-cyan-400 tracking-wider">
              {inc.id}
            </span>
            <SevBadge s={inc.severity} />
            <StatBadge s={inc.status} />
          </div>
          <button onClick={onClose} className="text-slate-500 hover:text-slate-300 transition-colors">
            <X size={16} />
          </button>
        </div>
        <div className="p-5 space-y-4 max-h-[70vh] overflow-y-auto">
          <p className="text-[12px] font-mono text-slate-200">{inc.desc}</p>
          <div className="grid grid-cols-2 gap-3">
            {[
              ["Type", inc.type],
              ["Protocol", inc.protocol],
              ["Source IP", inc.srcIp],
              ["Destination", inc.dstIp],
              ["Port", String(inc.port)],
              ["Analyst", inc.analyst],
              ["Timestamp", inc.timestamp],
              ["Last Updated", inc.updated],
            ].map(([k, v]) => (
              <div
                key={k}
                className="p-2 rounded"
                style={{
                  background: "rgba(0,212,255,0.03)",
                  border: "1px solid rgba(0,212,255,0.08)",
                }}
              >
                <div className="text-[9px] font-mono text-slate-600 uppercase tracking-wider mb-0.5">
                  {k}
                </div>
                <div className="text-[11px] font-mono text-slate-200">{v}</div>
              </div>
            ))}
          </div>
          <div>
            <div className="text-[10px] font-mono text-slate-500 uppercase tracking-wider mb-2">
              Event Timeline
            </div>
            <div className="space-y-2">
              {timeline.map((t, i) => (
                <div key={i} className="flex items-start gap-3">
                  <div
                    className="w-1.5 h-1.5 rounded-full bg-cyan-400 mt-1.5 shrink-0"
                    style={{ boxShadow: "0 0 4px #00d4ff" }}
                  />
                  <div>
                    <span className="text-[10px] font-mono text-cyan-400 mr-2">{t.time}</span>
                    <span className="text-[10px] font-mono text-slate-400">{t.event}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
          <div className="flex gap-2 pt-2 border-t" style={{ borderColor: "rgba(0,212,255,0.08)" }}>
            <button
              onClick={() => {
                onAssign();
                onClose();
              }}
              className="px-3 py-1.5 rounded text-[10px] font-mono text-yellow-400 hover:bg-yellow-400/10 transition-colors"
              style={{ border: "1px solid rgba(255,190,11,0.3)" }}
            >
              <UserCheck size={10} className="inline mr-1" />
              Assign
            </button>
            <button
              onClick={() => {
                onResolve();
                onClose();
              }}
              className="px-3 py-1.5 rounded text-[10px] font-mono text-green-400 hover:bg-green-400/10 transition-colors"
              style={{ border: "1px solid rgba(0,255,159,0.3)" }}
            >
              <CheckCircle size={10} className="inline mr-1" />
              Resolve
            </button>
            <button
              className="px-3 py-1.5 rounded text-[10px] font-mono text-cyan-400 hover:bg-cyan-400/10 transition-colors"
              style={{ border: "1px solid rgba(0,212,255,0.3)" }}
            >
              <Download size={10} className="inline mr-1" />
              Export
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

// ══════════════════════════════════════════════
// ASSIGN MODAL
// ══════════════════════════════════════════════
function AssignModal({
  incId,
  onConfirm,
  onCancel,
}: {
  incId: string;
  onConfirm: (analyst: string, notes: string) => void;
  onCancel: () => void;
}) {
  const [analyst, setAnalyst] = useState("analyst1");
  const [notes, setNotes] = useState("");
  const sel = {
    background: "#0a0f1e",
    border: "1px solid rgba(0,212,255,0.15)",
    color: "#00d4ff",
  };
  const inp = {
    background: "rgba(0,212,255,0.04)",
    border: "1px solid rgba(0,212,255,0.15)",
    color: "#cbd5e1",
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      style={{ background: "rgba(0,0,0,0.75)" }}
    >
      <div
        className="w-full max-w-sm rounded p-5"
        style={{
          background: "rgba(10,15,30,0.98)",
          border: "1px solid rgba(255,190,11,0.3)",
        }}
      >
        <div className="flex items-center gap-2 mb-4">
          <UserCheck size={16} className="text-yellow-400" />
          <span className="text-[12px] font-mono font-bold text-slate-200">
            Assign {incId}
          </span>
        </div>
        <div className="space-y-3">
          <div>
            <label className="text-[10px] font-mono text-slate-500 uppercase block mb-1">
              Assign To
            </label>
            <select
              value={analyst}
              onChange={(e) => setAnalyst(e.target.value)}
              className="w-full px-3 py-2 rounded text-[11px] font-mono outline-none"
              style={sel}
            >
              {["analyst1", "analyst2", "soc_lead", "admin"].map((v) => (
                <option key={v} style={{ background: "#0a0f1e" }}>
                  {v}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="text-[10px] font-mono text-slate-500 uppercase block mb-1">
              Notes
            </label>
            <textarea
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              rows={3}
              placeholder="Add assignment notes..."
              className="w-full px-3 py-2 rounded text-[11px] font-mono outline-none resize-none"
              style={inp}
            />
          </div>
        </div>
        <div className="flex gap-2 mt-4">
          <button
            onClick={onCancel}
            className="flex-1 py-2 rounded text-[11px] font-mono text-slate-400 transition-colors"
            style={{ border: "1px solid rgba(100,116,139,0.3)" }}
          >
            Cancel
          </button>
          <button
            onClick={() => onConfirm(analyst, notes)}
            className="flex-1 py-2 rounded text-[11px] font-mono text-yellow-400 hover:bg-yellow-400/10 transition-colors"
            style={{ border: "1px solid rgba(255,190,11,0.4)" }}
          >
            Confirm Assign
          </button>
        </div>
      </div>
    </div>
  );
}

// ══════════════════════════════════════════════
// INCIDENTS TABLE
// ══════════════════════════════════════════════
function IncidentsTable({ initialIncidents }: { initialIncidents: Incident[] }) {
  const [incidents, setIncidents] = useState<Incident[]>(initialIncidents);
  const [statF, setStatF] = useState("All");
  const [sevF, setSevF] = useState("All");
  const [analF, setAnalF] = useState("All");
  const [search, setSearch] = useState("");
  const [sortCol, setSortCol] = useState<keyof Incident>("updated");
  const [sortAsc, setSortAsc] = useState(false);
  const [page, setPage] = useState(0);
  const [detailInc, setDetailInc] = useState<Incident | null>(null);
  const [timeline, setTimeline] = useState<{ time: string; event: string }[]>([]);
  const [assignInc, setAssignInc] = useState<string | null>(null);
  const [modal, setModal] = useState<{ msg: string; onConfirm: () => void } | null>(null);
  const [toast, setToast] = useState<{ msg: string; type: "success" | "error" } | null>(null);
  const PER = 8;

  useEffect(() => {
    if (initialIncidents.length) setIncidents(initialIncidents);
  }, [initialIncidents]);

  const openDetail = async (inc: Incident) => {
    setDetailInc(inc);
    const d = await apiFetch<{ timeline: { time: string; event: string }[] }>(
      `/timeline/${inc.id}`
    );
    if (d) setTimeline(d.timeline);
  };

  const filtered = incidents.filter((i) => {
    if (statF !== "All" && i.status !== statF) return false;
    if (sevF !== "All" && i.severity !== sevF) return false;
    if (analF !== "All" && i.analyst !== analF) return false;
    if (
      search &&
      !i.id.toLowerCase().includes(search.toLowerCase()) &&
      !i.desc.toLowerCase().includes(search.toLowerCase())
    )
      return false;
    return true;
  });

  const sorted = [...filtered].sort((a, b) => {
    const av = a[sortCol];
    const bv = b[sortCol];
    return sortAsc
      ? String(av).localeCompare(String(bv))
      : String(bv).localeCompare(String(av));
  });

  const paged = sorted.slice(page * PER, (page + 1) * PER);
  const total = Math.ceil(sorted.length / PER);

  const sort = (c: keyof Incident) => {
    if (sortCol === c) setSortAsc(!sortAsc);
    else {
      setSortCol(c);
      setSortAsc(true);
    }
  };

  const resolve = (id: string) =>
    setModal({
      msg: `Resolve incident ${id}?`,
      onConfirm: async () => {
        const res = await apiFetch<{ success: boolean; incident: any }>(
          `/resolve/${id}`,
          { method: "POST" }
        );
        if (res?.success) {
          const mapped = normalizeIncident(res.incident);
          setIncidents((p) => p.map((i) => (i.id === id ? mapped : i)));
          setToast({ msg: `Incident ${id} resolved.`, type: "success" });
        } else setToast({ msg: `Failed to resolve ${id}.`, type: "error" });
        setModal(null);
      },
    });

  const closeInc = (id: string) =>
    setModal({
      msg: `Close incident ${id}? This cannot be undone.`,
      onConfirm: async () => {
        const res = await apiFetch<{ success: boolean; incident: any }>(
          `/close/${id}`,
          { method: "POST" }
        );
        if (res?.success) {
          const mapped = normalizeIncident(res.incident);
          setIncidents((p) => p.map((i) => (i.id === id ? mapped : i)));
          setToast({ msg: `Incident ${id} closed.`, type: "success" });
        } else setToast({ msg: `Failed to close ${id}.`, type: "error" });
        setModal(null);
      },
    });

  const markAll = () =>
    setModal({
      msg: "Mark ALL visible incidents as Resolved?",
      onConfirm: async () => {
        const ids = filtered.map((i) => i.id);
        const res = await apiFetch<{ resolved: string[]; count: number }>(
          "/resolve-all",
          { method: "POST", body: JSON.stringify({ ids }) }
        );
        if (res) {
          setIncidents((p) =>
            p.map((i) =>
              res.resolved.includes(i.id)
                ? { ...i, status: "Resolved" as IncidentStatus }
                : i
            )
          );
          setToast({ msg: `${res.count} incidents resolved.`, type: "success" });
        }
        setModal(null);
      },
    });

  const doAssign = async (analyst: string) => {
    if (!assignInc) return;
    const res = await apiFetch<{ success: boolean; incident: any }>(
      `/assign/${assignInc}`,
      { method: "POST", body: JSON.stringify({ analyst }) }
    );
    if (res?.success) {
      const mapped = normalizeIncident(res.incident);
      setIncidents((p) => p.map((i) => (i.id === assignInc ? mapped : i)));
      setToast({ msg: `${assignInc} assigned to ${analyst}.`, type: "success" });
    } else setToast({ msg: "Assignment failed.", type: "error" });
    setAssignInc(null);
  };

  const exportTxt = () => {
    const txt = filtered
      .map(
        (i) =>
          `[${i.id}] ${i.desc} | Type:${i.type} | Sev:${i.severity} | Status:${i.status} | Analyst:${i.analyst} | ${i.updated}`
      )
      .join("\n");
    const a = document.createElement("a");
    a.href = "data:text/plain;charset=utf-8," + encodeURIComponent(txt);
    a.download = "incidents.txt";
    a.click();
  };

  const exportPdf = async () => {
    try {
      const token = getToken();
      if (!token) {
        setToast({ msg: "Please login first.", type: "error" });
        return;
      }

      const qs = new URLSearchParams();
      if (sevF !== "All") qs.set("severity", sevF);
      if (statF !== "All") qs.set("status", statF);
      if (analF !== "All") qs.set("analyst", analF);
      if (search.trim()) qs.set("search", search.trim());

      const res = await fetch(`${API_REP}/incidents.pdf?${qs.toString()}`, {
        headers: { Authorization: `Bearer ${token}` },
      });

      if (!res.ok) {
        const txt = await res.text();
        setToast({ msg: `Export failed: ${txt}`, type: "error" });
        return;
      }

      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `incidents_report_${new Date()
        .toISOString()
        .slice(0, 19)
        .replace(/[:T]/g, "-")}.pdf`;
      a.click();
      window.URL.revokeObjectURL(url);
      setToast({ msg: "Incidents PDF downloaded.", type: "success" });
    } catch {
      setToast({ msg: "Export failed.", type: "error" });
    }
  };

  const selSty = {
    background: "#0a0f1e",
    border: "1px solid rgba(0,212,255,0.15)",
    color: "#00d4ff",
  };
  const inpSty = {
    background: "rgba(0,212,255,0.04)",
    border: "1px solid rgba(0,212,255,0.15)",
    color: "#cbd5e1",
  };

  return (
    <>
      {modal && (
        <Modal
          msg={modal.msg}
          onConfirm={modal.onConfirm}
          onCancel={() => setModal(null)}
        />
      )}
      {toast && (
        <Toast
          msg={toast.msg}
          type={toast.type}
          onClose={() => setToast(null)}
        />
      )}
      {detailInc && (
        <DetailModal
          inc={detailInc}
          timeline={timeline}
          onClose={() => setDetailInc(null)}
          onAssign={() => setAssignInc(detailInc.id)}
          onResolve={() => resolve(detailInc.id)}
        />
      )}
      {assignInc && (
        <AssignModal
          incId={assignInc}
          onCancel={() => setAssignInc(null)}
          onConfirm={doAssign}
        />
      )}

      {/* Filters */}
      <div className="flex flex-wrap gap-2 mb-3">
        <div className="relative">
          <Search
            size={11}
            className="absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500"
          />
          <input
            value={search}
            onChange={(e) => {
              setSearch(e.target.value);
              setPage(0);
            }}
            placeholder="Search by ID or description..."
            className="pl-8 pr-3 py-1.5 rounded text-[11px] font-mono outline-none w-52"
            style={inpSty}
          />
        </div>

        {(
          [
            ["Status", statF, setStatF, ["All", "Open", "In Progress", "Resolved", "Closed"]],
            ["Severity", sevF, setSevF, ["All", "Info", "Low", "Medium", "High", "Critical"]],
            ["Analyst", analF, setAnalF, ["All", "analyst1", "analyst2", "soc_lead", "admin"]],
          ] as [string, string, (v: string) => void, string[]][]
        ).map(([lbl, val, setter, opts]) => (
          <select
            key={lbl}
            value={val}
            onChange={(e) => {
              setter(e.target.value);
              setPage(0);
            }}
            className="px-2 py-1.5 rounded text-[11px] font-mono outline-none"
            style={selSty}
          >
            {opts.map((o) => (
              <option key={o} style={{ background: "#0a0f1e" }}>
                {o}
              </option>
            ))}
          </select>
        ))}

        <button
          onClick={() => {
            setStatF("All");
            setSevF("All");
            setAnalF("All");
            setSearch("");
            setPage(0);
          }}
          className="flex items-center gap-1 px-2 py-1.5 rounded text-[10px] font-mono text-slate-400 hover:text-slate-200 transition-colors"
          style={{ border: "1px solid rgba(100,116,139,0.3)" }}
        >
          <RotateCcw size={10} />
          Reset
        </button>

        <div className="ml-auto flex gap-2">
          <button
            onClick={markAll}
            className="px-3 py-1.5 rounded text-[10px] font-mono text-green-400 hover:bg-green-400/10 transition-colors"
            style={{ border: "1px solid rgba(0,255,159,0.25)" }}
          >
            <CheckCircle size={10} className="inline mr-1" />
            Mark All Resolved
          </button>

          <button
            onClick={exportTxt}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded text-[10px] font-mono text-cyan-400 hover:bg-cyan-400/10 transition-colors"
            style={{ border: "1px solid rgba(0,212,255,0.25)" }}
          >
            <Download size={10} />
            Export TXT
          </button>

          <button
            onClick={exportPdf}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded text-[10px] font-mono text-cyan-400 hover:bg-cyan-400/10 transition-colors"
            style={{ border: "1px solid rgba(0,212,255,0.25)" }}
          >
            <Download size={10} />
            Export PDF
          </button>
        </div>
      </div>

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-[11px] font-mono">
          <thead>
            <tr style={{ borderBottom: "1px solid rgba(0,212,255,0.1)" }}>
              {(
                [
                  ["id", "Incident ID"],
                  ["desc", "Detection Info"],
                  ["type", "Type"],
                  ["severity", "Severity"],
                  ["status", "Status"],
                  ["analyst", "Analyst"],
                  ["updated", "Last Updated"],
                ] as [keyof Incident, string][]
              ).map(([col, lbl]) => (
                <th
                  key={col}
                  onClick={() => sort(col)}
                  className="text-left py-2 px-2 text-slate-500 tracking-wider cursor-pointer hover:text-cyan-400 transition-colors whitespace-nowrap"
                >
                  <span className="flex items-center gap-1">
                    {lbl}
                    {sortCol === col ? (
                      sortAsc ? (
                        <ChevronUp size={10} />
                      ) : (
                        <ChevronDown size={10} />
                      )
                    ) : null}
                  </span>
                </th>
              ))}
              <th className="text-left py-2 px-2 text-slate-500 tracking-wider">
                Actions
              </th>
            </tr>
          </thead>
          <tbody>
            {paged.map((inc) => (
              <tr
                key={inc.id}
                className="border-b hover:bg-white/[0.02] transition-colors"
                style={{
                  borderColor: "rgba(0,212,255,0.05)",
                  background:
                    inc.severity === "Critical" &&
                    inc.status !== "Resolved" &&
                    inc.status !== "Closed"
                      ? "rgba(255,0,110,0.04)"
                      : inc.status === "Resolved"
                      ? "rgba(0,255,159,0.03)"
                      : "transparent",
                }}
              >
                <td className="py-2 px-2 text-cyan-400 font-bold whitespace-nowrap">
                  {inc.id}
                </td>
                <td className="py-2 px-2 text-slate-300 max-w-48 truncate">
                  {inc.desc}
                </td>
                <td className="py-2 px-2 text-slate-400 whitespace-nowrap">
                  {inc.type}
                </td>
                <td className="py-2 px-2">
                  <SevBadge s={inc.severity} />
                </td>
                <td className="py-2 px-2">
                  <StatBadge s={inc.status} />
                </td>
                <td className="py-2 px-2 text-slate-400">{inc.analyst}</td>
                <td className="py-2 px-2 text-slate-500 whitespace-nowrap">
                  {inc.updated}
                </td>
                <td className="py-2 px-2">
                  <div className="flex gap-1">
                    <button
                      onClick={() => openDetail(inc)}
                      className="px-1.5 py-0.5 rounded text-[9px] text-cyan-400 hover:bg-cyan-400/10 transition-colors"
                      style={{ border: "1px solid rgba(0,212,255,0.2)" }}
                      title="View"
                    >
                      <Eye size={9} />
                    </button>
                    <button
                      onClick={() => setAssignInc(inc.id)}
                      className="px-1.5 py-0.5 rounded text-[9px] text-yellow-400 hover:bg-yellow-400/10 transition-colors"
                      style={{ border: "1px solid rgba(255,190,11,0.2)" }}
                      title="Assign"
                    >
                      <UserCheck size={9} />
                    </button>
                    <button
                      onClick={() => resolve(inc.id)}
                      className="px-1.5 py-0.5 rounded text-[9px] text-green-400 hover:bg-green-400/10 transition-colors"
                      style={{ border: "1px solid rgba(0,255,159,0.2)" }}
                      title="Resolve"
                    >
                      <CheckCircle size={9} />
                    </button>
                    <button
                      onClick={() => closeInc(inc.id)}
                      className="px-1.5 py-0.5 rounded text-[9px] text-slate-400 hover:bg-slate-400/10 transition-colors"
                      style={{ border: "1px solid rgba(100,116,139,0.2)" }}
                      title="Close"
                    >
                      <X size={9} />
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      <div className="flex items-center justify-between mt-3">
        <span className="text-[10px] font-mono text-slate-600">
          Showing {Math.min(page * PER + 1, sorted.length)}–
          {Math.min((page + 1) * PER, sorted.length)} of {sorted.length}
        </span>
        <div className="flex items-center gap-1">
          <button
            onClick={() => setPage((p) => Math.max(0, p - 1))}
            disabled={page === 0}
            className="p-1 rounded text-slate-500 hover:text-cyan-400 disabled:opacity-30"
          >
            <ChevronLeft size={14} />
          </button>
          {Array.from({ length: Math.min(total, 5) }, (_, i) => (
            <button
              key={i}
              onClick={() => setPage(i)}
              className="w-6 h-6 rounded text-[10px] font-mono transition-colors"
              style={{
                background: page === i ? "rgba(0,212,255,0.15)" : "transparent",
                color: page === i ? "#00d4ff" : "#64748b",
              }}
            >
              {i + 1}
            </button>
          ))}
          <button
            onClick={() => setPage((p) => Math.min(total - 1, p + 1))}
            disabled={page >= total - 1}
            className="p-1 rounded text-slate-500 hover:text-cyan-400 disabled:opacity-30"
          >
            <ChevronRight size={14} />
          </button>
        </div>
      </div>
    </>
  );
}

// ══════════════════════════════════════════════
// DETECTIONS TABLE
// ══════════════════════════════════════════════
function DetectionsTable({ initialDetections }: { initialDetections: Detection[] }) {
  const [detections, setDetections] = useState<Detection[]>(initialDetections);
  const [detTypeF, setDetTypeF] = useState("All");
  const [sevF, setSevF] = useState("All");
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(0);
  const [toast, setToast] = useState<{ msg: string; type: "success" | "error" } | null>(null);
  const PER = 8;

  useEffect(() => {
    if (initialDetections.length) setDetections(initialDetections);
  }, [initialDetections]);

  const filtered = detections.filter((d) => {
    if (detTypeF !== "All" && d.detType !== detTypeF) return false;
    if (sevF !== "All" && d.severity !== sevF) return false;
    if (
      search &&
      !d.srcIp.includes(search) &&
      !d.dstIp.includes(search) &&
      !d.protocol.toLowerCase().includes(search.toLowerCase())
    )
      return false;
    return true;
  });

  const paged = filtered.slice(page * PER, (page + 1) * PER);
  const total = Math.ceil(filtered.length / PER);

  const blockIp = async (ip: string) => {
    const res = await apiFetch<{ message: string }>("/detections/block", {
      method: "POST",
      body: JSON.stringify({ ip }),
    });
    setToast({ msg: res?.message || `IP ${ip} blocked.`, type: "success" });
  };

  const whitelistIp = async (ip: string) => {
    const res = await apiFetch<{ message: string }>("/detections/whitelist", {
      method: "POST",
      body: JSON.stringify({ ip }),
    });
    setToast({ msg: res?.message || `IP ${ip} whitelisted.`, type: "success" });
  };

  const selSty = {
    background: "#0a0f1e",
    border: "1px solid rgba(0,212,255,0.15)",
    color: "#00d4ff",
  };
  const inpSty = {
    background: "rgba(0,212,255,0.04)",
    border: "1px solid rgba(0,212,255,0.15)",
    color: "#cbd5e1",
  };

  return (
    <>
      {toast && (
        <Toast msg={toast.msg} type={toast.type} onClose={() => setToast(null)} />
      )}

      {/* Filters */}
      <div className="flex flex-wrap gap-2 mb-3">
        <div className="relative">
          <Search
            size={11}
            className="absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500"
          />
          <input
            value={search}
            onChange={(e) => {
              setSearch(e.target.value);
              setPage(0);
            }}
            placeholder="Search by IP or protocol..."
            className="pl-8 pr-3 py-1.5 rounded text-[11px] font-mono outline-none w-48"
            style={inpSty}
          />
        </div>
        <select
          value={detTypeF}
          onChange={(e) => {
            setDetTypeF(e.target.value);
            setPage(0);
          }}
          className="px-2 py-1.5 rounded text-[11px] font-mono outline-none"
          style={selSty}
        >
          {["All", "Anomaly", "Signature", "Ransomware"].map((v) => (
            <option key={v} style={{ background: "#0a0f1e" }}>
              {v}
            </option>
          ))}
        </select>
        <select
          value={sevF}
          onChange={(e) => {
            setSevF(e.target.value);
            setPage(0);
          }}
          className="px-2 py-1.5 rounded text-[11px] font-mono outline-none"
          style={selSty}
        >
          {["All", "Info", "Low", "Medium", "High", "Critical"].map((v) => (
            <option key={v} style={{ background: "#0a0f1e" }}>
              {v}
            </option>
          ))}
        </select>
        <button
          onClick={() => {
            setDetTypeF("All");
            setSevF("All");
            setSearch("");
            setPage(0);
          }}
          className="flex items-center gap-1 px-2 py-1.5 rounded text-[10px] font-mono text-slate-400 hover:text-slate-200 transition-colors"
          style={{ border: "1px solid rgba(100,116,139,0.3)" }}
        >
          <RotateCcw size={10} />
          Reset
        </button>
      </div>

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-[11px] font-mono">
          <thead>
            <tr style={{ borderBottom: "1px solid rgba(0,212,255,0.1)" }}>
              {[
                "Timestamp",
                "Traffic Info",
                "Det. Type",
                "Severity",
                "Classification",
                "Explanation",
                "Actions",
              ].map((h) => (
                <th
                  key={h}
                  className="text-left py-2 px-2 text-slate-500 tracking-wider whitespace-nowrap"
                >
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {paged.map((d) => (
              <tr
                key={d.id}
                className="border-b hover:bg-white/[0.02] transition-colors"
                style={{
                  borderColor: "rgba(0,212,255,0.05)",
                  background:
                    d.classification === "Malicious"
                      ? "rgba(255,0,110,0.04)"
                      : d.classification === "Suspicious"
                      ? "rgba(255,190,11,0.03)"
                      : "transparent",
                }}
              >
                <td className="py-2 px-2 text-slate-500 whitespace-nowrap">
                  {d.timestamp}
                </td>
                <td className="py-2 px-2 whitespace-nowrap">
                  <div className="text-cyan-400">{d.srcIp}</div>
                  <div className="text-slate-600 text-[9px]">
                    → {d.dstIp} · {d.protocol}:{d.port}
                  </div>
                </td>
                <td className="py-2 px-2">
                  <span
                    className="px-2 py-0.5 rounded-full text-[9px] font-mono font-bold"
                    style={{
                      color: DET_COLOR[d.detType],
                      background: `${DET_COLOR[d.detType]}15`,
                      border: `1px solid ${DET_COLOR[d.detType]}40`,
                    }}
                  >
                    {d.detType}
                  </span>
                </td>
                <td className="py-2 px-2">
                  <SevBadge s={d.severity} />
                </td>
                <td className="py-2 px-2">
                  <span
                    className="text-[10px] font-mono font-bold"
                    style={{ color: CLASS_COLOR[d.classification] }}
                  >
                    {d.classification}
                  </span>
                </td>
                <td className="py-2 px-2 text-slate-400 max-w-56 truncate">
                  {d.explanation}
                </td>
                <td className="py-2 px-2">
                  <div className="flex gap-1">
                    <button
                      className="px-2 py-0.5 rounded text-[9px] text-cyan-400 hover:bg-cyan-400/10 transition-colors"
                      style={{ border: "1px solid rgba(0,212,255,0.2)" }}
                    >
                      Inspect
                    </button>
                    <button
                      onClick={() => blockIp(d.srcIp)}
                      className="px-2 py-0.5 rounded text-[9px] text-red-400 hover:bg-red-400/10 transition-colors"
                      style={{ border: "1px solid rgba(255,0,110,0.2)" }}
                    >
                      Block
                    </button>
                    <button
                      onClick={() => whitelistIp(d.srcIp)}
                      className="px-2 py-0.5 rounded text-[9px] text-green-400 hover:bg-green-400/10 transition-colors"
                      style={{ border: "1px solid rgba(0,255,159,0.2)" }}
                    >
                      Whitelist
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      <div className="flex items-center justify-between mt-3">
        <span className="text-[10px] font-mono text-slate-600">
          Showing {Math.min(page * PER + 1, filtered.length)}–
          {Math.min((page + 1) * PER, filtered.length)} of {filtered.length}
        </span>
        <div className="flex items-center gap-1">
          <button
            onClick={() => setPage((p) => Math.max(0, p - 1))}
            disabled={page === 0}
            className="p-1 rounded text-slate-500 hover:text-cyan-400 disabled:opacity-30"
          >
            <ChevronLeft size={14} />
          </button>
          {Array.from({ length: Math.min(total, 5) }, (_, i) => (
            <button
              key={i}
              onClick={() => setPage(i)}
              className="w-6 h-6 rounded text-[10px] font-mono transition-colors"
              style={{
                background: page === i ? "rgba(0,212,255,0.15)" : "transparent",
                color: page === i ? "#00d4ff" : "#64748b",
              }}
            >
              {i + 1}
            </button>
          ))}
          <button
            onClick={() => setPage((p) => Math.min(total - 1, p + 1))}
            disabled={page >= total - 1}
            className="p-1 rounded text-slate-500 hover:text-cyan-400 disabled:opacity-30"
          >
            <ChevronRight size={14} />
          </button>
        </div>
      </div>
    </>
  );
}

// ══════════════════════════════════════════════
// DONUT CHART
// ══════════════════════════════════════════════
function DonutChart({ data }: { data: DonutItem[] }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const total = data.reduce((s, d) => s + d.value, 0);

  useEffect(() => {
    const c = canvasRef.current;
    if (!c || !data.length) return;
    const ctx = c.getContext("2d");
    if (!ctx) return;

    c.width = c.offsetWidth;
    c.height = c.offsetHeight;

    const cx = c.width / 2;
    const cy = c.height / 2;
    const r = Math.min(cx, cy) - 16;
    let angle = -Math.PI / 2;

    data.forEach(({ value, color }) => {
      const slice = (value / total) * Math.PI * 2;
      ctx.beginPath();
      ctx.moveTo(cx, cy);
      ctx.arc(cx, cy, r, angle, angle + slice);
      ctx.closePath();
      ctx.fillStyle = color;
      ctx.shadowBlur = 8;
      ctx.shadowColor = color;
      ctx.fill();
      ctx.shadowBlur = 0;

      ctx.beginPath();
      ctx.moveTo(cx, cy);
      ctx.arc(cx, cy, r, angle, angle + slice);
      ctx.closePath();
      ctx.strokeStyle = "#030712";
      ctx.lineWidth = 3;
      ctx.stroke();

      angle += slice;
    });

    ctx.beginPath();
    ctx.arc(cx, cy, r * 0.52, 0, Math.PI * 2);
    ctx.fillStyle = "#0a0f1e";
    ctx.fill();

    ctx.fillStyle = "#00d4ff";
    ctx.font = "bold 13px 'JetBrains Mono',monospace";
    ctx.textAlign = "center";
    ctx.fillText(total.toLocaleString(), cx, cy - 4);
    ctx.fillStyle = "#64748b";
    ctx.font = "9px 'JetBrains Mono',monospace";
    ctx.fillText("Total", cx, cy + 10);
  }, [data, total]);

  return <canvas ref={canvasRef} className="w-full h-full" />;
}

// ══════════════════════════════════════════════
// SEVERITY BAR CHART
// ══════════════════════════════════════════════
function SeverityBarChart({ data }: { data: BarItem[] }) {
  const total = data.reduce((s, d) => s + d.value, 0) || 1;
  const [widths, setWidths] = useState(data.map(() => 0));
  const [hovered, setHovered] = useState<number | null>(null);

  useEffect(() => {
    if (!data.length) return;
    const t = setTimeout(() => setWidths(data.map((d) => (d.value / total) * 100)), 100);
    return () => clearTimeout(t);
  }, [data, total]);

  return (
    <div className="space-y-3 mt-2">
      {data.map(({ label, value, color }, i) => (
        <div
          key={label}
          className="space-y-1"
          onMouseEnter={() => setHovered(i)}
          onMouseLeave={() => setHovered(null)}
        >
          <div className="flex justify-between text-[10px] font-mono">
            <span style={{ color: hovered === i ? color : "#94a3b8" }}>{label}</span>
            <div className="flex gap-2">
              <span style={{ color }}>{value.toLocaleString()}</span>
              <span className="text-slate-600">{((value / total) * 100).toFixed(1)}%</span>
            </div>
          </div>
          <div className="h-5 rounded-full bg-slate-800 overflow-hidden">
            <div
              className="h-full rounded-full transition-all duration-700 ease-out"
              style={{
                width: `${widths[i]}%`,
                background: color,
                boxShadow:
                  hovered === i
                    ? `0 0 12px ${color},0 0 24px ${color}60`
                    : `0 0 6px ${color}60`,
                minWidth: "4px",
              }}
            />
          </div>
        </div>
      ))}
    </div>
  );
}

// ═══════════════════════════════════════════���══
// CHARTS SECTION
// ══════════════════════════════════════════════
function ChartsSection({ donut, bars }: { donut: DonutItem[]; bars: BarItem[] }) {
  const total = donut.reduce((s, d) => s + d.value, 0);
  const [open, setOpen] = useState(true);

  return (
    <div
      className="rounded overflow-hidden"
      style={{
        background: "rgba(10,15,30,0.95)",
        border: "1px solid rgba(0,212,255,0.12)",
      }}
    >
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center justify-between px-5 py-4 hover:bg-white/[0.02] transition-colors"
      >
        <div className="flex items-center gap-2">
          <Layers size={14} className="text-cyan-400" />
          <span className="text-[13px] font-mono font-semibold text-slate-200 tracking-wider uppercase">
            Detection Analytics
          </span>
        </div>
        {open ? (
          <ChevronUp size={14} className="text-slate-500" />
        ) : (
          <ChevronDown size={14} className="text-slate-500" />
        )}
      </button>

      {open && (
        <div
          className="px-5 pb-5 border-t grid grid-cols-1 lg:grid-cols-2 gap-6"
          style={{ borderColor: "rgba(0,212,255,0.08)" }}
        >
          {/* Donut */}
          <div className="pt-4">
            <div className="flex items-center gap-2 mb-3">
              <Activity size={13} className="text-cyan-400" />
              <span className="text-[11px] font-mono text-slate-300 uppercase tracking-wider font-semibold">
                Detections by Type
              </span>
            </div>
            {donut.length === 0 ? (
              <Skeleton className="h-36" />
            ) : (
              <div className="flex gap-4">
                <div className="w-36 h-36 shrink-0">
                  <DonutChart data={donut} />
                </div>
                <div className="flex flex-col justify-center gap-3">
                  {donut.map(({ label, value, color }) => (
                    <div key={label} className="flex items-center gap-2 text-[10px] font-mono">
                      <div
                        className="w-2.5 h-2.5 rounded-full shrink-0"
                        style={{ background: color, boxShadow: `0 0 4px ${color}` }}
                      />
                      <span className="text-slate-400 w-20">{label}</span>
                      <span style={{ color }} className="font-bold">
                        {value.toLocaleString()}
                      </span>
                      <span className="text-slate-600">
                        {((value / total) * 100).toFixed(1)}%
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Bar */}
          <div className="pt-4">
            <div className="flex items-center gap-2 mb-3">
              <BarChart2 size={13} className="text-cyan-400" />
              <span className="text-[11px] font-mono text-slate-300 uppercase tracking-wider font-semibold">
                Severity Distribution
              </span>
            </div>
            {bars.length === 0 ? <Skeleton className="h-36" /> : <SeverityBarChart data={bars} />}
          </div>
        </div>
      )}
    </div>
  );
}

// ══════════════════════════════════════════════
// MAIN PAGE
// ══════════════════════════════════════════════
export default function IncidentsPage() {
  const [tab, setTab] = useState<"incidents" | "detections">("incidents");
  const [stats, setStats] = useState<StatCard[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [detections, setDetections] = useState<Detection[]>([]);
  const [donut, setDonut] = useState<DonutItem[]>([]);
  const [bars, setBars] = useState<BarItem[]>([]);

  useEffect(() => {
    apiFetch<any>("/snapshot").then((snap) => {
      if (!snap) return;
      setStats(snap.stats?.stats ?? []);
      setIncidents((snap.incidents?.incidents ?? []).map(normalizeIncident));
      setDetections((snap.detections?.detections ?? []).map(normalizeDetection));
      setDonut(snap.charts?.donut ?? []);
      setBars(snap.charts?.severity_bars ?? []);
    });
  }, []);

  return (
    <div className="min-h-screen" style={{ background: "#030712" }}>
      <style>{`@keyframes critPulse{0%,100%{box-shadow:0 0 20px rgba(255,0,110,0.3)}50%{box-shadow:0 0 40px rgba(255,0,110,0.6)}}`}</style>
      <div
        className="fixed inset-0 pointer-events-none"
        style={{
          backgroundImage:
            "linear-gradient(rgba(0,212,255,0.018) 1px,transparent 1px),linear-gradient(90deg,rgba(0,212,255,0.018) 1px,transparent 1px)",
          backgroundSize: "40px 40px",
        }}
      />
      <Navbar />

      <main className="relative z-10 max-w-screen-xl mx-auto px-4 sm:px-6 py-6 space-y-5">
        <div className="flex items-center justify-between">
          <div>
            <h1
              className="text-xl font-bold text-slate-100 tracking-wider"
              style={{ fontFamily: "'Orbitron',monospace" }}
            >
              INCIDENTS & DETECTIONS
            </h1>
            <p className="text-[11px] font-mono text-slate-600 mt-0.5">
              Real-time threat monitoring · Detection analysis · Incident response
            </p>
          </div>
          <div className="flex items-center gap-1.5 text-[11px] font-mono text-green-400">
            <div className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
            LIVE
          </div>
        </div>

        <StatCards stats={stats} />

        <div
          className="rounded overflow-hidden"
          style={{
            background: "rgba(10,15,30,0.95)",
            border: "1px solid rgba(0,212,255,0.12)",
          }}
        >
          <div className="flex border-b" style={{ borderColor: "rgba(0,212,255,0.1)" }}>
            {(["incidents", "detections"] as const).map((t) => (
              <button
                key={t}
                onClick={() => setTab(t)}
                className={`px-6 py-3.5 text-[12px] font-mono tracking-wider border-b-2 transition-all duration-200 capitalize ${
                  tab === t
                    ? "text-cyan-400 border-cyan-400"
                    : "text-slate-500 border-transparent hover:text-slate-300"
                }`}
              >
                {t === "incidents" ? "🔴 Incidents" : "🔵 Detections"}
              </button>
            ))}
          </div>
          <div className="p-5">
            {tab === "incidents" ? (
              <IncidentsTable initialIncidents={incidents} />
            ) : (
              <DetectionsTable initialDetections={detections} />
            )}
          </div>
        </div>

        <ChartsSection donut={donut} bars={bars} />

        <div className="pt-2 pb-4 flex items-center justify-between text-[10px] font-mono text-slate-700">
          <span>CyGuardian-X v2.4.1 — INCIDENTS MODULE</span>
          <span>ALL INCIDENTS ARE LOGGED AND AUDITED</span>
        </div>
      </main>
    </div>
  );
}