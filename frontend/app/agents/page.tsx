"use client";

import NotificationBell from "../../components/NotificationBell";
import { useEffect, useState, useCallback } from "react";
import {
  Shield, Activity, AlertTriangle, FileText, Settings, LogOut,
  Bot, Eye, ShieldCheck, CheckCircle2, XCircle, Clock,
  Zap, Pause, Brain, Cpu, Network, Menu, X,
} from "lucide-react";

const API = "https://fyp-backend-production-944f.up.railway.app";

// ── Types ─────────────────────────────────────────────────
type AgentStatus = {
  name: string;
  running: boolean;
  subscribes_to: string[];
  last_heartbeat: string | null;
  events_processed: number;
  actions_recommended: number;
  errors: number;
};

type AgentAction = {
  id: number;
  agent_name: string;
  action_type: string;
  target: string;
  severity: "Critical" | "High" | "Medium" | "Low" | "Info";
  confidence: number;
  autonomy_level: "AUTO" | "APPROVAL_REQUIRED" | "RECOMMEND_ONLY";
  status: "PENDING" | "APPROVED" | "REJECTED" | "EXECUTED" | "FAILED" | "AUTO_APPROVED";
  reasoning: string;
  approved_by: string | null;
  approved_at: string | null;
  executed_at: string | null;
  error_message: string | null;
  created_at: string;
};

function authHeader(): HeadersInit {
  const t = typeof window !== "undefined" ? localStorage.getItem("token") : null;
  return t ? { Authorization: `Bearer ${t}` } : {};
}

function sevColor(s: string) {
  if (s === "Critical") return "#ff006e";
  if (s === "High")     return "#f59e0b";
  if (s === "Medium")   return "#fbbf24";
  if (s === "Low")      return "#00d4ff";
  return "#94a3b8";
}

function statusColor(s: string) {
  return ({
    PENDING:       "#fbbf24",
    APPROVED:      "#00d4ff",
    AUTO_APPROVED: "#00ff9f",
    EXECUTED:      "#00ff9f",
    REJECTED:      "#94a3b8",
    FAILED:        "#ff006e",
  } as Record<string, string>)[s] || "#94a3b8";
}

function autonomyColor(a: string) {
  return ({
    AUTO:              "#00ff9f",
    APPROVAL_REQUIRED: "#fbbf24",
    RECOMMEND_ONLY:    "#94a3b8",
  } as Record<string, string>)[a] || "#94a3b8";
}

function timeAgo(iso: string | null): string {
  if (!iso) return "—";
  const diff = (Date.now() - new Date(iso).getTime()) / 1000;
  if (diff < 60)    return `${Math.floor(diff)}s ago`;
  if (diff < 3600)  return `${Math.floor(diff/60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff/3600)}h ago`;
  return new Date(iso).toLocaleDateString();
}

const AGENT_ICONS: Record<string, any> = {
  MONITOR:  Eye,
  TRIAGE:   Brain,
  RESPONSE: ShieldCheck,
};

const NAV_LINKS = [
  { label: "Dashboard",          href: "/dashboard",     icon: Shield },
  { label: "Network Monitoring", href: "/network",       icon: Activity },
  { label: "Incidents",          href: "/incidents",     icon: AlertTriangle },
  { label: "Configuration",      href: "/configuration", icon: Settings },
  { label: "Audits",             href: "/audits",        icon: FileText },
  { label: "Agents",             href: "/agents",        icon: Bot },
];

// ══════════════════════════════════════════════════════════
// PAGE
// ══════════════════════════════════════════════════════════
export default function AgentsPage() {
  const [agents,  setAgents]  = useState<AgentStatus[]>([]);
  const [pending, setPending] = useState<AgentAction[]>([]);
  const [recent,  setRecent]  = useState<AgentAction[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy,    setBusy]    = useState<Record<number, string>>({});

  const fetchAll = useCallback(async () => {
    try {
      const [s, p, r] = await Promise.all([
        fetch(`${API}/api/agents/status`,          { headers: authHeader() }).then(r => r.json()),
        fetch(`${API}/api/agents/actions/pending`, { headers: authHeader() }).then(r => r.json()),
        fetch(`${API}/api/agents/actions?limit=30`, { headers: authHeader() }).then(r => r.json()),
      ]);
      setAgents(s.agents  || []);
      setPending(p.actions || []);
      setRecent(r.actions || []);
    } catch {}
    setLoading(false);
  }, []);

  useEffect(() => {
    fetchAll();
    const id = setInterval(fetchAll, 5000);
    return () => clearInterval(id);
  }, [fetchAll]);

  const act = async (id: number, kind: "approve" | "reject") => {
    setBusy(b => ({ ...b, [id]: kind }));
    try {
      await fetch(`${API}/api/agents/actions/${id}/${kind}`, {
        method: "POST",
        headers: authHeader(),
      });
      await fetchAll();
    } catch {}
    setBusy(b => { const x = { ...b }; delete x[id]; return x; });
  };

  // LLM explanation state
  const [explained, setExplained] = useState<Record<number, string>>({});
  const [explaining, setExplaining] = useState<Record<number, boolean>>({});

  const explain = async (id: number) => {
    setExplaining(e => ({ ...e, [id]: true }));
    try {
      const res = await fetch(`${API}/api/agents/actions/${id}/explain`, {
        method: "POST",
        headers: authHeader(),
      });
      const data = await res.json();
      setExplained(e => ({ ...e, [id]: data.reasoning || "No explanation available" }));
    } catch {
      setExplained(e => ({ ...e, [id]: "Failed to generate explanation (is Ollama running?)" }));
    }
    setExplaining(e => { const x = { ...e }; delete x[id]; return x; });
  };

  return (
    <div className="min-h-screen" style={{ background: "#030712" }}>
      <Navbar />
      <main className="relative z-10 max-w-screen-xl mx-auto px-4 sm:px-6 py-6 space-y-5">
        {/* Page heading */}
        <div className="flex items-end justify-between">
          <div>
            <h1 className="text-xl font-bold text-slate-100 tracking-wider"
                style={{ fontFamily: "'Orbitron', monospace" }}>
              MULTI-AGENT SYSTEM
            </h1>
            <p className="text-[11px] font-mono text-slate-600 mt-0.5">
              Autonomous threat response · MonitorAgent · TriageAgent · ResponseAgent
            </p>
          </div>
          <div className="flex items-center gap-1.5 text-[10px] font-mono">
            <div className="w-1.5 h-1.5 rounded-full bg-green-400 animate-pulse"
                 style={{ boxShadow: "0 0 4px #00ff9f" }} />
            <span className="text-green-400">AGENTS LIVE</span>
          </div>
        </div>

        {/* Agent status cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {agents.map(a => {
            const Icon = AGENT_ICONS[a.name] || Cpu;
            return (
              <div key={a.name}
                   className="p-5 rounded transition-all hover:border-cyan-400/30"
                   style={{ background: "rgba(10,15,30,0.95)", border: "1px solid rgba(0,212,255,0.12)" }}>
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-2">
                    <div className="w-9 h-9 rounded flex items-center justify-center"
                         style={{ background: "rgba(0,212,255,0.1)", border: "1px solid rgba(0,212,255,0.3)" }}>
                      <Icon size={16} className="text-cyan-400" />
                    </div>
                    <div>
                      <div className="text-[12px] font-bold text-cyan-400 tracking-widest"
                           style={{ fontFamily: "'Orbitron', monospace" }}>
                        {a.name}
                      </div>
                      <div className="text-[9px] font-mono text-slate-500">
                        {a.subscribes_to.length > 0
                          ? `subscribes: ${a.subscribes_to.join(", ")}`
                          : "polls correlations"}
                      </div>
                    </div>
                  </div>
                  <div className={`flex items-center gap-1.5 px-2 py-0.5 rounded text-[9px] font-mono tracking-wider ${
                    a.running ? "text-green-400" : "text-red-400"
                  }`} style={{
                    background: a.running ? "rgba(0,255,159,0.08)" : "rgba(255,0,110,0.08)",
                    border: `1px solid ${a.running ? "rgba(0,255,159,0.3)" : "rgba(255,0,110,0.3)"}`,
                  }}>
                    <div className={`w-1 h-1 rounded-full ${a.running ? "bg-green-400 animate-pulse" : "bg-red-400"}`} />
                    {a.running ? "RUNNING" : "STOPPED"}
                  </div>
                </div>
                <div className="grid grid-cols-3 gap-2 mt-4">
                  <Stat label="Events"   value={a.events_processed}    color="#00d4ff" />
                  <Stat label="Actions"  value={a.actions_recommended} color="#00ff9f" />
                  <Stat label="Errors"   value={a.errors}              color={a.errors > 0 ? "#ff006e" : "#94a3b8"} />
                </div>
                <div className="mt-3 pt-3 text-[9px] font-mono text-slate-600 flex items-center justify-between"
                     style={{ borderTop: "1px solid rgba(148,163,184,0.08)" }}>
                  <span>Last heartbeat</span>
                  <span className="text-slate-400">{timeAgo(a.last_heartbeat)}</span>
                </div>
              </div>
            );
          })}
        </div>

        {/* Pending approval queue */}
        <div className="rounded" style={{ background: "rgba(10,15,30,0.95)", border: "1px solid rgba(251,191,36,0.25)" }}>
          <div className="px-5 py-3 flex items-center justify-between"
               style={{ borderBottom: "1px solid rgba(251,191,36,0.15)" }}>
            <div className="flex items-center gap-3">
              <Clock size={15} className="text-yellow-400" />
              <h2 className="text-[12px] font-bold text-yellow-400 tracking-widest"
                  style={{ fontFamily: "'Orbitron', monospace" }}>
                PENDING APPROVAL
              </h2>
              {pending.length > 0 && (
                <span className="text-[10px] font-mono text-yellow-400 px-2 py-0.5 rounded animate-pulse"
                      style={{ background: "rgba(251,191,36,0.1)", border: "1px solid rgba(251,191,36,0.3)" }}>
                  {pending.length} REQUIRES REVIEW
                </span>
              )}
            </div>
          </div>
          <div className="p-3">
            {loading && <div className="text-center text-[11px] font-mono text-slate-500 py-6">Loading...</div>}
            {!loading && pending.length === 0 && (
              <div className="text-center text-[11px] font-mono text-slate-500 py-6">
                <CheckCircle2 size={22} className="mx-auto mb-2 opacity-30 text-green-400" />
                No pending actions — agents are handling threats autonomously
              </div>
            )}
            <div className="space-y-2">
              {pending.map(a => (
                <div key={a.id} className="px-4 py-3 rounded"
                     style={{ background: "rgba(3,7,18,0.6)", border: "1px solid rgba(251,191,36,0.2)" }}>
                  <div className="flex items-center justify-between gap-3 mb-2">
                    <div className="flex items-center gap-3">
                      <div className="w-2 h-2 rounded-full animate-pulse"
                           style={{ background: sevColor(a.severity), boxShadow: `0 0 6px ${sevColor(a.severity)}` }} />
                      <span className="text-[10px] font-mono tracking-widest" style={{ color: sevColor(a.severity) }}>
                        {a.severity.toUpperCase()}
                      </span>
                      <span className="text-[10px] font-mono text-slate-400">·</span>
                      <span className="text-[11px] font-mono font-bold text-cyan-400">{a.action_type}</span>
                      <span className="text-[10px] font-mono text-slate-400">·</span>
                      <span className="text-[11px] font-mono text-slate-200">{a.target}</span>
                      <span className="text-[10px] font-mono text-slate-500">({a.confidence}%)</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <button onClick={() => act(a.id, "approve")} disabled={!!busy[a.id]}
                              className="px-3 py-1 text-[10px] font-mono tracking-widest rounded transition-colors disabled:opacity-40"
                              style={{ background: "rgba(0,255,159,0.1)", color: "#00ff9f", border: "1px solid rgba(0,255,159,0.3)" }}>
                        {busy[a.id] === "approve" ? "..." : "✓ APPROVE"}
                      </button>
                      <button onClick={() => act(a.id, "reject")} disabled={!!busy[a.id]}
                              className="px-3 py-1 text-[10px] font-mono tracking-widest rounded transition-colors disabled:opacity-40"
                              style={{ background: "rgba(255,0,110,0.1)", color: "#ff006e", border: "1px solid rgba(255,0,110,0.3)" }}>
                        {busy[a.id] === "reject" ? "..." : "✗ REJECT"}
                      </button>
                    </div>
                  </div>
                  <div className="text-[10px] font-mono text-slate-500 pl-5">
                    <span className="text-slate-600">Reasoning:</span> {a.reasoning}
                  </div>
                  <div className="pl-5 mt-2">
                    <button onClick={() => explain(a.id)} disabled={!!explaining[a.id]}
                            className="px-2.5 py-1 text-[9px] font-mono tracking-widest rounded transition-colors disabled:opacity-40"
                            style={{ background: "rgba(167,139,250,0.1)", color: "#a78bfa", border: "1px solid rgba(167,139,250,0.3)" }}>
                      {explaining[a.id] ? "🧠 ANALYZING..." : "🧠 EXPLAIN WITH AI"}
                    </button>
                    {explained[a.id] && (
                      <div className="mt-2 p-3 rounded text-[10px] font-mono leading-relaxed"
                           style={{ background: "rgba(167,139,250,0.05)", border: "1px solid rgba(167,139,250,0.2)", color: "#cbd5e1" }}>
                        <div className="text-[9px] font-bold tracking-widest mb-1.5" style={{ color: "#a78bfa" }}>
                          AI ANALYST EXPLANATION
                        </div>
                        {explained[a.id]}
                      </div>
                    )}
                  </div>
                  <div className="text-[9px] font-mono text-slate-600 pl-5 mt-1">
                    Recommended by <span className="text-cyan-400">{a.agent_name}</span> · {timeAgo(a.created_at)}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Recent activity */}
        <div className="rounded" style={{ background: "rgba(10,15,30,0.95)", border: "1px solid rgba(0,212,255,0.12)" }}>
          <div className="px-5 py-3 flex items-center justify-between"
               style={{ borderBottom: "1px solid rgba(0,212,255,0.1)" }}>
            <div className="flex items-center gap-3">
              <Zap size={15} className="text-cyan-400" />
              <h2 className="text-[12px] font-bold text-cyan-400 tracking-widest"
                  style={{ fontFamily: "'Orbitron', monospace" }}>
                RECENT ACTIVITY
              </h2>
              <span className="text-[10px] font-mono text-slate-500">{recent.length} actions</span>
            </div>
          </div>
          <div className="p-3 max-h-[500px] overflow-y-auto">
            {recent.length === 0 && (
              <div className="text-center text-[11px] font-mono text-slate-500 py-6">
                <Pause size={20} className="mx-auto mb-2 opacity-30" />
                No agent activity yet — run an attack to see live decisions
              </div>
            )}
            <div className="space-y-1.5">
              {recent.map(a => (
                <div key={a.id} className="flex items-center gap-3 px-3 py-2 rounded text-[10px] font-mono"
                     style={{ background: "rgba(3,7,18,0.4)", border: "1px solid rgba(148,163,184,0.06)" }}>
                  <span className="w-16 text-cyan-400 font-bold">{a.agent_name}</span>
                  <span className="w-20 text-slate-300">{a.action_type}</span>
                  <span className="w-36 text-slate-400">{a.target}</span>
                  <span className="w-12" style={{ color: sevColor(a.severity) }}>{a.severity}</span>
                  <span className="w-10 text-slate-500">{a.confidence}%</span>
                  <span className="w-32 px-2 py-0.5 rounded text-center text-[9px]"
                        style={{ background: `${autonomyColor(a.autonomy_level)}15`, color: autonomyColor(a.autonomy_level),
                                 border: `1px solid ${autonomyColor(a.autonomy_level)}30` }}>
                    {a.autonomy_level}
                  </span>
                  <span className="flex-1 px-2 py-0.5 rounded text-center text-[9px]"
                        style={{ background: `${statusColor(a.status)}15`, color: statusColor(a.status),
                                 border: `1px solid ${statusColor(a.status)}30` }}>
                    {a.status}
                  </span>
                  <span className="text-slate-600">{timeAgo(a.created_at)}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="pt-2 pb-4 flex items-center justify-between text-[10px] font-mono text-slate-700">
          <span>CyGuardian-X v2.4.1 — AGENT CONSOLE</span>
          <span>HUMAN-IN-THE-LOOP MODE · BALANCED AUTONOMY</span>
        </div>
      </main>
    </div>
  );
}

// ══════════════════════════════════════════════════════════
// SMALL HELPERS
// ══════════════════════════════════════════════════════════
function Stat({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div className="text-center py-2 rounded"
         style={{ background: "rgba(3,7,18,0.4)", border: "1px solid rgba(148,163,184,0.05)" }}>
      <div className="text-[16px] font-bold tracking-wider"
           style={{ color, fontFamily: "'Orbitron', monospace" }}>
        {value.toLocaleString()}
      </div>
      <div className="text-[9px] font-mono text-slate-500 tracking-widest uppercase mt-0.5">
        {label}
      </div>
    </div>
  );
}

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
    <nav className="sticky top-0 z-40 w-full"
         style={{ background: "rgba(6,10,20,0.98)", borderBottom: "1px solid rgba(0,212,255,0.15)", backdropFilter: "blur(12px)" }}>
      <div className="flex items-center justify-between px-6 h-14">
        <div className="flex items-center gap-3 shrink-0">
          <div className="relative">
            <Shield size={20} className="text-cyan-400" />
            <div className="absolute -top-0.5 -right-0.5 w-2 h-2 rounded-full bg-green-400" style={{ boxShadow: "0 0 6px #00ff9f" }} />
          </div>
          <span style={{ fontFamily: "'Orbitron', monospace" }} className="text-cyan-400 font-bold tracking-widest text-sm hidden sm:block">
            CyGuardian-X
          </span>
        </div>
        <div className="hidden lg:flex items-center gap-0">
          {NAV_LINKS.map(({ label, href, icon: Icon }) => {
            const active = label === "Agents";
            return (
              <a key={label} href={href}
                 className={`flex items-center gap-1.5 px-3 py-4 text-[11px] font-mono tracking-wider border-b-2 transition-all duration-200 ${
                   active ? "text-cyan-400 border-cyan-400" : "text-slate-500 border-transparent hover:text-slate-300 hover:border-slate-700"
                 }`}>
                <Icon size={12} />{label.toUpperCase()}
              </a>
            );
          })}
        </div>
        <div className="flex items-center gap-3">
          <span className="text-[10px] font-mono text-slate-600 hidden md:block">{time}</span>
          <div className="flex items-center gap-2 px-3 py-1 rounded"
               style={{ background: "rgba(0,212,255,0.06)", border: "1px solid rgba(0,212,255,0.15)" }}>
            <div className="w-6 h-6 rounded-full flex items-center justify-center text-[10px] font-bold text-cyan-400"
                 style={{ background: "rgba(0,212,255,0.2)" }}>A</div>
            <span className="text-[11px] font-mono text-slate-400 hidden sm:block">ADMIN</span>
          </div>
          <NotificationBell />
          <a href="/logout" className="flex items-center gap-1.5 text-[10px] font-mono text-slate-600 hover:text-red-400 transition-colors">
            <LogOut size={13}/><span className="hidden sm:block">LOGOUT</span>
          </a>
          <button className="lg:hidden text-slate-400" onClick={() => setMenuOpen(!menuOpen)}>
            {menuOpen ? <X size={18} /> : <Menu size={18} />}
          </button>
        </div>
      </div>
      {menuOpen && (
        <div className="lg:hidden px-4 pb-3 space-y-1" style={{ borderTop: "1px solid rgba(0,212,255,0.1)" }}>
          {NAV_LINKS.map(({ label, href, icon: Icon }) => (
            <a key={label} href={href}
               className="flex items-center gap-2 px-3 py-2 text-[11px] font-mono text-slate-400 rounded hover:bg-cyan-400/5">
              <Icon size={13}/>{label.toUpperCase()}
            </a>
          ))}
        </div>
      )}
    </nav>
  );
}
