"use client";

import { useState, useEffect, useCallback } from "react";
import {
  Shield, Activity, AlertTriangle, Users, Network,
  Settings, FileText, Bell, LogOut, TrendingUp, TrendingDown,
  Eye, UserCheck, UserX, BarChart2, Layers, Lock,
  Radio, RefreshCw, Menu, X, CheckCircle, XCircle,
  AlertCircle, Clock, ArrowRight, WifiOff,
} from "lucide-react";

// ════════════════════════════════════════════════════════════════
// API BASE URL — change this if your backend port is different
// ════════════════════════════════════════════════════════════════
const API = "http://localhost:8000";

// ════════════════════════════════════════════════════════════════
// TYPES matching backend responses
// ════════════════════════════════════════════════════════════════
interface StatItem   { value: number; trend: "up"|"down"; change: string; sub: string; }
interface StatsData  { total_users: StatItem; active_attacks: StatItem; network_flows: StatItem; detections: StatItem; }
interface DetCat     { label: string; value: number; pct: number; color: string; }
interface DetData    { total: number; categories: DetCat[]; }
interface TrendDay   { date: string; full_date: string; anomaly: number; signature: number; ransomware: number; }
interface TrendData  { days: TrendDay[]; }
interface RoleItem   { role: string; count: number; color: string; pct: number; }
interface RolesData  { total: number; roles: RoleItem[]; }
interface UserItem   { name: string; email: string; role: string; status: string; avatar: string; last_active: string; }
interface UserAct    { name: string; email: string; role: string; avatar: string; time: string; }
interface UsersData  { recent: UserItem[]; last_created: UserAct; last_deactivated: UserAct; }
interface QAItem     { badge: string; count: number | null; }
interface QAData     { manage_users: QAItem; security_configuration: QAItem; network_monitoring: QAItem; alerts_incidents: QAItem; audit_reports: QAItem; }

// ════════════════════════════════════════════════════════════════
// FETCH HELPER — returns null on error (shows fallback UI)
// ════════════════════════════════════════════════════════════════
async function apiFetch<T>(path: string): Promise<T | null> {
  try {
    const res = await fetch(`${API}${path}`);
    if (!res.ok) return null;
    return await res.json() as T;
  } catch {
    return null;
  }
}

// ════════════════════════════════════════════════════════════════
// COUNT-UP HOOK
// ════════════════════════════════════════════════════════════════
function useCountUp(target: number, duration = 1200) {
  const [count, setCount] = useState(0);
  useEffect(() => {
    setCount(0);
    let start = 0;
    const step = target / (duration / 16);
    const timer = setInterval(() => {
      start += step;
      if (start >= target) { setCount(target); clearInterval(timer); }
      else setCount(Math.floor(start));
    }, 16);
    return () => clearInterval(timer);
  }, [target, duration]);
  return count;
}

// ════════════════════════════════════════════════════════════════
// NAVBAR
// ════════════════════════════════════════════════════════════════
const NAV_LINKS = [
  { label: "Dashboard",          href: "/dashboard",     icon: BarChart2   },
  { label: "Network Monitoring", href: "/network",       icon: Radio       },
  { label: "Incidents",          href: "/incidents",     icon: AlertTriangle },
  { label: "Configuration",      href: "/configuration", icon: Settings    },
  { label: "Audits",             href: "/audits",        icon: FileText    },
];

function Navbar({ active, setActive, backendOnline }: { active: string; setActive: (s: string) => void; backendOnline: boolean }) {
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
          {NAV_LINKS.map(({ label, href, icon: Icon }) => (
            <a key={label} href={href}
              className={`flex items-center gap-1.5 px-3 py-4 text-[11px] font-mono tracking-wider border-b-2 transition-all duration-200 ${
                active === label ? "text-cyan-400 border-cyan-400" : "text-slate-500 border-transparent hover:text-slate-300 hover:border-slate-700"
              }`}>
              <Icon size={12} />{label.toUpperCase()}
            </a>
          ))}
        </div>

        <div className="flex items-center gap-3">
          {/* Backend status indicator */}
          <div className="hidden md:flex items-center gap-1.5 text-[10px] font-mono">
            <div className={`w-1.5 h-1.5 rounded-full ${backendOnline ? "bg-green-400 animate-pulse" : "bg-red-400"}`}
              style={{ boxShadow: backendOnline ? "0 0 4px #00ff9f" : "0 0 4px #ff006e" }}/>
            <span className={backendOnline ? "text-green-400" : "text-red-400"}>
              {backendOnline ? "API LIVE" : "API OFFLINE"}
            </span>
          </div>
          <span className="text-[10px] font-mono text-slate-600 hidden md:block">{time}</span>
          <div className="flex items-center gap-2 px-3 py-1 rounded"
            style={{ background: "rgba(0,212,255,0.06)", border: "1px solid rgba(0,212,255,0.15)" }}>
            <div className="w-6 h-6 rounded-full flex items-center justify-center text-[10px] font-bold text-cyan-400"
              style={{ background: "rgba(0,212,255,0.2)" }}>A</div>
            <span className="text-[11px] font-mono text-slate-400 hidden sm:block">ADMIN</span>
          </div>
          <button onClick={() => (window.location.href = "/logout")}
            className="flex items-center gap-1.5 text-[10px] font-mono text-slate-600 hover:text-red-400 transition-colors">
            <LogOut size={13} /><span className="hidden sm:block">LOGOUT</span>
          </button>
          <button className="lg:hidden text-slate-400" onClick={() => setMenuOpen(!menuOpen)}>
            {menuOpen ? <X size={18} /> : <Menu size={18} />}
          </button>
        </div>
      </div>

      {menuOpen && (
        <div className="lg:hidden px-4 pb-3 space-y-1 border-t" style={{ borderColor: "rgba(0,212,255,0.1)" }}>
          {NAV_LINKS.map(({ label, href, icon: Icon }) => (
            <a key={label} href={href}
              className={`flex items-center gap-2 px-3 py-2 text-[11px] font-mono rounded transition-colors ${
                active === label ? "text-cyan-400 bg-cyan-400/10" : "text-slate-500 hover:text-slate-300"
              }`}>
              <Icon size={12} />{label}
            </a>
          ))}
        </div>
      )}
    </nav>
  );
}

// ════════════════════════════════════════════════════════════════
// SECTION HEADER
// ════════════════════════════════════════════════════════════════
function SectionHeader({ icon: Icon, title, sub }: { icon: any; title: string; sub: string }) {
  return (
    <div className="flex items-center justify-between mb-1">
      <div className="flex items-center gap-2">
        <Icon size={14} className="text-cyan-400" />
        <span className="text-[12px] font-mono text-slate-200 tracking-wider uppercase font-semibold">{title}</span>
      </div>
      <span className="text-[10px] font-mono text-slate-600">{sub}</span>
    </div>
  );
}

// ════════════════════════════════════════════════════════════════
// SKELETON LOADER — shown while fetching
// ════════════════════════════════════════════════════════════════
function Skeleton({ className = "" }: { className?: string }) {
  return (
    <div className={`rounded animate-pulse ${className}`}
      style={{ background: "rgba(0,212,255,0.06)" }}/>
  );
}

// ════════════════════════════════════════════════════════════════
// STAT CARDS — powered by /api/dashboard/stats
// ════════════════════════════════════════════════════════════════
function StatCard({ label, value, icon: Icon, color, border, sub, trend, change }: {
  label: string; value: number; icon: any; color: string;
  border: string; sub: string; trend?: "up"|"down"; change?: string;
}) {
  const count = useCountUp(value);
  return (
    <div className="relative p-5 rounded overflow-hidden group transition-all duration-300 hover:-translate-y-0.5 cursor-default"
      style={{ background: "rgba(10,15,30,0.95)", border: `1px solid ${border}`, boxShadow: `0 0 20px ${border}18` }}>
      <div className="absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity duration-300 pointer-events-none"
        style={{ background: `radial-gradient(ellipse at top left, ${border}0c, transparent 70%)` }} />
      <div className="relative z-10">
        <div className="flex items-start justify-between mb-3">
          <div className="p-2 rounded" style={{ background: `${border}18` }}>
            <Icon size={16} className={color} />
          </div>
          {trend && (
            <div className={`flex items-center gap-0.5 text-[10px] font-mono ${trend === "up" ? "text-green-400" : "text-red-400"}`}>
              {trend === "up" ? <TrendingUp size={10} /> : <TrendingDown size={10} />}
              {change}
            </div>
          )}
        </div>
        <div className={`text-3xl font-bold ${color} mb-1`} style={{ fontFamily: "'Orbitron', monospace" }}>
          {count.toLocaleString()}
        </div>
        <div className="text-[11px] font-mono text-slate-400 uppercase tracking-wider">{label}</div>
        <div className="text-[10px] font-mono text-slate-600 mt-0.5">{sub}</div>
      </div>
    </div>
  );
}

function StatCardsSection({ data }: { data: StatsData | null }) {
  if (!data) return (
    <div className="grid grid-cols-2 xl:grid-cols-4 gap-4">
      {[0,1,2,3].map(i => <Skeleton key={i} className="h-32"/>)}
    </div>
  );
  return (
    <div className="grid grid-cols-2 xl:grid-cols-4 gap-4">
      <StatCard label="Total Users"    value={data.total_users.value}    icon={Users}         color="text-cyan-400"   border="rgba(0,212,255,0.25)"  sub={data.total_users.sub}    trend={data.total_users.trend}    change={data.total_users.change}    />
      <StatCard label="Active Attacks" value={data.active_attacks.value} icon={AlertTriangle} color="text-red-400"    border="rgba(255,0,110,0.25)"  sub={data.active_attacks.sub} trend={data.active_attacks.trend} change={data.active_attacks.change} />
      <StatCard label="Network Flows"  value={data.network_flows.value}  icon={Activity}      color="text-green-400"  border="rgba(0,255,159,0.25)"  sub={data.network_flows.sub}  trend={data.network_flows.trend}  change={data.network_flows.change}  />
      <StatCard label="Detections"     value={data.detections.value}     icon={Eye}           color="text-yellow-400" border="rgba(255,190,11,0.25)" sub={data.detections.sub}     trend={data.detections.trend}     change={data.detections.change}     />
    </div>
  );
}

// ════════════════════════════════════════════════════════════════
// DETECTION SUMMARY — powered by /api/dashboard/detections
// ════════════════════════════════════════════════════════════════
const DET_ICONS: Record<string, any> = { Normal: CheckCircle, Suspicious: AlertCircle, Malicious: XCircle };

function DetectionSummary({ data }: { data: DetData | null }) {
  const vals = data?.categories.map(c => c.value) ?? [84721, 17832, 6291];
  const c0 = useCountUp(vals[0], 1500);
  const c1 = useCountUp(vals[1], 1500);
  const c2 = useCountUp(vals[2], 1500);
  const counts = [c0, c1, c2];
  const cats = data?.categories ?? [
    { label:"Normal", value:84721, pct:78, color:"#00ff9f" },
    { label:"Suspicious", value:17832, pct:16, color:"#ffbe0b" },
    { label:"Malicious", value:6291, pct:6, color:"#ff006e" },
  ];

  return (
    <div className="p-5 rounded h-full" style={{ background: "rgba(10,15,30,0.95)", border: "1px solid rgba(0,212,255,0.12)" }}>
      <SectionHeader icon={Eye} title="Detection Summary" sub="Last 24 hours" />
      <div className="space-y-4 mt-4">
        {cats.map((d, i) => {
          const Icon = DET_ICONS[d.label] ?? AlertCircle;
          return (
            <div key={d.label}>
              <div className="flex items-center justify-between mb-1.5">
                <div className="flex items-center gap-2">
                  <Icon size={13} style={{ color: d.color }} />
                  <span className="text-[11px] font-mono text-slate-300">{d.label}</span>
                </div>
                <div className="flex items-center gap-3">
                  <span className="text-[11px] font-mono" style={{ color: d.color }}>{counts[i].toLocaleString()}</span>
                  <span className="text-[10px] font-mono text-slate-600 w-8 text-right">{d.pct}%</span>
                </div>
              </div>
              <div className="h-1.5 rounded-full bg-slate-800 overflow-hidden">
                <div className="h-full rounded-full transition-all duration-1000"
                  style={{ width: `${d.pct}%`, background: d.color, boxShadow: `0 0 8px ${d.color}` }} />
              </div>
            </div>
          );
        })}
      </div>
      <div className="mt-5 flex items-center justify-center gap-5">
        {cats.map((d) => (
          <div key={d.label} className="flex items-center gap-1.5 text-[10px] font-mono text-slate-500">
            <div className="w-2 h-2 rounded-full" style={{ background: d.color, boxShadow: `0 0 4px ${d.color}` }} />
            {d.label}
          </div>
        ))}
      </div>
    </div>
  );
}

// ════════════════════════════════════════════════════════════════
// ALERT TRENDS — powered by /api/dashboard/alert-trends
// ════════════════════════════════════════════════════════════════
function AlertTrends({ data }: { data: TrendData | null }) {
  const [hovered, setHovered] = useState<number | null>(null);

  // Fallback static data if API is down
  const days = data?.days ?? [
    {date:"Mon",full_date:"",anomaly:120,signature:450,ransomware:20},
    {date:"Tue",full_date:"",anomaly:95, signature:380,ransomware:15},
    {date:"Wed",full_date:"",anomaly:200,signature:700,ransomware:55},
    {date:"Thu",full_date:"",anomaly:150,signature:600,ransomware:40},
    {date:"Fri",full_date:"",anomaly:180,signature:820,ransomware:70},
    {date:"Sat",full_date:"",anomaly:110,signature:490,ransomware:30},
    {date:"Sun",full_date:"",anomaly:220,signature:880,ransomware:75},
  ];

  const totals = days.map(d => d.anomaly + d.signature + d.ransomware);
  const maxVal = Math.max(...totals);

  return (
    <div className="p-5 rounded" style={{ background: "rgba(10,15,30,0.95)", border: "1px solid rgba(0,212,255,0.12)" }}>
      <SectionHeader icon={TrendingUp} title="Alert Trends" sub="7-day detection breakdown" />
      <div className="mt-5 flex items-end gap-2 h-36">
        {days.map((day, i) => {
          const total = day.anomaly + day.signature + day.ransomware;
          const h = (total / maxVal) * 100;
          const isHigh = total > maxVal * 0.6;
          return (
            <div key={i} className="flex-1 flex flex-col items-center gap-1 cursor-pointer"
              onMouseEnter={() => setHovered(i)} onMouseLeave={() => setHovered(null)}>
              {hovered === i && (
                <div className="text-[9px] font-mono text-cyan-400 mb-0.5 whitespace-nowrap text-center">
                  <div>{total.toLocaleString()}</div>
                </div>
              )}
              {/* Stacked bar — ransomware on top, signature middle, anomaly base */}
              <div className="w-full rounded-t overflow-hidden flex flex-col-reverse transition-all duration-300"
                style={{ height: `${Math.max(h, 4)}%`, opacity: hovered === null || hovered === i ? 1 : 0.4 }}>
                <div style={{ flex: day.anomaly,    minHeight: day.anomaly>0?2:0,    background: "#ffbe0b", boxShadow: hovered===i?"0 0 8px #ffbe0b":"none" }}/>
                <div style={{ flex: day.signature,  minHeight: day.signature>0?2:0,  background: "#00ff9f", boxShadow: hovered===i?"0 0 8px #00ff9f":"none" }}/>
                <div style={{ flex: day.ransomware, minHeight: day.ransomware>0?2:0, background: "#ff006e", boxShadow: hovered===i?"0 0 8px #ff006e":"none" }}/>
              </div>
              <span className="text-[8px] font-mono text-slate-700">{day.date}</span>
            </div>
          );
        })}
      </div>
      {/* Legend */}
      <div className="flex items-center gap-4 mt-2">
        {[["#00ff9f","Signature"],["#ffbe0b","Anomaly"],["#ff006e","Ransomware"]].map(([color,label])=>(
          <div key={label} className="flex items-center gap-1.5 text-[10px] font-mono text-slate-500">
            <div className="w-2 h-2 rounded-sm" style={{ background: color }}/>
            {label}
          </div>
        ))}
      </div>
    </div>
  );
}

// ════════════════════════════════════════════════════════════════
// USERS BY ROLE — powered by /api/dashboard/users-by-role
// ════════════════════════════════════════════════════════════════
const ROLE_ICONS: Record<string, any> = {
  "Super Admin": Shield, "Admin": UserCheck, "Analyst": Eye,
  "Viewer": Users, "SOC Analyst": Eye, "Network Engineer": Activity,
  "Security Manager": Shield, "Incident Responder": AlertTriangle,
};

function UsersByRole({ data }: { data: RolesData | null }) {
  const roles = data?.roles ?? [
    { role:"SOC Analyst",count:18,color:"#00d4ff",pct:45 },
    { role:"Network Engineer",count:10,color:"#00ff9f",pct:25 },
    { role:"Security Manager",count:6,color:"#ffbe0b",pct:15 },
    { role:"Incident Responder",count:4,color:"#f97316",pct:10 },
    { role:"Admin",count:2,color:"#a78bfa",pct:5 },
  ];
  const total = data?.total ?? 40;

  return (
    <div className="p-5 rounded" style={{ background: "rgba(10,15,30,0.95)", border: "1px solid rgba(0,212,255,0.12)" }}>
      <SectionHeader icon={Users} title="Users by Role" sub={`${total} total operators`} />
      <div className="mt-4 space-y-3">
        {roles.map(({ role, count, color, pct }) => {
          const Icon = ROLE_ICONS[role] ?? Users;
          return (
            <div key={role} className="flex items-center gap-3">
              <div className="w-7 h-7 rounded flex items-center justify-center shrink-0"
                style={{ background: `${color}18`, border: `1px solid ${color}40` }}>
                <Icon size={12} style={{ color }} />
              </div>
              <div className="flex-1">
                <div className="flex justify-between mb-1.5">
                  <span className="text-[11px] font-mono text-slate-300">{role}</span>
                  <span className="text-[11px] font-mono font-bold" style={{ color }}>{count}</span>
                </div>
                <div className="h-1 rounded-full bg-slate-800 overflow-hidden">
                  <div className="h-full rounded-full transition-all duration-700"
                    style={{ width: `${pct}%`, background: color }} />
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ════════════════════════════════════════════════════════════════
// RECENT USERS — powered by /api/dashboard/recent-users
// ════════════════════════════════════════════════════════════════
function RecentUsers({ data }: { data: UsersData | null }) {
  const created     = data?.last_created     ?? { name:"Zara Ahmed",  role:"Analyst", email:"z.ahmed@idps.local", time:"2 hours ago",     avatar:"ZA" };
  const deactivated = data?.last_deactivated ?? { name:"Marcus Webb", role:"Viewer",  email:"m.webb@idps.local",  time:"Yesterday 14:22", avatar:"MW" };

  return (
    <div className="p-5 rounded" style={{ background: "rgba(10,15,30,0.95)", border: "1px solid rgba(0,212,255,0.12)" }}>
      <SectionHeader icon={Clock} title="Recent User Activity" sub="Latest account changes" />
      <div className="mt-4 space-y-3">
        {/* Last Created */}
        <div className="p-3 rounded" style={{ background: "rgba(0,255,159,0.04)", border: "1px solid rgba(0,255,159,0.15)" }}>
          <div className="flex items-center gap-1.5 mb-2">
            <UserCheck size={11} className="text-green-400" />
            <span className="text-[10px] font-mono text-green-400 uppercase tracking-wider">Last Created</span>
          </div>
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-full flex items-center justify-center text-[11px] font-bold text-green-400"
              style={{ background: "rgba(0,255,159,0.15)", border: "1px solid rgba(0,255,159,0.3)" }}>
              {created.avatar}
            </div>
            <div>
              <div className="text-[12px] font-mono text-slate-200">{created.name}</div>
              <div className="text-[10px] font-mono text-slate-500">{created.email}</div>
            </div>
            <div className="ml-auto text-right">
              <span className="text-[10px] font-mono px-2 py-0.5 rounded-full text-green-400"
                style={{ background: "rgba(0,255,159,0.1)", border: "1px solid rgba(0,255,159,0.2)" }}>
                {created.role}
              </span>
              <div className="text-[9px] font-mono text-slate-600 mt-1">{created.time}</div>
            </div>
          </div>
        </div>

        {/* Last Deactivated */}
        <div className="p-3 rounded" style={{ background: "rgba(255,0,110,0.04)", border: "1px solid rgba(255,0,110,0.15)" }}>
          <div className="flex items-center gap-1.5 mb-2">
            <UserX size={11} className="text-red-400" />
            <span className="text-[10px] font-mono text-red-400 uppercase tracking-wider">Last Deactivated</span>
          </div>
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-full flex items-center justify-center text-[11px] font-bold text-red-400"
              style={{ background: "rgba(255,0,110,0.15)", border: "1px solid rgba(255,0,110,0.3)" }}>
              {deactivated.avatar}
            </div>
            <div>
              <div className="text-[12px] font-mono text-slate-200">{deactivated.name}</div>
              <div className="text-[10px] font-mono text-slate-500">{deactivated.email}</div>
            </div>
            <div className="ml-auto text-right">
              <span className="text-[10px] font-mono px-2 py-0.5 rounded-full text-red-400"
                style={{ background: "rgba(255,0,110,0.1)", border: "1px solid rgba(255,0,110,0.2)" }}>
                {deactivated.role}
              </span>
              <div className="text-[9px] font-mono text-slate-600 mt-1">{deactivated.time}</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

// ════════════════════════════════════════════════════════════════
// QUICK ACCESS — powered by /api/dashboard/quick-access
// ════════════════════════════════════════════════════════════════
function QuickAccess({ data }: { data: QAData | null }) {
  const sections = [
    { title:"Manage Users",           desc:"Add, edit, deactivate accounts and assign roles",            icon:Users,    color:"#00d4ff", href:"/admin",         badge: data?.manage_users.badge           ?? "40 users"     },
    { title:"Security Configuration", desc:"IDS/IPS rules, thresholds, firewall policies, signatures",   icon:Lock,     color:"#00ff9f", href:"/configuration", badge: data?.security_configuration.badge ?? "1,247 rules"  },
    { title:"Network Monitoring",     desc:"Live traffic, sensor status, packet capture, flow analysis", icon:Network,  color:"#ffbe0b", href:"/network",       badge: data?.network_monitoring.badge     ?? "32 sensors"   },
    { title:"Alerts & Incidents",     desc:"View, triage and respond to active security incidents",      icon:Bell,     color:"#ff006e", href:"/incidents",     badge: data?.alerts_incidents.badge       ?? "3 critical"   },
    { title:"Audit & Reports",        desc:"Audit logs, compliance reports, activity history",           icon:FileText, color:"#a78bfa", href:"/audits",        badge: data?.audit_reports.badge          ?? "Updated today" },
  ];

  return (
    <div className="p-5 rounded" style={{ background: "rgba(10,15,30,0.95)", border: "1px solid rgba(0,212,255,0.12)" }}>
      <SectionHeader icon={Layers} title="Quick Access" sub="Navigate to key sections" />
      <div className="mt-4 grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-5 gap-3">
        {sections.map(({ title, desc, icon: Icon, color, href, badge }) => (
          <a key={title} href={href}
            className="group flex items-start gap-3 p-4 rounded text-left w-full transition-all duration-200 hover:-translate-y-0.5"
            style={{ background: "rgba(255,255,255,0.02)", border: `1px solid ${color}22` }}
            onMouseEnter={(e) => {
              (e.currentTarget as HTMLElement).style.borderColor = `${color}55`;
              (e.currentTarget as HTMLElement).style.boxShadow = `0 4px 24px ${color}15`;
            }}
            onMouseLeave={(e) => {
              (e.currentTarget as HTMLElement).style.borderColor = `${color}22`;
              (e.currentTarget as HTMLElement).style.boxShadow = "none";
            }}>
            <div className="p-2 rounded shrink-0 mt-0.5" style={{ background: `${color}15`, border: `1px solid ${color}30` }}>
              <Icon size={14} style={{ color }} />
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex items-center justify-between gap-1 mb-1">
                <span className="text-[12px] font-mono text-slate-200 font-medium">{title}</span>
                <ArrowRight size={11} className="text-slate-700 group-hover:text-slate-400 shrink-0 transition-colors" />
              </div>
              <p className="text-[10px] font-mono text-slate-600 leading-relaxed mb-2">{desc}</p>
              <span className="text-[9px] font-mono px-2 py-0.5 rounded-full"
                style={{ background: `${color}12`, color, border: `1px solid ${color}28` }}>
                {badge}
              </span>
            </div>
          </a>
        ))}
      </div>
    </div>
  );
}

// ════════════════════════════════════════════════════════════════
// MAIN PAGE
// ════════════════════════════════════════════════════════════════
// ══════════════════════════════════════════════════════════════
// LIVE THREAT CORRELATIONS — Real-time hybrid IDPS decisions
// ══════════════════════════════════════════════════════════════
type Correlation = {
  src_ip: string;
  shieldnet_matches: number;
  deepdefend_matches: number;
  is_known_bad: boolean;
  timestamp: string;
  severity: "Info"|"Low"|"Medium"|"High"|"Critical";
  confidence: number;
  category: string;
  recommended: string;
  reason: string;
  engines: { shieldnet: string[]; deepdefend: {class:string;conf:number}[] };
};

type CorrelationStats = {
  total_correlations: number;
  both_engines_match: number;
  shieldnet_only: number;
  deepdefend_only: number;
  false_positives_filtered: number;
  active_shieldnet_ips: number;
  active_deepdefend_ips: number;
  blocked_ip_count: number;
};

function LiveCorrelations() {
  const [stats, setStats]         = useState<CorrelationStats|null>(null);
  const [items, setItems]         = useState<Correlation[]>([]);
  const [loading, setLoading]     = useState(true);
  const [paused, setPaused]       = useState(false);
  const [selected, setSelected]   = useState<Correlation|null>(null);
  const [filter, setFilter]       = useState<"all"|"critical"|"high"|"both">("all");

  useEffect(() => {
    let timer: NodeJS.Timeout;
    const fetchData = async () => {
      if (paused) return;
      try {
        const [s, c] = await Promise.all([
          fetch("http://localhost:8000/api/network/correlations/stats").then(r=>r.json()),
          fetch("http://localhost:8000/api/network/correlations?limit=20").then(r=>r.json()),
        ]);
        setStats(s);
        setItems(c.correlations || []);
        setLoading(false);
      } catch { setLoading(false); }
    };
    fetchData();
    timer = setInterval(fetchData, 3000);
    return () => clearInterval(timer);
  }, [paused]);

  const filtered = items.filter(c => {
    if (filter === "critical") return c.severity === "Critical";
    if (filter === "high")     return c.severity === "High" || c.severity === "Critical";
    if (filter === "both")     return c.shieldnet_matches > 0 && c.deepdefend_matches > 0;
    return true;
  });

  const sevColor = (s: string) => ({
    Critical: "#ff006e", High: "#f59e0b", Medium: "#fbbf24", Low: "#00d4ff", Info: "#94a3b8"
  }[s] || "#94a3b8");

  const catBadge = (cat: string) => {
    if (cat === "CONFIRMED THREAT") return { bg: "rgba(255,0,110,0.15)", color: "#ff006e", border: "rgba(255,0,110,0.4)" };
    if (cat === "SIGNATURE MATCH")  return { bg: "rgba(245,158,11,0.15)", color: "#f59e0b", border: "rgba(245,158,11,0.4)" };
    if (cat === "AI ANOMALY")       return { bg: "rgba(0,212,255,0.15)",  color: "#00d4ff", border: "rgba(0,212,255,0.4)" };
    return { bg: "rgba(148,163,184,0.15)", color: "#94a3b8", border: "rgba(148,163,184,0.4)" };
  };

  return (
    <div className="rounded" style={{ background: "rgba(10,15,30,0.95)", border: "1px solid rgba(0,212,255,0.2)" }}>
      {/* Header */}
      <div className="px-5 py-3 flex items-center justify-between" style={{ borderBottom: "1px solid rgba(0,212,255,0.1)" }}>
        <div className="flex items-center gap-3">
          <div className="relative">
            <Activity size={16} className="text-cyan-400" />
            <div className="absolute -top-0.5 -right-0.5 w-1.5 h-1.5 rounded-full bg-green-400 animate-pulse" />
          </div>
          <div>
            <h2 className="text-[13px] font-bold text-cyan-400 tracking-widest" style={{ fontFamily: "'Orbitron', monospace" }}>
              LIVE THREAT CORRELATIONS
            </h2>
            <p className="text-[10px] font-mono text-slate-500">Hybrid IDPS decisions — ShieldNet + DeepDefend</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {/* Filter buttons */}
          <div className="flex gap-1">
            {[
              {k:"all",      label:"All"},
              {k:"critical", label:"Critical"},
              {k:"high",     label:"High+"},
              {k:"both",     label:"Both Engines"},
            ].map(f => (
              <button key={f.k}
                onClick={() => setFilter(f.k as any)}
                className={`px-2.5 py-1 text-[10px] font-mono rounded transition-colors ${filter===f.k?"text-cyan-400":"text-slate-500 hover:text-slate-300"}`}
                style={{ border: `1px solid ${filter===f.k?"rgba(0,212,255,0.4)":"rgba(148,163,184,0.15)"}`,
                         background: filter===f.k?"rgba(0,212,255,0.08)":"transparent" }}>
                {f.label}
              </button>
            ))}
          </div>
          <button onClick={() => setPaused(!paused)}
            className="px-2.5 py-1 text-[10px] font-mono rounded transition-colors"
            style={{ border:"1px solid rgba(0,212,255,0.2)", color: paused?"#f59e0b":"#94a3b8" }}>
            {paused ? "▶ RESUME" : "⏸ PAUSE"}
          </button>
        </div>
      </div>

      {/* Stats strip */}
      {stats && (
        <div className="grid grid-cols-6 gap-2 px-5 py-3" style={{ borderBottom: "1px solid rgba(0,212,255,0.05)" }}>
          {[
            { label: "Total", value: stats.total_correlations, color: "#00d4ff" },
            { label: "Both Engines", value: stats.both_engines_match, color: "#ff006e", glow: stats.both_engines_match > 0 },
            { label: "Signature", value: stats.shieldnet_only, color: "#f59e0b" },
            { label: "AI Anomaly", value: stats.deepdefend_only, color: "#00d4ff" },
            { label: "FP Filtered", value: stats.false_positives_filtered, color: "#94a3b8" },
            { label: "Blocked IPs", value: stats.blocked_ip_count, color: "#00ff9f" },
          ].map(s => (
            <div key={s.label} className="text-center px-2 py-1.5 rounded"
              style={{
                background: s.glow ? "rgba(255,0,110,0.06)" : "rgba(0,212,255,0.02)",
                border: `1px solid ${s.glow ? "rgba(255,0,110,0.3)" : "rgba(148,163,184,0.1)"}`,
              }}>
              <div className="text-[18px] font-bold tracking-wider" style={{ color: s.color, fontFamily: "'Orbitron', monospace",
                textShadow: s.glow ? `0 0 8px ${s.color}` : "none" }}>
                {s.value.toLocaleString()}
              </div>
              <div className="text-[9px] font-mono text-slate-500 tracking-widest uppercase mt-0.5">{s.label}</div>
            </div>
          ))}
        </div>
      )}

      {/* Threats list */}
      <div className="px-5 py-3">
        {loading && <div className="text-center text-[11px] font-mono text-slate-500 py-8">Loading correlations...</div>}
        {!loading && filtered.length === 0 && (
          <div className="text-center text-[11px] font-mono text-slate-500 py-8">
            <Shield size={24} className="mx-auto mb-2 opacity-30"/>
            No correlated threats matching filter
          </div>
        )}
        <div className="space-y-1.5 max-h-[400px] overflow-y-auto pr-1" style={{ scrollbarWidth: "thin" }}>
          {filtered.map((c, i) => {
            const badge = catBadge(c.category);
            return (
              <div key={i} onClick={() => setSelected(c)}
                className="flex items-center gap-3 px-3 py-2.5 rounded cursor-pointer transition-all hover:bg-cyan-400/5"
                style={{ background: "rgba(3,7,18,0.6)", border: "1px solid rgba(148,163,184,0.06)" }}>
                {/* Severity dot */}
                <div className="flex-shrink-0">
                  <div className="w-2 h-2 rounded-full animate-pulse"
                    style={{ background: sevColor(c.severity), boxShadow: `0 0 6px ${sevColor(c.severity)}` }} />
                </div>
                {/* Category badge */}
                <div className="px-2 py-0.5 rounded text-[9px] font-mono tracking-wider flex-shrink-0 w-32 text-center"
                  style={{ background: badge.bg, color: badge.color, border: `1px solid ${badge.border}` }}>
                  {c.category}
                </div>
                {/* Source IP */}
                <div className="text-[11px] font-mono text-slate-300 w-32 flex-shrink-0">
                  {c.src_ip}
                </div>
                {/* Engine indicators */}
                <div className="flex items-center gap-2 text-[9px] font-mono w-24 flex-shrink-0">
                  <span className={c.shieldnet_matches>0?"text-orange-400":"text-slate-700"}>
                    SN:{c.shieldnet_matches}
                  </span>
                  <span className={c.deepdefend_matches>0?"text-cyan-400":"text-slate-700"}>
                    AI:{c.deepdefend_matches}
                  </span>
                </div>
                {/* Severity + confidence */}
                <div className="flex-shrink-0 text-[10px] font-mono" style={{ color: sevColor(c.severity) }}>
                  {c.severity}
                </div>
                <div className="flex-shrink-0 text-[10px] font-mono text-slate-500 w-12 text-right">
                  {c.confidence.toFixed(0)}%
                </div>
                {/* Reason */}
                <div className="flex-1 text-[10px] font-mono text-slate-400 truncate">{c.reason}</div>
                {/* Action */}
                <div className="flex-shrink-0 px-2 py-0.5 rounded text-[9px] font-mono tracking-wider"
                  style={{
                    background: c.recommended === "BLOCK" ? "rgba(255,0,110,0.1)" : "rgba(245,158,11,0.1)",
                    color:      c.recommended === "BLOCK" ? "#ff006e" : "#f59e0b",
                    border:     `1px solid ${c.recommended === "BLOCK" ? "rgba(255,0,110,0.3)" : "rgba(245,158,11,0.3)"}`,
                  }}>
                  {c.recommended}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Detail modal */}
      {selected && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4"
          style={{ background: "rgba(0,0,0,0.7)", backdropFilter: "blur(4px)" }}
          onClick={() => setSelected(null)}>
          <div className="w-full max-w-2xl p-6 rounded-lg" onClick={(e) => e.stopPropagation()}
            style={{ background: "rgba(10,15,30,0.98)", border: "1px solid rgba(0,212,255,0.3)" }}>
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-base font-bold text-cyan-400 tracking-widest" style={{ fontFamily: "'Orbitron', monospace" }}>
                THREAT CORRELATION DETAIL
              </h3>
              <button onClick={() => setSelected(null)} className="text-slate-500 hover:text-cyan-400">✕</button>
            </div>
            <div className="space-y-3">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <div className="text-[9px] font-mono text-slate-500 tracking-widest uppercase">Source IP</div>
                  <div className="text-[14px] font-mono text-slate-200">{selected.src_ip}</div>
                </div>
                <div>
                  <div className="text-[9px] font-mono text-slate-500 tracking-widest uppercase">Category</div>
                  <div className="text-[14px] font-mono" style={{ color: catBadge(selected.category).color }}>
                    {selected.category}
                  </div>
                </div>
                <div>
                  <div className="text-[9px] font-mono text-slate-500 tracking-widest uppercase">Severity</div>
                  <div className="text-[14px] font-mono" style={{ color: sevColor(selected.severity) }}>
                    {selected.severity}
                  </div>
                </div>
                <div>
                  <div className="text-[9px] font-mono text-slate-500 tracking-widest uppercase">Confidence</div>
                  <div className="text-[14px] font-mono text-slate-200">{selected.confidence.toFixed(2)}%</div>
                </div>
              </div>
              <div>
                <div className="text-[9px] font-mono text-slate-500 tracking-widest uppercase mb-1">Reason</div>
                <div className="text-[12px] font-mono text-slate-300 p-2 rounded"
                  style={{ background: "rgba(3,7,18,0.6)", border: "1px solid rgba(148,163,184,0.1)" }}>
                  {selected.reason}
                </div>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <div className="text-[9px] font-mono text-slate-500 tracking-widest uppercase mb-1">
                    ShieldNet Matches ({selected.shieldnet_matches})
                  </div>
                  <div className="text-[10px] font-mono text-orange-400 p-2 rounded min-h-[60px]"
                    style={{ background: "rgba(245,158,11,0.05)", border: "1px solid rgba(245,158,11,0.15)" }}>
                    {selected.engines.shieldnet.length > 0
                      ? selected.engines.shieldnet.join(", ")
                      : <span className="text-slate-600">No signature rules matched</span>}
                  </div>
                </div>
                <div>
                  <div className="text-[9px] font-mono text-slate-500 tracking-widest uppercase mb-1">
                    DeepDefend AI ({selected.deepdefend_matches})
                  </div>
                  <div className="text-[10px] font-mono text-cyan-400 p-2 rounded min-h-[60px] space-y-0.5"
                    style={{ background: "rgba(0,212,255,0.05)", border: "1px solid rgba(0,212,255,0.15)" }}>
                    {selected.engines.deepdefend.length > 0
                      ? selected.engines.deepdefend.map((d, i) => (
                          <div key={i}>• {d.class} <span className="text-slate-500">({d.conf.toFixed(1)}%)</span></div>
                        ))
                      : <span className="text-slate-600">No AI detections</span>}
                  </div>
                </div>
              </div>
              <div className="flex items-center justify-between pt-2">
                <div className="text-[10px] font-mono text-slate-500">
                  Recommended action:&nbsp;
                  <span style={{ color: selected.recommended === "BLOCK" ? "#ff006e" : "#f59e0b" }}>
                    {selected.recommended}
                  </span>
                </div>
                <div className="text-[10px] font-mono text-slate-600">
                  {new Date(selected.timestamp).toLocaleString()}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}


export default function DashboardPage() {
  const [active, setActive]         = useState("Dashboard");
  const [refreshing, setRefreshing] = useState(false);
  const [backendOnline, setBackendOnline] = useState(false);

  // API data states — null = loading, value = loaded (or failed → use fallback)
  const [statsData,    setStatsData]    = useState<StatsData  | null>(null);
  const [detData,      setDetData]      = useState<DetData    | null>(null);
  const [trendData,    setTrendData]    = useState<TrendData  | null>(null);
  const [rolesData,    setRolesData]    = useState<RolesData  | null>(null);
  const [usersData,    setUsersData]    = useState<UsersData  | null>(null);
  const [qaData,       setQaData]       = useState<QAData     | null>(null);

  // Fetch all 6 endpoints in parallel
  const fetchAll = useCallback(async () => {
    setRefreshing(true);
    const [stats, det, trend, roles, users, qa] = await Promise.all([
      apiFetch<StatsData>("/api/dashboard/stats"),
      apiFetch<DetData>("/api/dashboard/detections"),
      apiFetch<TrendData>("/api/dashboard/alert-trends"),
      apiFetch<RolesData>("/api/dashboard/users-by-role"),
      apiFetch<UsersData>("/api/dashboard/recent-users"),
      apiFetch<QAData>("/api/dashboard/quick-access"),
    ]);
    setStatsData(stats);
    setDetData(det);
    setTrendData(trend);
    setRolesData(roles);
    setUsersData(users);
    setQaData(qa);
    setBackendOnline(stats !== null);   // if stats came back, backend is live
    setRefreshing(false);
  }, []);

  // Fetch on mount
  useEffect(() => { fetchAll(); }, [fetchAll]);

  // Auto-refresh every 30 seconds
  useEffect(() => {
    const id = setInterval(fetchAll, 30000);
    return () => clearInterval(id);
  }, [fetchAll]);

  const handleRefresh = () => { fetchAll(); };

  return (
    <div className="min-h-screen" style={{ background: "#030712" }}>
      <div className="fixed inset-0 pointer-events-none" style={{
        backgroundImage: "linear-gradient(rgba(0,212,255,0.018) 1px,transparent 1px),linear-gradient(90deg,rgba(0,212,255,0.018) 1px,transparent 1px)",
        backgroundSize: "40px 40px",
      }} />

      <Navbar active={active} setActive={setActive} backendOnline={backendOnline} />

      <main className="relative z-10 max-w-screen-xl mx-auto px-4 sm:px-6 py-6 space-y-5">

        {/* Page heading */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-xl font-bold text-slate-100 tracking-wider" style={{ fontFamily: "'Orbitron', monospace" }}>
              ADMIN DASHBOARD
            </h1>
            <p className="text-[11px] font-mono text-slate-600 mt-0.5">Full system access — Security Operations Center</p>
          </div>
          <div className="flex items-center gap-3">
            {/* Offline warning banner */}
            {!backendOnline && (
              <div className="flex items-center gap-1.5 px-3 py-1.5 rounded text-[10px] font-mono text-red-400"
                style={{ background:"rgba(255,0,110,0.08)", border:"1px solid rgba(255,0,110,0.25)" }}>
                <WifiOff size={11}/>Backend offline — showing cached data
              </div>
            )}
            <button onClick={handleRefresh}
              className="flex items-center gap-2 px-3 py-2 text-[10px] font-mono text-slate-400 hover:text-cyan-400 rounded transition-colors"
              style={{ border: "1px solid rgba(0,212,255,0.15)" }}>
              <RefreshCw size={12} className={refreshing ? "animate-spin text-cyan-400" : ""} />
              REFRESH
            </button>
          </div>
        </div>

        {/* 1 ── Stat Cards */}
        <StatCardsSection data={statsData} />
        <LiveCorrelations />

        {/* 2 ── Detection Summary + Alert Trends */}
        <div className="grid grid-cols-1 lg:grid-cols-5 gap-4">
          <div className="lg:col-span-2"><DetectionSummary data={detData} /></div>
          <div className="lg:col-span-3"><AlertTrends data={trendData} /></div>
        </div>

        {/* 3 ── Users by Role + Recent Users */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <UsersByRole data={rolesData} />
          <RecentUsers data={usersData} />
        </div>

        {/* 4 ── Quick Access */}
        <QuickAccess data={qaData} />

        {/* Footer */}
        <div className="pt-2 pb-4 flex items-center justify-between text-[10px] font-mono text-slate-700">
          <span>CyGuardian-X v2.4.1 — ADMIN CONSOLE</span>
          <span>ALL ACTIVITY IS MONITORED AND LOGGED</span>
        </div>
      </main>
    </div>
  );
}