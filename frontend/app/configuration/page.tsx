"use client";
import NotificationBell from "../../components/NotificationBell";

import { useState, useEffect, useCallback } from "react";
import {
  Shield, Activity, AlertTriangle, Settings, FileText, LogOut,
  Radio, Menu, X, BarChart2, ChevronDown, ChevronUp, ToggleLeft,
  ToggleRight, Search, Edit2, CheckCircle,
  XCircle, Download, Plus, RotateCcw, Save,
  ChevronLeft, ChevronRight, Clock, Database, Lock,
  Trash2,
  Bot,
} from "lucide-react";

// ══════════════════════════════════════════════
// CONFIG
// ══════════════════════════════════════════════
const API = "https://fyp-backend-production-944f.up.railway.app/api/configuration";

async function apiFetch<T>(path: string, opts?: RequestInit): Promise<T | null> {
  try {
    const res = await fetch(`${API}${path}`, {
      headers: { "Content-Type": "application/json" },
      ...opts,
    });
    if (!res.ok) return null;
    return await res.json() as T;
  } catch { return null; }
}

// ══════════════════════════════════════════════
// TYPES
// ══════════════════════════════════════════════
type Severity     = "Low"|"Medium"|"High"|"Critical";
type AttackerStatus = "Active"|"Blocked"|"Monitoring";
type LogAction    = "Created"|"Modified"|"Deleted"|"Enabled"|"Disabled";

interface SigRule  { id:string; name:string; category:string; severity:Severity; protocol:string; action:string; status:"Active"|"Inactive"; lastTriggered:string; hits:number; }
interface Attacker { ip:string; country:string; type:string; firstSeen:string; lastSeen:string; packets:number; status:AttackerStatus; }
interface RansomRule { id:number; name:string; type:string; risk:"Critical"|"High"|"Medium"; status:"Active"|"Disabled"; lastTriggered:string; pattern:string; }
interface ChangeLog  { id:string; timestamp:string; by:string; section:string; action:LogAction; rule:string; prev:string; next:string; status:"Applied"|"Pending"|"Rolled Back"; }
interface SigStatus  { enabled:boolean; total:number; active:number; inactive:number; last_updated:string; hit_rate:string; }
interface AnomalySettings { enabled:boolean; sensitivity:string; packet_size:number; traffic_rate:number; baseline:string; auto_block:boolean; }

// ══════════════════════════════════════════════
// NAVBAR
// ══════════════════════════════════════════════
const NAV_LINKS = [
  { label:"Dashboard",          href:"/dashboard",     icon:BarChart2     },
  { label:"Network Monitoring", href:"/network",       icon:Radio         },
  { label:"Incidents",          href:"/incidents",     icon:AlertTriangle },
  { label:"Configuration",      href:"/configuration", icon:Settings      },
  { label:"Audits",             href:"/audits",        icon:FileText      },
  { label: "Agents", href: "/agents", icon: Bot },
];

function Navbar() {
  const [menuOpen,setMenuOpen] = useState(false);
  const [time,setTime]         = useState("");
  useEffect(()=>{
    const tick=()=>setTime(new Date().toUTCString().slice(5,25)+" UTC");
    tick(); const id=setInterval(tick,1000); return ()=>clearInterval(id);
  },[]);
  return (
    <nav className="sticky top-0 z-50 w-full" style={{background:"rgba(6,10,20,0.98)",borderBottom:"1px solid rgba(0,212,255,0.15)",backdropFilter:"blur(12px)"}}>
      <div className="flex items-center justify-between px-6 h-14">
        <div className="flex items-center gap-3 shrink-0">
          <div className="relative">
            <Shield size={20} className="text-cyan-400"/>
            <div className="absolute -top-0.5 -right-0.5 w-2 h-2 rounded-full bg-green-400" style={{boxShadow:"0 0 6px #00ff9f"}}/>
          </div>
          <span style={{fontFamily:"'Orbitron',monospace"}} className="text-cyan-400 font-bold tracking-widest text-sm hidden sm:block">CyGuardian-X</span>
        </div>
        <div className="hidden lg:flex items-center">
          {NAV_LINKS.map(({label,href,icon:Icon})=>(
            <a key={label} href={href} className={`flex items-center gap-1.5 px-3 py-4 text-[11px] font-mono tracking-wider border-b-2 transition-all duration-200 ${label==="Configuration"?"text-cyan-400 border-cyan-400":"text-slate-500 border-transparent hover:text-slate-300 hover:border-slate-700"}`}>
              <Icon size={12}/>{label.toUpperCase()}
            </a>
          ))}
        </div>
        <div className="flex items-center gap-3">
          <span className="text-[10px] font-mono text-slate-600 hidden md:block">{time}</span>
          <div className="flex items-center gap-2 px-3 py-1 rounded" style={{background:"rgba(0,212,255,0.06)",border:"1px solid rgba(0,212,255,0.15)"}}>
            <div className="w-6 h-6 rounded-full flex items-center justify-center text-[10px] font-bold text-cyan-400" style={{background:"rgba(0,212,255,0.2)"}}>A</div>
            <span className="text-[11px] font-mono text-slate-400 hidden sm:block">ADMIN</span>
          </div>
          <NotificationBell />
          <a href="/logout" className="flex items-center gap-1.5 text-[10px] font-mono text-slate-600 hover:text-red-400 transition-colors">
            <LogOut size={13}/><span className="hidden sm:block">LOGOUT</span>
          </a>
          <button className="lg:hidden text-slate-400" onClick={()=>setMenuOpen(!menuOpen)}>
            {menuOpen?<X size={18}/>:<Menu size={18}/>}
          </button>
        </div>
      </div>
      {menuOpen&&(
        <div className="lg:hidden px-4 pb-3 space-y-1 border-t" style={{borderColor:"rgba(0,212,255,0.1)"}}>
          {NAV_LINKS.map(({label,href,icon:Icon})=>(
            <a key={label} href={href} className={`flex items-center gap-2 px-3 py-2 text-[11px] font-mono rounded ${label==="Configuration"?"text-cyan-400 bg-cyan-400/10":"text-slate-500"}`}>
              <Icon size={12}/>{label}
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
function SectionCard({title,icon:Icon,children,defaultOpen=true}:{title:string;icon:any;children:React.ReactNode;defaultOpen?:boolean}) {
  const [open,setOpen]=useState(defaultOpen);
  return (
    <div className="rounded overflow-hidden" style={{background:"rgba(10,15,30,0.95)",border:"1px solid rgba(0,212,255,0.12)"}}>
      <button onClick={()=>setOpen(!open)} className="w-full flex items-center justify-between px-5 py-4 hover:bg-white/[0.02] transition-colors">
        <div className="flex items-center gap-2">
          <Icon size={15} className="text-cyan-400"/>
          <span className="text-[13px] font-mono font-semibold text-slate-200 tracking-wider uppercase">{title}</span>
        </div>
        {open?<ChevronUp size={14} className="text-slate-500"/>:<ChevronDown size={14} className="text-slate-500"/>}
      </button>
      {open&&<div className="px-5 pb-5 border-t" style={{borderColor:"rgba(0,212,255,0.08)"}}>{children}</div>}
    </div>
  );
}

const sevColor:Record<string,string> = {Low:"#00ff9f",Medium:"#ffbe0b",High:"#f97316",Critical:"#ff006e"};
const sevBg:Record<string,string>    = {Low:"rgba(0,255,159,0.1)",Medium:"rgba(255,190,11,0.1)",High:"rgba(249,115,22,0.1)",Critical:"rgba(255,0,110,0.1)"};

function SevBadge({s}:{s:string}) {
  return <span className="px-2 py-0.5 rounded-full text-[9px] font-mono font-bold" style={{color:sevColor[s]||"#94a3b8",background:sevBg[s]||"rgba(148,163,184,0.1)",border:`1px solid ${sevColor[s]||"#94a3b8"}40`}}>{s}</span>;
}

function Toast({msg,type,onClose}:{msg:string;type:"success"|"error";onClose:()=>void}) {
  useEffect(()=>{const t=setTimeout(onClose,3500);return()=>clearTimeout(t);},[]);
  return (
    <div className="fixed top-20 right-4 z-50 px-4 py-3 rounded flex items-center gap-2 text-[11px] font-mono shadow-lg"
      style={{background:type==="success"?"rgba(0,255,159,0.15)":"rgba(255,0,110,0.15)",border:`1px solid ${type==="success"?"rgba(0,255,159,0.4)":"rgba(255,0,110,0.4)"}`,color:type==="success"?"#00ff9f":"#ff006e"}}>
      {type==="success"?<CheckCircle size={13}/>:<XCircle size={13}/>}{msg}
    </div>
  );
}

function Modal({msg,onConfirm,onCancel}:{msg:string;onConfirm:()=>void;onCancel:()=>void}) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center" style={{background:"rgba(0,0,0,0.75)"}}>
      <div className="p-6 rounded max-w-sm w-full mx-4" style={{background:"rgba(10,15,30,0.98)",border:"1px solid rgba(255,0,110,0.4)"}}>
        <AlertTriangle size={22} className="text-red-400 mb-3"/>
        <div className="text-sm font-mono text-slate-200 mb-2 font-bold">Confirm Action</div>
        <div className="text-[11px] font-mono text-slate-400 mb-4">{msg}</div>
        <div className="flex gap-3">
          <button onClick={onCancel} className="flex-1 py-2 rounded text-[11px] font-mono text-slate-400 hover:text-slate-200 transition-colors" style={{border:"1px solid rgba(100,116,139,0.3)"}}>Cancel</button>
          <button onClick={onConfirm} className="flex-1 py-2 rounded text-[11px] font-mono text-red-400 hover:bg-red-400/10 transition-colors" style={{border:"1px solid rgba(255,0,110,0.4)"}}>Confirm</button>
        </div>
      </div>
    </div>
  );
}

function Skeleton({className=""}:{className?:string}) {
  return <div className={`rounded animate-pulse ${className}`} style={{background:"rgba(0,212,255,0.06)"}}/>;
}

const inputCls   = "w-full px-3 py-2 rounded text-[11px] font-mono outline-none text-slate-200";
const inputStyle = {background:"rgba(0,212,255,0.04)",border:"1px solid rgba(0,212,255,0.15)",color:"#cbd5e1"};
const selectStyle= {background:"#0a0f1e",border:"1px solid rgba(0,212,255,0.15)",color:"#00d4ff"};

// ══════════════════════════════════════════════
// SECTION 1 — SIGNATURE-BASED DETECTION
// ══════════════════════════════════════════════
function SignatureDetection() {
  const [data,setData]   = useState<SigStatus|null>(null);
  const [toast,setToast] = useState<{msg:string;type:"success"|"error"}|null>(null);

  const load = useCallback(async()=>{
    const d = await apiFetch<SigStatus>("/signature/status");
    if(d) setData(d);
  },[]);

  useEffect(()=>{ load(); },[load]);

  const toggle = async()=>{
    if(!data) return;
    const res = await apiFetch<{enabled:boolean}>("/signature/toggle",{
      method:"POST", body:JSON.stringify({enabled:!data.enabled}),
    });
    if(res){ setData(d=>d?{...d,enabled:res.enabled}:d); setToast({msg:`Signature detection ${res.enabled?"enabled":"disabled"}.`,type:"success"}); }
    else setToast({msg:"Failed to toggle. Check backend.",type:"error"});
  };

  const enabled = data?.enabled ?? true;

  return (
    <SectionCard title="Signature-Based Detection" icon={Database}>
      {toast&&<Toast msg={toast.msg} type={toast.type} onClose={()=>setToast(null)}/>}
      <div className="mt-4">
        <div className="flex items-center justify-between mb-4 p-3 rounded" style={{background:"rgba(0,212,255,0.04)",border:"1px solid rgba(0,212,255,0.1)"}}>
          <div className="flex items-center gap-3">
            <span className="text-[11px] font-mono text-slate-300">Global Signature Detection</span>
            <span className="px-2 py-0.5 rounded-full text-[9px] font-mono font-bold"
              style={{color:enabled?"#00ff9f":"#ff006e",background:enabled?"rgba(0,255,159,0.1)":"rgba(255,0,110,0.1)",border:`1px solid ${enabled?"rgba(0,255,159,0.3)":"rgba(255,0,110,0.3)"}`}}>
              {enabled?"ACTIVE":"INACTIVE"}
            </span>
          </div>
          <button onClick={toggle} className="transition-all duration-300">
            {enabled
              ?<div className="flex items-center gap-1 text-green-400"><ToggleRight size={24}/><span className="text-[10px] font-mono">ON</span></div>
              :<div className="flex items-center gap-1 text-slate-600"><ToggleLeft size={24}/><span className="text-[10px] font-mono">OFF</span></div>}
          </button>
        </div>
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
          {data ? [
            {label:"Total Signatures", value:String(data.total),        color:"#00d4ff"},
            {label:"Active Rules",     value:String(data.active),       color:"#00ff9f"},
            {label:"Last Updated",     value:data.last_updated.slice(11,16), color:"#ffbe0b"},
            {label:"Hit Rate",         value:data.hit_rate,             color:"#f97316"},
          ].map(({label,value,color})=>(
            <div key={label} className="p-3 rounded text-center" style={{background:"rgba(255,255,255,0.02)",border:`1px solid ${color}22`}}>
              <div className="text-lg font-bold font-mono mb-1" style={{color,fontFamily:"'Orbitron',monospace"}}>{value}</div>
              <div className="text-[10px] font-mono text-slate-500 uppercase tracking-wider">{label}</div>
            </div>
          )) : [0,1,2,3].map(i=><Skeleton key={i} className="h-16"/>)}
        </div>
      </div>
    </SectionCard>
  );
}

// ══════════════════════════════════════════════
// SECTION 2 — ANOMALY DETECTION
// ══════════════════════════════════════════════
function AnomalyDetection() {
  const [settings,setSettings] = useState<AnomalySettings|null>(null);
  const [saving,setSaving]     = useState(false);
  const [toast,setToast]       = useState<{msg:string;type:"success"|"error"}|null>(null);

  useEffect(()=>{
    apiFetch<AnomalySettings>("/anomaly/settings").then(d=>{ if(d) setSettings(d); });
  },[]);

  const save = async()=>{
    if(!settings) return;
    setSaving(true);
    const res = await apiFetch("/anomaly/settings",{method:"POST",body:JSON.stringify(settings)});
    setSaving(false);
    if(res) setToast({msg:"Anomaly detection settings saved successfully.",type:"success"});
    else    setToast({msg:"Failed to save. Check backend.",type:"error"});
  };

  const set = (k:keyof AnomalySettings, v:any) => setSettings(s=>s?{...s,[k]:v}:s);

  if(!settings) return (
    <SectionCard title="Anomaly Detection Settings" icon={Activity}>
      <div className="mt-4 space-y-3">{[0,1,2,3,4,5].map(i=><Skeleton key={i} className="h-14"/>)}</div>
    </SectionCard>
  );

  return (
    <SectionCard title="Anomaly Detection Settings" icon={Activity}>
      {toast&&<Toast msg={toast.msg} type={toast.type} onClose={()=>setToast(null)}/>}
      <div className="mt-4 space-y-3">
        {/* Sensitivity */}
        <div className="flex items-center justify-between p-3 rounded" style={{background:"rgba(255,255,255,0.02)",border:"1px solid rgba(0,212,255,0.08)"}}>
          <div>
            <div className="text-[11px] font-mono text-slate-300 mb-0.5">Sensitivity Level</div>
            <div className="text-[9px] font-mono text-slate-600">Detection aggressiveness</div>
          </div>
          <div className="flex items-center gap-2">
            <SevBadge s={settings.sensitivity}/>
            <select value={settings.sensitivity} onChange={e=>set("sensitivity",e.target.value)} className="px-2 py-1.5 rounded text-[11px] font-mono outline-none" style={selectStyle}>
              {["Low","Medium","High","Critical"].map(v=><option key={v}>{v}</option>)}
            </select>
          </div>
        </div>
        {/* Packet Size */}
        <div className="flex items-center justify-between p-3 rounded" style={{background:"rgba(255,255,255,0.02)",border:"1px solid rgba(0,212,255,0.08)"}}>
          <div>
            <div className="text-[11px] font-mono text-slate-300 mb-0.5">Packet Size Threshold</div>
            <div className="text-[9px] font-mono text-slate-600">Flag packets exceeding this size</div>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-[10px] font-mono text-cyan-400">{settings.packet_size} bytes</span>
            <input type="number" value={settings.packet_size} onChange={e=>set("packet_size",Number(e.target.value))} className="w-24 px-2 py-1.5 rounded text-[11px] font-mono outline-none text-center" style={inputStyle}/>
          </div>
        </div>
        {/* Traffic Rate */}
        <div className="flex items-center justify-between p-3 rounded" style={{background:"rgba(255,255,255,0.02)",border:"1px solid rgba(0,212,255,0.08)"}}>
          <div>
            <div className="text-[11px] font-mono text-slate-300 mb-0.5">Traffic Rate Threshold</div>
            <div className="text-[9px] font-mono text-slate-600">Packets per second limit</div>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-[10px] font-mono text-cyan-400">{settings.traffic_rate} pps</span>
            <input type="number" value={settings.traffic_rate} onChange={e=>set("traffic_rate",Number(e.target.value))} className="w-28 px-2 py-1.5 rounded text-[11px] font-mono outline-none text-center" style={inputStyle}/>
          </div>
        </div>
        {/* Detection Status */}
        <div className="flex items-center justify-between p-3 rounded" style={{background:"rgba(255,255,255,0.02)",border:"1px solid rgba(0,212,255,0.08)"}}>
          <div>
            <div className="text-[11px] font-mono text-slate-300 mb-0.5">Detection Status</div>
            <div className="text-[9px] font-mono text-slate-600">Enable/disable anomaly engine</div>
          </div>
          <button onClick={()=>set("enabled",!settings.enabled)} className="transition-all duration-300">
            {settings.enabled
              ?<div className="flex items-center gap-1 text-green-400"><ToggleRight size={22}/><span className="text-[10px] font-mono">ON</span></div>
              :<div className="flex items-center gap-1 text-slate-600"><ToggleLeft size={22}/><span className="text-[10px] font-mono">OFF</span></div>}
          </button>
        </div>
        {/* Baseline */}
        <div className="flex items-center justify-between p-3 rounded" style={{background:"rgba(255,255,255,0.02)",border:"1px solid rgba(0,212,255,0.08)"}}>
          <div>
            <div className="text-[11px] font-mono text-slate-300 mb-0.5">Baseline Learning Period</div>
            <div className="text-[9px] font-mono text-slate-600">Time to build normal traffic baseline</div>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-[10px] font-mono text-cyan-400">{settings.baseline}</span>
            <select value={settings.baseline} onChange={e=>set("baseline",e.target.value)} className="px-2 py-1.5 rounded text-[11px] font-mono outline-none" style={selectStyle}>
              {["1 hour","6 hours","24 hours"].map(v=><option key={v}>{v}</option>)}
            </select>
          </div>
        </div>
        {/* Auto-block */}
        <div className="flex items-center justify-between p-3 rounded" style={{background:"rgba(255,255,255,0.02)",border:"1px solid rgba(0,212,255,0.08)"}}>
          <div>
            <div className="text-[11px] font-mono text-slate-300 mb-0.5">Auto-block on Anomaly</div>
            <div className="text-[9px] font-mono text-slate-600">Automatically block anomalous IPs</div>
          </div>
          <button onClick={()=>set("auto_block",!settings.auto_block)} className="transition-all duration-300">
            {settings.auto_block
              ?<div className="flex items-center gap-1 text-green-400"><ToggleRight size={22}/><span className="text-[10px] font-mono">ON</span></div>
              :<div className="flex items-center gap-1 text-slate-600"><ToggleLeft size={22}/><span className="text-[10px] font-mono">OFF</span></div>}
          </button>
        </div>
        <button onClick={save} disabled={saving} className="mt-2 flex items-center gap-2 px-4 py-2 rounded text-[11px] font-mono text-cyan-400 hover:bg-cyan-400/10 transition-colors disabled:opacity-50" style={{border:"1px solid rgba(0,212,255,0.3)"}}>
          <Save size={12}/>{saving?"Saving...":"Save Settings"}
        </button>
      </div>
    </SectionCard>
  );
}

// ══════════════════════════════════════════════
// SECTION 3 — ACTIVE ATTACKERS
// ══════════════════════════════════════════════
function ActiveAttackers() {
  const [attackers,setAttackers] = useState<Attacker[]>([]);
  const [loading,setLoading]     = useState(true);
  const [search,setSearch]       = useState("");
  const [modal,setModal]         = useState<{msg:string;onConfirm:()=>void}|null>(null);
  const [toast,setToast]         = useState<{msg:string;type:"success"|"error"}|null>(null);

  const load = useCallback(async()=>{
    const d = await apiFetch<{attackers:Attacker[]}>("/attackers/full");
    if(d?.attackers) setAttackers(d.attackers);
    setLoading(false);
  },[]);

  useEffect(()=>{ load(); },[load]);

  const filtered = attackers.filter(a=>!search||a.ip.includes(search)||a.type.toLowerCase().includes(search.toLowerCase()));

  const statusStyle=(s:AttackerStatus)=>{
    if(s==="Active")     return {color:"#ff006e",background:"rgba(255,0,110,0.1)",  border:"1px solid rgba(255,0,110,0.3)"};
    if(s==="Blocked")    return {color:"#94a3b8",background:"rgba(148,163,184,0.08)",border:"1px solid rgba(148,163,184,0.2)"};
    return                      {color:"#ffbe0b",background:"rgba(255,190,11,0.1)", border:"1px solid rgba(255,190,11,0.3)"};
  };

  const act = (ip:string, action:"Block"|"Monitor"|"Whitelist") => {
    setModal({msg:`${action} IP ${ip}?`, onConfirm: async()=>{
      const res = await apiFetch<{attacker:Attacker}>("/attackers/action",{
        method:"POST", body:JSON.stringify({ip,action}),
      });
      if(res){ setAttackers(prev=>prev.map(a=>a.ip===ip?res.attacker:a)); setToast({msg:`${action} applied to ${ip}`,type:"success"}); }
      else     setToast({msg:"Action failed. Check backend.",type:"error"});
      setModal(null);
    }});
  };

  return (
    <SectionCard title="Active Ransomware Attackers" icon={AlertTriangle}>
      {modal&&<Modal msg={modal.msg} onConfirm={modal.onConfirm} onCancel={()=>setModal(null)}/>}
      {toast&&<Toast msg={toast.msg} type={toast.type} onClose={()=>setToast(null)}/>}
      <div className="mt-4">
        <div className="relative mb-3">
          <Search size={11} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500"/>
          <input value={search} onChange={e=>setSearch(e.target.value)} placeholder="Filter by IP or attack type..." className="pl-8 pr-3 py-2 rounded text-[11px] font-mono outline-none w-full sm:w-72" style={inputStyle}/>
        </div>
        {loading ? <div className="space-y-2">{[0,1,2].map(i=><Skeleton key={i} className="h-10"/>)}</div> : (
          <div className="overflow-x-auto">
            <table className="w-full text-[11px] font-mono">
              <thead>
                <tr style={{borderBottom:"1px solid rgba(0,212,255,0.1)"}}>
                  {["Attacker IP","Country","Attack Type","First Seen","Last Seen","Packets","Status","Actions"].map(h=>(
                    <th key={h} className="text-left py-2 px-2 text-slate-500 tracking-wider whitespace-nowrap">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filtered.map(a=>(
                  <tr key={a.ip} className="border-b hover:bg-white/[0.02] transition-colors"
                    style={{borderColor:"rgba(0,212,255,0.05)",background:a.status==="Active"?"rgba(255,0,110,0.03)":a.status==="Blocked"?"rgba(148,163,184,0.02)":"transparent"}}>
                    <td className="py-2 px-2 text-cyan-400 font-bold">{a.ip}</td>
                    <td className="py-2 px-2 text-slate-300">{a.country}</td>
                    <td className="py-2 px-2 text-slate-300">{a.type}</td>
                    <td className="py-2 px-2 text-slate-500">{a.firstSeen}</td>
                    <td className="py-2 px-2 text-slate-500">{a.lastSeen}</td>
                    <td className="py-2 px-2 text-slate-400">{a.packets.toLocaleString()}</td>
                    <td className="py-2 px-2"><span className="px-2 py-0.5 rounded-full text-[9px]" style={statusStyle(a.status)}>{a.status}</span></td>
                    <td className="py-2 px-2">
                      <div className="flex gap-1">
                        <button onClick={()=>act(a.ip,"Block")}     className="px-2 py-0.5 rounded text-[9px] text-red-400 hover:bg-red-400/10 transition-colors"    style={{border:"1px solid rgba(255,0,110,0.2)"}}>Block</button>
                        <button onClick={()=>act(a.ip,"Monitor")}   className="px-2 py-0.5 rounded text-[9px] text-yellow-400 hover:bg-yellow-400/10 transition-colors" style={{border:"1px solid rgba(255,190,11,0.2)"}}>Monitor</button>
                        <button onClick={()=>act(a.ip,"Whitelist")} className="px-2 py-0.5 rounded text-[9px] text-green-400 hover:bg-green-400/10 transition-colors"  style={{border:"1px solid rgba(0,255,159,0.2)"}}>Whitelist</button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </SectionCard>
  );
}

// ══════════════════════════════════════════════
// SECTION 4 — SIGNATURE DATABASE
// ══════════════════════════════════════════════
function SignatureDatabase() {
  const [rules,setRules]     = useState<SigRule[]>([]);
  const [loading,setLoading] = useState(true);
  const [search,setSearch]   = useState("");
  const [sevF,setSevF]       = useState("All");
  const [actF,setActF]       = useState("All");
  const [statF,setStatF]     = useState("All");
  const [catF,setCatF]       = useState("All");
  const [sortCol,setSortCol] = useState<keyof SigRule>("id");
  const [sortAsc,setSortAsc] = useState(true);
  const [page,setPage]       = useState(0);
  const [toast,setToast]     = useState<{msg:string;type:"success"|"error"}|null>(null);
  const PER = 8;

  const load = useCallback(async()=>{
  const d = await apiFetch<any[]>("/signatures");
  if(Array.isArray(d)){
    setRules(d.map(r=>({
      id:           r.id,
      name:         r.name,
      category:     r.category,
      severity:     r.severity,
      protocol:     r.protocol,
      action:       r.action,
      status:       r.enabled ? "Active" : "Inactive",
      lastTriggered: r.updated_at?.slice(0,16).replace("T"," ") ?? "Never",
      hits:         0,
    })));
  }
  setLoading(false);
},[]);

  useEffect(()=>{ load(); },[load]);

  const filtered = (rules||[]).filter(r=>{
    if(search&&!r.name.toLowerCase().includes(search.toLowerCase())&&!r.id.includes(search)) return false;
    if(sevF!=="All"&&r.severity!==sevF)  return false;
    if(actF!=="All"&&r.action!==actF)    return false;
    if(statF!=="All"&&r.status!==statF)  return false;
    if(catF!=="All"&&r.category!==catF)  return false;
    return true;
  });
  const sorted=[...filtered].sort((a,b)=>{
    const av=a[sortCol],bv=b[sortCol];
    if(typeof av==="number"&&typeof bv==="number") return sortAsc?av-bv:bv-av;
    return sortAsc?String(av).localeCompare(String(bv)):String(bv).localeCompare(String(av));
  });
  const paged = sorted.slice(page*PER,(page+1)*PER);
  const total = Math.ceil(sorted.length/PER);
  const sort  = (c:keyof SigRule)=>{ if(sortCol===c) setSortAsc(!sortAsc); else{setSortCol(c);setSortAsc(true);} };

  const toggleRule = async(id:string)=>{
    const res = await apiFetch<{rule:SigRule}>(`/signatures/${id}/toggle`,{method:"POST"});
    if(res){ setRules(prev=>prev.map(r=>r.id===id?res.rule:r)); setToast({msg:`Rule ${id} toggled.`,type:"success"}); }
    else setToast({msg:"Toggle failed.",type:"error"});
  };

  const deleteRule = async(id:string, name:string)=>{
    if(!confirm(`Delete rule ${id} — ${name}?`)) return;
    const res = await apiFetch(`/signatures/${id}`,{method:"DELETE"});
    if(res){ setRules(prev=>prev.filter(r=>r.id!==id)); setToast({msg:`Rule ${id} deleted.`,type:"success"}); }
    else setToast({msg:"Delete failed.",type:"error"});
  };

  return (
    <SectionCard title="Signature Database" icon={Database}>
      {toast&&<Toast msg={toast.msg} type={toast.type} onClose={()=>setToast(null)}/>}
      <div className="mt-4 space-y-3">
        <div className="flex flex-wrap gap-2">
          <div className="relative">
            <Search size={11} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500"/>
            <input value={search} onChange={e=>{setSearch(e.target.value);setPage(0);}} placeholder="Search name or ID..." className="pl-8 pr-3 py-1.5 rounded text-[11px] font-mono outline-none w-48" style={inputStyle}/>
          </div>
          {([["Severity",sevF,setSevF,["All","Low","Medium","High","Critical"]],
             ["Action",actF,setActF,["All","Alert","Block","Drop","Log"]],
             ["Status",statF,setStatF,["All","Active","Inactive"]],
             ["Category",catF,setCatF,["All","SQL Injection","XSS","DDoS","Port Scan","Brute Force","Malware"]],
            ] as [string,string,(v:string)=>void,string[]][]).map(([label,val,setter,opts])=>(
            <select key={label} value={val} onChange={e=>{setter(e.target.value);setPage(0);}} className="px-2 py-1.5 rounded text-[11px] font-mono outline-none" style={selectStyle}>
              {opts.map(o=><option key={o} style={{background:"#0a0f1e"}}>{o}</option>)}
            </select>
          ))}
        </div>
        {loading ? <div className="space-y-2">{[0,1,2,3].map(i=><Skeleton key={i} className="h-10"/>)}</div> : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full text-[11px] font-mono">
                <thead>
                  <tr style={{borderBottom:"1px solid rgba(0,212,255,0.1)"}}>
                    {([["id","ID"],["name","Signature Name"],["category","Category"],["severity","Severity"],["protocol","Protocol"],["action","Action"],["status","Status"],["lastTriggered","Last Triggered"],["hits","Hits"]] as [keyof SigRule,string][]).map(([col,label])=>(
                      <th key={col} onClick={()=>sort(col)} className="text-left py-2 px-2 text-slate-500 tracking-wider cursor-pointer hover:text-cyan-400 transition-colors whitespace-nowrap">
                        <span className="flex items-center gap-1">{label}{sortCol===col?(sortAsc?<ChevronUp size={10}/>:<ChevronDown size={10}/>):null}</span>
                      </th>
                    ))}
                    <th className="text-left py-2 px-2 text-slate-500">Del</th>
                  </tr>
                </thead>
                <tbody>
                  {(paged||[]).map(r=>(
                    <tr key={r.id} className="border-b hover:bg-white/[0.02] transition-colors" style={{borderColor:"rgba(0,212,255,0.05)"}}>
                      <td className="py-2 px-2 text-cyan-400">{r.id}</td>
                      <td className="py-2 px-2 text-slate-200">{r.name}</td>
                      <td className="py-2 px-2 text-slate-400">{r.category}</td>
                      <td className="py-2 px-2"><SevBadge s={r.severity}/></td>
                      <td className="py-2 px-2 text-slate-400">{r.protocol}</td>
                      <td className="py-2 px-2 text-slate-300">{r.action}</td>
                      <td className="py-2 px-2">
                        <button onClick={()=>toggleRule(r.id)} className="transition-all duration-300">
                          {r.status==="Active"
                            ?<div className="flex items-center gap-1 text-green-400"><ToggleRight size={18}/><span className="text-[9px]">Active</span></div>
                            :<div className="flex items-center gap-1 text-slate-600"><ToggleLeft size={18}/><span className="text-[9px]">Inactive</span></div>}
                        </button>
                      </td>
                      <td className="py-2 px-2 text-slate-500 whitespace-nowrap">{r.lastTriggered}</td>
                      <td className="py-2 px-2 text-slate-400">{r.hits.toLocaleString()}</td>
                      <td className="py-2 px-2">
                        <button onClick={()=>deleteRule(r.id,r.name)} className="p-1 rounded text-red-400 hover:bg-red-400/10 transition-colors">
                          <Trash2 size={11}/>
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-mono text-slate-600">Showing {page*PER+1}–{Math.min((page+1)*PER,sorted.length)} of {sorted.length}</span>
              <div className="flex items-center gap-1">
                <button onClick={()=>setPage(p=>Math.max(0,p-1))} disabled={page===0} className="p-1 rounded text-slate-500 hover:text-cyan-400 disabled:opacity-30"><ChevronLeft size={14}/></button>
                {Array.from({length:Math.min(total,5)},(_,i)=>(
                  <button key={i} onClick={()=>setPage(i)} className="w-6 h-6 rounded text-[10px] font-mono transition-colors" style={{background:page===i?"rgba(0,212,255,0.15)":"transparent",color:page===i?"#00d4ff":"#64748b"}}>{i+1}</button>
                ))}
                <button onClick={()=>setPage(p=>Math.min(total-1,p+1))} disabled={page>=total-1} className="p-1 rounded text-slate-500 hover:text-cyan-400 disabled:opacity-30"><ChevronRight size={14}/></button>
              </div>
            </div>
          </>
        )}
      </div>
    </SectionCard>
  );
}

// ══════════════════════════════════════════════
// SECTION 5 — CREATE CUSTOM RULE
// ══════════════════════════════════════════════
function CreateRule() {
  const blank = {name:"",category:"SQL Injection",protocol:"TCP",srcIp:"",dstIp:"",port:"",severity:"Medium",action:"Alert",pattern:"",desc:"",enabled:true};
  const [form,setForm]   = useState(blank);
  const [saving,setSaving] = useState(false);
  const [toast,setToast] = useState<{msg:string;type:"success"|"error"}|null>(null);
  const set = (k:string,v:string|boolean)=>setForm(f=>({...f,[k]:v}));

  const save = async()=>{
    if(!form.name||!form.pattern){ setToast({msg:"ERROR: Rule Name and Pattern are required.",type:"error"}); return; }
    setSaving(true);
    const res = await apiFetch<{rule:SigRule}>("/signatures/create",{
      method:"POST", body:JSON.stringify({
        name:form.name, category:form.category, severity:form.severity,
        protocol:form.protocol, action:form.action, pattern:form.pattern,
      }),
    });
    setSaving(false);
    if(res){ setToast({msg:`Rule "${res.rule.id} ${form.name}" saved successfully!`,type:"success"}); setForm(blank); }
    else setToast({msg:"Failed to create rule. Check backend.",type:"error"});
  };

  return (
    <SectionCard title="Create Custom Rule" icon={Plus}>
      {toast&&<Toast msg={toast.msg} type={toast.type} onClose={()=>setToast(null)}/>}
      <div className="mt-4 grid grid-cols-1 md:grid-cols-2 gap-3">
        <div>
          <label className="text-[10px] font-mono text-slate-500 uppercase tracking-wider block mb-1">Rule Name *</label>
          <input value={form.name} onChange={e=>set("name",e.target.value)} placeholder="e.g. Custom SSH Geo Block" className={inputCls} style={inputStyle}/>
        </div>
        <div>
          <label className="text-[10px] font-mono text-slate-500 uppercase tracking-wider block mb-1">Category</label>
          <select value={form.category} onChange={e=>set("category",e.target.value)} className={inputCls} style={selectStyle}>
            {["SQL Injection","XSS","DDoS","Port Scan","Brute Force","Malware"].map(v=><option key={v} style={{background:"#0a0f1e"}}>{v}</option>)}
          </select>
        </div>
        <div>
          <label className="text-[10px] font-mono text-slate-500 uppercase tracking-wider block mb-1">Protocol</label>
          <select value={form.protocol} onChange={e=>set("protocol",e.target.value)} className={inputCls} style={selectStyle}>
            {["TCP","UDP","ICMP","HTTP","HTTPS","ANY"].map(v=><option key={v} style={{background:"#0a0f1e"}}>{v}</option>)}
          </select>
        </div>
        <div>
          <label className="text-[10px] font-mono text-slate-500 uppercase tracking-wider block mb-1">Source IP / CIDR</label>
          <input value={form.srcIp} onChange={e=>set("srcIp",e.target.value)} placeholder="e.g. 192.168.1.0/24 or ANY" className={inputCls} style={inputStyle}/>
        </div>
        <div>
          <label className="text-[10px] font-mono text-slate-500 uppercase tracking-wider block mb-1">Destination IP / CIDR</label>
          <input value={form.dstIp} onChange={e=>set("dstIp",e.target.value)} placeholder="e.g. 10.0.0.0/8 or ANY" className={inputCls} style={inputStyle}/>
        </div>
        <div>
          <label className="text-[10px] font-mono text-slate-500 uppercase tracking-wider block mb-1">Port Range</label>
          <input value={form.port} onChange={e=>set("port",e.target.value)} placeholder="e.g. 80, 443, 1000-2000" className={inputCls} style={inputStyle}/>
        </div>
        <div>
          <label className="text-[10px] font-mono text-slate-500 uppercase tracking-wider block mb-1">Severity</label>
          <select value={form.severity} onChange={e=>set("severity",e.target.value)} className={inputCls} style={selectStyle}>
            {["Low","Medium","High","Critical"].map(v=><option key={v} style={{background:"#0a0f1e"}}>{v}</option>)}
          </select>
        </div>
        <div>
          <label className="text-[10px] font-mono text-slate-500 uppercase tracking-wider block mb-1">Action</label>
          <select value={form.action} onChange={e=>set("action",e.target.value)} className={inputCls} style={selectStyle}>
            {["Alert","Block","Drop","Log"].map(v=><option key={v} style={{background:"#0a0f1e"}}>{v}</option>)}
          </select>
        </div>
        <div>
          <label className="text-[10px] font-mono text-slate-500 uppercase tracking-wider block mb-1">Enable Immediately</label>
          <div className="flex items-center gap-2 mt-2">
            <button onClick={()=>set("enabled",!form.enabled)} className="transition-all duration-300">
              {form.enabled
                ?<div className="flex items-center gap-1 text-green-400"><ToggleRight size={22}/><span className="text-[10px] font-mono">ON</span></div>
                :<div className="flex items-center gap-1 text-slate-600"><ToggleLeft size={22}/><span className="text-[10px] font-mono">OFF</span></div>}
            </button>
          </div>
        </div>
        <div className="md:col-span-2">
          <label className="text-[10px] font-mono text-slate-500 uppercase tracking-wider block mb-1">Detection Pattern * (regex or keyword)</label>
          <textarea value={form.pattern} onChange={e=>set("pattern",e.target.value)} rows={3} placeholder="e.g. (?i)(union|select|insert|drop)\s+.*from" className={`${inputCls} resize-none`} style={inputStyle}/>
        </div>
        <div className="md:col-span-2">
          <label className="text-[10px] font-mono text-slate-500 uppercase tracking-wider block mb-1">Description</label>
          <textarea value={form.desc} onChange={e=>set("desc",e.target.value)} rows={2} placeholder="Describe what this rule detects..." className={`${inputCls} resize-none`} style={inputStyle}/>
        </div>
      </div>
      <div className="flex gap-3 mt-4">
        <button onClick={save} disabled={saving} className="flex items-center gap-2 px-4 py-2 rounded text-[11px] font-mono text-cyan-400 hover:bg-cyan-400/10 transition-colors disabled:opacity-50" style={{border:"1px solid rgba(0,212,255,0.35)"}}>
          <Save size={12}/>{saving?"Saving...":"Save Rule"}
        </button>
        <button onClick={()=>setForm(blank)} className="flex items-center gap-2 px-4 py-2 rounded text-[11px] font-mono text-slate-400 hover:bg-slate-400/10 transition-colors" style={{border:"1px solid rgba(100,116,139,0.3)"}}>
          <RotateCcw size={12}/>Reset Form
        </button>
      </div>
    </SectionCard>
  );
}

// ══════════════════════════════════════════════
// SECTION 6 — RANSOMWARE RULES
// ══════════════════════════════════════════════
function RansomwareRules() {
  const [rules,setRules]     = useState<RansomRule[]>([]);
  const [loading,setLoading] = useState(true);
  const [editId,setEditId]   = useState<number|null>(null);
  const [editForm,setEditForm] = useState<Partial<RansomRule>>({});
  const [modal,setModal]     = useState<{msg:string;onConfirm:()=>void}|null>(null);
  const [toast,setToast]     = useState<{msg:string;type:"success"|"error"}|null>(null);

  const load = useCallback(async()=>{
     const d = await apiFetch<RansomRule[]>("/ransomware/rules");
     if(Array.isArray(d)) setRules(d);
     setLoading(false);
  },[]);

  useEffect(()=>{ load(); },[load]);

  const riskColor:Record<string,string> = {Critical:"#ff006e",High:"#f97316",Medium:"#ffbe0b"};

  const startEdit  = (r:RansomRule)=>{ setEditId(r.id); setEditForm({...r}); };
  const cancelEdit = ()=>{ setEditId(null); setEditForm({}); };
  const saveEdit   = ()=>{
    setRules(prev=>prev.map(r=>r.id===editId?{...r,...editForm} as RansomRule:r));
    setToast({msg:"Rule updated successfully.",type:"success"});
    cancelEdit();
  };

  const toggleStatus = (r:RansomRule)=>{
    const next = r.status==="Active"?"Disabled":"Active";
    setModal({msg:`${next==="Disabled"?"Disable":"Enable"} rule "${r.name}"?`, onConfirm: async()=>{
      const res = await apiFetch<{rule:RansomRule}>(`/ransomware/rules/${r.id}/toggle`,{method:"POST"});
      if(res){ setRules(prev=>prev.map(x=>x.id===r.id?res.rule:x)); setToast({msg:`Rule "${r.name}" ${next.toLowerCase()}.`,type:"success"}); }
      else setToast({msg:"Toggle failed.",type:"error"});
      setModal(null);
    }});
  };

  return (
    <SectionCard title="Ransomware Detection Rules" icon={Lock}>
      {modal&&<Modal msg={modal.msg} onConfirm={modal.onConfirm} onCancel={()=>setModal(null)}/>}
      {toast&&<Toast msg={toast.msg} type={toast.type} onClose={()=>setToast(null)}/>}
      <div className="mt-4 overflow-x-auto">
        {loading ? <div className="space-y-2">{[0,1,2,3].map(i=><Skeleton key={i} className="h-10"/>)}</div> : (
          <table className="w-full text-[11px] font-mono">
            <thead>
              <tr style={{borderBottom:"1px solid rgba(0,212,255,0.1)"}}>
                {["Rule Name","Type","Risk","Status","Last Triggered","Actions"].map(h=>(
                  <th key={h} className="text-left py-2 px-2 text-slate-500 tracking-wider whitespace-nowrap">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rules.map(r=>(
                <>
                  <tr key={r.id} className="border-b hover:bg-white/[0.02] transition-colors" style={{borderColor:"rgba(0,212,255,0.05)"}}>
                    <td className="py-2 px-2 text-slate-200 font-medium">{r.name}</td>
                    <td className="py-2 px-2 text-slate-400">{r.type}</td>
                    <td className="py-2 px-2"><span className="px-2 py-0.5 rounded-full text-[9px] font-mono font-bold" style={{color:riskColor[r.risk],background:`${riskColor[r.risk]}15`,border:`1px solid ${riskColor[r.risk]}40`}}>{r.risk}</span></td>
                    <td className="py-2 px-2">
                      <span className="px-2 py-0.5 rounded-full text-[9px]" style={{color:r.status==="Active"?"#00ff9f":"#94a3b8",background:r.status==="Active"?"rgba(0,255,159,0.08)":"rgba(148,163,184,0.08)",border:`1px solid ${r.status==="Active"?"rgba(0,255,159,0.2)":"rgba(148,163,184,0.2)"}`}}>{r.status}</span>
                    </td>
                    <td className="py-2 px-2 text-slate-500 whitespace-nowrap">{r.lastTriggered}</td>
                    <td className="py-2 px-2">
                      <div className="flex gap-1">
                        <button onClick={()=>editId===r.id?cancelEdit():startEdit(r)} className="px-2 py-0.5 rounded text-[9px] text-cyan-400 hover:bg-cyan-400/10 transition-colors" style={{border:"1px solid rgba(0,212,255,0.2)"}}>
                          <Edit2 size={9} className="inline mr-1"/>{editId===r.id?"Cancel":"Edit"}
                        </button>
                        <button onClick={()=>toggleStatus(r)} className={`px-2 py-0.5 rounded text-[9px] transition-colors ${r.status==="Active"?"text-red-400 hover:bg-red-400/10":"text-green-400 hover:bg-green-400/10"}`} style={{border:`1px solid ${r.status==="Active"?"rgba(255,0,110,0.2)":"rgba(0,255,159,0.2)"}`}}>
                          {r.status==="Active"?"Disable":"Enable"}
                        </button>
                      </div>
                    </td>
                  </tr>
                  {editId===r.id&&(
                    <tr key={`edit-${r.id}`} style={{background:"rgba(0,212,255,0.03)"}}>
                      <td colSpan={6} className="px-4 py-4">
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                          <div>
                            <label className="text-[10px] font-mono text-slate-500 uppercase block mb-1">Rule Name</label>
                            <input value={editForm.name||""} onChange={e=>setEditForm(f=>({...f,name:e.target.value}))} className={inputCls} style={inputStyle}/>
                          </div>
                          <div>
                            <label className="text-[10px] font-mono text-slate-500 uppercase block mb-1">Type</label>
                            <select value={editForm.type||""} onChange={e=>setEditForm(f=>({...f,type:e.target.value as any}))} className={inputCls} style={selectStyle}>
                              {["Encryption","File System","Network","Registry","Experimental"].map(v=><option key={v} style={{background:"#0a0f1e"}}>{v}</option>)}
                            </select>
                          </div>
                          <div>
                            <label className="text-[10px] font-mono text-slate-500 uppercase block mb-1">Risk Level</label>
                            <select value={editForm.risk||""} onChange={e=>setEditForm(f=>({...f,risk:e.target.value as any}))} className={inputCls} style={selectStyle}>
                              {["Critical","High","Medium"].map(v=><option key={v} style={{background:"#0a0f1e"}}>{v}</option>)}
                            </select>
                          </div>
                          <div>
                            <label className="text-[10px] font-mono text-slate-500 uppercase block mb-1">Status</label>
                            <select value={editForm.status||""} onChange={e=>setEditForm(f=>({...f,status:e.target.value as any}))} className={inputCls} style={selectStyle}>
                              {["Active","Disabled"].map(v=><option key={v} style={{background:"#0a0f1e"}}>{v}</option>)}
                            </select>
                          </div>
                          <div className="md:col-span-2">
                            <label className="text-[10px] font-mono text-slate-500 uppercase block mb-1">Pattern / Signature</label>
                            <textarea value={editForm.pattern||""} onChange={e=>setEditForm(f=>({...f,pattern:e.target.value}))} rows={2} className={`${inputCls} resize-none`} style={inputStyle}/>
                          </div>
                        </div>
                        <div className="flex gap-2 mt-3">
                          <button onClick={saveEdit} className="flex items-center gap-1.5 px-3 py-1.5 rounded text-[10px] font-mono text-cyan-400 hover:bg-cyan-400/10 transition-colors" style={{border:"1px solid rgba(0,212,255,0.3)"}}>
                            <Save size={10}/>Save Changes
                          </button>
                          <button onClick={cancelEdit} className="flex items-center gap-1.5 px-3 py-1.5 rounded text-[10px] font-mono text-slate-400 hover:bg-slate-400/10 transition-colors" style={{border:"1px solid rgba(100,116,139,0.3)"}}>
                            <X size={10}/>Cancel
                          </button>
                        </div>
                      </td>
                    </tr>
                  )}
                </>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </SectionCard>
  );
}

// ══════════════════════════════════════════════
// SECTION 7 — CHANGE LOG
// ══════════════════════════════════════════════
function ChangeLogTable() {
  const [logs,setLogs]   = useState<ChangeLog[]>([]);
  const [loading,setLoading] = useState(true);
  const [search,setSearch]   = useState("");
  const [actF,setActF]       = useState("All");
  const [page,setPage]       = useState(0);
  const PER = 8;

  const load = useCallback(async()=>{
    const d = await apiFetch<{changelog:any[]}>("/changelog?limit=100");
     if(d?.changelog) setLogs(d.changelog);
     setLoading(false);
  },[]);

  useEffect(()=>{ load(); },[load]);

  const actionColor:Record<string,string> = {Created:"#00ff9f",Modified:"#00d4ff",Deleted:"#ff006e",Enabled:"#00ff9f",Disabled:"#94a3b8"};
  const statusColor:Record<string,string> = {Applied:"#00ff9f",Pending:"#ffbe0b","Rolled Back":"#ff006e"};

  const filtered = logs.filter(l=>{
    if(search&&!l.rule.toLowerCase().includes(search.toLowerCase())&&!l.by.includes(search)) return false;
    if(actF!=="All"&&l.action!==actF) return false;
    return true;
  });
  const paged = filtered.slice(page*PER,(page+1)*PER);
  const total = Math.ceil(filtered.length/PER);

  const download = ()=>{
    const txt = logs.map(l=>`[${l.timestamp}] ${l.id} | BY: ${l.by} | SECTION: ${l.section} | ACTION: ${l.action} | RULE: ${l.rule} | ${l.prev} → ${l.next} | ${l.status}`).join("\n");
    const a = document.createElement("a");
    a.href = "data:text/plain;charset=utf-8,"+encodeURIComponent(txt);
    a.download = "config-changelog.txt"; a.click();
  };

  return (
    <SectionCard title="Configuration Change Log" icon={Clock}>
      <div className="mt-4 space-y-3">
        <div className="flex flex-wrap items-center gap-2 justify-between">
          <div className="flex flex-wrap gap-2">
            <div className="relative">
              <Search size={11} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500"/>
              <input value={search} onChange={e=>{setSearch(e.target.value);setPage(0);}} placeholder="Search rule or admin..." className="pl-8 pr-3 py-1.5 rounded text-[11px] font-mono outline-none w-48" style={inputStyle}/>
            </div>
            <select value={actF} onChange={e=>{setActF(e.target.value);setPage(0);}} className="px-2 py-1.5 rounded text-[11px] font-mono outline-none" style={selectStyle}>
              {["All","Created","Modified","Deleted","Enabled","Disabled"].map(v=><option key={v} style={{background:"#0a0f1e"}}>{v}</option>)}
            </select>
            <button onClick={load} className="px-2 py-1.5 rounded text-[10px] font-mono text-cyan-400 hover:bg-cyan-400/10 transition-colors" style={{border:"1px solid rgba(0,212,255,0.2)"}}>↻ Refresh</button>
          </div>
          <button onClick={download} className="flex items-center gap-1.5 px-3 py-1.5 rounded text-[10px] font-mono text-green-400 hover:bg-green-400/10 transition-colors" style={{border:"1px solid rgba(0,255,159,0.25)"}}>
            <Download size={11}/>Export Logs
          </button>
        </div>
        {loading ? <div className="space-y-2">{[0,1,2].map(i=><Skeleton key={i} className="h-10"/>)}</div> : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full text-[11px] font-mono">
                <thead>
                  <tr style={{borderBottom:"1px solid rgba(0,212,255,0.1)"}}>
                    {["Log ID","Timestamp","Changed By","Section","Action","Rule Affected","Prev Value","New Value","Status"].map(h=>(
                      <th key={h} className="text-left py-2 px-2 text-slate-500 tracking-wider whitespace-nowrap">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {paged.map(l=>(
                    <tr key={l.id} className="border-b hover:bg-white/[0.02] transition-colors" style={{borderColor:"rgba(0,212,255,0.05)"}}>
                      <td className="py-2 px-2 text-cyan-400">{l.id}</td>
                      <td className="py-2 px-2 text-slate-500 whitespace-nowrap">{l.timestamp}</td>
                      <td className="py-2 px-2 text-slate-300">{l.by}</td>
                      <td className="py-2 px-2 text-slate-400">{l.section}</td>
                      <td className="py-2 px-2">
                        <span className="px-2 py-0.5 rounded-full text-[9px] font-bold" style={{color:actionColor[l.action]||"#94a3b8",background:`${actionColor[l.action]||"#94a3b8"}15`,border:`1px solid ${actionColor[l.action]||"#94a3b8"}40`}}>{l.action}</span>
                      </td>
                      <td className="py-2 px-2 text-slate-300 max-w-32 truncate">{l.rule}</td>
                      <td className="py-2 px-2 text-slate-500">{l.prev}</td>
                      <td className="py-2 px-2 text-slate-300">{l.next}</td>
                      <td className="py-2 px-2">
                        <span className="text-[9px] font-mono" style={{color:statusColor[l.status]||"#94a3b8"}}>{l.status}</span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-mono text-slate-600">Showing {page*PER+1}–{Math.min((page+1)*PER,filtered.length)} of {filtered.length}</span>
              <div className="flex items-center gap-1">
                <button onClick={()=>setPage(p=>Math.max(0,p-1))} disabled={page===0} className="p-1 rounded text-slate-500 hover:text-cyan-400 disabled:opacity-30"><ChevronLeft size={14}/></button>
                {Array.from({length:Math.min(total,5)},(_,i)=>(
                  <button key={i} onClick={()=>setPage(i)} className="w-6 h-6 rounded text-[10px] font-mono transition-colors" style={{background:page===i?"rgba(0,212,255,0.15)":"transparent",color:page===i?"#00d4ff":"#64748b"}}>{i+1}</button>
                ))}
                <button onClick={()=>setPage(p=>Math.min(total-1,p+1))} disabled={page>=total-1} className="p-1 rounded text-slate-500 hover:text-cyan-400 disabled:opacity-30"><ChevronRight size={14}/></button>
              </div>
            </div>
          </>
        )}
      </div>
    </SectionCard>
  );
}

// ══════════════════════════════════════════════
// MAIN PAGE
// ══════════════════════════════════════════════
export default function ConfigurationPage() {
  return (
    <div className="min-h-screen" style={{background:"#030712"}}>
      <div className="fixed inset-0 pointer-events-none" style={{backgroundImage:"linear-gradient(rgba(0,212,255,0.018) 1px,transparent 1px),linear-gradient(90deg,rgba(0,212,255,0.018) 1px,transparent 1px)",backgroundSize:"40px 40px"}}/>
      <Navbar/>
      <main className="relative z-10 max-w-screen-xl mx-auto px-4 sm:px-6 py-6 space-y-5">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-xl font-bold text-slate-100 tracking-wider" style={{fontFamily:"'Orbitron',monospace"}}>SECURITY CONFIGURATION</h1>
            <p className="text-[11px] font-mono text-slate-600 mt-0.5">Manage detection rules · Signatures · Anomaly thresholds</p>
          </div>
          <div className="flex items-center gap-1.5 text-[11px] font-mono text-green-400">
            <div className="w-2 h-2 rounded-full bg-green-400 animate-pulse"/>ENGINE ACTIVE
          </div>
        </div>
        <SignatureDetection/>
        <AnomalyDetection/>
        <ActiveAttackers/>
        <SignatureDatabase/>
        <CreateRule/>
        <RansomwareRules/>
        <ChangeLogTable/>
        <div className="pt-2 pb-4 flex items-center justify-between text-[10px] font-mono text-slate-700">
          <span>CyGuardian-X v2.4.1 — CONFIGURATION MODULE</span>
          <span>ALL CHANGES ARE LOGGED AND AUDITED</span>
        </div>
      </main>
    </div>
  );
}