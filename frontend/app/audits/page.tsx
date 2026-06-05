"use client";
import NotificationBell from "../../components/NotificationBell";

import { useState, useEffect, useCallback } from "react";
import {
  Shield, Activity, AlertTriangle, Settings, FileText, LogOut,
  Radio, Menu, X, BarChart2, AlertCircle, Lock, ChevronDown,
  ChevronUp, Search, Download, ChevronLeft, ChevronRight,
  RotateCcw, CheckCircle, XCircle, TrendingUp, TrendingDown,
  Layers, Database, Globe, Clock, Eye,
  Bot,
} from "lucide-react";

// ══════════════════════════════════════════════
// CONFIG
// ══════════════════════════════════════════════
const API = "fyp-backend-production-944f.up.railway.app/api/audits";

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
type MaliciousIP = {
  ip: string; events: number; type: "Anomaly"|"Signature"|"Ransomware";
  avgSev: "Low"|"Medium"|"High"|"Critical"; protocol: string; country: string; lastSeen: string;
};
type AuditLog = {
  id: string; timestamp: string; actor: string;
  changeType: "Created"|"Modified"|"Deleted"|"Enabled"|"Disabled";
  target: string; action: string; details: string; rolled_back: boolean;
};
type Metric   = { label:string; value:number; change:string; up:boolean; color:string; sub:string; spark:number[]; };
type PieItem  = { label:string; value:number; color:string; pct:number; };
type DistItem = { label:string; pct:number; color:string; desc:string; };
type ProtoItem= { proto:string; pct:number; packets:number; color:string; status:string; };
type Outcome  = { label:string; count:number; resolved:number; color:string; };

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
            <a key={label} href={href} className={"flex items-center gap-1.5 px-3 py-4 text-[11px] font-mono tracking-wider border-b-2 transition-all duration-200 "+(label==="Audits"?"text-cyan-400 border-cyan-400":"text-slate-500 border-transparent hover:text-slate-300 hover:border-slate-700")}>
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
            <a key={label} href={href} className={"flex items-center gap-2 px-3 py-2 text-[11px] font-mono rounded "+(label==="Audits"?"text-cyan-400 bg-cyan-400/10":"text-slate-500")}>
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

function Toast({msg,type,onClose}:{msg:string;type:"success"|"error";onClose:()=>void}) {
  useEffect(()=>{const t=setTimeout(onClose,3000);return()=>clearTimeout(t);},[]);
  return (
    <div className="fixed top-20 right-4 z-50 px-4 py-3 rounded flex items-center gap-2 text-[11px] font-mono shadow-lg"
      style={{background:type==="success"?"rgba(0,255,159,0.15)":"rgba(255,0,110,0.15)",border:"1px solid "+(type==="success"?"rgba(0,255,159,0.4)":"rgba(255,0,110,0.4)"),color:type==="success"?"#00ff9f":"#ff006e"}}>
      {type==="success"?<CheckCircle size={13}/>:<XCircle size={13}/>}{msg}
    </div>
  );
}

function Modal({msg,onConfirm,onCancel}:{msg:string;onConfirm:()=>void;onCancel:()=>void}) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center" style={{background:"rgba(0,0,0,0.75)"}}>
      <div className="p-6 rounded max-w-sm w-full mx-4" style={{background:"rgba(10,15,30,0.98)",border:"1px solid rgba(255,0,110,0.4)"}}>
        <AlertTriangle size={22} className="text-red-400 mb-3"/>
        <div className="text-sm font-mono text-slate-200 mb-2 font-bold">Confirm Rollback</div>
        <div className="text-[11px] font-mono text-slate-400 mb-4">{msg}</div>
        <div className="flex gap-3">
          <button onClick={onCancel} className="flex-1 py-2 rounded text-[11px] font-mono text-slate-400" style={{border:"1px solid rgba(100,116,139,0.3)"}}>Cancel</button>
          <button onClick={onConfirm} className="flex-1 py-2 rounded text-[11px] font-mono text-red-400 hover:bg-red-400/10" style={{border:"1px solid rgba(255,0,110,0.4)"}}>Confirm</button>
        </div>
      </div>
    </div>
  );
}

function Skeleton({className=""}:{className?:string}) {
  return <div className={`rounded animate-pulse ${className}`} style={{background:"rgba(0,212,255,0.06)"}}/>;
}

function useCountUp(target:number, duration=1200){
  const [count,setCount]=useState(0);
  useEffect(()=>{
    if(!target) return;
    let s=0; const step=target/(duration/16);
    const t=setInterval(()=>{s+=step;if(s>=target){setCount(target);clearInterval(t);}else setCount(Math.floor(s));},16);
    return()=>clearInterval(t);
  },[target]);
  return count;
}

function Sparkline({data,color}:{data:number[];color:string}) {
  if(!data||data.length<2) return <svg width={80} height={32}/>;
  const max=Math.max(...data),min=Math.min(...data);
  const h=32,w=80,pad=2;
  const pts=data.map((v,i)=>({x:pad+(i/(data.length-1))*(w-2*pad),y:h-pad-((v-min)/(max-min||1))*(h-2*pad)}));
  const d=pts.map((p,i)=>(i===0?"M":"L")+p.x+","+p.y).join(" ");
  const last=pts[pts.length-1];
  return (
    <svg width={w} height={h} className="overflow-visible">
      <path d={d} fill="none" stroke={color} strokeWidth="1.5" style={{filter:"drop-shadow(0 0 3px "+color+")"}}/>
      {last&&<circle cx={last.x} cy={last.y} r="2.5" fill={color} style={{filter:"drop-shadow(0 0 4px "+color+")"}}/>}
    </svg>
  );
}

// ══════════════════════════════════════════════
// SECTION 1 — SUMMARY METRICS
// ══════════════════════════════════════════════
function MetricCard({m}:{m:Metric}) {
  const count=useCountUp(m.value);
  const Icon=m.label==="Total Alerts"?Activity:m.label==="Incidents Resolved"?CheckCircle:m.label==="Malicious Traffic"?AlertTriangle:AlertCircle;
  return (
    <div className="p-4 rounded relative overflow-hidden group transition-all duration-300 hover:-translate-y-1"
      style={{background:"rgba(10,15,30,0.95)",border:"1px solid "+m.color+"25",boxShadow:"0 0 20px "+m.color+"08"}}>
      <div className="absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none"
        style={{background:"radial-gradient(ellipse at top right,"+m.color+"08,transparent 70%)"}}/>
      <div className="flex items-start justify-between mb-2">
        <div className="p-1.5 rounded" style={{background:m.color+"15",border:"1px solid "+m.color+"25"}}>
          <Icon size={14} style={{color:m.color}}/>
        </div>
        <div className={"flex items-center gap-0.5 text-[10px] font-mono font-bold "+(m.up?"text-green-400":"text-red-400")}>
          {m.up?<TrendingUp size={10}/>:<TrendingDown size={10}/>}{m.change}
        </div>
      </div>
      <div className="text-2xl font-bold mb-0.5" style={{color:m.color,fontFamily:"'Orbitron',monospace"}}>{count.toLocaleString()}</div>
      <div className="text-[10px] font-mono text-slate-400 uppercase tracking-wider mb-0.5">{m.label}</div>
      <div className="text-[9px] font-mono text-slate-600 mb-3">{m.sub}</div>
      <Sparkline data={m.spark} color={m.color}/>
    </div>
  );
}

function SummaryMetrics({metrics}:{metrics:Metric[]}) {
  if(!metrics.length) return (
    <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
      {[0,1,2,3].map(i=><Skeleton key={i} className="h-40"/>)}
    </div>
  );
  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
      {metrics.map(m=><MetricCard key={m.label} m={m}/>)}
    </div>
  );
}

// ══════════════════════════════════════════════
// SECTION 2 — TREND ANALYSIS
// ══════════════════════════════════════════════
function TrendAnalysis({initialPie, initialTrend, initialTotal}:{initialPie:PieItem[];initialTrend:number[];initialTotal:number}) {
  const [hovIdx,setHovIdx]   = useState<number|null>(null);
  const [period,setPeriod]   = useState<"24h"|"7d"|"30d">("7d");
  const [trendData,setTrend] = useState<number[]>(initialTrend);
  const [pie,setPie]         = useState<PieItem[]>(initialPie);
  const [total,setTotal]     = useState(initialTotal);
  const [loading,setLoading] = useState(false);

  // Sync when snapshot data arrives from parent
  useEffect(()=>{ if(initialTrend.length) setTrend(initialTrend); },[initialTrend]);
  useEffect(()=>{ if(initialPie.length)   setPie(initialPie);     },[initialPie]);
  useEffect(()=>{ if(initialTotal)        setTotal(initialTotal); },[initialTotal]);

  const fetchTrend = useCallback(async(p:string)=>{
    setLoading(true);
    const d = await apiFetch<{period:string;trend:number[];pie:PieItem[];total:number}>(`/trend?period=${p}`);
    if(d){ setTrend(d.trend); setPie(d.pie); setTotal(d.total); }
    setLoading(false);
  },[]);

  useEffect(()=>{ if(period!=="7d") fetchTrend(period); },[period]);

  const safeData = trendData.length >= 2 ? trendData : [];
  const tMax=safeData.length ? Math.max(...safeData) : 1;
  const tMin=safeData.length ? Math.min(...safeData) : 0;
  const pts=safeData.map((v,i)=>({x:20+(i/(safeData.length-1))*260,y:60-((v-tMin)/(tMax-tMin||1))*50}));
  const linePath = pts.map((p,i)=>(i===0?"M":"L")+p.x+","+p.y).join(" ");

  let cumAngle=-90;
  const slices=pie.map((d)=>{
    const deg=(d.value/(total||1))*360;
    const start=cumAngle; cumAngle+=deg;
    const r=70,cx=90,cy=90;
    const toRad=(a:number)=>a*Math.PI/180;
    const x1=cx+r*Math.cos(toRad(start)),y1=cy+r*Math.sin(toRad(start));
    const x2=cx+r*Math.cos(toRad(start+deg)),y2=cy+r*Math.sin(toRad(start+deg));
    const lx=cx+r*0.65*Math.cos(toRad(start+deg/2)),ly=cy+r*0.65*Math.sin(toRad(start+deg/2));
    const large=deg>180?1:0;
    return {path:`M${cx},${cy} L${x1},${y1} A${r},${r},0,${large},1,${x2},${y2} Z`,lx,ly,d};
  });

  return (
    <SectionCard title="Trend Analysis" icon={TrendingUp}>
      <div className="mt-4 grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Pie */}
        <div>
          <div className="text-[10px] font-mono text-slate-500 uppercase tracking-wider mb-3">Alerts by Detection Type</div>
          <div className="flex items-center gap-6">
            <svg width="180" height="180" viewBox="0 0 180 180">
              {slices.map(({path,lx,ly,d},i)=>(
                <g key={d.label} onMouseEnter={()=>setHovIdx(i)} onMouseLeave={()=>setHovIdx(null)}>
                  <path d={path} fill={d.color} stroke="#030712" strokeWidth="2"
                    style={{filter:hovIdx===i?"drop-shadow(0 0 8px "+d.color+")":"none",opacity:hovIdx!==null&&hovIdx!==i?0.6:1,transition:"all 0.2s"}}/>
                  <text x={lx} y={ly} textAnchor="middle" dominantBaseline="middle"
                    style={{fontSize:"9px",fontFamily:"monospace",fill:"#030712",fontWeight:"bold",pointerEvents:"none"}}>{d.pct}%</text>
                </g>
              ))}
              <circle cx="90" cy="90" r="38" fill="#0a0f1e"/>
              <text x="90" y="86" textAnchor="middle" style={{fontSize:"11px",fontFamily:"'JetBrains Mono',monospace",fill:"#00d4ff",fontWeight:"bold"}}>{total.toLocaleString()}</text>
              <text x="90" y="100" textAnchor="middle" style={{fontSize:"8px",fontFamily:"monospace",fill:"#475569"}}>Total</text>
            </svg>
            <div className="space-y-3">
              {pie.map((d,i)=>(
                <div key={d.label} className="flex items-center gap-2 cursor-pointer" onMouseEnter={()=>setHovIdx(i)} onMouseLeave={()=>setHovIdx(null)}>
                  <div className="w-3 h-3 rounded-sm shrink-0" style={{background:d.color,boxShadow:"0 0 4px "+d.color}}/>
                  <div>
                    <div className="text-[11px] font-mono text-slate-300">{d.label}</div>
                    <div className="text-[9px] font-mono text-slate-500">{d.value.toLocaleString()} · {d.pct}%</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
        {/* Line chart */}
        <div>
          <div className="flex items-center justify-between mb-3">
            <div className="text-[10px] font-mono text-slate-500 uppercase tracking-wider">Alert Volume Trend</div>
            <div className="flex gap-1">
              {(["24h","7d","30d"] as const).map(p=>(
                <button key={p} onClick={()=>setPeriod(p)} className="px-2 py-0.5 rounded text-[10px] font-mono transition-colors"
                  style={{background:period===p?"rgba(0,212,255,0.15)":"transparent",color:period===p?"#00d4ff":"#64748b",border:"1px solid "+(period===p?"rgba(0,212,255,0.3)":"rgba(100,116,139,0.2)")}}>
                  {p}
                </button>
              ))}
            </div>
          </div>
          <div className="p-3 rounded relative" style={{background:"rgba(0,0,0,0.3)",border:"1px solid rgba(0,212,255,0.08)"}}>
            {loading&&<div className="absolute inset-0 flex items-center justify-center text-[10px] font-mono text-slate-500">Loading...</div>}
            {pts.length>=2 ? (
            <svg width="100%" height="80" viewBox="0 0 300 80" preserveAspectRatio="none">
              {[0,1,2,3].map(i=><line key={i} x1="20" y1={10+i*15} x2="280" y2={10+i*15} stroke="rgba(0,212,255,0.06)" strokeWidth="1"/>)}
              <defs>
                <linearGradient id="trendGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#00d4ff" stopOpacity="0.2"/>
                  <stop offset="100%" stopColor="#00d4ff" stopOpacity="0"/>
                </linearGradient>
              </defs>
              <path d={linePath+" L"+pts[pts.length-1].x+",70 L"+pts[0].x+",70 Z"} fill="url(#trendGrad)"/>
              <path d={linePath} fill="none" stroke="#00d4ff" strokeWidth="2" style={{filter:"drop-shadow(0 0 3px #00d4ff)"}}/>
              {pts.map((p,i)=><circle key={i} cx={p.x} cy={p.y} r="2" fill="#00d4ff" style={{filter:"drop-shadow(0 0 3px #00d4ff)"}}/>)}
            </svg>
            ) : (
            <div className="h-20 flex items-center justify-center text-[10px] font-mono text-slate-600">Loading chart...</div>
            )}
          </div>
          <div className="mt-2 flex justify-between text-[9px] font-mono text-slate-600">
            <span>{period==="24h"?"12h ago":period==="7d"?"7d ago":"30d ago"}</span><span>Now</span>
          </div>
        </div>
      </div>
    </SectionCard>
  );
}

// ══════════════════════════════════════════════
// SECTION 3 — DETECTION DISTRIBUTION
// ══════════════════════════════════════════════
function DetectionDistribution({data}:{data:DistItem[]}) {
  const [widths,setWidths]   = useState(data.map(()=>0));
  const [hovered,setHovered] = useState<number|null>(null);
  useEffect(()=>{
    if(!data.length) return;
    const t=setTimeout(()=>setWidths(data.map(d=>d.pct)),150);
    return()=>clearTimeout(t);
  },[data]);
  return (
    <SectionCard title="Detection Distribution" icon={Layers}>
      <div className="mt-4 space-y-5">
        {data.length===0?[0,1,2].map(i=><Skeleton key={i} className="h-14"/>):
          data.map(({label,pct,color,desc},i)=>(
            <div key={label} onMouseEnter={()=>setHovered(i)} onMouseLeave={()=>setHovered(null)}>
              <div className="flex items-center justify-between mb-1.5">
                <span className="text-[11px] font-mono text-slate-300">{label}</span>
                <span className="text-[11px] font-mono font-bold px-2 py-0.5 rounded" style={{color,background:color+"15",border:"1px solid "+color+"30"}}>{pct}%</span>
              </div>
              <div className="h-6 rounded-full bg-slate-800 overflow-hidden">
                <div className="h-full rounded-full flex items-center justify-end pr-2 transition-all duration-700 ease-out"
                  style={{width:widths[i]+"%",background:"linear-gradient(90deg,"+color+"80,"+color+")",
                    boxShadow:hovered===i?"0 0 16px "+color+"60,0 0 32px "+color+"30":"0 0 8px "+color+"40",minWidth:"4px"}}>
                  <span className="text-[9px] font-mono text-black font-bold">{pct}%</span>
                </div>
              </div>
              <p className="text-[9px] font-mono text-slate-600 mt-1">{desc}</p>
            </div>
          ))}
      </div>
    </SectionCard>
  );
}

// ══════════════════════════════════════════════
// SECTION 4 — TRAFFIC BY PROTOCOL
// ══════════════════════════════════════════════
function TrafficByProtocol({data}:{data:ProtoItem[]}) {
  const [widths,setWidths]=useState(data.map(()=>0));
  useEffect(()=>{
    if(!data.length) return;
    const t=setTimeout(()=>setWidths(data.map(d=>d.pct)),200);
    return()=>clearTimeout(t);
  },[data]);
  const statusColor:Record<string,string>={HIGH:"#ff006e",ELEVATED:"#ffbe0b",NORMAL:"#00ff9f",LOW:"#64748b"};
  return (
    <SectionCard title="Traffic by Protocol" icon={Globe}>
      <div className="mt-4 grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-5 gap-3">
        {data.length===0?[0,1,2,3,4].map(i=><Skeleton key={i} className="h-28"/>):
          data.map(({proto,pct,packets,color,status},i)=>(
            <div key={proto} className="p-4 rounded hover:-translate-y-0.5 transition-all duration-200"
              style={{background:"rgba(255,255,255,0.02)",border:"1px solid "+color+"25"}}>
              <div className="flex items-center justify-between mb-2">
                <span className="text-[12px] font-bold font-mono" style={{color,fontFamily:"'Orbitron',monospace"}}>{proto}</span>
                <span className="text-[9px] font-mono px-1.5 py-0.5 rounded" style={{color:statusColor[status],background:statusColor[status]+"15",border:"1px solid "+statusColor[status]+"30"}}>{status}</span>
              </div>
              <div className="text-2xl font-bold mb-1" style={{color,fontFamily:"'Orbitron',monospace"}}>{pct}%</div>
              <div className="text-[9px] font-mono text-slate-500 mb-2">{packets.toLocaleString()} pkts</div>
              <div className="h-1.5 rounded-full bg-slate-800 overflow-hidden">
                <div className="h-full rounded-full transition-all duration-700" style={{width:widths[i]+"%",background:color,boxShadow:"0 0 6px "+color+"80"}}/>
              </div>
            </div>
          ))}
      </div>
    </SectionCard>
  );
}

// ══════════════════════════════════════════════
// SECTION 5 — SEVERITY OUTCOMES
// ══════════════════════════════════════════════
function OutcomeCard({o}:{o:Outcome}) {
  const count=useCountUp(o.count);
  const [bar,setBar]=useState(0);
  useEffect(()=>{ const t=setTimeout(()=>setBar(o.resolved),300); return()=>clearTimeout(t); },[o.resolved]);
  return (
    <div className="p-4 rounded" style={{background:"rgba(255,255,255,0.02)",border:"1px solid "+o.color+"25"}}>
      <div className="flex items-center gap-2 mb-3">
        <div className="w-2 h-2 rounded-full" style={{background:o.color,boxShadow:"0 0 6px "+o.color}}/>
        <span className="text-[12px] font-mono font-semibold" style={{color:o.color}}>{o.label}</span>
      </div>
      <div className="text-2xl font-bold mb-0.5" style={{color:o.color,fontFamily:"'Orbitron',monospace"}}>{count.toLocaleString()}</div>
      <div className="text-[9px] font-mono text-slate-600 mb-3">Total incidents</div>
      <div className="space-y-1">
        <div className="flex justify-between text-[10px] font-mono">
          <span className="text-slate-400">Resolution Rate</span>
          <span style={{color:o.color}} className="font-bold">{o.resolved}%</span>
        </div>
        <div className="h-3 rounded-full bg-slate-800 overflow-hidden">
          <div className="h-full rounded-full transition-all duration-700 ease-out"
            style={{width:bar+"%",background:"linear-gradient(90deg,"+o.color+"80,"+o.color+")",boxShadow:"0 0 8px "+o.color+"50"}}/>
        </div>
        <div className="flex justify-between text-[9px] font-mono text-slate-600">
          <span>Resolved: {Math.round(o.count*(o.resolved/100)).toLocaleString()}</span>
          <span>Open: {Math.round(o.count*(1-o.resolved/100)).toLocaleString()}</span>
        </div>
      </div>
    </div>
  );
}

function SeverityOutcomes({data}:{data:Outcome[]}) {
  return (
    <SectionCard title="Incident Outcomes by Severity" icon={Shield}>
      <div className="mt-4 grid grid-cols-1 md:grid-cols-3 gap-4">
        {data.length===0?[0,1,2].map(i=><Skeleton key={i} className="h-40"/>):
          data.map(o=><OutcomeCard key={o.label} o={o}/>)}
      </div>
    </SectionCard>
  );
}

// ══════════════════════════════════════════════
// SECTION 6 — MALICIOUS IPs
// ══════════════════════════════════════════════
const SEV_COLOR:Record<string,string>={Low:"#00ff9f",Medium:"#ffbe0b",High:"#f97316",Critical:"#ff006e"};
const DET_COLOR:Record<string,string>={Anomaly:"#ffbe0b",Signature:"#00d4ff",Ransomware:"#f97316"};

function MaliciousIPs({initialIps}:{initialIps:MaliciousIP[]}) {
  const [ips,setIps]         = useState<MaliciousIP[]>(initialIps);
  const [search,setSearch]   = useState("");
  const [sortCol,setSortCol] = useState<keyof MaliciousIP>("events");
  const [sortAsc,setSortAsc] = useState(false);
  const [page,setPage]       = useState(0);
  const [selected,setSelected] = useState<MaliciousIP|null>(null);
  const PER = 5;

  const load = useCallback(async(q?:string)=>{
    const path = q ? `/malicious-ips?search=${encodeURIComponent(q)}` : "/malicious-ips";
    const d = await apiFetch<{ips:MaliciousIP[];}>(path);
    if(d) setIps(d.ips);
  },[]);

  useEffect(()=>{ load(search||undefined); },[search]);

  const sorted=[...ips].sort((a,b)=>{
    const av=a[sortCol],bv=b[sortCol];
    if(typeof av==="number"&&typeof bv==="number") return sortAsc?av-bv:bv-av;
    return sortAsc?String(av).localeCompare(String(bv)):String(bv).localeCompare(String(av));
  });
  const paged=sorted.slice(page*PER,(page+1)*PER);
  const total=Math.ceil(sorted.length/PER);
  const sort=(c:keyof MaliciousIP)=>{if(sortCol===c)setSortAsc(!sortAsc);else{setSortCol(c);setSortAsc(false);}};

  const inpSty={background:"rgba(0,212,255,0.04)",border:"1px solid rgba(0,212,255,0.15)",color:"#cbd5e1"};
  return (
    <SectionCard title="Top Malicious Source IPs" icon={Database}>
      {selected&&(
        <div className="fixed right-4 top-20 z-40 w-72 rounded shadow-2xl" style={{background:"rgba(10,15,30,0.99)",border:"1px solid rgba(0,212,255,0.25)"}}>
          <div className="px-4 py-3 border-b flex items-center justify-between" style={{borderColor:"rgba(0,212,255,0.1)"}}>
            <div className="flex items-center gap-2"><Globe size={13} className="text-cyan-400"/><span className="text-[12px] font-mono font-bold text-cyan-400">{selected.ip}</span></div>
            <button onClick={()=>setSelected(null)}><X size={12} className="text-slate-500"/></button>
          </div>
          <div className="p-4 space-y-2">
            {[["Country",selected.country],["Type",selected.type],["Avg Severity",selected.avgSev],["Protocol",selected.protocol],["Events",selected.events.toLocaleString()],["Last Seen",selected.lastSeen]].map(([k,v])=>(
              <div key={k} className="flex justify-between text-[10px] font-mono"><span className="text-slate-500">{k}</span><span className="text-slate-200">{v}</span></div>
            ))}
          </div>
        </div>
      )}
      <div className="mt-4">
        <div className="flex items-center gap-2 mb-3">
          <div className="relative">
            <Search size={11} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500"/>
            <input value={search} onChange={e=>{setSearch(e.target.value);setPage(0);}} placeholder="Filter by IP or type..."
              className="pl-8 pr-3 py-1.5 rounded text-[11px] font-mono outline-none w-56" style={inpSty}/>
          </div>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-[11px] font-mono">
            <thead>
              <tr style={{borderBottom:"1px solid rgba(0,212,255,0.1)"}}>
                {([["ip","Source IP"],["events","Events"],["type","Primary Type"],["avgSev","Avg Severity"],["protocol","Protocol"]] as [keyof MaliciousIP,string][]).map(([col,lbl])=>(
                  <th key={col} onClick={()=>sort(col)} className="text-left py-2 px-2 text-slate-500 tracking-wider cursor-pointer hover:text-cyan-400 transition-colors whitespace-nowrap">
                    <span className="flex items-center gap-1">{lbl}{sortCol===col?(sortAsc?<ChevronUp size={10}/>:<ChevronDown size={10}/>):null}</span>
                  </th>
                ))}
                <th className="text-left py-2 px-2 text-slate-500">Detail</th>
              </tr>
            </thead>
            <tbody>
              {paged.map(ip=>(
                <tr key={ip.ip} className="border-b transition-colors cursor-pointer hover:bg-white/[0.03]"
                  style={{borderColor:"rgba(0,212,255,0.05)",background:selected?.ip===ip.ip?"rgba(0,212,255,0.05)":ip.avgSev==="Critical"?"rgba(255,0,110,0.04)":"transparent"}}>
                  <td className="py-2 px-2 text-cyan-400 font-bold">{ip.ip}</td>
                  <td className="py-2 px-2 text-slate-300">{ip.events.toLocaleString()}</td>
                  <td className="py-2 px-2"><span className="px-2 py-0.5 rounded-full text-[9px] font-bold" style={{color:DET_COLOR[ip.type],background:DET_COLOR[ip.type]+"15",border:"1px solid "+DET_COLOR[ip.type]+"30"}}>{ip.type}</span></td>
                  <td className="py-2 px-2"><span className="px-2 py-0.5 rounded-full text-[9px] font-bold" style={{color:SEV_COLOR[ip.avgSev],background:SEV_COLOR[ip.avgSev]+"15",border:"1px solid "+SEV_COLOR[ip.avgSev]+"30"}}>{ip.avgSev}</span></td>
                  <td className="py-2 px-2 text-slate-400">{ip.protocol}</td>
                  <td className="py-2 px-2">
                    <button onClick={()=>setSelected(selected?.ip===ip.ip?null:ip)} className="px-2 py-0.5 rounded text-[9px] text-cyan-400 hover:bg-cyan-400/10 transition-colors" style={{border:"1px solid rgba(0,212,255,0.2)"}}>
                      <Eye size={9} className="inline mr-1"/>View
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="flex items-center justify-between mt-3">
          <span className="text-[10px] font-mono text-slate-600">Showing {page*PER+1}–{Math.min((page+1)*PER,sorted.length)} of {sorted.length}</span>
          <div className="flex items-center gap-1">
            <button onClick={()=>setPage(p=>Math.max(0,p-1))} disabled={page===0} className="p-1 rounded text-slate-500 hover:text-cyan-400 disabled:opacity-30"><ChevronLeft size={14}/></button>
            {Array.from({length:Math.min(total,3)},(_,i)=>(
              <button key={i} onClick={()=>setPage(i)} className="w-6 h-6 rounded text-[10px] font-mono transition-colors" style={{background:page===i?"rgba(0,212,255,0.15)":"transparent",color:page===i?"#00d4ff":"#64748b"}}>{i+1}</button>
            ))}
            <button onClick={()=>setPage(p=>Math.min(total-1,p+1))} disabled={page>=total-1} className="p-1 rounded text-slate-500 hover:text-cyan-400 disabled:opacity-30"><ChevronRight size={14}/></button>
          </div>
        </div>
      </div>
    </SectionCard>
  );
}

// ══════════════════════════════════════════════
// SECTION 7 — AUDIT LOG TABLE
// ══════════════════════════════════════════════
const ACT_COLOR:Record<string,string>={Created:"#00ff9f",Modified:"#00d4ff",Deleted:"#ff006e",Enabled:"#00ff9f",Disabled:"#94a3b8"};

function AuditLogTable({initialLogs}:{initialLogs:AuditLog[]}) {
  const [logs,setLogs]     = useState<AuditLog[]>(initialLogs);
  const [actorF,setActorF] = useState("All");
  const [typeF,setTypeF]   = useState("All");
  const [search,setSearch] = useState("");
  const [sortAsc,setSortAsc] = useState(false);
  const [page,setPage]     = useState(0);
  const [modal,setModal]   = useState<{msg:string;onConfirm:()=>void}|null>(null);
  const [toast,setToast]   = useState<{msg:string;type:"success"|"error"}|null>(null);
  const PER = 8;

  const reload = useCallback(async()=>{
    const params = new URLSearchParams();
    if(actorF!=="All") params.set("actor",actorF);
    if(typeF!=="All")  params.set("changeType",typeF);
    if(search)         params.set("search",search);
    params.set("sort_asc",String(sortAsc));
    const d = await apiFetch<{logs:AuditLog[]}>(`/logs?${params}`);
    if(d) setLogs(d.logs);
  },[actorF,typeF,search,sortAsc]);

  useEffect(()=>{ reload(); },[reload]);

  const filtered=logs; // filtering handled server-side
  const paged=filtered.slice(page*PER,(page+1)*PER);
  const total=Math.ceil(filtered.length/PER);

  const exportLogs=()=>{
    const txt=logs.map(l=>"["+l.timestamp+"] "+l.id+" | "+l.actor+" | "+l.changeType+" | "+l.target+" | "+l.details).join("\n");
    const a=document.createElement("a");
    a.href="data:text/plain;charset=utf-8,"+encodeURIComponent(txt);
    a.download="audit-log.txt"; a.click();
    setToast({msg:"Audit log exported successfully.",type:"success"});
  };

  const rollback=(id:string)=>setModal({
    msg:`Rollback change ${id}? This will revert the configuration to its previous state.`,
    onConfirm: async()=>{
      const res = await apiFetch<{success:boolean;message:string;new_entry?:AuditLog}>(`/logs/${id}/rollback`,{method:"POST"});
      if(res?.success){
        setToast({msg:res.message,type:"success"});
        reload();
      } else {
        setToast({msg:res?.message||"Rollback failed.",type:"error"});
      }
      setModal(null);
    }
  });

  const selSty={background:"#0a0f1e",border:"1px solid rgba(0,212,255,0.15)",color:"#00d4ff"};
  const inpSty={background:"rgba(0,212,255,0.04)",border:"1px solid rgba(0,212,255,0.15)",color:"#cbd5e1"};

  return (
    <SectionCard title="Configuration Change Audit Log" icon={Clock}>
      {modal&&<Modal msg={modal.msg} onConfirm={modal.onConfirm} onCancel={()=>setModal(null)}/>}
      {toast&&<Toast msg={toast.msg} type={toast.type} onClose={()=>setToast(null)}/>}
      <div className="mt-4 space-y-3">
        <div className="flex flex-wrap items-center gap-2 justify-between">
          <div className="flex flex-wrap gap-2">
            <div className="relative">
              <Search size={11} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500"/>
              <input value={search} onChange={e=>{setSearch(e.target.value);setPage(0);}} placeholder="Search target or actor..."
                className="pl-8 pr-3 py-1.5 rounded text-[11px] font-mono outline-none w-48" style={inpSty}/>
            </div>
            <select value={actorF} onChange={e=>{setActorF(e.target.value);setPage(0);}} className="px-2 py-1.5 rounded text-[11px] font-mono outline-none" style={selSty}>
              {["All","admin","soc_lead","analyst1","analyst2"].map(v=><option key={v} style={{background:"#0a0f1e"}}>{v}</option>)}
            </select>
            <select value={typeF} onChange={e=>{setTypeF(e.target.value);setPage(0);}} className="px-2 py-1.5 rounded text-[11px] font-mono outline-none" style={selSty}>
              {["All","Created","Modified","Deleted","Enabled","Disabled"].map(v=><option key={v} style={{background:"#0a0f1e"}}>{v}</option>)}
            </select>
            <button onClick={()=>{setActorF("All");setTypeF("All");setSearch("");}} className="flex items-center gap-1 px-2 py-1.5 rounded text-[10px] font-mono text-slate-400 hover:text-slate-200" style={{border:"1px solid rgba(100,116,139,0.3)"}}>
              <RotateCcw size={10}/>Reset
            </button>
          </div>
          <div className="flex gap-2">
            <button onClick={()=>setSortAsc(!sortAsc)} className="flex items-center gap-1.5 px-3 py-1.5 rounded text-[10px] font-mono text-slate-400 hover:text-slate-200" style={{border:"1px solid rgba(100,116,139,0.3)"}}>
              <Clock size={10}/>{sortAsc?"Oldest First":"Newest First"}
            </button>
            <button onClick={exportLogs} className="flex items-center gap-1.5 px-3 py-1.5 rounded text-[10px] font-mono text-green-400 hover:bg-green-400/10" style={{border:"1px solid rgba(0,255,159,0.25)"}}>
              <Download size={11}/>Export
            </button>
          </div>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-[11px] font-mono">
            <thead>
              <tr style={{borderBottom:"1px solid rgba(0,212,255,0.1)"}}>
                {["Log ID","Timestamp","Actor","Change Type","Target","Action","Details","Rollback"].map(h=>(
                  <th key={h} className="text-left py-2 px-2 text-slate-500 tracking-wider whitespace-nowrap">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {paged.map(l=>(
                <tr key={l.id} className="border-b hover:bg-white/[0.02] transition-colors"
                  style={{borderColor:"rgba(0,212,255,0.05)",background:l.rolled_back?"rgba(249,115,22,0.03)":"transparent"}}>
                  <td className="py-2 px-2 text-cyan-400">{l.id}</td>
                  <td className="py-2 px-2 text-slate-500 whitespace-nowrap">{l.timestamp}</td>
                  <td className="py-2 px-2 text-slate-300">{l.actor}</td>
                  <td className="py-2 px-2">
                    <span className="px-2 py-0.5 rounded-full text-[9px] font-bold" style={{color:ACT_COLOR[l.changeType]||"#94a3b8",background:(ACT_COLOR[l.changeType]||"#94a3b8")+"15",border:"1px solid "+(ACT_COLOR[l.changeType]||"#94a3b8")+"30"}}>{l.changeType}</span>
                  </td>
                  <td className="py-2 px-2 text-slate-300 max-w-32 truncate">{l.target}</td>
                  <td className="py-2 px-2 text-slate-400">{l.action}</td>
                  <td className="py-2 px-2 text-slate-500 max-w-36 truncate">{l.details}</td>
                  <td className="py-2 px-2">
                    {l.rolled_back
                      ? <span className="text-[9px] font-mono text-orange-400 opacity-60">Rolled Back</span>
                      : <button onClick={()=>rollback(l.id)} className="px-2 py-0.5 rounded text-[9px] text-orange-400 hover:bg-orange-400/10 transition-colors" style={{border:"1px solid rgba(249,115,22,0.25)"}}>
                          <RotateCcw size={9} className="inline mr-1"/>Rollback
                        </button>}
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
      </div>
    </SectionCard>
  );
}

// ══════════════════════════════════════════════
// MAIN PAGE — single snapshot fetch on load
// ══════════════════════════════════════════════
interface Snapshot {
  summary:               { metrics: Metric[] };
  trend:                 { period:string; trend:number[]; pie:PieItem[]; total:number };
  detection_distribution:{ distributions: DistItem[] };
  traffic_protocol:      { protocols: ProtoItem[] };
  severity_outcomes:     { outcomes: Outcome[] };
  malicious_ips:         { ips: MaliciousIP[] };
  audit_logs:            { logs: AuditLog[] };
}

export default function AuditsPage() {
  const [snap,setSnap] = useState<Snapshot|null>(null);

  useEffect(()=>{
    apiFetch<Snapshot>("/snapshot").then(d=>{ if(d) setSnap(d); });
  },[]);

  return (
    <div className="min-h-screen" style={{background:"#030712"}}>
      <div className="fixed inset-0 pointer-events-none" style={{backgroundImage:"linear-gradient(rgba(0,212,255,0.018) 1px,transparent 1px),linear-gradient(90deg,rgba(0,212,255,0.018) 1px,transparent 1px)",backgroundSize:"40px 40px"}}/>
      <Navbar/>
      <main className="relative z-10 max-w-screen-xl mx-auto px-4 sm:px-6 py-6 space-y-5">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-xl font-bold text-slate-100 tracking-wider" style={{fontFamily:"'Orbitron',monospace"}}>SECURITY AUDIT & ANALYTICS</h1>
            <p className="text-[11px] font-mono text-slate-600 mt-0.5">System visibility · Detection insights · Compliance tracking</p>
          </div>
          <div className="flex items-center gap-1.5 text-[11px] font-mono text-green-400">
            <div className="w-2 h-2 rounded-full bg-green-400 animate-pulse"/>LIVE
          </div>
        </div>

        <SummaryMetrics metrics={snap?.summary.metrics ?? []}/>

        <TrendAnalysis
          initialPie={snap?.trend.pie ?? []}
          initialTrend={snap?.trend.trend ?? []}
          initialTotal={snap?.trend.total ?? 0}
        />

        <DetectionDistribution data={snap?.detection_distribution.distributions ?? []}/>

        <TrafficByProtocol data={snap?.traffic_protocol.protocols ?? []}/>

        <SeverityOutcomes data={snap?.severity_outcomes.outcomes ?? []}/>

        <MaliciousIPs initialIps={snap?.malicious_ips.ips ?? []}/>

        <AuditLogTable initialLogs={snap?.audit_logs.logs ?? []}/>

        <div className="pt-2 pb-4 flex items-center justify-between text-[10px] font-mono text-slate-700">
          <span>CyGuardian-X v2.4.1 — AUDIT & ANALYTICS MODULE</span>
          <span>ALL AUDIT RECORDS ARE IMMUTABLE AND TAMPER-EVIDENT</span>
        </div>
      </main>
    </div>
  );
}