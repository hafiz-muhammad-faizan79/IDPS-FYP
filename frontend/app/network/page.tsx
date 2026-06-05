"use client";
import NotificationBell from "../../components/NotificationBell";

import { useState, useEffect, useRef, useCallback } from "react";
import {
  Shield, Activity, AlertTriangle, Settings, FileText,
  LogOut, Radio, Menu, X, BarChart2, Wifi,
  Download, Trash2, RotateCcw, Eye, Ban, Plus, ChevronUp,
  ChevronDown, Search, Filter, Terminal, Cpu,
  Server, Zap, Globe, ArrowUp, ArrowDown,
  CheckCircle, Bell, Lock, ToggleLeft, ToggleRight,
  ChevronLeft, ChevronRight, WifiOff,
  Bot,
} from "lucide-react";

// ══════════════════════════════════════════════════════════════
// CONFIG
// ══════════════════════════════════════════════════════════════
const API_HTTP = "https://fyp-backend-production-944f.up.railway.app";
const API_WS   = "ws://localhost:8000/api/network/ws";

// ══════════════════════════════════════════════════════════════
// TYPES
// ══════════════════════════════════════════════════════════════
type Severity   = "Info"|"Low"|"Medium"|"High"|"Critical";
type ConnStatus = "Established"|"Suspicious"|"Blocked";
type Protocol   = "TCP"|"UDP"|"ICMP"|"HTTP"|"HTTPS";

interface Connection {
  id:number; srcIp:string; dstIp:string; protocol:Protocol;
  port:number; status:ConnStatus; data:string; duration:string; flagged:boolean;
}
interface Alert {
  id:number; time:string; severity:Severity; srcIp:string;
  type:string; desc:string; glowing:boolean;
}
interface LogEntry { time:string; event:string; ip:string; action:string; status:string; detail:string; }
interface Stats {
  total_packets:number; pps:number; bandwidth:number;
  upload:number; download:number; active_connections:number;
  threats_detected:number; threats_blocked:number;
}
interface Health { cpu:number; mem:number; pkt_loss:number; latency:number; }
interface Snapshot {
  stats:Stats;
  proto_dist:Record<string,number>;
  traffic_type:Record<string,number>;
  pps_history:number[];
  bw_history:number[];
  health:Health;
  connections:Connection[];
  alerts:Alert[];
  logs:LogEntry[];
}

// ══════════════════════════════════════════════════════════════
// NAVBAR
// ══════════════════════════════════════════════════════════════
const NAV_LINKS = [
  { label:"Dashboard",          href:"/dashboard",     icon:BarChart2      },
  { label:"Network Monitoring", href:"/network",       icon:Radio          },
  { label:"Incidents",          href:"/incidents",     icon:AlertTriangle  },
  { label:"Configuration",      href:"/configuration", icon:Settings       },
  { label:"Audits",             href:"/audits",        icon:FileText       },
  { label: "Agents", href: "/agents", icon: Bot },
];

function Navbar({ wsConnected }:{ wsConnected:boolean }) {
  const [menuOpen,setMenuOpen] = useState(false);
  const [time,setTime]         = useState("");
  useEffect(()=>{
    const tick=()=>setTime(new Date().toUTCString().slice(5,25)+" UTC");
    tick(); const id=setInterval(tick,1000); return ()=>clearInterval(id);
  },[]);
  return (
    <nav className="sticky top-0 z-50 w-full"
      style={{background:"rgba(6,10,20,0.98)",borderBottom:"1px solid rgba(0,212,255,0.15)",backdropFilter:"blur(12px)"}}>
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
            <a key={label} href={href}
              className={`flex items-center gap-1.5 px-3 py-4 text-[11px] font-mono tracking-wider border-b-2 transition-all duration-200 ${
                label==="Network Monitoring"?"text-cyan-400 border-cyan-400":"text-slate-500 border-transparent hover:text-slate-300 hover:border-slate-700"}`}>
              <Icon size={12}/>{label.toUpperCase()}
            </a>
          ))}
        </div>
        <div className="flex items-center gap-3">
          {/* WebSocket status */}
          <div className="hidden md:flex items-center gap-1.5 text-[10px] font-mono">
            <div className={`w-1.5 h-1.5 rounded-full ${wsConnected?"bg-green-400 animate-pulse":"bg-red-400"}`}
              style={{boxShadow:wsConnected?"0 0 4px #00ff9f":"0 0 4px #ff006e"}}/>
            <span className={wsConnected?"text-green-400":"text-red-400"}>
              {wsConnected?"WS LIVE":"WS OFFLINE"}
            </span>
          </div>
          <span className="text-[10px] font-mono text-slate-600 hidden md:block">{time}</span>
          <div className="flex items-center gap-2 px-3 py-1 rounded"
            style={{background:"rgba(0,212,255,0.06)",border:"1px solid rgba(0,212,255,0.15)"}}>
            <div className="w-6 h-6 rounded-full flex items-center justify-center text-[10px] font-bold text-cyan-400"
              style={{background:"rgba(0,212,255,0.2)"}}>A</div>
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
            <a key={label} href={href}
              className={`flex items-center gap-2 px-3 py-2 text-[11px] font-mono rounded ${label==="Network Monitoring"?"text-cyan-400 bg-cyan-400/10":"text-slate-500"}`}>
              <Icon size={12}/>{label}
            </a>
          ))}
        </div>
      )}
    </nav>
  );
}

// ══════════════════════════════════════════════════════════════
// SECTION HEADER
// ══════════════════════════════════════════════════════════════
function SH({icon:Icon,title,sub,children}:{icon:any;title:string;sub?:string;children?:React.ReactNode}) {
  return (
    <div className="flex items-center justify-between mb-4">
      <div className="flex items-center gap-2">
        <Icon size={14} className="text-cyan-400"/>
        <span className="text-[12px] font-mono text-slate-200 tracking-wider uppercase font-semibold">{title}</span>
        {sub&&<span className="text-[10px] font-mono text-slate-600 ml-2">{sub}</span>}
      </div>
      {children}
    </div>
  );
}

// ══════════════════════════════════════════════════════════════
// STAT CARDS
// ══════════════════════════════════════════════════════════════
function StatCards({stats}:{stats:Stats}) {
  const fmt=(n:number)=>n.toLocaleString();
  const cards=[
    {label:"Total Packets",      value:fmt(stats.total_packets),      sub:"Live counter",        icon:Activity, color:"#00d4ff"},
    {label:"Packets / sec",      value:fmt(stats.pps),                sub:"Current throughput",  icon:Zap,      color:"#00ff9f"},
    {label:"Bandwidth",          value:`${stats.bandwidth} Mbps`,     sub:"Total usage",         icon:Wifi,     color:"#ffbe0b"},
    {label:"Upload",             value:`${stats.upload} Mbps`,        sub:"Outbound traffic",    icon:ArrowUp,  color:"#a78bfa"},
    {label:"Download",           value:`${stats.download} Mbps`,      sub:"Inbound traffic",     icon:ArrowDown,color:"#f97316"},
    {label:"Active Connections", value:fmt(stats.active_connections), sub:"Open sessions",       icon:Globe,    color:"#ff006e"},
  ];
  return (
    <div className="grid grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-3">
      {cards.map(({label,value,sub,icon:Icon,color})=>(
        <div key={label} className="p-4 rounded relative overflow-hidden group transition-all duration-300 hover:-translate-y-0.5"
          style={{background:"rgba(10,15,30,0.95)",border:`1px solid ${color}30`,boxShadow:`0 0 16px ${color}10`}}>
          <div className="absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity"
            style={{background:`radial-gradient(ellipse at top left,${color}08,transparent)`}}/>
          <Icon size={14} style={{color}} className="mb-2"/>
          <div className="text-lg font-bold mb-0.5 transition-all duration-300" style={{color,fontFamily:"'Orbitron',monospace"}}>{value}</div>
          <div className="text-[10px] font-mono text-slate-400 uppercase tracking-wider">{label}</div>
          <div className="text-[9px] font-mono text-slate-600">{sub}</div>
        </div>
      ))}
    </div>
  );
}

// ══════════════════════════════════════════════════════════════
// LINE CHART (canvas) — pps_history
// ══════════════════════════════════════════════════════════════
function LineChart({data}:{data:number[]}) {
  const canvasRef=useRef<HTMLCanvasElement>(null);
  useEffect(()=>{
    const c=canvasRef.current; if(!c) return;
    const ctx=c.getContext("2d"); if(!ctx) return;
    c.width=c.offsetWidth; c.height=c.offsetHeight;
    const w=c.width,h=c.height,pad=20;
    ctx.clearRect(0,0,w,h);
    ctx.strokeStyle="rgba(0,212,255,0.06)"; ctx.lineWidth=1;
    for(let i=0;i<6;i++){const y=pad+((h-2*pad)/5)*i;ctx.beginPath();ctx.moveTo(pad,y);ctx.lineTo(w-pad,y);ctx.stroke();}
    if(data.length<2) return;
    const max=Math.max(...data)||1;
    const pts=data.map((v,i)=>({x:pad+(i/(data.length-1))*(w-2*pad),y:h-pad-(v/max)*(h-2*pad)}));
    const grad=ctx.createLinearGradient(0,0,0,h);
    grad.addColorStop(0,"rgba(0,212,255,0.25)"); grad.addColorStop(1,"rgba(0,212,255,0)");
    ctx.beginPath(); ctx.moveTo(pts[0].x,h-pad);
    pts.forEach(p=>ctx.lineTo(p.x,p.y));
    ctx.lineTo(pts[pts.length-1].x,h-pad);
    ctx.closePath(); ctx.fillStyle=grad; ctx.fill();
    ctx.beginPath();
    pts.forEach((p,i)=>i===0?ctx.moveTo(p.x,p.y):ctx.lineTo(p.x,p.y));
    ctx.strokeStyle="#00d4ff"; ctx.lineWidth=2; ctx.shadowBlur=8; ctx.shadowColor="#00d4ff"; ctx.stroke(); ctx.shadowBlur=0;
    const last=pts[pts.length-1];
    ctx.beginPath(); ctx.arc(last.x,last.y,4,0,Math.PI*2);
    ctx.fillStyle="#00d4ff"; ctx.shadowBlur=12; ctx.shadowColor="#00d4ff"; ctx.fill(); ctx.shadowBlur=0;
  },[data]);
  return <canvas ref={canvasRef} className="w-full h-full"/>;
}

// ══════════════════════════════════════════════════════════════
// BAR CHART — protocol distribution
// ══════════════════════════════════════════════════════════════
function BarChart({protoData}:{protoData:Record<string,number>}) {
  const colors:Record<string,string>={TCP:"#00d4ff",UDP:"#00ff9f",ICMP:"#ffbe0b",HTTP:"#f97316",HTTPS:"#a78bfa"};
  const max=Math.max(...Object.values(protoData))||1;
  return (
    <div className="flex items-end gap-3 h-28 mt-2">
      {Object.entries(protoData).map(([proto,val])=>(
        <div key={proto} className="flex-1 flex flex-col items-center gap-1">
          <span className="text-[9px] font-mono" style={{color:colors[proto]||"#94a3b8"}}>{val}%</span>
          <div className="w-full rounded-t transition-all duration-500"
            style={{height:`${(val/max)*100}%`,minHeight:"4px",background:colors[proto]||"#94a3b8",boxShadow:`0 0 8px ${colors[proto]||"#94a3b8"}88`}}/>
          <span className="text-[9px] font-mono text-slate-500">{proto}</span>
        </div>
      ))}
    </div>
  );
}

// ══════════════════════════════════════════════════════════════
// PIE CHART (canvas) — traffic type
// ══════════════════════════════════════════════════════════════
function PieChart({data}:{data:{label:string;value:number;color:string}[]}) {
  const canvasRef=useRef<HTMLCanvasElement>(null);
  useEffect(()=>{
    const c=canvasRef.current; if(!c) return;
    const ctx=c.getContext("2d"); if(!ctx) return;
    c.width=c.offsetWidth; c.height=c.offsetHeight;
    const cx=c.width/2,cy=c.height/2,r=Math.min(cx,cy)-10;
    const total=data.reduce((s,d)=>s+d.value,0)||1;
    let angle=-Math.PI/2;
    data.forEach(({value,color})=>{
      const slice=(value/total)*Math.PI*2;
      ctx.beginPath(); ctx.moveTo(cx,cy);
      ctx.arc(cx,cy,r,angle,angle+slice);
      ctx.closePath(); ctx.fillStyle=color;
      ctx.shadowBlur=6; ctx.shadowColor=color; ctx.fill(); ctx.shadowBlur=0;
      ctx.beginPath(); ctx.moveTo(cx,cy);
      ctx.arc(cx,cy,r,angle,angle+slice);
      ctx.closePath(); ctx.strokeStyle="#030712"; ctx.lineWidth=2; ctx.stroke();
      angle+=slice;
    });
    ctx.beginPath(); ctx.arc(cx,cy,r*0.55,0,Math.PI*2);
    ctx.fillStyle="#0a0f1e"; ctx.fill();
  },[data]);
  return <canvas ref={canvasRef} className="w-full h-full"/>;
}

// ══════════════════════════════════════════════════════════════
// CONNECTIONS TABLE
// ══════════════════════════════════════════════════════════════
function ConnectionsTable({connections,onBlockIp}:{connections:Connection[];onBlockIp:(ip:string)=>void}) {
  const [search,setSearch]   = useState("");
  const [sortCol,setSortCol] = useState<keyof Connection>("id");
  const [sortAsc,setSortAsc] = useState(true);
  const [page,setPage]       = useState(0);
  const PER=8;

  const filtered=connections.filter(c=>
    !search||c.srcIp.includes(search)||c.dstIp.includes(search)||c.protocol.toLowerCase().includes(search.toLowerCase())
  );
  const sorted=[...filtered].sort((a,b)=>{
    const av=a[sortCol],bv=b[sortCol];
    if(typeof av==="number"&&typeof bv==="number") return sortAsc?av-bv:bv-av;
    return sortAsc?String(av).localeCompare(String(bv)):String(bv).localeCompare(String(av));
  });
  const paged=sorted.slice(page*PER,(page+1)*PER);
  const totalPages=Math.ceil(sorted.length/PER);
  const sort=(col:keyof Connection)=>{if(sortCol===col)setSortAsc(!sortAsc);else{setSortCol(col);setSortAsc(true);}};

  const statusStyle=(s:ConnStatus)=>{
    if(s==="Suspicious") return {color:"#ffbe0b",background:"rgba(255,190,11,0.1)",border:"1px solid rgba(255,190,11,0.3)"};
    if(s==="Blocked")    return {color:"#94a3b8",background:"rgba(148,163,184,0.08)",border:"1px solid rgba(148,163,184,0.2)"};
    return                      {color:"#00ff9f",background:"rgba(0,255,159,0.08)",border:"1px solid rgba(0,255,159,0.2)"};
  };

  return (
    <div className="p-5 rounded" style={{background:"rgba(10,15,30,0.95)",border:"1px solid rgba(0,212,255,0.12)"}}>
      <SH icon={Globe} title="Active Connections" sub={`${filtered.length} connections`}>
        <div className="flex items-center gap-2">
          <div className="relative">
            <Search size={11} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500"/>
            <input value={search} onChange={e=>{setSearch(e.target.value);setPage(0);}}
              placeholder="Filter by IP or protocol..."
              className="pl-8 pr-3 py-1.5 text-[11px] font-mono rounded outline-none w-52"
              style={{background:"rgba(0,212,255,0.04)",border:"1px solid rgba(0,212,255,0.15)",color:"#cbd5e1"}}/>
          </div>
          <Filter size={12} className="text-slate-500"/>
        </div>
      </SH>
      <div className="overflow-x-auto">
        <table className="w-full text-[11px] font-mono">
          <thead>
            <tr style={{borderBottom:"1px solid rgba(0,212,255,0.1)"}}>
              {([["srcIp","Source IP"],["dstIp","Dest IP"],["protocol","Protocol"],["port","Port"],["status","Status"],["data","Data"],["duration","Duration"]] as [keyof Connection,string][]).map(([col,label])=>(
                <th key={col} onClick={()=>sort(col)}
                  className="text-left py-2 px-2 text-slate-500 tracking-wider cursor-pointer hover:text-cyan-400 transition-colors whitespace-nowrap">
                  <span className="flex items-center gap-1">{label}
                    {sortCol===col?(sortAsc?<ChevronUp size={10}/>:<ChevronDown size={10}/>):null}
                  </span>
                </th>
              ))}
              <th className="text-left py-2 px-2 text-slate-500">Action</th>
            </tr>
          </thead>
          <tbody>
            {paged.map(conn=>(
              <tr key={conn.id} className="border-b transition-colors hover:bg-white/[0.02]"
                style={{borderColor:"rgba(0,212,255,0.05)",
                  background:conn.status==="Suspicious"?"rgba(255,190,11,0.04)":conn.status==="Blocked"?"rgba(148,163,184,0.03)":"transparent"}}>
                <td className="py-2 px-2 text-slate-300">{conn.srcIp}</td>
                <td className="py-2 px-2 text-slate-400">{conn.dstIp}</td>
                <td className="py-2 px-2 text-cyan-400">{conn.protocol}</td>
                <td className="py-2 px-2 text-slate-400">{conn.port}</td>
                <td className="py-2 px-2">
                  <span className="px-2 py-0.5 rounded-full text-[9px]" style={statusStyle(conn.status)}>{conn.status}</span>
                </td>
                <td className="py-2 px-2 text-slate-400">{conn.data}</td>
                <td className="py-2 px-2 text-slate-500">{conn.duration}</td>
                <td className="py-2 px-2">
                  <div className="flex items-center gap-1">
                    <button onClick={()=>onBlockIp(conn.srcIp)}
                      className="px-2 py-0.5 rounded text-[9px] font-mono text-red-400 hover:bg-red-400/10 transition-colors"
                      style={{border:"1px solid rgba(255,0,110,0.2)"}}>Block</button>
                    <button className="px-2 py-0.5 rounded text-[9px] font-mono text-green-400 hover:bg-green-400/10 transition-colors"
                      style={{border:"1px solid rgba(0,255,159,0.2)"}}>Allow</button>
                    <button className="px-2 py-0.5 rounded text-[9px] font-mono text-cyan-400 hover:bg-cyan-400/10 transition-colors"
                      style={{border:"1px solid rgba(0,212,255,0.2)"}}>Inspect</button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="flex items-center justify-between mt-3">
        <span className="text-[10px] font-mono text-slate-600">
          Showing {page*PER+1}–{Math.min((page+1)*PER,sorted.length)} of {sorted.length}
        </span>
        <div className="flex items-center gap-1">
          <button onClick={()=>setPage(p=>Math.max(0,p-1))} disabled={page===0}
            className="p-1 rounded text-slate-500 hover:text-cyan-400 disabled:opacity-30"><ChevronLeft size={14}/></button>
          {Array.from({length:Math.min(totalPages,5)},(_,i)=>(
            <button key={i} onClick={()=>setPage(i)} className="w-6 h-6 rounded text-[10px] font-mono transition-colors"
              style={{background:page===i?"rgba(0,212,255,0.15)":"transparent",color:page===i?"#00d4ff":"#64748b"}}>{i+1}</button>
          ))}
          <button onClick={()=>setPage(p=>Math.min(totalPages-1,p+1))} disabled={page>=totalPages-1}
            className="p-1 rounded text-slate-500 hover:text-cyan-400 disabled:opacity-30"><ChevronRight size={14}/></button>
        </div>
      </div>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════
// ALERT PANEL
// ══════════════════════════════════════════════════════════════
function AlertPanel({alerts,onBlockIp,onClearAlerts}:{alerts:Alert[];onBlockIp:(ip:string)=>void;onClearAlerts:()=>void}) {
  const sevColor:Record<string,string>={Info:"#94a3b8",Low:"#00ff9f",Medium:"#ffbe0b",High:"#f97316",Critical:"#ff006e"};
  const sevBg:Record<string,string>   ={Info:"rgba(148,163,184,0.06)",Low:"rgba(0,255,159,0.06)",Medium:"rgba(255,190,11,0.06)",High:"rgba(249,115,22,0.06)",Critical:"rgba(255,0,110,0.06)"};
  return (
    <div className="p-5 rounded" style={{background:"rgba(10,15,30,0.95)",border:"1px solid rgba(0,212,255,0.12)"}}>
      <SH icon={Bell} title="Alerts & Detections" sub={`${alerts.length} active`}>
        <button onClick={onClearAlerts}
          className="flex items-center gap-1 px-2 py-1 rounded text-[10px] font-mono text-slate-400 hover:text-red-400 transition-colors"
          style={{border:"1px solid rgba(100,116,139,0.3)"}}>
          <Trash2 size={10}/>Clear
        </button>
      </SH>
      <div className="space-y-3 max-h-96 overflow-y-auto pr-1">
        {alerts.length===0&&(
          <div className="text-center py-8 text-[11px] font-mono text-slate-600">No active alerts</div>
        )}
        {alerts.map(alert=>(
          <div key={alert.id} className="p-3 rounded relative overflow-hidden"
            style={{
              background:sevBg[alert.severity]||sevBg.Info,
              border:`1px solid ${sevColor[alert.severity]||"#94a3b8"}30`,
              boxShadow:alert.glowing?`0 0 16px ${sevColor[alert.severity]}30`:"none",
              animation:alert.glowing?"criticalPulse 2s ease-in-out infinite":"none",
            }}>
            <div className="flex items-start justify-between gap-2 mb-2">
              <div className="flex items-center gap-2">
                <AlertTriangle size={12} style={{color:sevColor[alert.severity]||"#94a3b8"}}/>
                <span className="text-[11px] font-mono font-semibold text-slate-200">{alert.type}</span>
              </div>
              <span className="text-[9px] font-mono px-2 py-0.5 rounded-full shrink-0"
                style={{background:`${sevColor[alert.severity]||"#94a3b8"}15`,color:sevColor[alert.severity]||"#94a3b8",border:`1px solid ${sevColor[alert.severity]||"#94a3b8"}40`}}>
                {alert.severity}
              </span>
            </div>
            <div className="text-[10px] font-mono text-slate-500 mb-1">{alert.desc}</div>
            <div className="flex items-center gap-3 text-[9px] font-mono text-slate-600 mb-2">
              <span>🕐 {alert.time}</span><span>📍 {alert.srcIp}</span>
            </div>
            <div className="flex items-center gap-2">
              <button onClick={()=>onBlockIp(alert.srcIp)}
                className="px-2 py-1 rounded text-[9px] font-mono text-red-400 hover:bg-red-400/10 transition-colors"
                style={{border:"1px solid rgba(255,0,110,0.25)"}}>
                <Ban size={9} className="inline mr-1"/>Block IP
              </button>
              <button className="px-2 py-1 rounded text-[9px] font-mono text-yellow-400 hover:bg-yellow-400/10 transition-colors"
                style={{border:"1px solid rgba(255,190,11,0.25)"}}>
                <Plus size={9} className="inline mr-1"/>Watchlist
              </button>
              <button className="px-2 py-1 rounded text-[9px] font-mono text-cyan-400 hover:bg-cyan-400/10 transition-colors"
                style={{border:"1px solid rgba(0,212,255,0.25)"}}>
                <Eye size={9} className="inline mr-1"/>Details
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════
// CONTROL PANEL
// ══════════════════════════════════════════════════════════════
function ControlPanel({onBlockAll,onClearLogs}:{onBlockAll:()=>void;onClearLogs:()=>void}) {
  const [toggles,setToggles]=useState({autoBlock:true,ddos:true,portScan:true,firewall:false,deepInspect:true});
  const [sensitivity,setSensitivity]=useState("High");
  const [inspectMode,setInspectMode]=useState("Hybrid");
  const [modal,setModal]=useState<{msg:string;cb:()=>void}|null>(null);

  const toggle=(k:keyof typeof toggles)=>setToggles(t=>({...t,[k]:!t[k]}));
  const Toggle=({k,label}:{k:keyof typeof toggles;label:string})=>(
    <div className="flex items-center justify-between py-2.5 border-b" style={{borderColor:"rgba(0,212,255,0.08)"}}>
      <span className="text-[11px] font-mono text-slate-300">{label}</span>
      <button onClick={()=>toggle(k)}>
        {toggles[k]
          ?<div className="flex items-center gap-1 text-green-400"><ToggleRight size={22}/><span className="text-[10px]">ON</span></div>
          :<div className="flex items-center gap-1 text-slate-600"><ToggleLeft size={22}/><span className="text-[10px]">OFF</span></div>}
      </button>
    </div>
  );
  const ask=(msg:string,cb:()=>void)=>setModal({msg,cb});

  return (
    <>
      {modal&&(
        <div className="fixed inset-0 z-50 flex items-center justify-center" style={{background:"rgba(0,0,0,0.7)"}}>
          <div className="p-6 rounded max-w-sm w-full mx-4" style={{background:"rgba(10,15,30,0.98)",border:"1px solid rgba(255,0,110,0.4)"}}>
            <AlertTriangle size={24} className="text-red-400 mb-3"/>
            <div className="text-sm font-mono text-slate-200 mb-2 font-bold">Confirm Action</div>
            <div className="text-[11px] font-mono text-slate-400 mb-4">{modal.msg}</div>
            <div className="flex gap-3">
              <button onClick={()=>setModal(null)} className="flex-1 py-2 rounded text-[11px] font-mono text-slate-400" style={{border:"1px solid rgba(100,116,139,0.3)"}}>Cancel</button>
              <button onClick={()=>{modal.cb();setModal(null);}} className="flex-1 py-2 rounded text-[11px] font-mono text-red-400 hover:bg-red-400/10" style={{border:"1px solid rgba(255,0,110,0.4)"}}>Confirm</button>
            </div>
          </div>
        </div>
      )}
      <div className="p-5 rounded" style={{background:"rgba(10,15,30,0.95)",border:"1px solid rgba(0,212,255,0.12)"}}>
        <SH icon={Settings} title="Prevention Controls" sub="Admin panel"/>
        <Toggle k="autoBlock"   label="Auto IP Blocking"/>
        <Toggle k="ddos"        label="DDoS Protection"/>
        <Toggle k="portScan"    label="Port Scan Detection"/>
        <Toggle k="firewall"    label="Firewall Integration"/>
        <Toggle k="deepInspect" label="Real-time Packet Inspection"/>
        <div className="mt-4 space-y-3">
          <div>
            <label className="text-[10px] font-mono text-slate-500 uppercase tracking-wider block mb-1">Sensitivity Level</label>
            <select value={sensitivity} onChange={e=>setSensitivity(e.target.value)}
              className="w-full px-3 py-2 rounded text-[11px] font-mono outline-none"
              style={{background:"rgba(0,212,255,0.04)",border:"1px solid rgba(0,212,255,0.15)",color:"#00d4ff"}}>
              {["Low","Medium","High"].map(v=><option key={v} style={{background:"#0a0f1e"}}>{v}</option>)}
            </select>
          </div>
          <div>
            <label className="text-[10px] font-mono text-slate-500 uppercase tracking-wider block mb-1">Inspection Mode</label>
            <select value={inspectMode} onChange={e=>setInspectMode(e.target.value)}
              className="w-full px-3 py-2 rounded text-[11px] font-mono outline-none"
              style={{background:"rgba(0,212,255,0.04)",border:"1px solid rgba(0,212,255,0.15)",color:"#00d4ff"}}>
              {["Signature-based","Anomaly-based","Hybrid"].map(v=><option key={v} style={{background:"#0a0f1e"}}>{v}</option>)}
            </select>
          </div>
        </div>
        <div className="mt-4 space-y-2">
          <button onClick={()=>ask("Block ALL suspicious IPs? This cannot be undone.",onBlockAll)}
            className="w-full py-2 rounded text-[11px] font-mono text-red-400 hover:bg-red-400/10 transition-colors"
            style={{border:"1px solid rgba(255,0,110,0.3)"}}>
            <Ban size={11} className="inline mr-2"/>Block All Suspicious IPs
          </button>
          <button onClick={()=>ask("Clear all event logs?",onClearLogs)}
            className="w-full py-2 rounded text-[11px] font-mono text-yellow-400 hover:bg-yellow-400/10 transition-colors"
            style={{border:"1px solid rgba(255,190,11,0.3)"}}>
            <Trash2 size={11} className="inline mr-2"/>Clear Logs
          </button>
          <button onClick={()=>ask("Reset monitoring engine?",()=>{})}
            className="w-full py-2 rounded text-[11px] font-mono text-slate-400 hover:bg-slate-400/10 transition-colors"
            style={{border:"1px solid rgba(100,116,139,0.3)"}}>
            <RotateCcw size={11} className="inline mr-2"/>Reset Monitoring
          </button>
        </div>
      </div>
    </>
  );
}

// ══════════════════════════════════════════════════════════════
// TERMINAL LOG  — scroll bug fixed (scrollTop only, no scrollIntoView)
// ══════════════════════════════════════════════════════════════
function TerminalLog({logs,onDownload,onClear}:{logs:LogEntry[];onDownload:()=>void;onClear:()=>void}) {
  const scrollRef=useRef<HTMLDivElement>(null);
  useEffect(()=>{
    const el=scrollRef.current; if(!el) return;
    const near=el.scrollHeight-el.scrollTop-el.clientHeight<80;
    if(near) el.scrollTop=el.scrollHeight;   // ✅ container only, never page
  },[logs]);

  const statusColor:Record<string,string>={SUCCESS:"#00ff9f",WARNING:"#ffbe0b",CRITICAL:"#ff006e",INFO:"#00d4ff"};
  return (
    <div className="p-5 rounded" style={{background:"rgba(10,15,30,0.95)",border:"1px solid rgba(0,212,255,0.12)"}}>
      <SH icon={Terminal} title="System Event Log" sub="Live SOC console">
        <div className="flex gap-2">
          <button onClick={onDownload}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded text-[10px] font-mono text-green-400 hover:bg-green-400/10 transition-colors"
            style={{border:"1px solid rgba(0,255,159,0.25)"}}>
            <Download size={11}/>Download
          </button>
          <button onClick={onClear}
            className="flex items-center gap-1.5 px-2 py-1.5 rounded text-[10px] font-mono text-slate-400 hover:text-red-400 transition-colors"
            style={{border:"1px solid rgba(100,116,139,0.25)"}}>
            <Trash2 size={11}/>
          </button>
        </div>
      </SH>
      <div className="rounded overflow-hidden" style={{background:"#020408",border:"1px solid rgba(0,212,255,0.08)"}}>
        <div className="flex items-center gap-2 px-3 py-2 border-b" style={{borderColor:"rgba(0,212,255,0.08)"}}>
          <div className="w-2.5 h-2.5 rounded-full bg-red-500"/>
          <div className="w-2.5 h-2.5 rounded-full bg-yellow-500"/>
          <div className="w-2.5 h-2.5 rounded-full bg-green-500"/>
          <span className="text-[10px] font-mono text-slate-600 ml-2">idps-console — root@noc</span>
        </div>
        <div ref={scrollRef} className="p-3 h-56 overflow-y-auto space-y-0.5"
          style={{fontFamily:"'JetBrains Mono',monospace"}}>
          {logs.map((log,i)=>(
            <div key={i} className="text-[10px] flex items-start gap-2">
              <span className="text-slate-600 shrink-0">[{log.time}]</span>
              <span className="text-cyan-500 shrink-0 w-20">{log.event}</span>
              <span className="text-slate-400 shrink-0">ip:{log.ip}</span>
              <span className="text-slate-500 shrink-0">→{log.action}</span>
              <span className="shrink-0 font-bold" style={{color:statusColor[log.status]||"#94a3b8"}}>[{log.status}]</span>
              {log.detail&&<span className="text-slate-700 truncate">{log.detail}</span>}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════
// SYSTEM HEALTH
// ══════════════════════════════════════════════════════════════
function CircularGauge({value,label,unit="%"}:{value:number;label:string;unit?:string}) {
  const color=value>80?"#ff006e":value>60?"#ffbe0b":"#00ff9f";
  const r=28,circ=2*Math.PI*r,dash=circ*(Math.min(value,100)/100);
  return (
    <div className="flex flex-col items-center gap-2">
      <div className="relative w-20 h-20">
        <svg className="w-full h-full -rotate-90" viewBox="0 0 72 72">
          <circle cx="36" cy="36" r={r} fill="none" stroke="rgba(0,212,255,0.08)" strokeWidth="6"/>
          <circle cx="36" cy="36" r={r} fill="none" stroke={color} strokeWidth="6"
            strokeDasharray={`${dash} ${circ}`} strokeLinecap="round"
            style={{filter:`drop-shadow(0 0 4px ${color})`,transition:"stroke-dasharray 0.5s ease"}}/>
        </svg>
        <div className="absolute inset-0 flex items-center justify-center">
          <span className="text-sm font-bold font-mono" style={{color}}>{value}{unit}</span>
        </div>
      </div>
      <span className="text-[10px] font-mono text-slate-500 text-center">{label}</span>
    </div>
  );
}

function SystemHealth({health}:{health:Health}) {
  const services=[
    {name:"Network Adapter",  status:"ONLINE",  ok:true},
    {name:"IDS Engine",       status:"ACTIVE",  ok:true},
    {name:"Firewall",         status:"ACTIVE",  ok:true},
    {name:"Packet Inspector", status:"RUNNING", ok:true},
  ];
  return (
    <div className="p-5 rounded" style={{background:"rgba(10,15,30,0.95)",border:"1px solid rgba(0,212,255,0.12)"}}>
      <SH icon={Cpu} title="System Health" sub="Real-time metrics"/>
      <div className="grid grid-cols-4 gap-2 mb-5">
        <CircularGauge value={health.cpu}      label="CPU Usage"/>
        <CircularGauge value={health.mem}      label="Memory"/>
        <CircularGauge value={health.pkt_loss} label="Pkt Loss"/>
        <CircularGauge value={Math.min(100,health.latency)} label={`${health.latency}ms`} unit=""/>
      </div>
      <div className="space-y-2">
        {services.map(({name,status,ok})=>(
          <div key={name} className="flex items-center justify-between py-1.5 border-b" style={{borderColor:"rgba(0,212,255,0.06)"}}>
            <div className="flex items-center gap-2">
              <Server size={11} className="text-slate-500"/>
              <span className="text-[11px] font-mono text-slate-400">{name}</span>
            </div>
            <div className="flex items-center gap-1.5">
              <div className="w-1.5 h-1.5 rounded-full animate-pulse"
                style={{background:ok?"#00ff9f":"#ff006e",boxShadow:`0 0 4px ${ok?"#00ff9f":"#ff006e"}`}}/>
              <span className="text-[10px] font-mono" style={{color:ok?"#00ff9f":"#ff006e"}}>{status}</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════
// TOAST
// ══════════════════════════════════════════════════════════════
function Toast({msg,type,onClose}:{msg:string;type:"success"|"error";onClose:()=>void}) {
  useEffect(()=>{const t=setTimeout(onClose,3000);return()=>clearTimeout(t);},[]);
  return (
    <div className="fixed top-20 right-4 z-50 px-4 py-3 rounded flex items-center gap-2 text-[11px] font-mono shadow-lg"
      style={{background:type==="success"?"rgba(0,255,159,0.15)":"rgba(255,0,110,0.15)",
        border:`1px solid ${type==="success"?"rgba(0,255,159,0.4)":"rgba(255,0,110,0.4)"}`,
        color:type==="success"?"#00ff9f":"#ff006e"}}>
      <CheckCircle size={13}/>{msg}
    </div>
  );
}

// ══════════════════════════════════════════════════════════════
// MAIN PAGE
// ══════════════════════════════════════════════════════════════

// Default empty state shown before first WS message
const DEFAULT_STATS:Stats={total_packets:0,pps:0,bandwidth:0,upload:0,download:0,active_connections:0,threats_detected:0,threats_blocked:0};
const DEFAULT_HEALTH:Health={cpu:0,mem:0,pkt_loss:0,latency:0};


// ══════════════════════════════════════════════════════════════
// WIRESHARK-STYLE LIVE PACKET TABLE
// ══════════════════════════════════════════════════════════════
interface Packet {
  id: number; src_ip: string; dst_ip: string; protocol: string;
  port: number; length: number; status: string; flagged: boolean; timestamp: string;
}

const PROTO_COLORS: Record<string, { bg: string; color: string }> = {
  HTTPS:    { bg: "rgba(167,139,250,0.15)", color: "#a78bfa" },
  HTTP:     { bg: "rgba(249,115,22,0.15)",  color: "#f97316" },
  DNS:      { bg: "rgba(255,190,11,0.15)",  color: "#ffbe0b" },
  TCP:      { bg: "rgba(0,212,255,0.15)",   color: "#00d4ff" },
  UDP:      { bg: "rgba(0,255,159,0.15)",   color: "#00ff9f" },
  SSH:      { bg: "rgba(255,0,110,0.15)",   color: "#ff006e" },
  ICMP:     { bg: "rgba(148,163,184,0.15)", color: "#94a3b8" },
  MySQL:    { bg: "rgba(255,126,0,0.15)",   color: "#ff7e00" },
  OTHER:    { bg: "rgba(100,116,139,0.12)", color: "#64748b" },
};

function getProtoStyle(proto: string, flagged: boolean) {
  if (flagged) return { bg: "rgba(255,0,110,0.18)", color: "#ff006e" };
  return PROTO_COLORS[proto] || PROTO_COLORS.OTHER;
}

function getInfo(pkt: Packet): string {
  const port = pkt.port;
  if (pkt.flagged)           return `⚠ FLAGGED — ${pkt.status} on port ${port}`;
  if (pkt.protocol === "DNS")    return `DNS query on port ${port}`;
  if (pkt.protocol === "HTTPS")  return `TLS encrypted — port ${port}`;
  if (pkt.protocol === "HTTP")   return `HTTP request — port ${port}`;
  if (pkt.protocol === "SSH")    return `SSH session — port ${port}`;
  if (pkt.protocol === "TCP")    return `TCP segment — port ${port}`;
  if (pkt.protocol === "UDP")    return `UDP datagram — port ${port}`;
  return `${pkt.protocol} — port ${port}`;
}

function PacketTable() {
  const [packets, setPackets]       = useState<Packet[]>([]);
  const [paused, setPaused]         = useState(false);
  const [protoF, setProtoF]         = useState("All");
  const [search, setSearch]         = useState("");
  const [selected, setSelected]     = useState<Packet | null>(null);
  const [loading, setLoading]       = useState(true);
  const tableRef                    = useRef<HTMLDivElement>(null);
  const pausedRef                   = useRef(false);
  const MAX_ROWS                    = 200;

  // Initial load from DB
  useEffect(() => {
    fetch("https://fyp-backend-production-944f.up.railway.app/api/network/packets?limit=50")
      .then(r => r.json())
      .then(d => {
        if (d?.packets) setPackets(d.packets);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, []);

  // Poll for new packets every 3 seconds
  useEffect(() => {
    const interval = setInterval(async () => {
      if (pausedRef.current) return;
      try {
        const res  = await fetch("https://fyp-backend-production-944f.up.railway.app/api/network/packets?limit=10");
        const data = await res.json();
        if (!data?.packets?.length) return;
        setPackets(prev => {
          const existingIds = new Set(prev.map(p => p.id));
          const newPkts = data.packets.filter((p: Packet) => !existingIds.has(p.id));
          if (!newPkts.length) return prev;
          const merged = [...newPkts, ...prev].slice(0, MAX_ROWS);
          return merged;
        });
        // Auto-scroll to top ONLY if user is already at top
        if (tableRef.current && !pausedRef.current) {
          if (tableRef.current.scrollTop < 100) {
            tableRef.current.scrollTop = 0;
          }
        }
      } catch {}
    }, 3000);
    return () => clearInterval(interval);
  }, []);

  const togglePause = () => {
    pausedRef.current = !pausedRef.current;
    setPaused(p => !p);
  };

  const filtered = packets.filter(p => {
    if (protoF !== "All" && p.protocol !== protoF) return false;
    if (search && !p.src_ip.includes(search) && !p.dst_ip.includes(search)) return false;
    return true;
  });

  const protocols = ["All", "HTTPS", "HTTP", "TCP", "UDP", "DNS", "SSH", "ICMP"];

  return (
    <div className="rounded overflow-hidden" style={{ background: "rgba(6,8,18,0.98)", border: "1px solid rgba(0,212,255,0.15)" }}>
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b" style={{ borderColor: "rgba(0,212,255,0.1)", background: "rgba(0,212,255,0.03)" }}>
        <div className="flex items-center gap-2">
          <Activity size={14} className="text-cyan-400" />
          <span className="text-[12px] font-mono font-bold text-slate-200 tracking-wider">LIVE PACKET CAPTURE</span>
          <span className="text-[10px] font-mono text-slate-600 ml-1">Wireshark-style</span>
          <div className={`w-2 h-2 rounded-full ml-2 ${paused ? "bg-yellow-400" : "bg-green-400 animate-pulse"}`} />
          <span className="text-[10px] font-mono" style={{ color: paused ? "#ffbe0b" : "#00ff9f" }}>
            {paused ? "PAUSED" : "LIVE"}
          </span>
        </div>
        <div className="flex items-center gap-2">
          {/* Search */}
          <div className="relative">
            <Search size={10} className="absolute left-2 top-1/2 -translate-y-1/2 text-slate-500" />
            <input value={search} onChange={e => setSearch(e.target.value)}
              placeholder="Filter IP..."
              className="pl-6 pr-2 py-1 rounded text-[10px] font-mono outline-none w-32"
              style={{ background: "rgba(0,212,255,0.05)", border: "1px solid rgba(0,212,255,0.15)", color: "#cbd5e1" }} />
          </div>
          {/* Protocol filter */}
          <select value={protoF} onChange={e => setProtoF(e.target.value)}
            className="px-2 py-1 rounded text-[10px] font-mono outline-none"
            style={{ background: "#0a0f1e", border: "1px solid rgba(0,212,255,0.15)", color: "#00d4ff" }}>
            {protocols.map(p => <option key={p}>{p}</option>)}
          </select>
          {/* Pause/Resume */}
          <button onClick={togglePause}
            className="flex items-center gap-1 px-3 py-1 rounded text-[10px] font-mono transition-colors"
            style={{
              border: `1px solid ${paused ? "rgba(255,190,11,0.4)" : "rgba(0,212,255,0.3)"}`,
              color: paused ? "#ffbe0b" : "#00d4ff",
              background: paused ? "rgba(255,190,11,0.08)" : "rgba(0,212,255,0.06)",
            }}>
            {paused ? "▶ RESUME" : "⏸ PAUSE"}
          </button>
          <span className="text-[10px] font-mono text-slate-600">{filtered.length} packets</span>
        </div>
      </div>

      {/* Column headers */}
      <div className="grid text-[10px] font-mono text-slate-500 px-2 py-1.5 border-b"
        style={{ gridTemplateColumns: "50px 140px 140px 70px 55px 65px 1fr", borderColor: "rgba(0,212,255,0.08)", background: "rgba(0,0,0,0.3)" }}>
        <span>No.</span>
        <span>Source IP</span>
        <span>Destination IP</span>
        <span>Protocol</span>
        <span>Port</span>
        <span>Length</span>
        <span>Info</span>
      </div>

      {/* Packet rows */}
      <div ref={tableRef} className="overflow-y-auto" style={{ height: "380px" }}>
        {loading ? (
          <div className="flex items-center justify-center h-full text-[11px] font-mono text-slate-600">
            Loading packets...
          </div>
        ) : filtered.length === 0 ? (
          <div className="flex items-center justify-center h-full text-[11px] font-mono text-slate-600">
            No packets captured yet
          </div>
        ) : (
          filtered.map((pkt, idx) => {
            const style = getProtoStyle(pkt.protocol, pkt.flagged);
            const isSelected = selected?.id === pkt.id;
            return (
              <div key={pkt.id}
                onClick={() => setSelected(isSelected ? null : pkt)}
                className="grid items-center px-2 py-0.5 cursor-pointer border-b text-[10px] font-mono transition-colors"
                style={{
                  gridTemplateColumns: "50px 140px 140px 70px 55px 65px 1fr",
                  borderColor: "rgba(0,212,255,0.04)",
                  background: isSelected ? "rgba(0,212,255,0.12)" : pkt.flagged ? "rgba(255,0,110,0.06)" : idx % 2 === 0 ? "rgba(0,0,0,0.2)" : "transparent",
                }}>
                <span className="text-slate-600">{pkt.id}</span>
                <span className="text-cyan-300 truncate">{pkt.src_ip}</span>
                <span className="text-slate-300 truncate">{pkt.dst_ip}</span>
                <span>
                  <span className="px-1.5 py-0.5 rounded text-[9px] font-bold"
                    style={{ background: style.bg, color: style.color }}>
                    {pkt.protocol}
                  </span>
                </span>
                <span className="text-slate-400">{pkt.port}</span>
                <span className="text-slate-500">{pkt.length} B</span>
                <span className="text-slate-400 truncate">{getInfo(pkt)}</span>
              </div>
            );
          })
        )}
      </div>

      {/* Packet detail panel */}
      {selected && (
        <div className="border-t px-4 py-3" style={{ borderColor: "rgba(0,212,255,0.15)", background: "rgba(0,212,255,0.03)" }}>
          <div className="text-[10px] font-mono text-cyan-400 mb-2 font-bold">PACKET DETAILS — #{selected.id}</div>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            {[
              { label: "Source IP",    value: selected.src_ip },
              { label: "Destination", value: selected.dst_ip },
              { label: "Protocol",    value: selected.protocol },
              { label: "Port",        value: String(selected.port) },
              { label: "Length",      value: `${selected.length} bytes` },
              { label: "Status",      value: selected.status },
              { label: "Flagged",     value: selected.flagged ? "⚠ YES" : "No" },
              { label: "Timestamp",   value: selected.timestamp },
            ].map(({ label, value }) => (
              <div key={label} className="p-2 rounded" style={{ background: "rgba(0,0,0,0.3)", border: "1px solid rgba(0,212,255,0.08)" }}>
                <div className="text-[9px] text-slate-600 uppercase tracking-wider mb-0.5">{label}</div>
                <div className="text-[10px] font-mono text-slate-200" style={{ color: label === "Flagged" && selected.flagged ? "#ff006e" : undefined }}>
                  {value}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Footer stats */}
      <div className="flex items-center gap-4 px-4 py-2 border-t text-[10px] font-mono text-slate-600"
        style={{ borderColor: "rgba(0,212,255,0.08)", background: "rgba(0,0,0,0.3)" }}>
        <span>Showing {filtered.length} of {packets.length} captured</span>
        <span className="text-red-400">{packets.filter(p => p.flagged).length} flagged</span>
        {Object.entries(
          packets.reduce((acc, p) => ({ ...acc, [p.protocol]: (acc[p.protocol] || 0) + 1 }), {} as Record<string, number>)
        ).slice(0, 4).map(([proto, count]) => (
          <span key={proto} style={{ color: PROTO_COLORS[proto]?.color || "#64748b" }}>{proto}: {count}</span>
        ))}
      </div>
    </div>
  );
}

export default function NetworkMonitoringPage() {
  const [wsConnected,setWsConnected] = useState(false);
  const [toast,setToast]             = useState<{msg:string;type:"success"|"error"}|null>(null);

  // Data from backend
  const [stats,setStats]           = useState<Stats>(DEFAULT_STATS);
  const [health,setHealth]         = useState<Health>(DEFAULT_HEALTH);
  const [protoData,setProtoData]   = useState<Record<string,number>>({TCP:45,UDP:22,ICMP:8,HTTP:12,HTTPS:13});
  const [trafficType,setTrafficType] = useState([
    {label:"Internal",value:42,color:"#00d4ff"},
    {label:"External",value:33,color:"#00ff9f"},
    {label:"Suspicious",value:15,color:"#ffbe0b"},
    {label:"Blocked",value:10,color:"#ff006e"},
  ]);
  const [ppsHistory,setPpsHistory] = useState<number[]>(Array(60).fill(0));
  const [connections,setConnections] = useState<Connection[]>([]);
  const [alerts,setAlerts]         = useState<Alert[]>([]);
  const [logs,setLogs]             = useState<LogEntry[]>([]);

  // ── WebSocket connection ──────────────────────────────────
  useEffect(()=>{
    let ws:WebSocket;
    let retryTimeout:NodeJS.Timeout;

    const connect=()=>{
      ws=new WebSocket(API_WS);

      ws.onopen=()=>{
        setWsConnected(true);
        console.log("[WS] Connected to backend");
      };

      ws.onmessage=(event)=>{
        try {
          const snap:Snapshot=JSON.parse(event.data);
          setStats(snap.stats);
          setHealth(snap.health);
          setProtoData(snap.proto_dist);
          setPpsHistory(snap.pps_history);
          setConnections(snap.connections);
          setAlerts(snap.alerts);
          setLogs(snap.logs);
          // Rebuild traffic type array from object
          const tt=snap.traffic_type;
          const colors=["#00d4ff","#00ff9f","#ffbe0b","#ff006e"];
          setTrafficType(Object.entries(tt).map(([label,value],i)=>({label,value,color:colors[i]||"#94a3b8"})));
        } catch(e){
          console.error("[WS] Parse error",e);
        }
      };

      ws.onerror=()=>{
        setWsConnected(false);
      };

      ws.onclose=()=>{
        setWsConnected(false);
        console.log("[WS] Disconnected — retrying in 3s");
        retryTimeout=setTimeout(connect,3000);   // auto-reconnect
      };
    };

    connect();
    return ()=>{
      clearTimeout(retryTimeout);
      ws?.close();
    };
  },[]);

  // ── Action handlers (call REST endpoints) ────────────────
  const handleBlockIp=useCallback(async(ip:string)=>{
    try {
      const res=await fetch(`${API_HTTP}/api/network/block-ip`,{
        method:"POST",headers:{"Content-Type":"application/json"},
        body:JSON.stringify({ip}),
      });
      if(res.ok){
        setToast({msg:`IP ${ip} blocked successfully`,type:"success"});
      }
    } catch {
      setToast({msg:"Failed to block IP — backend unreachable",type:"error"});
    }
  },[]);

  const handleClearAlerts=useCallback(async()=>{
    try {
      await fetch(`${API_HTTP}/api/network/clear-alerts`,{method:"POST"});
      setAlerts([]);
      setToast({msg:"All alerts cleared",type:"success"});
    } catch {
      setToast({msg:"Failed to clear alerts",type:"error"});
    }
  },[]);

  const handleClearLogs=useCallback(async()=>{
    try {
      await fetch(`${API_HTTP}/api/network/clear-logs`,{method:"POST"});
      setLogs([]);
      setToast({msg:"Logs cleared",type:"success"});
    } catch {
      setToast({msg:"Failed to clear logs",type:"error"});
    }
  },[]);

  const handleBlockAll=useCallback(async()=>{
    const suspicious=connections.filter(c=>c.status==="Suspicious").map(c=>c.srcIp);
    let count=0;
    for(const ip of suspicious){
      try {
        await fetch(`${API_HTTP}/api/network/block-ip`,{
          method:"POST",headers:{"Content-Type":"application/json"},
          body:JSON.stringify({ip}),
        });
        count++;
      } catch {}
    }
    setToast({msg:`${count} suspicious IPs blocked`,type:"success"});
  },[connections]);

  const handleDownloadLogs=useCallback(()=>{
    const txt=logs.map(l=>`[${l.time}] ${l.event} | IP:${l.ip} | →${l.action} | [${l.status}] ${l.detail}`).join("\n");
    const a=document.createElement("a");
    a.href="data:text/plain;charset=utf-8,"+encodeURIComponent(txt);
    a.download="cyguardian-logs.txt"; a.click();
    setToast({msg:"Logs downloaded",type:"success"});
  },[logs]);

  return (
    <div className="min-h-screen" style={{background:"#030712"}}>
      <div className="fixed inset-0 pointer-events-none" style={{
        backgroundImage:"linear-gradient(rgba(0,212,255,0.018) 1px,transparent 1px),linear-gradient(90deg,rgba(0,212,255,0.018) 1px,transparent 1px)",
        backgroundSize:"40px 40px",
      }}/>
      <style>{`@keyframes criticalPulse{0%,100%{box-shadow:0 0 16px rgba(255,0,110,0.3)}50%{box-shadow:0 0 32px rgba(255,0,110,0.6)}}`}</style>

      {toast&&<Toast msg={toast.msg} type={toast.type} onClose={()=>setToast(null)}/>}

      <Navbar wsConnected={wsConnected}/>

      <main className="relative z-10 max-w-screen-2xl mx-auto px-4 sm:px-6 py-6 space-y-5">

        {/* Page heading */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-xl font-bold text-slate-100 tracking-wider" style={{fontFamily:"'Orbitron',monospace"}}>
              NETWORK MONITORING
            </h1>
            <p className="text-[11px] font-mono text-slate-600 mt-0.5">
              Live traffic analysis · Packet inspection · Threat detection
            </p>
          </div>
          <div className="flex items-center gap-3">
            {!wsConnected&&(
              <div className="flex items-center gap-1.5 px-3 py-1.5 rounded text-[10px] font-mono text-red-400"
                style={{background:"rgba(255,0,110,0.08)",border:"1px solid rgba(255,0,110,0.25)"}}>
                <WifiOff size={11}/>Backend offline — reconnecting...
              </div>
            )}
            <div className="flex items-center gap-1.5 text-[11px] font-mono text-green-400">
              <div className={`w-2 h-2 rounded-full ${wsConnected?"bg-green-400 animate-pulse":"bg-red-400"}`}/>
              {wsConnected?"LIVE MONITORING":"DISCONNECTED"}
            </div>
          </div>
        </div>

        {/* Stat Cards */}
        <StatCards stats={stats}/>

        {/* Charts row */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <div className="lg:col-span-1 p-5 rounded" style={{background:"rgba(10,15,30,0.95)",border:"1px solid rgba(0,212,255,0.12)"}}>
            <SH icon={Activity} title="Traffic Over Time" sub="60s window"/>
            <div className="h-36"><LineChart data={ppsHistory}/></div>
          </div>
          <div className="p-5 rounded" style={{background:"rgba(10,15,30,0.95)",border:"1px solid rgba(0,212,255,0.12)"}}>
            <SH icon={BarChart2} title="Protocol Distribution"/>
            <BarChart protoData={protoData}/>
          </div>
          <div className="p-5 rounded" style={{background:"rgba(10,15,30,0.95)",border:"1px solid rgba(0,212,255,0.12)"}}>
            <SH icon={Filter} title="Traffic Type"/>
            <div className="flex gap-4">
              <div className="h-32 flex-1"><PieChart data={trafficType}/></div>
              <div className="flex flex-col justify-center gap-2">
                {trafficType.map(d=>(
                  <div key={d.label} className="flex items-center gap-1.5 text-[10px] font-mono">
                    <div className="w-2 h-2 rounded-full shrink-0" style={{background:d.color}}/>
                    <span className="text-slate-400">{d.label}</span>
                    <span className="text-slate-600 ml-auto">{d.value}%</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* Connections Table */}
        <ConnectionsTable connections={connections} onBlockIp={handleBlockIp}/>

        {/* Alerts + Controls */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <div className="lg:col-span-2">
            <AlertPanel alerts={alerts} onBlockIp={handleBlockIp} onClearAlerts={handleClearAlerts}/>
          </div>
          <ControlPanel onBlockAll={handleBlockAll} onClearLogs={handleClearLogs}/>
        </div>

        {/* Terminal + Health */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <div className="lg:col-span-2">
            <TerminalLog logs={logs} onDownload={handleDownloadLogs} onClear={handleClearLogs}/>
          </div>
          <SystemHealth health={health}/>
        </div>

        {/* Wireshark Live Packet Table */}
        <PacketTable/>
        {/* Footer */}
        <div className="pt-2 pb-4 flex items-center justify-between text-[10px] font-mono text-slate-700">
          <span>CyGuardian-X v2.4.1 — NETWORK MONITORING MODULE</span>
          <span>ALL TRAFFIC IS MONITORED AND LOGGED</span>
        </div>
      </main>
    </div>
  );
}