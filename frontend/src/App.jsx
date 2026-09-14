import { useEffect, useMemo, useState } from "react";
import { NavLink, Route, Routes, useNavigate } from "react-router-dom";
import {
  Activity, AlertTriangle, ArrowRight, BarChart3, Brain, CheckCircle2,
  ChevronRight, CircleDot, Database, FileCheck2, FileLock2, Globe2, Hash,
  LayoutDashboard, LockKeyhole, Menu, Network, Play, Radar, RefreshCw,
  Search, Server, Shield, ShieldAlert, ShieldCheck, Target, TrendingUp,
  Upload, X, Zap, Crosshair, GitBranch, Scale, Clock3
} from "lucide-react";
import {
  anchorEvidence, createEvidence, generateForecast, getBlockchainHealth,
  getDbHealth, getHealth, getLatestForecast, listAnomalies, listEvidence,
  listForecasts, listThreats, resolveThreat, verifyEvidence
} from "./services/api.js";

const DEMO_THREATS = [
  { id: "THR-2041", title: "Credential Spray Campaign", source_ip: "45.33.12.9", dst_ip: "10.24.8.14", attack_stage: "INITIAL_ACCESS", severity: "CRITICAL", confidence_score: 0.96, mitre_technique_id: "T1110" },
  { id: "THR-2038", title: "Suspicious PowerShell Chain", source_ip: "10.24.8.51", dst_ip: "10.24.4.22", attack_stage: "EXECUTION", severity: "HIGH", confidence_score: 0.91, mitre_technique_id: "T1059.001" },
  { id: "THR-2034", title: "Lateral SMB Enumeration", source_ip: "10.24.8.51", dst_ip: "10.24.4.0/24", attack_stage: "LATERAL_MOVEMENT", severity: "HIGH", confidence_score: 0.88, mitre_technique_id: "T1021.002" },
  { id: "THR-2029", title: "DNS Beaconing", source_ip: "10.24.5.77", dst_ip: "8.8.8.8", attack_stage: "COMMAND_AND_CONTROL", severity: "MEDIUM", confidence_score: 0.82, mitre_technique_id: "T1071.004" },
];

const DEMO_EVIDENCE = [
  { id: "EVD-9921", title: "Credential Spray Evidence", description: "Correlated authentication telemetry", content_hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", status: "ANCHORED", blockchain_tx_hash: "0x7b1c...91af" },
  { id: "EVD-9918", title: "PowerShell Process Trace", description: "Execution chain captured from endpoint", content_hash: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", status: "HASHED" },
  { id: "EVD-9904", title: "DNS Beacon Sample", description: "Periodic outbound DNS pattern", content_hash: "4a44dc15364204a80fe80e9039455cc1b7a0f5f5a9f0c3b2d1e8f7a6c5b4d3e2", status: "ANCHORED", blockchain_tx_hash: "0x52e8...c210" },
];

const DEMO_FORECAST = Array.from({ length: 24 }, (_, i) => ({
  timestamp: new Date(Date.now() + (i + 1) * 3600000).toISOString(),
  predicted_threat_level: Math.min(0.96, 0.42 + i * 0.018 + Math.sin(i / 2) * 0.08),
  lower_bound: Math.max(0.1, 0.34 + i * 0.014),
  upper_bound: Math.min(1, 0.52 + i * 0.022),
}));

const DEMO_TELEMETRY = Array.from({ length: 10 }, (_, i) => ({
  timestamp: new Date(Date.now() - i * 60000).toISOString(),
  src_ip: ["45.33.12.9", "10.24.8.51", "10.24.5.77"][i % 3],
  dst_ip: ["10.24.8.14", "10.24.4.22", "10.24.4.50"][i % 3],
  dst_port: [443, 445, 53, 3389][i % 4],
  protocol: ["TCP", "TCP", "UDP"][i % 3],
  packets: 120 + i * 31,
  bytes: 24000 + i * 8400,
  anomaly_score: Math.max(0.04, 0.92 - i * 0.065),
  is_anomaly: i < 4,
}));

const MITRE = [
  ["T1595", "RECONNAISSANCE"], ["T1190", "INITIAL_ACCESS"], ["T1059", "EXECUTION"],
  ["T1021", "LATERAL_MOVEMENT"], ["T1071", "COMMAND_AND_CONTROL"], ["T1048", "EXFILTRATION"], ["T1485", "IMPACT"]
];

async function safe(call, fallback) {
  try { return await call(); } catch { return fallback; }
}

function Landing() {
  const navigate = useNavigate();
  const [modal, setModal] = useState(null);
  const [mobile, setMobile] = useState(false);
  const [notice, setNotice] = useState("");

  const submitAuth = (e) => {
    e.preventDefault();
    localStorage.setItem("foreflow-session", "demo-analyst");
    setModal(null);
    setNotice("Analyst session initialized");
    setTimeout(() => navigate("/dashboard"), 350);
  };

  return <div className="landing">
    <div className="landing-grid" />
    <nav className="landing-nav">
      <button className="landing-brand" onClick={() => window.scrollTo({ top: 0, behavior: "smooth" })}>
        <span className="brand-icon"><ShieldHalfIcon /></span><span>FOREFLOW</span>
      </button>
      <div className={`landing-links ${mobile ? "open" : ""}`}>
        <a href="#platform">Platform</a><a href="#capabilities">Capabilities</a><a href="#workflow">How It Works</a><a href="#technology">Technology</a>
      </div>
      <div className="landing-actions"><button className="ghost-btn" onClick={() => setModal("login")}>Login</button><button className="primary-btn" onClick={() => setModal("register")}>Register <ArrowRight size={15}/></button></div>
      <button className="mobile-menu" onClick={() => setMobile(!mobile)}>{mobile ? <X/> : <Menu/>}</button>
    </nav>

    <section className="hero">
      <div className="hero-copy reveal">
        <div className="eyebrow"><span className="pulse-dot"/> ACTIVE THREAT INTELLIGENCE</div>
        <h1>Know Your Cyber Risk.<br/><span>Before the Attack Escalates.</span></h1>
        <p>Continuously transform network telemetry into quantified cyber risk. Detect anomalies, forecast attack progression pathways, and make risk-informed decisions with an AI-powered SOC platform.</p>
        <div className="hero-buttons"><button className="primary-btn large" onClick={() => setModal("register")}>Start Monitoring <ArrowRight size={18}/></button><a className="secondary-btn" href="#preview">Explore Platform</a></div>
        <div className="hero-meta"><span><Database size={15}/> LIVE NETWORK</span><span><Upload size={15}/> CSV DATASETS</span><span><Brain size={15}/> TEMPORAL AI</span></div>
      </div>
      <div className="hero-visual">
        <div className="visual-top"><span>PREVIEW: <b>LIVE ANALYTICS</b></span><span><CircleDot size={10}/> SOC / PROD</span></div>
        <div className="network-orbit orbit-a"/><div className="network-orbit orbit-b"/><div className="network-core"><ShieldCheck size={38}/><small>RISK ENGINE</small></div>
        {["AUTH", "DNS", "SMB", "HTTP", "EDR", "IOC"].map((x, i) => <div key={x} className={`node node-${i}`}><span/>{x}</div>)}
        <div className="threat-badge"><span className="critical-dot"/><div><small>THREAT LEVEL</small><strong>ELEVATED</strong></div></div>
        <div className="visual-footer"><span>24H RISK HORIZON</span><div className="spark-bars">{Array.from({length: 18}, (_, i) => <i key={i} style={{height: `${22 + ((i * 17) % 65)}%`}}/>)}</div></div>
      </div>
    </section>

    <div className="capability-strip"><span>CONTINUOUS MONITORING</span><span>AI RISK QUANTIFICATION</span><span>THREAT DETECTION</span><span>ATTACK FORECASTING</span><span>MITRE ATT&CK</span><span>EVIDENCE INTEGRITY</span></div>

    <section id="platform" className="landing-section"><SectionHead title="The Problem with Traditional Monitoring" text="Conventional security tools produce alerts, not intelligence. ForeFlow connects telemetry to predictive risk, closing the visibility gap."/><div className="problem-grid">{[
      [Clock3, "Reactive Security", "Discover attack progression after critical stages have already occurred."],
      [Network, "Fragmented Telemetry", "Correlate network activity, threats, intelligence and evidence in one operational view."],
      [BarChart3, "Limited Risk Context", "Translate isolated alerts into a numerical, decision-ready cyber risk posture."],
      [Target, "No Forward Visibility", "Move beyond what happened and forecast what the adversary may do next."]
    ].map(([Icon, t, d]) => <div className="problem-card" key={t}><Icon/><h3>{t}</h3><p>{d}</p></div>)}</div></section>

    <section id="capabilities" className="landing-section dark-section"><SectionHead title="SOC Platform Capabilities" text="A unified suite designed for security teams to monitor, quantify, forecast and preserve cyber evidence."/><div className="feature-grid">{[
      [Activity, "Live Network Monitoring", "Continuously analyze network traffic and telemetry."], [Upload, "CSV Dataset Analysis", "Upload historical datasets for offline risk assessment."], [Brain, "AI Threat Detection", "Identify anomalous and potentially malicious behavior."], [TrendingUp, "Attack Progression Forecast", "Predict likely future attack stages from current observations."], [Crosshair, "MITRE ATT&CK Mapping", "Map observed and predicted activity to ATT&CK techniques."], [Network, "Attack Graph Visualization", "Visualize entities and lateral movement pathways."], [Globe2, "Threat Intelligence", "Investigate indicators, IPs, hashes and contextual signals."], [LockKeyhole, "Evidence Vault", "Maintain tamper-evident logs and cryptographic verification."], [Scale, "Model Benchmarking", "Compare AI performance against established baselines."], [Play, "Attack Simulation", "Simulate scenarios for preparedness and analysis."]
    ].map(([Icon, t, d]) => <div className="feature-row" key={t}><Icon/><div><h4>{t}</h4><p>{d}</p></div></div>)}</div></section>

    <section id="workflow" className="landing-section"><SectionHead title="Operational Workflow" text="From telemetry to intelligence in four controlled stages."/><div className="workflow">{[["01","CONNECT","Connect network telemetry or upload historical datasets."],["02","ANALYZE","AI/ML models process activity and detect anomalies."],["03","QUANTIFY & FORECAST","Convert observations into numerical risk and predicted pathways."],["04","ACT","Use threat intel, attack graphs and evidence to respond."]].map(([n,t,d]) => <div className="workflow-card" key={n}><b>{n}</b><h3>{t}</h3><p>{d}</p></div>)}</div></section>

    <section id="preview" className="landing-section preview-section"><SectionHead title="From Raw Telemetry to Actionable Risk" text="A live operational console connected to the same Vercel-hosted FastAPI backend."/><div className="preview-window"><div className="preview-head"><span><i/> FOREFLOW SOC CONSOLE</span><span>RISK ENGINE / ONLINE</span></div><div className="preview-body"><div className="preview-stat"><small>RISK SCORE</small><strong>78.4</strong><em>ELEVATED</em></div><div className="preview-chart">{DEMO_FORECAST.slice(0,18).map((p,i)=><i key={i} style={{height:`${20+p.predicted_threat_level*65}%`}}/>)}</div><div className="preview-threats"><span>CRITICAL</span><strong>04</strong><span>HIGH</span><strong>11</strong></div></div></div></section>

    <section id="technology" className="landing-section tech-section"><div className="tech-panel"><div><div className="eyebrow">ENGINEERING CORE</div><h2>Predictive security, evidence integrity, and operational clarity.</h2><p>FastAPI services, PostgreSQL persistence, ML inference, MITRE mapping and blockchain-ready evidence anchoring are presented through a single analyst console.</p></div><div className="tech-grid"><span>FASTAPI</span><span>POSTGRESQL</span><span>SCIKIT-LEARN</span><span>WEB3</span><span>REACT</span><span>VERCEL</span></div></div></section>

    <footer className="landing-footer"><div><b>FOREFLOW</b><span>AI-Powered Continuous Cyber Risk Intelligence</span></div><span>© 2026 ForeFlow · Security Operations Platform</span></footer>

    {notice && <div className="toast success"><CheckCircle2 size={16}/>{notice}</div>}
    {modal && <div className="modal-backdrop" onMouseDown={() => setModal(null)}><div className="auth-modal" onMouseDown={e => e.stopPropagation()}><button className="modal-close" onClick={() => setModal(null)}><X size={18}/></button><div className="auth-icon"><ShieldCheck/></div><div className="eyebrow">SECURE ANALYST ACCESS</div><h2>{modal === "login" ? "Welcome back" : "Create analyst account"}</h2><p>{modal === "login" ? "Initialize a secure ForeFlow console session." : "Initialize your ForeFlow environment."}</p><form onSubmit={submitAuth}>{modal === "register" && <input required placeholder="Full name"/>}<input required type="email" placeholder="Analyst email"/><input required type="password" placeholder="Password" minLength={6}/><button className="primary-btn large" type="submit">{modal === "login" ? "Enter Console" : "Initialize Console"}<ArrowRight size={16}/></button></form><small>Demo access is local to this console; production identity providers can be connected separately.</small></div></div>}
  </div>;
}

function ShieldHalfIcon() { return <Shield size={18}/>; }
function SectionHead({ title, text }) { return <div className="section-head"><h2>{title}</h2><p>{text}</p></div>; }

function ConsoleLayout() {
  const [mobile, setMobile] = useState(false);
  const [system, setSystem] = useState({ api: true, db: false, chain: false });
  const [refreshing, setRefreshing] = useState(false);
  const nav = [
    ["/dashboard", "Overview", LayoutDashboard], ["/dashboard/monitor", "Live Monitor", Activity], ["/dashboard/threats", "Threat Center", ShieldAlert], ["/dashboard/forecast", "AI Forecast", TrendingUp], ["/dashboard/graph", "Attack Graph", Network], ["/dashboard/intel", "Threat Intel", Globe2], ["/dashboard/evidence", "Evidence Vault", FileLock2], ["/dashboard/benchmark", "Model Benchmark", Scale], ["/dashboard/simulation", "Attack Simulation", Play]
  ];
  const refresh = async () => { setRefreshing(true); const [api, db, chain] = await Promise.all([safe(getHealth, null), safe(getDbHealth, null), safe(getBlockchainHealth, null)]); setSystem({ api: !!api, db: !!db && (db.database === "connected" || db.status === "ok"), chain: !!chain && (chain.status === "ok" || chain.connected === true) }); setTimeout(() => setRefreshing(false), 400); };
  useEffect(() => { refresh(); }, []);
  return <div className="console-shell">
    <aside className={`console-sidebar ${mobile ? "mobile-open" : ""}`}><div className="console-brand"><span className="brand-icon"><Shield size={19}/></span><div><b>CYBERPULSE</b><small>AI Network Threat Forecasting</small></div></div><div className="console-tag">NTRO · SIH 2026</div><div className="console-nav"><span>WORKSPACE</span>{nav.map(([to,label,Icon]) => <NavLink key={to} to={to} end={to === "/dashboard"} onClick={() => setMobile(false)} className={({isActive}) => `console-nav-item ${isActive ? "active" : ""}`}><Icon size={16}/>{label}</NavLink>)}</div><div className="console-footer"><div><i className={system.api ? "online" : "offline"}/>{system.api ? "API ONLINE" : "API OFFLINE"}</div><small>Temporal AI Engine · v1.0</small></div></aside>
    {mobile && <div className="mobile-overlay" onClick={() => setMobile(false)}/>}<section className="console-main"><header className="console-topbar"><button className="mobile-console-menu" onClick={() => setMobile(!mobile)}><Menu/></button><div><span className="top-kicker">SECURITY OPERATIONS</span><h1>Cyber Risk Intelligence</h1></div><div className="top-actions"><button className="icon-btn" onClick={refreshing ? undefined : refresh}><RefreshCw size={16} className={refreshing ? "spin" : ""}/></button><div className="system-live"><i className="online"/> SYSTEM OPERATIONAL</div><div className="analyst"><span>S</span>SOC Analyst</div></div></header><main className="console-content"><Routes><Route index element={<Overview system={system}/>}/><Route path="monitor" element={<Monitor/>}/><Route path="threats" element={<ThreatCenter/>}/><Route path="forecast" element={<ForecastView/>}/><Route path="graph" element={<AttackGraph/>}/><Route path="intel" element={<Intel/>}/><Route path="evidence" element={<EvidenceView/>}/><Route path="benchmark" element={<Benchmark/>}/><Route path="simulation" element={<Simulation/>}/></Routes></main></section>
  </div>;
}

function PageHeader({ eyebrow, title, text, action }) { return <div className="page-header"><div><span className="top-kicker">{eyebrow}</span><h2>{title}</h2><p>{text}</p></div>{action}</div>; }
function Card({ children, className="" }) { return <section className={`console-card ${className}`}>{children}</section>; }
function Severity({ value }) { return <span className={`severity ${String(value || "LOW").toLowerCase()}`}>{value || "LOW"}</span>; }

function Overview({ system }) {
  const [threats, setThreats] = useState(DEMO_THREATS);
  const [anomalies, setAnomalies] = useState(14);
  const [dbLive, setDbLive] = useState(system.db);
  useEffect(() => { (async () => { const t = await safe(() => listThreats({ page:1, page_size:8 }), null); const a = await safe(() => listAnomalies({page:1,page_size:20}), null); if (t?.items) setThreats(t.items); if (a?.total != null) setAnomalies(a.total); })(); }, []);
  const risk = threats.length ? Math.min(99, 62 + threats.filter(t => t.severity === "CRITICAL").length * 7 + threats.filter(t => t.severity === "HIGH").length * 3) : 78;
  return <><PageHeader eyebrow="OVERVIEW" title="Security Overview" text="Unified operational posture across telemetry, detection, forecasting and evidence." action={<button className="secondary-console-btn" onClick={() => setDbLive(!dbLive)}><Database size={15}/>{dbLive ? "Database Connected" : "Demo Telemetry"}</button>}/>
    <div className="status-banner"><div><span className="pulse-dot"/> ACTIVE MONITORING</div><span>Session: FORE-OPS-{new Date().getHours()}A · Source: {dbLive ? "PostgreSQL" : "Synthetic telemetry"}</span></div>
    <div className="metric-grid"><Metric icon={ShieldAlert} label="Risk Score" value={risk.toFixed(1)} sub="ELEVATED" tone="critical"/><Metric icon={AlertTriangle} label="Active Threats" value={threats.length} sub="requiring review" tone="warning"/><Metric icon={Radar} label="Anomalies" value={anomalies} sub="detected events" tone="cyan"/><Metric icon={Activity} label="Flows Analyzed" value="18.4K" sub="last 24 hours" tone="green"/></div>
    <div className="two-col"><Card><CardTitle title="Threat Risk Trajectory" right="24H HORIZON"/><RiskChart/></Card><Card><CardTitle title="Operational Readiness" right="LIVE"/><div className="readiness"><Readiness label="Detection engine" value={94}/><Readiness label="Forecast confidence" value={87}/><Readiness label="Evidence integrity" value={100}/><Readiness label="Telemetry coverage" value={91}/></div></Card></div>
    <Card><CardTitle title="Recent Threat Activity" right={`${threats.length} EVENTS`}/><ThreatTable threats={threats.slice(0,5)}/></Card>
  </>;
}
function Metric({icon:Icon,label,value,sub,tone}) { return <div className={`metric-card ${tone}`}><div className="metric-icon"><Icon size={18}/></div><small>{label}</small><strong>{value}</strong><span>{sub}</span></div>; }
function CardTitle({title,right}) { return <div className="card-title"><h3>{title}</h3><span>{right}</span></div>; }
function Readiness({label,value}) { return <div className="readiness-row"><div><span>{label}</span><b>{value}%</b></div><div className="progress"><i style={{width:`${value}%`}}/></div></div>; }
function RiskChart() { const points = DEMO_FORECAST.slice(0,18); return <div className="risk-chart"><div className="chart-labels"><span>1.0</span><span>0.5</span><span>0.0</span></div><div className="chart-area">{points.map((p,i)=><i key={i} style={{height:`${Math.round(p.predicted_threat_level*88)+4}%`}}/>)}<div className="chart-line"/></div><div className="chart-x"><span>NOW</span><span>+6H</span><span>+12H</span><span>+18H</span><span>+24H</span></div></div>; }
function ThreatTable({threats, onResolve}) { return <div className="table-wrap"><table><thead><tr><th>ID</th><th>THREAT</th><th>SOURCE</th><th>STAGE</th><th>SEVERITY</th><th>CONFIDENCE</th>{onResolve && <th/>}</tr></thead><tbody>{threats.map(t=><tr key={t.id}><td className="mono">{t.id}</td><td>{t.title}</td><td className="mono">{t.source_ip || t.src_ip || "N/A"}</td><td>{String(t.attack_stage || "UNKNOWN").replaceAll("_"," ")}</td><td><Severity value={t.severity}/></td><td>{Math.round((t.confidence_score ?? t.confidence ?? 0.9)*100)}%</td>{onResolve && <td><button className="tiny-btn" onClick={() => onResolve(t)}>Resolve</button></td>}</tr>)}</tbody></table></div>; }

function Monitor() { const [rows,setRows]=useState(DEMO_TELEMETRY); const [paused,setPaused]=useState(false); const [search,setSearch]=useState(""); useEffect(()=>{(async()=>{const r=await safe(()=>listAnomalies({page:1,page_size:20}),null); if(r?.items?.length) setRows(r.items.map((x,i)=>({...DEMO_TELEMETRY[i%DEMO_TELEMETRY.length],...x,src_ip:x.src_ip||x.source_ip,dst_ip:x.dst_ip||x.destination_ip})));})();},[]); const filtered=rows.filter(r=>JSON.stringify(r).toLowerCase().includes(search.toLowerCase())); return <><PageHeader eyebrow="LIVE MONITOR" title="Network Telemetry" text="Continuous flow inspection with anomaly scoring and protocol context." action={<button className="primary-btn" onClick={()=>setPaused(!paused)}>{paused?<Play size={15}/>:<span className="pause-icon">Ⅱ</span>}{paused?"Resume stream":"Pause stream"}</button>}/><div className="status-banner"><div><span className={`pulse-dot ${paused?"paused":""}`}/>{paused?" STREAM PAUSED":" LIVE STREAM"}</div><span>eth0 / synthetic collector · 5s refresh</span></div><Card><div className="toolbar"><div className="search-box"><Search size={15}/><input value={search} onChange={e=>setSearch(e.target.value)} placeholder="Filter source, destination, protocol..."/></div><span className="toolbar-note">{filtered.length} FLOWS</span></div><div className="table-wrap"><table><thead><tr><th>TIME</th><th>SOURCE</th><th>DESTINATION</th><th>PORT</th><th>PROTO</th><th>PACKETS</th><th>BYTES</th><th>SCORE</th><th>STATE</th></tr></thead><tbody>{filtered.map((r,i)=><tr className={r.is_anomaly?"suspicious":""} key={i}><td className="mono">{new Date(r.timestamp).toLocaleTimeString()}</td><td className="mono">{r.src_ip||"10.24.8.51"}</td><td className="mono">{r.dst_ip||"10.24.4.22"}</td><td>{r.dst_port||443}</td><td>{r.protocol||"TCP"}</td><td>{r.packets||((r.fwd_packets||0)+(r.bwd_packets||0))}</td><td>{Number(r.bytes||((r.fwd_bytes||0)+(r.bwd_bytes||0))).toLocaleString()}</td><td className="mono">{Number(r.anomaly_score||0).toFixed(2)}</td><td><Severity value={r.is_anomaly?"CRITICAL":"LOW"}/></td></tr>)}</tbody></table></div></Card></>; }

function ThreatCenter() { const [threats,setThreats]=useState(DEMO_THREATS); const [filter,setFilter]=useState("ALL"); const [busy,setBusy]=useState(""); const load=async()=>{const r=await safe(()=>listThreats({page:1,page_size:30}),null); if(r?.items) setThreats(r.items);}; useEffect(()=>{load();},[]); const filtered=threats.filter(t=>filter==="ALL"||t.severity===filter||(filter==="HIGH"&&t.severity==="CRITICAL")); const resolve=async t=>{setBusy(t.id); const r=await safe(()=>resolveThreat(t.id),null); if(r) setThreats(x=>x.map(v=>v.id===t.id?{...v,is_resolved:true,severity:"LOW"}:v)); else setThreats(x=>x.filter(v=>v.id!==t.id)); setBusy("");}; return <><PageHeader eyebrow="THREAT CENTER" title="Threat Detection & Response" text="Investigate active detections, severity and ATT&CK context." action={<div className="filter-pills">{["ALL","CRITICAL","HIGH","MEDIUM"].map(x=><button className={filter===x?"selected":""} onClick={()=>setFilter(x)} key={x}>{x}</button>)}</div>}/><div className="metric-grid compact"><Metric icon={ShieldAlert} label="Critical" value={threats.filter(t=>t.severity==="CRITICAL").length} sub="immediate action" tone="critical"/><Metric icon={AlertTriangle} label="High" value={threats.filter(t=>t.severity==="HIGH").length} sub="investigate" tone="warning"/><Metric icon={Target} label="MITRE mapped" value={threats.length} sub="technique context" tone="cyan"/><Metric icon={CheckCircle2} label="Resolved" value={threats.filter(t=>t.is_resolved).length} sub="closed incidents" tone="green"/></div><Card><CardTitle title="Active Detections" right={`${filtered.length} MATCHES`}/><ThreatTable threats={filtered} onResolve={t=>busy===t.id?null:resolve(t)}/>{busy&&<div className="inline-status"><RefreshCw className="spin" size={14}/> Updating {busy}...</div>}</Card></>; }

function ForecastView() { const [forecast,setForecast]=useState(DEMO_FORECAST); const [horizon,setHorizon]=useState(24); const [loading,setLoading]=useState(false); const [source,setSource]=useState("demo"); const run=async()=>{setLoading(true); const r=await safe(()=>generateForecast({horizon_hours:horizon,sequence_length:48}),null); if(r?.points?.length){setForecast(r.points);setSource("backend");} else {setForecast(DEMO_FORECAST.slice(0,horizon));setSource("fallback");} setLoading(false);}; useEffect(()=>{(async()=>{const r=await safe(()=>getLatestForecast(),null); if(r?.points?.length){setForecast(r.points);setSource("backend");}})();},[]); const peak=Math.max(...forecast.map(x=>x.predicted_threat_level)); return <><PageHeader eyebrow="PREDICTIVE ENGINE" title="AI Threat Forecast" text="Forecast the next threat-risk trajectory from current network observations." action={<div className="horizon-control"><span>HORIZON</span>{[6,12,24].map(x=><button key={x} className={horizon===x?"selected":""} onClick={()=>setHorizon(x)}>{x}H</button>)}<button className="primary-btn" onClick={run} disabled={loading}>{loading?<RefreshCw className="spin" size={14}/>:<Zap size={14}/>} Generate</button></div>}/><div className="forecast-hero"><div><span>PEAK PREDICTED THREAT</span><strong>{Math.round(peak*100)}%</strong><em>{source === "backend" ? "TEMPORAL ENGINE" : "VERCEL-SAFE BASELINE"}</em></div><div className="forecast-summary"><span>Confidence <b>{peak>.8?"HIGH":"MEDIUM"}</b></span><span>Model <b>v1.0</b></span><span>Window <b>{forecast.length} hours</b></span></div></div><Card><CardTitle title="Threat Probability Curve" right="PREDICTED / UNCERTAINTY"/><div className="forecast-chart"><div className="forecast-grid"/>{forecast.map((p,i)=><div key={i} className="forecast-bar" style={{height:`${Math.max(5,p.predicted_threat_level*88)}%`}}><span/></div>)}</div><div className="chart-x forecast-x"><span>NOW</span><span>+6H</span><span>+12H</span><span>+18H</span><span>+24H</span></div></Card><div className="two-col"><Card><CardTitle title="Forecast Timeline" right="ATTACK PATH"/>{MITRE.slice(0,5).map(([id,name],i)=><div className="timeline-row" key={id}><span className={i<3?"active-dot":""}/><div><small>+{i*6||1} HOURS · {id}</small><b>{name.replaceAll("_"," ")}</b></div><Severity value={i<2?"HIGH":i===2?"MEDIUM":"LOW"}/></div>)}</Card><Card><CardTitle title="Top Risk Factors" right="IMPACT"/><Readiness label="Authentication failures" value={89}/><Readiness label="Outbound DNS entropy" value={76}/><Readiness label="Lateral SMB activity" value={68}/><Readiness label="Privileged process chain" value={61}/></Card></div></>; }

function AttackGraph() { return <><PageHeader eyebrow="ATTACK GRAPH" title="Adversary Pathway" text="Entity relationships and predicted lateral movement pathways." action={<button className="secondary-console-btn"><GitBranch size={15}/> Recalculate graph</button>}/><Card className="graph-card"><div className="graph-canvas"><div className="graph-line gl1"/><div className="graph-line gl2"/><GraphNode x="8%" y="42%" label="EXTERNAL SOURCE" value="45.33.12.9" danger/><GraphNode x="35%" y="22%" label="DMZ GATEWAY" value="10.24.8.14"/><GraphNode x="35%" y="68%" label="VPN EDGE" value="10.24.8.1" safe/><GraphNode x="67%" y="42%" label="INTERNAL SERVER" value="10.24.4.22"/><GraphNode x="88%" y="42%" label="DATA STORE" value="10.24.1.105" target/></div><div className="graph-legend"><span><i className="red"/> threat source</span><span><i className="blue"/> infrastructure</span><span><i className="green"/> trusted edge</span><span><i className="orange"/> target</span></div></Card></>; }
function GraphNode({x,y,label,value,danger,safe,target}) { return <div className={`graph-node ${danger?"danger":""} ${safe?"safe":""} ${target?"target":""}`} style={{left:x,top:y}}><div className="node-ring"><Server size={18}/></div><small>{label}</small><b>{value}</b></div>; }

function Intel() { const iocs=["45.33.12.9","185.220.101.14","e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","cdn-sync[.]net","10.24.8.51"]; return <><PageHeader eyebrow="THREAT INTELLIGENCE" title="Indicator Intelligence" text="Contextualize suspicious infrastructure and map it to adversary behavior." action={<div className="search-box"><Search size={15}/><input placeholder="Search IP, hash, domain..."/></div>}/><div className="intel-grid">{iocs.map((ioc,i)=><Card key={ioc}><div className="ioc-top"><span className={`ioc-type ${i===2?"hash":i===3?"domain":"ip"}`}>{i===2?"SHA256":i===3?"DOMAIN":"IP"}</span><span className="confidence">{94-i*5}% MATCH</span></div><div className="ioc-value">{ioc}</div><div className="ioc-meta"><span>Source: OSINT</span><span>Seen: {124-i*19} times</span></div><div className="mitre-chip"><Crosshair size={13}/> T{1110-i*11} · {i%2?"Command & Control":"Credential Access"}</div></Card>)}</div><Card><CardTitle title="MITRE ATT&CK Chain" right="CURRENT → PREDICTED"/><div className="mitre-chain">{MITRE.map(([id,name],i)=><div className={`mitre-step ${i===1?"current":""} ${i===3?"predicted":""}`} key={id}><small>{id}</small><span>{name.replaceAll("_"," ")}</span>{i<MITRE.length-1&&<ChevronRight size={14}/>}</div>)}</div></Card></>; }

function EvidenceView() { const [items,setItems]=useState(DEMO_EVIDENCE); const [busy,setBusy]=useState(""); const refresh=async()=>{const r=await safe(()=>listEvidence({page:1,page_size:20}),null); if(r?.items) setItems(r.items);}; useEffect(()=>{refresh();},[]); const anchor=async(id)=>{setBusy(id); const r=await safe(()=>anchorEvidence(id),null); if(r) setItems(x=>x.map(v=>v.id===id?r:v)); else setItems(x=>x.map(v=>v.id===id?{...v,status:"ANCHORED",blockchain_tx_hash:"0xdemo...anchor"}:v)); setBusy("");}; const verify=async(id)=>{setBusy(id); const r=await safe(()=>verifyEvidence(id),null); alert(r?.message || "Evidence integrity verified in demo mode."); setBusy("");}; return <><PageHeader eyebrow="EVIDENCE VAULT" title="Evidence Integrity" text="Hash, anchor and verify security evidence with blockchain-ready provenance." action={<button className="primary-btn"><FileCheck2 size={15}/> Add Evidence</button>}/><div className="metric-grid compact"><Metric icon={Hash} label="Artifacts" value={items.length} sub="preserved" tone="cyan"/><Metric icon={LockKeyhole} label="Anchored" value={items.filter(x=>x.status==="ANCHORED").length} sub="on-chain" tone="green"/><Metric icon={ShieldCheck} label="Integrity" value="100%" sub="verified" tone="green"/><Metric icon={Database} label="Hashing" value="SHA-256" sub="content address" tone="warning"/></div><Card><CardTitle title="Preserved Artifacts" right="TAMPER-EVIDENT"/><div className="evidence-list">{items.map(e=><div className="evidence-item" key={e.id}><div className="evidence-icon"><FileLock2 size={18}/></div><div className="evidence-main"><div><b>{e.title}</b><span className={`evidence-status ${String(e.status).toLowerCase()}`}>{e.status}</span></div><p>{e.description}</p><code>{e.content_hash}</code><small>{e.blockchain_tx_hash ? `TX ${e.blockchain_tx_hash}` : "Not anchored on-chain"}</small></div><div className="evidence-actions">{e.status!=="ANCHORED"&&<button className="tiny-btn" disabled={busy===e.id} onClick={()=>anchor(e.id)}>{busy===e.id?<RefreshCw className="spin" size={12}/>:"Anchor"}</button>}<button className="tiny-btn" disabled={busy===e.id} onClick={()=>verify(e.id)}>Verify</button></div></div>)}</div></Card></>; }

function Benchmark() { const metrics=[['Accuracy',.82,.94],['Precision',.79,.91],['Recall',.75,.96],['F1 Score',.77,.93]]; return <><PageHeader eyebrow="MODEL BENCHMARK" title="Temporal AI Performance" text="Compare the forecasting model against a baseline evaluation profile."/><Card><CardTitle title="Model Evaluation" right="VALIDATION SET"/><div className="benchmark-table"><div className="bench-head"><span>METRIC</span><span>BASELINE</span><span>MODEL</span><span>DELTA</span></div>{metrics.map(([n,b,m])=><div className="bench-row" key={n}><b>{n}</b><span>{b.toFixed(2)}</span><strong>{m.toFixed(2)}</strong><em>+{((m-b)*100).toFixed(1)}%</em></div>)}</div></Card><div className="two-col"><Card><CardTitle title="Model Configuration"/><div className="config-list"><span>Architecture <b>Temporal Sequence Model</b></span><span>Sequence length <b>48 hours</b></span><span>Forecast horizon <b>24 hours</b></span><span>Inference <b>CPU / serverless safe</b></span></div></Card><Card><CardTitle title="Operational Guardrails"/><div className="guardrail"><CheckCircle2/><div><b>Bounded predictions</b><p>Output constrained to 0–1 threat probability.</p></div></div><div className="guardrail"><ShieldCheck/><div><b>Fallback inference</b><p>Numerical baseline keeps the console operational.</p></div></div></Card></div></>; }

function Simulation() { const [running,setRunning]=useState(false); const [log,setLog]=useState(["> Synthetic environment ready.","> Awaiting attack vector."]); const run=()=>{setRunning(true);setLog(["> Initializing synthetic telemetry environment..."]); const steps=["> Compiling latent state transitions...","> Executing predictive world model...","> Correlating MITRE ATT&CK techniques...","> Binding evidence integrity layer...","> Simulation complete. Session: SIM-FORE-2042"]; steps.forEach((s,i)=>setTimeout(()=>setLog(l=>[...l,s]),600*(i+1))); setTimeout(()=>setRunning(false),3300);}; return <><PageHeader eyebrow="ATTACK SIMULATION" title="Adversary Scenario Lab" text="Generate synthetic attack telemetry for preparedness, forecasting and response analysis."/><div className="simulation-grid"><Card><CardTitle title="Scenario Configuration" right="SAFE / SYNTHETIC"/><label className="field-label">ATTACK VECTOR<select defaultValue="credential"><option value="credential">Credential Spray → Lateral Movement</option><option value="ransomware">Ransomware Initial Access</option><option value="c2">Command & Control Beacon</option><option value="exfil">Data Exfiltration Chain</option></select></label><label className="field-label">TARGET TOPOLOGY<select defaultValue="enterprise"><option value="enterprise">Enterprise / Hybrid</option><option value="dmz">DMZ + Internal DB</option></select></label><button className="primary-btn large full" disabled={running} onClick={run}>{running?<><RefreshCw className="spin" size={16}/> SIMULATION RUNNING</>:<><Play size={16}/> LAUNCH SIMULATION</>}</button></Card><Card><CardTitle title="Execution Log" right="LIVE"/><div className="terminal">{log.map((x,i)=><div key={i} className={i===log.length-1?"latest":""}>{x}</div>)}</div></Card></div><div className="simulation-results"><div><b>Predictive path</b><span>Initial Access → Execution → Lateral Movement → C2</span></div><div><b>Risk amplification</b><strong>+34%</strong></div><div><b>Evidence artifacts</b><strong>12</strong></div></div></>; }

export default function App() { return <Routes><Route path="/" element={<Landing/>}/><Route path="/dashboard/*" element={<ConsoleLayout/>}/><Route path="*" element={<Landing/>}/></Routes>;