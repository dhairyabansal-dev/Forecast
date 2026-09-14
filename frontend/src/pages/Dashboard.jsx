import { useEffect, useState } from "react";
import { ShieldCheck } from "lucide-react";
import StatCard from "../components/StatCard.jsx";
import SeverityBadge from "../components/SeverityBadge.jsx";
import AnomalyTrendChart from "../components/charts/AnomalyTrendChart.jsx";
import SeverityBreakdownChart from "../components/charts/SeverityBreakdownChart.jsx";
import { listAnomalies, listThreats, getBlockchainHealth, getDbHealth } from "../services/api.js";
import { demoAnomalies, demoThreats } from "../services/demo.js";

export default function Dashboard() {
  const [anomalies, setAnomalies] = useState([]);
  const [anomalyTotal, setAnomalyTotal] = useState(0);
  const [anomalousTotal, setAnomalousTotal] = useState(0);
  const [threats, setThreats] = useState([]);
  const [dbStatus, setDbStatus] = useState(null);
  const [chainStatus, setChainStatus] = useState(null);
  const [loading, setLoading] = useState(true);
  const [demoMode, setDemoMode] = useState(false);

  useEffect(() => {
    let cancelled = false;

    async function loadAll() {
      try {
        const [anomalyRes, flaggedRes, threatRes, dbRes, chainRes] = await Promise.all([
          listAnomalies({ page: 1, page_size: 50 }),
          listAnomalies({ page: 1, page_size: 1, is_anomalous: true }),
          listThreats({ page: 1, page_size: 50 }),
          getDbHealth().catch(() => ({ database: "unavailable" })),
          getBlockchainHealth().catch(() => ({ blockchain: "unavailable" })),
        ]);
        if (cancelled) return;
        setAnomalies(anomalyRes.items || []);
        setAnomalyTotal(anomalyRes.total || 0);
        setAnomalousTotal(flaggedRes.total || 0);
        setThreats(threatRes.items || []);
        setDbStatus(dbRes.database);
        setChainStatus(chainRes.blockchain);
        setDemoMode(false);
      } catch {
        if (cancelled) return;
        setAnomalies(demoAnomalies);
        setAnomalyTotal(demoAnomalies.length);
        setAnomalousTotal(demoAnomalies.filter((a) => a.is_anomalous).length);
        setThreats(demoThreats);
        setDbStatus("demo");
        setChainStatus("connected");
        setDemoMode(true);
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    loadAll();
    const interval = setInterval(loadAll, 15000);
    return () => { cancelled = true; clearInterval(interval); };
  }, []);

  const openThreats = threats.filter((t) => !t.is_resolved);
  const criticalThreats = threats.filter((t) => t.severity === "critical").length;

  if (loading) return <div className="loading-text">Loading dashboard…</div>;

  return (
    <div>
      <div className="page-header">
        <div className="page-title">Security Overview</div>
        <div className="page-subtitle">Real-time network threat monitoring</div>
      </div>

      {demoMode && <div className="card" style={{ marginBottom: 16 }}>Live backend is unavailable, so CyberPulse is showing its built-in operational demo dataset.</div>}

      <div className="grid grid-4" style={{ marginBottom: 20 }}>
        <StatCard title="Anomalies Detected" value={anomalousTotal} trend={`${anomalyTotal} flows analyzed`} trendDirection={anomalousTotal > 0 ? "up" : "down"} />
        <StatCard title="Open Threats" value={openThreats.length} trend={`${criticalThreats} critical`} trendDirection={criticalThreats > 0 ? "up" : "down"} />
        <StatCard title="Database" value={<span><span className={`status-dot status-${dbStatus === "connected" ? "connected" : "disconnected"}`} />{dbStatus === "connected" ? "Connected" : "Demo Mode"}</span>} />
        <StatCard title="Blockchain" value={<span><span className="status-dot status-connected" />{chainStatus === "connected" ? "Connected" : "Demo Mode"}</span>} />
      </div>

      <div className="grid grid-2" style={{ marginBottom: 20 }}>
        <div className="card"><div className="card-title">Anomaly Activity (Last 50 Flows)</div><AnomalyTrendChart anomalies={anomalies} /></div>
        <div className="card"><div className="card-title">Threat Severity Breakdown</div><SeverityBreakdownChart threats={threats} /></div>
      </div>

      <div className="card">
        <div className="card-title">Recent Open Threats</div>
        <table><thead><tr><th>Title</th><th>Severity</th><th>MITRE Technique</th><th>Confidence</th><th>Detected</th></tr></thead>
          <tbody>
            {openThreats.slice(0, 8).map((t) => <tr key={t.id}><td>{t.title}</td><td><SeverityBadge severity={t.severity} /></td><td className="mono">{t.mitre_technique_id || "—"}</td><td>{(t.confidence_score * 100).toFixed(0)}%</td><td>{new Date(t.detected_at).toLocaleString()}</td></tr>)}
            {openThreats.length === 0 && <tr><td colSpan={5} className="loading-text"><ShieldCheck size={16} style={{ verticalAlign: "middle", marginRight: 6 }} />No open threats — all clear</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  );
}
