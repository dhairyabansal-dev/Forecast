import { useEffect, useState } from "react";
import { ShieldAlert, CheckCircle2 } from "lucide-react";
import SeverityBadge from "../components/SeverityBadge.jsx";
import MitreTacticRadar from "../components/charts/MitreTacticRadar.jsx";
import { listThreats, resolveThreat } from "../services/api.js";

export default function ThreatIntel() {
  const [threats, setThreats] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState("all");
  const [resolvingId, setResolvingId] = useState(null);

  async function load() {
    setLoading(true);
    try {
      const params = { page: 1, page_size: 100 };
      if (filter !== "all") params.is_resolved = filter === "resolved";
      const res = await listThreats(params);
      setThreats(res.items || []);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
    const interval = setInterval(load, 15000);
    return () => clearInterval(interval);
  }, [filter]);

  async function handleResolve(id) {
    setResolvingId(id);
    try {
      await resolveThreat(id);
      await load();
    } finally {
      setResolvingId(null);
    }
  }

  return (
    <div>
      <div className="page-header" style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-end" }}>
        <div>
          <div className="page-title">Threat Intelligence</div>
          <div className="page-subtitle">MITRE ATT&CK mapped threats and detections</div>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          {["all", "open", "resolved"].map((f) => (
            <button
              key={f}
              className="btn"
              style={{
                background: filter === f ? "#234a68" : "#10141d",
                borderColor: filter === f ? "#2a5578" : "#1f2430",
              }}
              onClick={() => setFilter(f)}
            >
              {f[0].toUpperCase() + f.slice(1)}
            </button>
          ))}
        </div>
      </div>

      <div className="card" style={{ marginBottom: 20 }}>
        <div className="card-title">Tactic Distribution (MITRE ATT&CK)</div>
        <MitreTacticRadar threats={threats} />
      </div>

      <div className="card">
        <div className="card-title">Threats</div>
        {loading ? (
          <div className="loading-text">Loading threats…</div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Title</th>
                <th>Severity</th>
                <th>Src IP</th>
                <th>Dst IP</th>
                <th>MITRE</th>
                <th>Confidence</th>
                <th>Status</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {threats.map((t) => (
                <tr key={t.id}>
                  <td>{t.title}</td>
                  <td><SeverityBadge severity={t.severity} /></td>
                  <td className="mono">{t.src_ip || "—"}</td>
                  <td className="mono">{t.dst_ip || "—"}</td>
                  <td className="mono">{t.mitre_technique_id || "—"}</td>
                  <td>{(t.confidence_score * 100).toFixed(0)}%</td>
                  <td>
                    {t.is_resolved ? (
                      <span style={{ color: "#4ade80", fontSize: 12 }}>
                        <CheckCircle2 size={13} style={{ verticalAlign: "middle", marginRight: 4 }} />
                        Resolved
                      </span>
                    ) : (
                      <span style={{ color: "#fbbf24", fontSize: 12 }}>
                        <ShieldAlert size={13} style={{ verticalAlign: "middle", marginRight: 4 }} />
                        Open
                      </span>
                    )}
                  </td>
                  <td>
                    {!t.is_resolved && (
                      <button
                        className="btn"
                        style={{ padding: "4px 10px", fontSize: 12 }}
                        onClick={() => handleResolve(t.id)}
                        disabled={resolvingId === t.id}
                      >
                        {resolvingId === t.id ? "…" : "Resolve"}
                      </button>
                    )}
                  </td>
                </tr>
              ))}
              {threats.length === 0 && (
                <tr><td colSpan={8} className="loading-text">No threats found</td></tr>
              )}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}