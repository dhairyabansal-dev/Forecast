import { useEffect, useState } from "react";
import { TrendingUp, Radio } from "lucide-react";
import ThreatLevelChart from "../components/charts/ThreatLevelChart.jsx";
import StatCard from "../components/StatCard.jsx";
import { getLatestForecast, startLiveForecast, getLiveForecastStatus } from "../services/api.js";

export default function Forecast() {
  const [forecast, setForecast] = useState(null);
  const [loading, setLoading] = useState(true);
  const [horizon, setHorizon] = useState(24);
  const [error, setError] = useState(null);
  const [capturing, setCapturing] = useState(false);

  async function loadLatest() {
    setLoading(true);
    try {
      const data = await getLatestForecast();
      setForecast(data);
    } catch {
      setForecast(null);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadLatest();
  }, []);

  async function handleLiveForecast() {
    setCapturing(true);
    setError(null);
    try {
      const job = await startLiveForecast({ forecast_steps: horizon });
      let status = job;
      while (status.status !== "completed" && status.status !== "failed") {
        await new Promise((resolve) => setTimeout(resolve, 1000));
        status = await getLiveForecastStatus(job.job_id);
      }
      if (status.status === "failed") {
        throw new Error(status.error || "Live forecast failed");
      }
      setForecast(await getLatestForecast());
    } catch (err) {
      const detail = err?.response?.data?.detail;
      setError(Array.isArray(detail) ? detail.map((d) => d.msg).join(", ") : detail || err.message);
    } finally {
      setCapturing(false);
    }
  }

  const peak = forecast?.points?.reduce(
    (max, p) => (p.predicted_threat_level > max.predicted_threat_level ? p : max),
    forecast?.points?.[0] || { predicted_threat_level: 0, timestamp: null }
  );

  return (
    <div>
      <div className="page-header" style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-end" }}>
        <div>
          <div className="page-title">Threat Forecast</div>
          <div className="page-subtitle">AI-predicted threat levels for the next {horizon} hours</div>
        </div>
        <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
          <select
            value={horizon}
            onChange={(e) => setHorizon(Number(e.target.value))}
            style={{ background: "#10141d", color: "#e6e8ec", border: "1px solid #1f2430", borderRadius: 8, padding: "8px 10px", fontSize: 13 }}
          >
            <option value={12}>12 hours</option>
            <option value={24}>24 hours</option>
            <option value={48}>48 hours</option>
            <option value={72}>72 hours</option>
          </select>
          <button className="btn" onClick={handleLiveForecast} disabled={capturing}>
            <Radio size={14} style={{ verticalAlign: "middle", marginRight: 6 }} />
            {capturing ? "Capturing…" : "Capture Live Forecast"}
          </button>
        </div>
      </div>

      {error && <div className="card" style={{ marginBottom: 16, color: "#f87171" }}>{error}</div>}

      {loading ? (
        <div className="loading-text">Loading forecast…</div>
      ) : !forecast ? (
        <div className="card">
          <div className="loading-text">
            <TrendingUp size={20} style={{ verticalAlign: "middle", marginRight: 8 }} />
            No forecast yet — click "Generate New Forecast" to run the model.
          </div>
        </div>
      ) : (
        <>
          <div className="grid grid-4" style={{ marginBottom: 20 }}>
            <StatCard title="Confidence" value={forecast.confidence} />
            <StatCard
              title="Peak Threat Level"
              value={`${(peak.predicted_threat_level * 100).toFixed(0)}%`}
              trend={peak.timestamp ? new Date(peak.timestamp).toLocaleString() : ""}
            />
            <StatCard title="Model Version" value={forecast.model_version} />
            <StatCard
              title="Predicted Stage"
              value={forecast.points?.[0]?.predicted_stage || "Unavailable"}
            />
            <StatCard
              title="Generated"
              value={new Date(forecast.generated_at).toLocaleTimeString()}
            />
          </div>

          <div className="card">
            <div className="card-title">Predicted Threat Level Over Time</div>
            <ThreatLevelChart points={forecast.points} />
          </div>
        </>
      )}
    </div>
  );
}