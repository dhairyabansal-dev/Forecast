import { Routes, Route, NavLink } from "react-router-dom";
import { LayoutDashboard, TrendingUp, ShieldAlert, FileLock2 } from "lucide-react";
import Dashboard from "./pages/Dashboard.jsx";
import Forecast from "./pages/Forecast.jsx";
import ThreatIntel from "./pages/ThreatIntel.jsx";
import Evidence from "./pages/Evidence.jsx";

const NAV_ITEMS = [
  { to: "/", label: "Overview", icon: LayoutDashboard, end: true },
  { to: "/forecast", label: "AI Forecast", icon: TrendingUp },
  { to: "/threats", label: "Threat Intel", icon: ShieldAlert },
  { to: "/evidence", label: "Evidence Vault", icon: FileLock2 },
];

export default function App() {
  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand-wrap">
          <div className="brand-mark">◉</div>
          <div>
            <div className="sidebar-brand">CYBERPULSE</div>
            <div className="brand-subtitle">AI Network Threat Forecasting</div>
          </div>
        </div>
        <div className="brand-tag">NTRO · SIH 2026</div>

        <nav className="nav-stack">
          <div className="nav-section-label">WORKSPACE</div>
          {NAV_ITEMS.map(({ to, label, icon: Icon, end }) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              className={({ isActive }) => `nav-item${isActive ? " active" : ""}`}
            >
              <Icon size={17} strokeWidth={1.8} />
              <span>{label}</span>
            </NavLink>
          ))}
        </nav>

        <div className="sidebar-footer">
          <div className="mini-status"><span className="status-dot status-connected" />SYSTEM ONLINE</div>
          <div className="mini-meta">Temporal AI Engine · v1.0</div>
        </div>
      </aside>

      <section className="workspace">
        <header className="topbar">
          <div className="topbar-title">Security Overview</div>
          <div className="topbar-right">
            <div className="system-live"><span className="live-pulse" /> SYSTEM OPERATIONAL</div>
            <div className="analyst-chip"><span className="analyst-avatar">S</span><span>SOC Analyst</span></div>
          </div>
        </header>

        <main className="main-content">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/forecast" element={<Forecast />} />
            <Route path="/threats" element={<ThreatIntel />} />
            <Route path="/evidence" element={<Evidence />} />
          </Routes>
        </main>
      </section>
    </div>
  );
}
