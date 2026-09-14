import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
} from "recharts";

function formatTime(iso) {
  const d = new Date(iso);
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

export default function ThreatLevelChart({ points = [] }) {
  const data = points.map((p) => ({
    time: formatTime(p.timestamp),
    level: +(p.predicted_threat_level * 100).toFixed(1),
    lower: +(p.lower_bound * 100).toFixed(1),
    upper: +(p.upper_bound * 100).toFixed(1),
  }));

  return (
    <ResponsiveContainer width="100%" height={280}>
      <AreaChart data={data} margin={{ top: 10, right: 16, left: 0, bottom: 0 }}>
        <defs>
          <linearGradient id="threatFill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#24b8d4" stopOpacity={0.35} />
            <stop offset="100%" stopColor="#24b8d4" stopOpacity={0} />
          </linearGradient>
          <linearGradient id="bandFill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#ef6b73" stopOpacity={0.12} />
            <stop offset="100%" stopColor="#ef6b73" stopOpacity={0} />
          </linearGradient>
        </defs>
        <CartesianGrid strokeDasharray="3 3" stroke="#e8edf4" vertical={false} />
        <XAxis dataKey="time" stroke="#8a96a8" fontSize={11} tickLine={false} axisLine={false} />
        <YAxis
          stroke="#8a96a8"
          fontSize={11}
          tickLine={false}
          axisLine={false}
          domain={[0, 100]}
          unit="%"
        />
        <Tooltip
          contentStyle={{ background: "#ffffff", border: "1px solid #e6eaf1", borderRadius: 10, fontSize: 12, boxShadow: "0 12px 30px rgba(18,35,60,.12)" }}
          labelStyle={{ color: "#7b8494" }}
        />
        <Area type="monotone" dataKey="upper" stroke="none" fill="url(#bandFill)" />
        <Area type="monotone" dataKey="lower" stroke="none" fill="#ffffff" fillOpacity={1} />
        <Area
          type="monotone"
          dataKey="level"
          stroke="#24b8d4"
          strokeWidth={2}
          fill="url(#threatFill)"
        />
      </AreaChart>
    </ResponsiveContainer>
  );
}