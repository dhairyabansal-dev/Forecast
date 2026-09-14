import { PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer } from "recharts";

const SEVERITY_COLORS = {
  critical: "#fb7185",
  high: "#fb923c",
  medium: "#fbbf24",
  low: "#4ade80",
};

export default function SeverityBreakdownChart({ threats = [] }) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  threats.forEach((t) => {
    if (counts[t.severity] !== undefined) counts[t.severity] += 1;
  });

  const data = Object.entries(counts)
    .filter(([, count]) => count > 0)
    .map(([severity, count]) => ({ name: severity, value: count }));

  if (data.length === 0) {
    return <div className="loading-text">No threats to display</div>;
  }

  return (
    <ResponsiveContainer width="100%" height={240}>
      <PieChart>
        <Pie
          data={data}
          dataKey="value"
          nameKey="name"
          cx="50%"
          cy="50%"
          innerRadius={55}
          outerRadius={85}
          paddingAngle={3}
        >
          {data.map((entry) => (
            <Cell key={entry.name} fill={SEVERITY_COLORS[entry.name]} />
          ))}
        </Pie>
        <Tooltip
          contentStyle={{ background: "#ffffff", border: "1px solid #e6eaf1", borderRadius: 10, fontSize: 12, boxShadow: "0 12px 30px rgba(18,35,60,.12)" }}
        />
        <Legend
          verticalAlign="bottom"
          height={24}
          formatter={(value) => <span style={{ color: "#9aa4b2", fontSize: 12, textTransform: "capitalize" }}>{value}</span>}
        />
      </PieChart>
    </ResponsiveContainer>
  );
}