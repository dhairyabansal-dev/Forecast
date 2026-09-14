import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell,
} from "recharts";

export default function AnomalyTrendChart({ anomalies = [] }) {
  // Bucket anomalies by hour for a simple frequency histogram
  const buckets = {};
  anomalies.forEach((a) => {
    const hour = new Date(a.detected_at).toISOString().slice(0, 13);
    buckets[hour] = buckets[hour] || { hour, total: 0, anomalous: 0 };
    buckets[hour].total += 1;
    if (a.is_anomalous) buckets[hour].anomalous += 1;
  });

  const data = Object.values(buckets)
    .sort((a, b) => a.hour.localeCompare(b.hour))
    .map((b) => ({
      ...b,
      label: new Date(b.hour + ":00:00Z").toLocaleTimeString([], { hour: "2-digit" }),
    }));

  return (
    <ResponsiveContainer width="100%" height={240}>
      <BarChart data={data} margin={{ top: 10, right: 16, left: 0, bottom: 0 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#e8edf4" vertical={false} />
        <XAxis dataKey="label" stroke="#8a96a8" fontSize={11} tickLine={false} axisLine={false} />
        <YAxis stroke="#8a96a8" fontSize={11} tickLine={false} axisLine={false} allowDecimals={false} />
        <Tooltip
          contentStyle={{ background: "#ffffff", border: "1px solid #e6eaf1", borderRadius: 10, fontSize: 12, boxShadow: "0 12px 30px rgba(18,35,60,.12)" }}
          labelStyle={{ color: "#7b8494" }}
        />
        <Bar dataKey="total" radius={[4, 4, 0, 0]}>
          {data.map((entry, i) => (
            <Cell key={i} fill={entry.anomalous > 0 ? "#ef6b73" : "#7da6c4"} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}