export default function StatCard({ title, value, trend, trendDirection }) {
  return (
    <div className="card">
      <div className="card-title">{title}</div>
      <div className="card-value">{value}</div>
      {trend && (
        <div className={`card-trend ${trendDirection === "up" ? "trend-up" : "trend-down"}`}>
          {trend}
        </div>
      )}
    </div>
  );
}