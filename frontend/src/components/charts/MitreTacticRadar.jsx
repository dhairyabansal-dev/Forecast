import {
  RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Radar, ResponsiveContainer, Tooltip,
} from "recharts";

const ALL_TACTICS = [
  "reconnaissance", "initial-access", "execution", "persistence",
  "credential-access", "discovery", "lateral-movement",
  "command-and-control", "exfiltration", "impact",
];

export default function MitreTacticRadar({ threats = [] }) {
  const counts = Object.fromEntries(ALL_TACTICS.map((t) => [t, 0]));
  threats.forEach((t) => {
    if (t.mitre_tactic && counts[t.mitre_tactic] !== undefined) {
      counts[t.mitre_tactic] += 1;
    }
  });

  const data = ALL_TACTICS.map((tactic) => ({
    tactic: tactic.replace("-", " "),
    count: counts[tactic],
  }));

  return (
    <ResponsiveContainer width="100%" height={280}>
      <RadarChart data={data}>
        <PolarGrid stroke="#e8edf4" />
        <PolarAngleAxis dataKey="tactic" stroke="#8a96a8" fontSize={10} />
        <PolarRadiusAxis stroke="#e8edf4" fontSize={10} allowDecimals={false} />
        <Radar
          name="Detections"
          dataKey="count"
          stroke="#24b8d4"
          fill="#24b8d4"
          fillOpacity={0.25}
        />
        <Tooltip
          contentStyle={{ background: "#ffffff", border: "1px solid #e6eaf1", borderRadius: 10, fontSize: 12, boxShadow: "0 12px 30px rgba(18,35,60,.12)" }}
        />
      </RadarChart>
    </ResponsiveContainer>
  );
}