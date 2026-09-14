const now = Date.now();

export const demoAnomalies = [
  { id: "demo-a1", flow_id: "flow-demo-001", src_ip: "10.10.4.21", dst_ip: "185.199.108.153", src_port: 51824, dst_port: 443, protocol: "TCP", anomaly_score: 0.94, is_anomalous: true, status: "confirmed", detected_at: new Date(now - 4 * 60000).toISOString() },
  { id: "demo-a2", flow_id: "flow-demo-002", src_ip: "10.10.8.14", dst_ip: "10.10.1.5", src_port: 49152, dst_port: 445, protocol: "TCP", anomaly_score: 0.81, is_anomalous: true, status: "pending", detected_at: new Date(now - 9 * 60000).toISOString() },
  { id: "demo-a3", flow_id: "flow-demo-003", src_ip: "10.10.3.77", dst_ip: "8.8.8.8", src_port: 53412, dst_port: 53, protocol: "UDP", anomaly_score: 0.37, is_anomalous: false, status: "false_positive", detected_at: new Date(now - 15 * 60000).toISOString() },
  { id: "demo-a4", flow_id: "flow-demo-004", src_ip: "10.10.6.44", dst_ip: "172.16.0.9", src_port: 49821, dst_port: 3389, protocol: "TCP", anomaly_score: 0.73, is_anomalous: true, status: "pending", detected_at: new Date(now - 22 * 60000).toISOString() },
];

export const demoThreats = [
  { id: "demo-t1", title: "Credential Access Pattern Detected", description: "Unusual outbound authentication traffic.", severity: "critical", src_ip: "10.10.4.21", dst_ip: "185.199.108.153", mitre_technique_id: "T1078", mitre_tactic: "credential-access", confidence_score: 0.96, is_resolved: false, detected_at: new Date(now - 4 * 60000).toISOString() },
  { id: "demo-t2", title: "Internal SMB Lateral Movement", description: "Abnormal SMB connections across protected segments.", severity: "high", src_ip: "10.10.8.14", dst_ip: "10.10.1.5", mitre_technique_id: "T1021.002", mitre_tactic: "lateral-movement", confidence_score: 0.89, is_resolved: false, detected_at: new Date(now - 9 * 60000).toISOString() },
  { id: "demo-t3", title: "Suspicious DNS Beaconing", description: "Periodic DNS traffic matched beaconing cadence.", severity: "medium", src_ip: "10.10.3.77", dst_ip: "8.8.8.8", mitre_technique_id: "T1071.004", mitre_tactic: "command-and-control", confidence_score: 0.72, is_resolved: true, detected_at: new Date(now - 15 * 60000).toISOString() },
];

export const demoEvidence = [
  { id: "demo-e1", title: "Credential Access Evidence", content_hash: "a4f2e8c9d17b6a55d6c1f3e8b4a9012233445566778899aabbccddeeff00112233", status: "hashed", blockchain_tx_hash: null },
  { id: "demo-e2", title: "SMB Movement Evidence", content_hash: "b7c9e1a2d3f405162738495a6b7c8d9e00112233445566778899aabbccddeeff00", status: "anchored", blockchain_tx_hash: "0x9f4a7b21d4e8c2aa11b5d7e1f4c0a9b8d6e5f43210abcdef1234567890abcdef12" },
  { id: "demo-e3", title: "DNS Beacon Evidence", content_hash: "c8d0f2b3e4a5162738495a6b7c8d9e00112233445566778899aabbccddeeff0011", status: "verified", blockchain_tx_hash: "0x1a2b3c4d5e6f78900112233445566778899aabbccddeeff001122334455667788" },
];

export function makeDemoForecast(horizon = 24) {
  const points = Array.from({ length: horizon }, (_, i) => {
    const wave = 0.34 + 0.12 * Math.sin(i / 3.2) + 0.015 * i;
    const value = Math.max(0.08, Math.min(0.92, wave));
    const timestamp = new Date(now + (i + 1) * 3600000).toISOString();
    return {
      timestamp,
      predicted_threat_level: value,
      lower_bound: Math.max(0, value - 0.08),
      upper_bound: Math.min(1, value + 0.08),
      predicted_stage: value > 0.7 ? "Escalation" : value > 0.45 ? "Elevated" : "Stable",
    };
  });
  return {
    id: "demo-forecast",
    horizon_hours: horizon,
    sequence_length: 48,
    confidence: "high",
    model_version: "v1-demo-temporal",
    points,
    peak_threat_level: Math.max(...points.map((p) => p.predicted_threat_level)),
    generated_at: new Date().toISOString(),
  };
}
