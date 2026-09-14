import { useEffect, useState } from "react";
import { Link2, ShieldCheck, ShieldX, Loader2 } from "lucide-react";
import { listEvidence, anchorEvidence, verifyEvidence } from "../services/api.js";

const STATUS_COLORS = {
  draft: "#7b8494",
  hashed: "#fbbf24",
  anchored: "#4ade80",
  verified: "#6ee7ff",
  tampered: "#f87171",
};

export default function Evidence() {
  const [records, setRecords] = useState([]);
  const [loading, setLoading] = useState(true);
  const [busyId, setBusyId] = useState(null);
  const [verifyResults, setVerifyResults] = useState({});

  async function load() {
    setLoading(true);
    try {
      const res = await listEvidence({ page: 1, page_size: 100 });
      setRecords(res.items || []);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
  }, []);

  async function handleAnchor(id) {
    setBusyId(id);
    try {
      await anchorEvidence(id);
      await load();
    } catch (err) {
      alert(err?.response?.data?.detail || "Failed to anchor evidence");
    } finally {
      setBusyId(null);
    }
  }

  async function handleVerify(id) {
    setBusyId(id);
    try {
      const result = await verifyEvidence(id);
      setVerifyResults((prev) => ({ ...prev, [id]: result }));
    } catch (err) {
      alert(err?.response?.data?.detail || "Failed to verify evidence");
    } finally {
      setBusyId(null);
    }
  }

  return (
    <div>
      <div className="page-header">
        <div className="page-title">Evidence Vault</div>
        <div className="page-subtitle">Blockchain-anchored, tamper-evident threat evidence</div>
      </div>

      <div className="card">
        <div className="card-title">Evidence Records</div>
        {loading ? (
          <div className="loading-text">Loading evidence…</div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Title</th>
                <th>Content Hash</th>
                <th>Status</th>
                <th>Tx Hash</th>
                <th>Verification</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {records.map((e) => {
                const verifyResult = verifyResults[e.id];
                return (
                  <tr key={e.id}>
                    <td>{e.title}</td>
                    <td className="mono" title={e.content_hash}>
                      {e.content_hash.slice(0, 12)}…
                    </td>
                    <td>
                      <span style={{ color: STATUS_COLORS[e.status], fontSize: 12, fontWeight: 600, textTransform: "uppercase" }}>
                        {e.status}
                      </span>
                    </td>
                    <td className="mono">
                      {e.blockchain_tx_hash ? `${e.blockchain_tx_hash.slice(0, 10)}…` : "—"}
                    </td>
                    <td>
                      {verifyResult ? (
                        verifyResult.is_valid ? (
                          <span style={{ color: "#4ade80", fontSize: 12 }}>
                            <ShieldCheck size={13} style={{ verticalAlign: "middle", marginRight: 4 }} />
                            Verified on-chain
                          </span>
                        ) : (
                          <span style={{ color: "#f87171", fontSize: 12 }}>
                            <ShieldX size={13} style={{ verticalAlign: "middle", marginRight: 4 }} />
                            {verifyResult.message}
                          </span>
                        )
                      ) : (
                        <span style={{ color: "#7b8494", fontSize: 12 }}>Not checked</span>
                      )}
                    </td>
                    <td style={{ display: "flex", gap: 6 }}>
                      {e.status !== "anchored" && e.status !== "verified" && (
                        <button
                          className="btn"
                          style={{ padding: "4px 10px", fontSize: 12 }}
                          onClick={() => handleAnchor(e.id)}
                          disabled={busyId === e.id}
                        >
                          {busyId === e.id ? <Loader2 size={12} className="spin" /> : <Link2 size={12} />}
                          {" "}Anchor
                        </button>
                      )}
                      {(e.status === "anchored" || e.status === "verified") && (
                        <button
                          className="btn"
                          style={{ padding: "4px 10px", fontSize: 12 }}
                          onClick={() => handleVerify(e.id)}
                          disabled={busyId === e.id}
                        >
                          {busyId === e.id ? "…" : "Verify"}
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })}
              {records.length === 0 && (
                <tr><td colSpan={6} className="loading-text">No evidence records yet</td></tr>
              )}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}