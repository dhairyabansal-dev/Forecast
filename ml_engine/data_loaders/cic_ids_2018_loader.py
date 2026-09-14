import pandas as pd
import numpy as np

from ml_engine.world_model.state_representation import (
    STATE_DIMENSIONS,
    normalize_raw_features,
)

# Maps CIC-IDS-2018's actual CSV column names to our internal state schema.
# CIC-IDS-2018 uses CICFlowMeter output columns (with leading spaces in some releases).
CIC_IDS_2018_COLUMN_MAP = {
    "Flow Duration": "flow_duration",
    "Tot Fwd Pkts": "fwd_packets",
    "Tot Bwd Pkts": "bwd_packets",
    "TotLen Fwd Pkts": "fwd_bytes",
    "TotLen Bwd Pkts": "bwd_bytes",
    "Flow Byts/s": "bytes_per_second",
    "Flow Pkts/s": "packets_per_second",
    "Flow IAT Mean": "iat_mean",
    "Flow IAT Std": "iat_std",
    "SYN Flag Cnt": "syn_count",
    "ACK Flag Cnt": "ack_count",
    "Label": "label",
}


def load_cic_ids_2018(csv_path: str, nrows: int | None = None) -> pd.DataFrame:
    """Load a CIC-IDS-2018 CSV and rename to our internal schema where columns match."""
    df = pd.read_csv(csv_path, nrows=nrows, low_memory=False)
    df.columns = [c.strip() for c in df.columns]  # CIC-IDS-2018 CSVs often have leading spaces

    available = {k: v for k, v in CIC_IDS_2018_COLUMN_MAP.items() if k in df.columns}
    df = df.rename(columns=available)

    return df


def derive_state_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Derive our 8-dim state vector columns from CIC-IDS-2018 raw fields.
    This is what lets the same world model train on CIC-IDS-2018 data.
    """
    row_count = len(df)

    def series(name: str) -> pd.Series:
        value = df.get(name)
        if value is None:
            return pd.Series(np.zeros(row_count), index=df.index, dtype=np.float32)
        return pd.to_numeric(value, errors="coerce").fillna(0.0)

    forward_packets = series("fwd_packets")
    backward_packets = series("bwd_packets")
    total_packets = forward_packets + backward_packets
    forward_bytes = series("fwd_bytes")
    backward_bytes = series("bwd_bytes")
    total_bytes = forward_bytes + backward_bytes
    duration_s = series("flow_duration").clip(lower=1.0) / 1_000_000
    syn = series("syn_count")
    ack = series("ack_count")

    raw = {
        "flow_rate": total_packets / duration_s.clip(lower=1e-6),
        "syn_flag_ratio": syn / (syn + ack).clip(lower=1.0),
        "port_scan_score": np.zeros(row_count),
        "avg_packet_size": total_bytes / total_packets.clip(lower=1.0),
        "iat_variance": series("iat_std") ** 2,
        "bytes_asymmetry": (forward_bytes - backward_bytes).abs() / total_bytes.clip(lower=1.0),
        "unique_dst_ip_count": np.ones(row_count),
        "retransmission_rate": np.zeros(row_count),
    }
    state_matrix = np.asarray([
        normalize_raw_features({dimension: raw[dimension].iloc[row] if isinstance(raw[dimension], pd.Series) else raw[dimension][row] for dimension in STATE_DIMENSIONS})
        for row in range(row_count)
    ], dtype=np.float32).reshape(row_count, len(STATE_DIMENSIONS))

    out = pd.DataFrame(state_matrix, columns=STATE_DIMENSIONS, index=df.index)

    if "label" in df.columns:
        out["label"] = (df["label"].astype(str).str.strip().str.upper() != "BENIGN").astype(int)

    return out[STATE_DIMENSIONS + (["label"] if "label" in out.columns else [])]