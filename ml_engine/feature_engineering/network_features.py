import numpy as np
import pandas as pd


def compute_flow_features(flow: dict) -> dict:
    """
    Compute statistical features for a single network flow.
    `flow` is expected to have: packet_sizes (list), timestamps (list),
    duration_seconds, protocol, src_bytes, dst_bytes, packet_count.
    """
    packet_sizes = np.array(flow.get("packet_sizes", []), dtype=np.float64)
    timestamps = np.array(flow.get("timestamps", []), dtype=np.float64)

    duration = float(flow.get("duration_seconds", 0.0)) or 1e-6
    packet_count = int(flow.get("packet_count", len(packet_sizes)))
    src_bytes = float(flow.get("src_bytes", 0.0))
    dst_bytes = float(flow.get("dst_bytes", 0.0))
    total_bytes = src_bytes + dst_bytes

    inter_arrival_times = np.diff(timestamps) if len(timestamps) > 1 else np.array([0.0])

    features = {
        "packet_count": packet_count,
        "total_bytes": total_bytes,
        "src_bytes": src_bytes,
        "dst_bytes": dst_bytes,
        "byte_ratio": src_bytes / (dst_bytes + 1e-6),
        "duration_seconds": duration,
        "packets_per_second": packet_count / duration,
        "bytes_per_second": total_bytes / duration,
        "avg_packet_size": float(np.mean(packet_sizes)) if len(packet_sizes) else 0.0,
        "std_packet_size": float(np.std(packet_sizes)) if len(packet_sizes) else 0.0,
        "min_packet_size": float(np.min(packet_sizes)) if len(packet_sizes) else 0.0,
        "max_packet_size": float(np.max(packet_sizes)) if len(packet_sizes) else 0.0,
        "avg_inter_arrival_time": float(np.mean(inter_arrival_times)),
        "std_inter_arrival_time": float(np.std(inter_arrival_times)),
        "is_tcp": 1.0 if str(flow.get("protocol", "")).upper() == "TCP" else 0.0,
        "is_udp": 1.0 if str(flow.get("protocol", "")).upper() == "UDP" else 0.0,
    }

    return features


def compute_flow_features_batch(flows: list[dict]) -> pd.DataFrame:
    rows = []
    for flow in flows:
        row = compute_flow_features(flow)
        row["flow_id"] = flow.get("flow_id")
        row["src_ip"] = flow.get("src_ip")
        row["dst_ip"] = flow.get("dst_ip")
        rows.append(row)
    return pd.DataFrame(rows)


def feature_vector_from_dict(features: dict, feature_order: list[str]) -> list[float]:
    """Extract features in a consistent order for model inference."""
    return [float(features.get(name, 0.0)) for name in feature_order]


DEFAULT_FEATURE_ORDER = [
    "packet_count",
    "total_bytes",
    "src_bytes",
    "dst_bytes",
    "byte_ratio",
    "duration_seconds",
    "packets_per_second",
    "bytes_per_second",
    "avg_packet_size",
    "std_packet_size",
    "avg_inter_arrival_time",
    "std_inter_arrival_time",
]