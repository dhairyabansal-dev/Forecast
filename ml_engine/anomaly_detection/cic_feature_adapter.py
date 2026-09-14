from __future__ import annotations

from typing import Iterable

import numpy as np
import pandas as pd

from network_engine.feature_extractor import FeatureExtractor


def _normalise_columns(dataframe: pd.DataFrame) -> pd.DataFrame:
    result = dataframe.copy()
    result.columns = [" ".join(str(column).strip().split()) for column in result.columns]
    return result


def _numeric(dataframe: pd.DataFrame, names: Iterable[str], default: float = 0.0) -> np.ndarray:
    columns = {str(column).lower(): column for column in dataframe.columns}
    for name in names:
        column = columns.get(name.lower())
        if column is not None:
            values = pd.to_numeric(dataframe[column], errors="coerce")
            return values.replace([np.inf, -np.inf], np.nan).fillna(default).to_numpy(dtype=np.float32)
    return np.full(len(dataframe), default, dtype=np.float32)


def cic_dataframe_to_live_features(dataframe: pd.DataFrame) -> np.ndarray:
    """Derive the live FeatureExtractor schema from CICFlowMeter columns."""
    dataframe = _normalise_columns(dataframe)
    forward_packets = _numeric(dataframe, ("Tot Fwd Pkts",))
    backward_packets = _numeric(dataframe, ("Tot Bwd Pkts",))
    packet_count = forward_packets + backward_packets
    forward_bytes = _numeric(dataframe, ("TotLen Fwd Pkts",))
    backward_bytes = _numeric(dataframe, ("TotLen Bwd Pkts",))
    byte_count = forward_bytes + backward_bytes
    duration = _numeric(dataframe, ("Flow Duration",)).clip(min=1.0) / 1_000_000.0
    total_packets = np.maximum(packet_count, 1.0)
    total_bytes = np.maximum(byte_count, 1.0)

    values = {
        "duration_seconds": duration,
        "packet_count": packet_count,
        "byte_count": byte_count,
        "packets_per_second": packet_count / duration,
        "bytes_per_second": byte_count / duration,
        "average_packet_size": byte_count / total_packets,
        "packet_size_std": _numeric(dataframe, ("Pkt Len Std",)),
        "min_packet_size": _numeric(dataframe, ("Pkt Len Min",)),
        "max_packet_size": _numeric(dataframe, ("Pkt Len Max",)),
        "forward_packet_ratio": forward_packets / total_packets,
        "reverse_packet_ratio": backward_packets / total_packets,
        "forward_byte_ratio": forward_bytes / total_bytes,
        "reverse_byte_ratio": backward_bytes / total_bytes,
        "syn_count": _numeric(dataframe, ("SYN Flag Cnt",)),
        "ack_count": _numeric(dataframe, ("ACK Flag Cnt",)),
        "fin_count": _numeric(dataframe, ("FIN Flag Cnt",)),
        "rst_count": _numeric(dataframe, ("RST Flag Cnt",)),
        "psh_count": _numeric(dataframe, ("PSH Flag Cnt",)),
        "urg_count": _numeric(dataframe, ("URG Flag Count", "URG Flag Cnt")),
        "interarrival_mean": _numeric(dataframe, ("Flow IAT Mean",)),
        "interarrival_std": _numeric(dataframe, ("Flow IAT Std",)),
        "source_port": _numeric(dataframe, ("Src Port", "Source Port")),
        "destination_port": _numeric(dataframe, ("Dst Port", "Destination Port")),
    }
    protocol = _numeric(dataframe, ("Protocol",))
    values["protocol_tcp"] = (protocol == 6).astype(np.float32)
    values["protocol_udp"] = (protocol == 17).astype(np.float32)

    matrix = np.column_stack([
        values[name] for name in FeatureExtractor.FEATURE_NAMES
    ]).astype(np.float32)
    return np.nan_to_num(matrix, nan=0.0, posinf=0.0, neginf=0.0)