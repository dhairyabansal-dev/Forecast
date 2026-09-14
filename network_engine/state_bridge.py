"""
Bridges live-captured NetworkFlow objects (from flow_tracker.py) into the
world model's state-vector format, so real captured traffic can drive the
K-step infiltration forecast instead of synthetic data.
"""
from typing import Iterable

import numpy as np

from ml_engine.world_model.state_representation import (
    STATE_DIMENSIONS,
    STATE_DIM,
    STATE_SCALE_HINTS,
    normalize_raw_features as normalize_state_features,
    validate_state_dimensions,
)

from .flow_tracker import NetworkFlow


def _port_scan_score(flows: list[NetworkFlow]) -> float:
    """Heuristic: many distinct destination ports from the same source in a short window."""
    if len(flows) < 2:
        return 0.0
    ports = {f.destination_port for f in flows if f.destination_port}
    return min(len(ports) / max(len(flows), 1), 1.0)


def _iat_variance(flow: NetworkFlow) -> float:
    if len(flow.timestamps) < 2:
        return 0.0
    diffs = np.diff(sorted(flow.timestamps))
    return float(np.var(diffs)) if len(diffs) > 0 else 0.0


def flow_to_raw_features(flow: NetworkFlow, sibling_flows: list[NetworkFlow]) -> dict:
    """Convert one NetworkFlow (plus its sibling flows sharing the same src_ip) into raw features."""
    total_syn_ack = max(
        flow.tcp_flags["SYN"] + flow.tcp_flags["ACK"],
        1.0
    )
    total_bytes = max(flow.byte_count, 1)

    return {
        "flow_rate": flow.packets_per_second(),
        "syn_flag_ratio": flow.tcp_flags["SYN"] / total_syn_ack,
        "port_scan_score": _port_scan_score(sibling_flows),
        "avg_packet_size": float(np.mean(flow.packet_sizes)) if flow.packet_sizes else 0.0,
        "iat_variance": _iat_variance(flow),
        "bytes_asymmetry": abs(flow.forward_bytes - flow.reverse_bytes) / total_bytes,
        "unique_dst_ip_count": len({f.destination_ip for f in sibling_flows}),
        "retransmission_rate": 0.0,  # not tracked yet in flow_tracker; safe default
    }


def normalize_raw_features(raw: dict, scale_hints: dict) -> np.ndarray:
    """
    Squash raw features into roughly [0,1] using simple scale hints, so they're
    comparable to the MITRE stage centroids (which are defined in 0-1 space).
    scale_hints: {dimension_name: approximate_max_value}
    """
    validate_state_dimensions(STATE_DIMENSIONS, "live state")
    return normalize_state_features(raw, scale_hints)


DEFAULT_SCALE_HINTS = STATE_SCALE_HINTS


def flows_to_state_trajectory(
    flows: Iterable[NetworkFlow], scale_hints: dict | None = None
) -> np.ndarray:
    """
    Convert a list of captured flows (ordered by time) into a state-vector
    trajectory the world model can consume. Each flow becomes one "state" step.
    """
    scale_hints = scale_hints or DEFAULT_SCALE_HINTS
    validate_state_dimensions(STATE_DIMENSIONS, "live state")
    flows = list(flows)

    trajectory = []
    for i, flow in enumerate(flows):
        siblings = [f for f in flows if f.source_ip == flow.source_ip]
        raw = flow_to_raw_features(flow, siblings)
        vec = normalize_raw_features(raw, scale_hints)
        trajectory.append(vec)

    result = (
        np.array(trajectory, dtype=np.float32)
        if trajectory
        else np.zeros((1, STATE_DIM), dtype=np.float32)
    )
    if result.ndim != 2 or result.shape[1] != STATE_DIM:
        raise ValueError(
            f"Live trajectory must have shape (n, {STATE_DIM}), received {result.shape}"
        )
    return result