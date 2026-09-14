import numpy as np

# The network "state" at time t is a small feature vector summarizing
# aggregate flow/packet behavior in that time window — this is what the
# world model learns to predict forward, instead of a single scalar.
STATE_DIMENSIONS = [
    "flow_rate",          # flows per second in this window
    "syn_flag_ratio",     # fraction of packets with SYN flag set
    "port_scan_score",    # sequential/randomized port access indicator
    "avg_packet_size",
    "iat_variance",       # inter-arrival time variance (timing irregularity)
    "bytes_asymmetry",    # |src_bytes - dst_bytes| / total_bytes
    "unique_dst_ip_count",
    "retransmission_rate",
]

STATE_DIM = len(STATE_DIMENSIONS)

STATE_SCALE_HINTS = {
    "flow_rate": 1000.0,
    "syn_flag_ratio": 1.0,
    "port_scan_score": 1.0,
    "avg_packet_size": 1500.0,
    "iat_variance": 5.0,
    "bytes_asymmetry": 1.0,
    "unique_dst_ip_count": 20.0,
    "retransmission_rate": 1.0,
}


def validate_state_dimensions(
    dimensions: list[str] | tuple[str, ...],
    context: str = "state vector"
) -> None:
    expected = tuple(STATE_DIMENSIONS)
    actual = tuple(dimensions)

    if actual != expected:
        raise ValueError(
            f"{context} dimensions/order mismatch: expected {list(expected)}, "
            f"received {list(actual)}"
        )


def normalize_raw_features(
    raw: dict[str, float],
    scale_hints: dict[str, float] | None = None
) -> np.ndarray:
    """Normalize raw state features with the fixed live/training scales."""
    validate_state_dimensions(STATE_DIMENSIONS, "canonical state")
    scales = scale_hints or STATE_SCALE_HINTS
    vector = np.zeros(STATE_DIM, dtype=np.float32)

    for index, dimension in enumerate(STATE_DIMENSIONS):
        scale = float(scales.get(dimension, 1.0))
        if scale <= 0:
            raise ValueError(f"Scale for state dimension '{dimension}' must be positive")
        vector[index] = np.clip(float(raw.get(dimension, 0.0)) / scale, 0.0, 1.0)

    return vector


def build_state_vector(window_features: dict) -> np.ndarray:
    """Extract the 8-dim state vector from a dict of window-aggregated features."""
    validate_state_dimensions(STATE_DIMENSIONS, "canonical state")
    return np.array(
        [float(window_features.get(name, 0.0)) for name in STATE_DIMENSIONS],
        dtype=np.float32,
    )


def state_vector_to_dict(vec: np.ndarray) -> dict:
    return {name: float(vec[i]) for i, name in enumerate(STATE_DIMENSIONS)}


def normalize_state(vec: np.ndarray, stats: dict) -> np.ndarray:
    """Normalize using precomputed per-dimension mean/std (stats = {'mean': [...], 'std': [...]})."""
    mean = np.array(stats["mean"], dtype=np.float32)
    std = np.array(stats["std"], dtype=np.float32) + 1e-6
    return (vec - mean) / std


def denormalize_state(vec: np.ndarray, stats: dict) -> np.ndarray:
    mean = np.array(stats["mean"], dtype=np.float32)
    std = np.array(stats["std"], dtype=np.float32) + 1e-6
    return vec * std + mean