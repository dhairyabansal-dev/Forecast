import numpy as np

from ml_engine.world_model.state_representation import STATE_DIMENSIONS

# Each MITRE stage is characterized by a rough "centroid" over the state
# dimensions — e.g. Reconnaissance looks like high port_scan_score + high
# unique_dst_ip_count + low bytes; Exfiltration looks like high bytes_asymmetry
# + sustained flow_rate. These centroids are illustrative priors; in a full
# build they'd be fit from labelled attack-stage segments in CIC-IDS-2018/CTU-13.
STAGE_CENTROIDS = {
    "reconnaissance": {
        "flow_rate": 0.7, "syn_flag_ratio": 0.6, "port_scan_score": 0.9,
        "avg_packet_size": 0.2, "iat_variance": 0.3, "bytes_asymmetry": 0.2,
        "unique_dst_ip_count": 0.8, "retransmission_rate": 0.1,
    },
    "initial-access": {
        "flow_rate": 0.4, "syn_flag_ratio": 0.5, "port_scan_score": 0.3,
        "avg_packet_size": 0.5, "iat_variance": 0.4, "bytes_asymmetry": 0.3,
        "unique_dst_ip_count": 0.3, "retransmission_rate": 0.2,
    },
    "lateral-movement": {
        "flow_rate": 0.5, "syn_flag_ratio": 0.3, "port_scan_score": 0.4,
        "avg_packet_size": 0.4, "iat_variance": 0.2, "bytes_asymmetry": 0.2,
        "unique_dst_ip_count": 0.6, "retransmission_rate": 0.15,
    },
    "command-and-control": {
        "flow_rate": 0.3, "syn_flag_ratio": 0.2, "port_scan_score": 0.1,
        "avg_packet_size": 0.3, "iat_variance": 0.15, "bytes_asymmetry": 0.4,
        "unique_dst_ip_count": 0.2, "retransmission_rate": 0.1,
    },
    "exfiltration": {
        "flow_rate": 0.6, "syn_flag_ratio": 0.1, "port_scan_score": 0.05,
        "avg_packet_size": 0.8, "iat_variance": 0.1, "bytes_asymmetry": 0.9,
        "unique_dst_ip_count": 0.1, "retransmission_rate": 0.05,
    },
}


def _centroid_vector(stage: str) -> np.ndarray:
    centroid = STAGE_CENTROIDS[stage]
    return np.array([centroid[dim] for dim in STATE_DIMENSIONS], dtype=np.float32)


def map_state_to_stage(normalized_state: np.ndarray) -> dict:
    """
    Given a normalized (0-1 range) predicted state vector, find the nearest
    MITRE stage centroid by Euclidean distance, and return a confidence score
    (inverse-distance based) alongside the match.
    """
    distances = {
        stage: float(np.linalg.norm(normalized_state - _centroid_vector(stage)))
        for stage in STAGE_CENTROIDS
    }
    best_stage = min(distances, key=distances.get)
    max_dist = max(distances.values()) + 1e-6
    confidence = 1.0 - (distances[best_stage] / max_dist)

    return {
        "predicted_stage": best_stage,
        "confidence": round(confidence, 3),
        "distances": {k: round(v, 3) for k, v in distances.items()},
    }


def map_rollout_to_stages(predicted_states: np.ndarray) -> list[dict]:
    """Apply stage mapping across every step of a K-step rollout."""
    # clip/normalize into roughly [0,1] for centroid comparison
    clipped = np.clip(predicted_states, 0, 1)
    return [map_state_to_stage(clipped[i]) for i in range(len(clipped))]