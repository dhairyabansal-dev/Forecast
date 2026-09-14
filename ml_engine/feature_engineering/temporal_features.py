from datetime import datetime

import numpy as np
import pandas as pd


def aggregate_to_time_buckets(
    events: pd.DataFrame,
    timestamp_col: str = "detected_at",
    bucket_minutes: int = 60,
    value_cols: list[str] | None = None,
) -> pd.DataFrame:
    """
    Aggregate irregular events (e.g. anomalies/threats) into fixed-size time buckets
    for feeding into the temporal forecasting model.
    """
    df = events.copy()
    df[timestamp_col] = pd.to_datetime(df[timestamp_col])
    df = df.set_index(timestamp_col).sort_index()

    freq = f"{bucket_minutes}min"
    agg = {"event_count": ("flow_id", "count")} if "flow_id" in df.columns else {}

    resampled = df.resample(freq)

    result = pd.DataFrame()
    result["event_count"] = resampled.size()

    if value_cols:
        for col in value_cols:
            if col in df.columns:
                result[f"{col}_mean"] = resampled[col].mean()
                result[f"{col}_max"] = resampled[col].max()

    result = result.fillna(0.0)
    return result.reset_index()


def build_threat_level_series(
    bucketed: pd.DataFrame,
    event_count_col: str = "event_count",
    severity_weight_col: str | None = "anomaly_score_mean",
) -> np.ndarray:
    """
    Combine event frequency and severity into a single normalized threat-level
    series in [0, 1], used as the target the temporal model learns to predict.
    """
    counts = bucketed[event_count_col].to_numpy(dtype=np.float64)
    normalized_counts = counts / (counts.max() + 1e-6)

    if severity_weight_col and severity_weight_col in bucketed.columns:
        severity = bucketed[severity_weight_col].to_numpy(dtype=np.float64)
        severity_norm = (severity - severity.min()) / (severity.max() - severity.min() + 1e-6)
        threat_level = 0.6 * normalized_counts + 0.4 * severity_norm
    else:
        threat_level = normalized_counts

    return np.clip(threat_level, 0.0, 1.0)


def make_sliding_windows(
    series: np.ndarray, sequence_length: int, horizon: int
) -> tuple[np.ndarray, np.ndarray]:
    """
    Build (X, y) training pairs from a 1D time series using a sliding window:
    X[i] = series[i : i+sequence_length]
    y[i] = series[i+sequence_length : i+sequence_length+horizon]
    """
    X, y = [], []
    for start in range(len(series) - sequence_length - horizon + 1):
        X.append(series[start : start + sequence_length])
        y.append(series[start + sequence_length : start + sequence_length + horizon])
    return np.array(X), np.array(y)