from pathlib import Path

import numpy as np
import pandas as pd

from feature_engineering.network_features import (
    DEFAULT_FEATURE_ORDER,
    compute_flow_features_batch,
    feature_vector_from_dict,
)


class FeaturePipeline:
    """End-to-end pipeline: raw flow dicts -> feature DataFrame -> model-ready arrays."""

    def __init__(self, feature_order: list[str] | None = None):
        self.feature_order = feature_order or DEFAULT_FEATURE_ORDER

    def transform(self, flows: list[dict]) -> pd.DataFrame:
        return compute_flow_features_batch(flows)

    def to_model_input(self, features_df: pd.DataFrame) -> np.ndarray:
        missing = [c for c in self.feature_order if c not in features_df.columns]
        if missing:
            raise ValueError(f"Missing expected feature columns: {missing}")
        return features_df[self.feature_order].to_numpy(dtype=np.float32)

    def single_flow_to_vector(self, flow: dict) -> list[float]:
        from feature_engineering.network_features import compute_flow_features
        features = compute_flow_features(flow)
        return feature_vector_from_dict(features, self.feature_order)

    def save_features(self, features_df: pd.DataFrame, path: str | Path) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        features_df.to_csv(path, index=False)

    def run_from_flows(self, flows: list[dict], output_path: str | Path | None = None) -> pd.DataFrame:
        features_df = self.transform(flows)
        if output_path:
            self.save_features(features_df, output_path)
        return features_df