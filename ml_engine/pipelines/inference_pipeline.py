import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import numpy as np

from anomaly_detection.isolation_forest import AnomalyDetector
from explainability.shap_explainer import AnomalyExplainer
from feature_engineering.feature_pipeline import FeaturePipeline


class InferencePipeline:
    """
    Runs the full anomaly-detection inference chain for a batch of raw flows:
    feature extraction -> scoring -> (optional) SHAP explanation.
    """

    def __init__(
        self,
        anomaly_model_path: str,
        background_sample: np.ndarray | None = None,
    ):
        self.pipeline = FeaturePipeline()
        self.detector = AnomalyDetector.load(anomaly_model_path)
        self.explainer = (
            AnomalyExplainer(self.detector.model, background_data=background_sample)
            if background_sample is not None
            else None
        )

    def run(self, flows: list[dict], explain: bool = False) -> list[dict]:
        features_df = self.pipeline.transform(flows)
        X = self.pipeline.to_model_input(features_df)

        scores = self.detector.decision_function(X)
        predictions = self.detector.predict(X)

        results = []
        for i, flow in enumerate(flows):
            entry = {
                "flow_id": flow.get("flow_id"),
                "src_ip": flow.get("src_ip"),
                "dst_ip": flow.get("dst_ip"),
                "anomaly_score": float(scores[i]),
                "is_anomalous": bool(predictions[i] == -1),
            }

            if explain and self.explainer is not None:
                explanation = self.explainer.explain(X[i:i+1], self.pipeline.feature_order)[0]
                entry["explanation"] = explanation
                entry["top_features"] = self.explainer.top_features(explanation)
                entry["explanation_summary"] = self.explainer.summarize(explanation)

            results.append(entry)

        return results