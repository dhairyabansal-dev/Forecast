from typing import Optional

import numpy as np
import shap


class AnomalyExplainer:
    """
    Wraps SHAP's TreeExplainer/KernelExplainer to explain why the Isolation
    Forest flagged a given flow as anomalous.
    """

    def __init__(self, model, background_data: Optional[np.ndarray] = None):
        """
        model: the underlying sklearn IsolationForest (not the wrapper class)
        background_data: a small representative sample used as the SHAP baseline
        """
        self.model = model

        if background_data is not None:
            # KernelExplainer works generically with any model.decision_function
            self.explainer = shap.KernelExplainer(
                model.decision_function, shap.sample(background_data, min(100, len(background_data)))
            )
        else:
            self.explainer = shap.TreeExplainer(model)

    def explain(self, X: np.ndarray, feature_names: list[str]) -> list[dict]:
        """
        X: (n_samples, n_features)
        Returns a list of dicts per sample: {feature_name: shap_value}
        """
        shap_values = self.explainer.shap_values(X)

        results = []
        for row in shap_values:
            results.append({name: float(val) for name, val in zip(feature_names, row)})
        return results

    def top_features(self, explanation: dict, n: int = 3) -> list[str]:
        """Return the top-N features by absolute SHAP value magnitude."""
        sorted_features = sorted(explanation.items(), key=lambda kv: abs(kv[1]), reverse=True)
        return [name for name, _ in sorted_features[:n]]

    def summarize(self, explanation: dict, n: int = 3) -> str:
        top = self.top_features(explanation, n)
        parts = []
        for feature in top:
            value = explanation[feature]
            direction = "increased" if value < 0 else "decreased"
            # Note: for IsolationForest, lower decision_function = more anomalous,
            # so a negative SHAP contribution means that feature pushed toward anomaly.
            parts.append(f"{feature} {direction} anomaly likelihood")
        return "; ".join(parts) if parts else "No significant contributing features identified."