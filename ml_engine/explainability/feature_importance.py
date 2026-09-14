import numpy as np
import pandas as pd


def global_feature_importance_from_shap(
    shap_explanations: list[dict], feature_names: list[str]
) -> pd.DataFrame:
    """
    Aggregate per-sample SHAP explanations into a global feature importance ranking
    (mean absolute SHAP value per feature across all samples).
    """
    matrix = np.array([[exp.get(f, 0.0) for f in feature_names] for exp in shap_explanations])
    mean_abs_importance = np.mean(np.abs(matrix), axis=1) if matrix.ndim == 1 else np.mean(np.abs(matrix), axis=0)

    df = pd.DataFrame({
        "feature": feature_names,
        "mean_abs_shap": mean_abs_importance,
    })
    return df.sort_values("mean_abs_shap", ascending=False).reset_index(drop=True)


def isolation_forest_feature_importance(model, feature_names: list[str]) -> pd.DataFrame:
    """
    Approximate feature importance for IsolationForest using average depth
    of splits per feature across all trees (proxy importance, since sklearn's
    IsolationForest doesn't expose feature_importances_ directly).
    """
    importances = np.zeros(len(feature_names))
    counts = np.zeros(len(feature_names))

    for estimator in model.estimators_:
        tree = estimator.tree_
        for feature_idx in tree.feature:
            if feature_idx >= 0:  # -2 indicates a leaf node
                importances[feature_idx] += 1
                counts[feature_idx] += 1

    # Normalize by total splits to get a relative frequency-based importance
    total_splits = importances.sum()
    normalized = importances / total_splits if total_splits > 0 else importances

    df = pd.DataFrame({
        "feature": feature_names,
        "split_frequency_importance": normalized,
    })
    return df.sort_values("split_frequency_importance", ascending=False).reset_index(drop=True)