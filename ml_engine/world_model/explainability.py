import numpy as np

from ml_engine.world_model.state_representation import STATE_DIMENSIONS
from ml_engine.world_model.state_transition_model import rollout_k_steps


def perturbation_attribution(model, window: np.ndarray, k: int = 1, epsilon: float = 0.1) -> dict:
    """
    Feature attribution via input perturbation: for each state dimension in
    the most recent observed window step, perturb it slightly and measure
    the change in predicted infiltration risk at step k. Larger change =
    that feature is driving the prediction more. This is a lightweight,
    model-agnostic stand-in for SHAP that works directly on the sequence
    model without needing a differentiable-through-time SHAP explainer.
    """
    _, _, baseline_logits = rollout_k_steps(
        model,
        window,
        k=k,
        return_risk_logits=True
    )
    baseline_logit = baseline_logits[k - 1]

    attributions = {}
    for i, dim_name in enumerate(STATE_DIMENSIONS):
        perturbed = window.copy()
        perturbed[-1, i] += epsilon  # nudge the most recent observed state

        _, _, perturbed_logits = rollout_k_steps(
            model,
            perturbed,
            k=k,
            return_risk_logits=True
        )
        perturbed_logit = perturbed_logits[k - 1]

        attributions[dim_name] = float(perturbed_logit - baseline_logit)

    return attributions


def top_contributing_features(attributions: dict, n: int = 3) -> list[str]:
    ranked = sorted(attributions.items(), key=lambda kv: abs(kv[1]), reverse=True)
    return [name for name, _ in ranked[:n]]


def summarize_attribution(attributions: dict, n: int = 3) -> str:
    top = top_contributing_features(attributions, n)
    parts = []
    for feat in top:
        direction = "increases" if attributions[feat] > 0 else "decreases"
        parts.append(f"{feat} {direction} predicted infiltration risk")
    return "; ".join(parts)