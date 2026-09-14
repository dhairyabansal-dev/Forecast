"""
Fully offline demo entry point for the SIH prototype.
Usage:
    python scripts/offline_world_model_demo.py --input path/to/flows.csv
    python scripts/offline_world_model_demo.py --synthetic   (no file needed, generates demo data)

Runs the full pipeline: load traffic -> build state vectors -> world model
K-step rollout -> MITRE stage mapping -> explainability -> baseline comparison.
No database, no web server, no blockchain dependency.
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "ml-engine"))

import numpy as np
import pandas as pd
import torch

from ml_engine.world_model.state_representation import STATE_DIMENSIONS, STATE_DIM
from ml_engine.world_model.state_transition_model import NetworkStateTransitionModel, rollout_k_steps
from ml_engine.world_model.attack_stage_mapper import map_rollout_to_stages
from ml_engine.world_model.explainability import perturbation_attribution, summarize_attribution
from ml_engine.baselines.logistic_regression_baseline import run_baseline_comparison, print_comparison_table


def generate_synthetic_trajectory(n_steps: int = 60, attack_onset: int = 40) -> np.ndarray:
    """
    Builds a synthetic state-vector trajectory that starts benign and
    escalates into a port-scan-like pattern after `attack_onset`, so the
    demo has a visible narrative arc for the judges.
    """
    rng = np.random.default_rng(42)
    states = np.zeros((n_steps, STATE_DIM), dtype=np.float32)

    for t in range(n_steps):
        if t < attack_onset:
            states[t] = rng.normal(loc=0.15, scale=0.05, size=STATE_DIM).clip(0, 1)
        else:
            escalation = min((t - attack_onset) / 15, 1.0)
            states[t] = rng.normal(loc=0.15 + 0.6 * escalation, scale=0.08, size=STATE_DIM).clip(0, 1)

    return states


def print_rollout_report(predicted_states: np.ndarray, risk_scores: np.ndarray, stages: list[dict]):
    print("\n=== K-Step Forward Simulation ===")
    print(f"{'Step':<6}{'Infiltration Risk':<20}{'Predicted Stage':<22}{'Confidence':<12}")
    print("-" * 60)
    for i in range(len(predicted_states)):
        print(
            f"t+{i+1:<4}"
            f"{risk_scores[i]*100:>6.1f}%             "
            f"{stages[i]['predicted_stage']:<22}"
            f"{stages[i]['confidence']*100:.1f}%"
        )


def main():
    parser = argparse.ArgumentParser(description="Offline world-model infiltration forecasting demo")
    parser.add_argument("--input", help="Path to a CIC-IDS-2018 style CSV (optional)")
    parser.add_argument("--synthetic", action="store_true", help="Use synthetic demo trajectory")
    parser.add_argument("--window", type=int, default=20, help="Observed window length fed to the model")
    parser.add_argument("--k", type=int, default=12, help="Number of future steps to roll out")
    args = parser.parse_args()

    if args.input:
        from ml_engine.data_loaders.cic_ids_2018_loader import load_cic_ids_2018, derive_state_features
        print(f"Loading real traffic data from {args.input} ...")
        raw = load_cic_ids_2018(args.input, nrows=5000)
        state_df = derive_state_features(raw)
        trajectory = state_df[STATE_DIMENSIONS].to_numpy(dtype=np.float32)
        labels = state_df["label"].to_numpy() if "label" in state_df.columns else None
    else:
        print("Using synthetic demo trajectory (no --input file provided) ...")
        trajectory = generate_synthetic_trajectory()
        labels = None

    if len(trajectory) < args.window:
        print(f"Not enough data ({len(trajectory)} rows) for window={args.window}, reducing window.")
        args.window = max(4, len(trajectory) - 1)

    window = trajectory[-args.window:]

    # Untrained model for demo purposes — in production this is loaded from
    # ml-engine/saved_models/world_model.pt after running the training pipeline.
    model = NetworkStateTransitionModel(state_dim=STATE_DIM)
    model.eval()

    predicted_states, risk_scores = rollout_k_steps(model, window, k=args.k)
    stages = map_rollout_to_stages(predicted_states)

    print_rollout_report(predicted_states, risk_scores, stages)

    print("\n=== Explainability (feature attribution for t+1 prediction) ===")
    attributions = perturbation_attribution(model, window, k=1)
    for dim, val in sorted(attributions.items(), key=lambda kv: abs(kv[1]), reverse=True):
        print(f"  {dim:<22} {val:+.4f}")
    print(f"\nSummary: {summarize_attribution(attributions)}")

    if labels is not None and len(set(labels)) > 1:
        print("\n=== Baseline Comparison: Logistic Regression vs Isolation Forest ===")
        results = run_baseline_comparison(trajectory, labels)
        print_comparison_table(results)
    else:
        print("\n(Baseline comparison skipped — provide labelled --input data to enable it.)")


if __name__ == "__main__":
    main()