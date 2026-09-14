import argparse
import sys
import time
from pathlib import Path

import torch

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from app.core.config import settings
from network_engine.capture import NetworkCapture
from network_engine.flow_tracker import FlowTracker
from network_engine.state_bridge import flows_to_state_trajectory

from ml_engine.world_model.state_representation import (
    STATE_DIM,
    STATE_DIMENSIONS,
    STATE_SCALE_HINTS,
    validate_state_dimensions,
)
from ml_engine.world_model.state_transition_model import NetworkStateTransitionModel, rollout_k_steps
from ml_engine.world_model.attack_stage_mapper import map_rollout_to_stages
from ml_engine.world_model.explainability import perturbation_attribution, summarize_attribution


def try_live_capture(duration: int, packet_limit: int = 2000):
    try:
        tracker = FlowTracker()

        def on_packet(pkt):
            tracker.process_packet(pkt)

        capture = NetworkCapture(
            packet_callback=on_packet,
            packet_limit=packet_limit
        )

        started = capture.start()

        if not started:
            print("[!] Could not start live capture.")
            return None

        print(f"[*] Capturing live traffic for {duration}s (browse something now)...")

        time.sleep(duration)

        capture.stop()

        flows = tracker.get_active_flows()

        if not flows:
            print("[!] No live flows captured.")
            return None

        print(f"[+] Captured {len(flows)} real flows.")

        return flows

    except Exception as e:
        print(f"[!] Live capture failed ({e}).")
        return None


def generate_synthetic_fallback():
    try:
        from scripts.offline_world_model_demo import generate_synthetic_trajectory
    except ModuleNotFoundError:
        from offline_world_model_demo import generate_synthetic_trajectory

    print("[!] Using synthetic trajectory because live capture failed.")
    return generate_synthetic_trajectory()


def load_trained_model(model_path: str | Path | None = None):
    configured_path = Path(model_path or settings.WORLD_MODEL_PATH)
    if not configured_path.is_absolute():
        configured_path = ROOT_DIR / configured_path
    model_path = configured_path.resolve()

    if not model_path.exists():
        raise FileNotFoundError(f"Trained model not found: {model_path}")

    try:
        checkpoint = torch.load(
            model_path,
            map_location=torch.device("cpu"),
            weights_only=True
        )
    except TypeError:
        print("[!] PyTorch does not support weights_only; using legacy safe loader.")
        checkpoint = torch.load(
            model_path,
            map_location=torch.device("cpu")
        )
    except Exception as exc:
        raise ValueError(
            f"Could not safely load checkpoint {model_path}: {exc}"
        ) from exc

    if not isinstance(checkpoint, dict):
        raise ValueError(
            "Checkpoint must be a metadata dictionary; refusing an unverified model."
        )

    config = checkpoint.get("model_config")
    if not isinstance(config, dict):
        raise ValueError(
            "Checkpoint lacks model_config metadata; retrain with "
            "scripts/train_world_model.py"
        )

    checkpoint_state_dim = config.get("state_dim")
    if not isinstance(checkpoint_state_dim, int) or checkpoint_state_dim != STATE_DIM:
        raise ValueError(
            f"Checkpoint state_dim must be {STATE_DIM}, "
            f"received {checkpoint_state_dim}"
        )

    checkpoint_dimensions = config.get("state_dimensions")
    if checkpoint_dimensions is None:
        raise ValueError("Checkpoint lacks state_dimensions metadata")
    validate_state_dimensions(checkpoint_dimensions, "model checkpoint")

    checkpoint_scales = config.get("state_scale_hints")
    if checkpoint_scales != STATE_SCALE_HINTS:
        raise ValueError(
            "Model checkpoint normalization scales do not match live inference"
        )

    preprocessing = config.get("preprocessing", {})
    if preprocessing:
        validate_state_dimensions(
            preprocessing.get("state_dimensions", []),
            "checkpoint preprocessing"
        )
        if preprocessing.get("state_scale_hints") != STATE_SCALE_HINTS:
            raise ValueError(
                "Checkpoint preprocessing scales do not match live inference"
            )

    hidden_size = config.get("hidden_size")
    num_layers = config.get("num_layers")
    if not isinstance(hidden_size, int) or hidden_size < 1:
        raise ValueError(f"Invalid checkpoint hidden_size: {hidden_size}")
    if not isinstance(num_layers, int) or num_layers < 1:
        raise ValueError(f"Invalid checkpoint num_layers: {num_layers}")

    model = NetworkStateTransitionModel(
        state_dim=checkpoint_state_dim,
        hidden_size=hidden_size,
        num_layers=num_layers
    )

    state_dict = checkpoint.get("model_state_dict", checkpoint.get("state_dict"))
    if not isinstance(state_dict, dict):
        raise ValueError("Checkpoint lacks model_state_dict weights")

    try:
        model.load_state_dict(state_dict)
    except RuntimeError as exc:
        raise ValueError(
            f"Checkpoint weights do not match its model_config: {exc}"
        ) from exc

    model.eval()

    print("\n[+] TRAINED WORLD MODEL LOADED")

    print(f"[+] Training Epoch: {checkpoint.get('epoch', 'unknown')}")
    validation_loss = checkpoint.get("validation_loss", checkpoint.get("val_loss"))
    if validation_loss is not None:
        print(f"[+] Validation Loss: {validation_loss:.6f}")
    print(f"[+] Model Architecture: state_dim={checkpoint_state_dim}, "
          f"hidden_size={hidden_size}, num_layers={num_layers}")
    print(f"[+] Feature Order: {', '.join(checkpoint_dimensions)}")
    print(f"[+] Normalization: {preprocessing.get('normalization', 'fixed_scale_clip_0_1')}")

    print(f"[+] Model Path: {model_path}")

    return model


def print_report(predicted_states, risk_scores, stages, attributions):

    print("\n=== K-Step Forward Simulation ===")
    print(
        f"Risk distribution: min={risk_scores.min():.4f}, "
        f"max={risk_scores.max():.4f}, mean={risk_scores.mean():.4f}, "
        f"std={risk_scores.std():.4f}"
    )

    print(
        f"{'Step':<8}"
        f"{'Infiltration Risk':<22}"
        f"{'Predicted Stage':<25}"
        f"{'Confidence':<12}"
    )

    print("-" * 70)

    for i in range(len(predicted_states)):

        print(
            f"t+{i+1:<6}"
            f"{risk_scores[i] * 100:>6.1f}%{'':<15}"
            f"{stages[i]['predicted_stage']:<25}"
            f"{stages[i]['confidence'] * 100:.1f}%"
        )

    print("\n=== Explainability ===")

    for dim, val in sorted(
        attributions.items(),
        key=lambda kv: abs(kv[1]),
        reverse=True
    ):

        print(
            f"  {dim:<25} {val:+.4f}"
        )


def main():

    parser = argparse.ArgumentParser(
        description="Live-capture trained network world model demo"
    )

    parser.add_argument(
        "--duration",
        type=int,
        default=12
    )

    parser.add_argument(
        "--window",
        type=int,
        default=10
    )

    parser.add_argument(
        "--k",
        type=int,
        default=10
    )

    args = parser.parse_args()

    flows = try_live_capture(args.duration)
    trajectory = (
        flows_to_state_trajectory(flows)
        if flows is not None
        else generate_synthetic_fallback()
    )

    if trajectory.ndim != 2 or trajectory.shape[1] != STATE_DIM:
        raise ValueError(
            f"Live input must have shape (n, {STATE_DIM}), received {trajectory.shape}"
        )

    if len(trajectory) < args.window:

        args.window = max(2, len(trajectory))

    window = trajectory[-args.window:]

    print(
        f"\n[+] Input trajectory shape: {trajectory.shape}"
    )

    print(
        f"[+] Model window size: {len(window)}"
    )

    model = load_trained_model()

    rollout = rollout_k_steps(
        model,
        window,
        k=args.k
    )
    predicted_states = rollout[0]
    risk_scores = rollout[1]

    stages = map_rollout_to_stages(
        predicted_states
    )

    attributions = perturbation_attribution(
        model,
        window,
        k=1
    )

    print_report(
        predicted_states,
        risk_scores,
        stages,
        attributions
    )

    print(
        f"\nSummary: "
        f"{summarize_attribution(attributions)}"
    )


if __name__ == "__main__":
    main()
