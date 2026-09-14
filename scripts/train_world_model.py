import argparse
import random
import sys
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn

from torch.optim import Adam
from torch.utils.data import DataLoader

sys.path.insert(
    0,
    str(Path(__file__).resolve().parent.parent)
)

from ml_engine.data.cic2018_dataset import (
    NetworkSequenceDataset,
    load_cic2018_data
)

from ml_engine.world_model.state_representation import (
    STATE_DIM,
    STATE_DIMENSIONS,
    STATE_SCALE_HINTS,
    validate_state_dimensions,
)

from ml_engine.world_model.state_transition_model import (
    NetworkStateTransitionModel
)


def set_seed(seed: int = 42):
    random.seed(seed)
    np.random.seed(seed)

    torch.manual_seed(seed)

    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)


def train_epoch(
    model,
    loader,
    optimizer,
    state_loss_fn,
    risk_loss_fn,
    device
):
    model.train()

    total_loss = 0.0
    total_state_loss = 0.0
    total_risk_loss = 0.0
    total_state_mae = 0.0
    total_risk_mae = 0.0
    total_batches = 0

    for sequences, next_states, future_risks in loader:
        sequences = sequences.to(device)
        next_states = next_states.to(device)
        future_risks = future_risks.to(device)

        optimizer.zero_grad()

        predicted_states, predicted_risks = model(
            sequences,
            k_steps=1
        )

        predicted_state = predicted_states[:, 0, :]
        predicted_risk = predicted_risks[:, 0, :]

        state_loss = state_loss_fn(
            predicted_state,
            next_states
        )

        risk_loss = risk_loss_fn(
            predicted_risk,
            future_risks
        )

        loss = state_loss + risk_loss

        loss.backward()

        torch.nn.utils.clip_grad_norm_(
            model.parameters(),
            max_norm=1.0
        )

        optimizer.step()

        total_loss += loss.item()
        total_state_loss += state_loss.item()
        total_risk_loss += risk_loss.item()
        total_state_mae += torch.abs(predicted_state - next_states).mean().item()
        total_risk_mae += torch.abs(predicted_risk - future_risks).mean().item()
        total_batches += 1

    divisor = max(total_batches, 1)
    return {
        "total_loss": total_loss / divisor,
        "state_loss": total_state_loss / divisor,
        "risk_loss": total_risk_loss / divisor,
        "state_mae": total_state_mae / divisor,
        "risk_mae": total_risk_mae / divisor,
    }


def validate_epoch(
    model,
    loader,
    state_loss_fn,
    risk_loss_fn,
    device
):
    model.eval()

    total_loss = 0.0
    total_state_loss = 0.0
    total_risk_loss = 0.0
    total_state_mae = 0.0
    total_risk_mae = 0.0
    total_batches = 0

    with torch.no_grad():
        for sequences, next_states, future_risks in loader:
            sequences = sequences.to(device)
            next_states = next_states.to(device)
            future_risks = future_risks.to(device)

            predicted_states, predicted_risks = model(
                sequences,
                k_steps=1
            )

            predicted_state = predicted_states[:, 0, :]
            predicted_risk = predicted_risks[:, 0, :]

            state_loss = state_loss_fn(
                predicted_state,
                next_states
            )

            risk_loss = risk_loss_fn(
                predicted_risk,
                future_risks
            )

            loss = state_loss + risk_loss

            total_loss += loss.item()
            total_state_loss += state_loss.item()
            total_risk_loss += risk_loss.item()
            total_state_mae += torch.abs(predicted_state - next_states).mean().item()
            total_risk_mae += torch.abs(predicted_risk - future_risks).mean().item()
            total_batches += 1

    divisor = max(total_batches, 1)
    return {
        "total_loss": total_loss / divisor,
        "state_loss": total_state_loss / divisor,
        "risk_loss": total_risk_loss / divisor,
        "state_mae": total_state_mae / divisor,
        "risk_mae": total_risk_mae / divisor,
    }


def collect_risk_diagnostics(model, loader, device):
    model.eval()
    predictions = []
    targets = []

    with torch.no_grad():
        for sequences, _, future_risks in loader:
            _, risks = model(sequences.to(device), k_steps=1)
            predictions.append(risks[:, 0, 0].cpu().numpy())
            targets.append(future_risks[:, 0].cpu().numpy())

    predicted = np.concatenate(predictions) if predictions else np.array([])
    target = np.concatenate(targets) if targets else np.array([])
    return predicted, target


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--data",
        required=True
    )

    parser.add_argument(
        "--epochs",
        type=int,
        default=20
    )

    parser.add_argument(
        "--batch-size",
        type=int,
        default=64
    )

    parser.add_argument(
        "--sequence-length",
        type=int,
        default=20
    )

    parser.add_argument(
        "--stride",
        type=int,
        default=5
    )

    parser.add_argument(
        "--learning-rate",
        type=float,
        default=0.001
    )

    parser.add_argument(
        "--max-rows-per-file",
        type=int,
        default=None
    )

    parser.add_argument(
        "--chunksize",
        type=int,
        default=100_000
    )

    parser.add_argument(
        "--patience",
        type=int,
        default=5
    )

    parser.add_argument(
        "--min-delta",
        type=float,
        default=1e-4
    )

    parser.add_argument(
        "--seed",
        type=int,
        default=42
    )

    args = parser.parse_args()

    if args.epochs < 1 or args.batch_size < 1 or args.patience < 1:
        raise ValueError("epochs, batch-size, and patience must be positive")
    if args.chunksize is not None and args.chunksize < 1:
        raise ValueError("chunksize must be positive")

    set_seed(args.seed)

    device = torch.device(
        "cuda"
        if torch.cuda.is_available()
        else "cpu"
    )

    print(f"Using device: {device}")

    states, risks = load_cic2018_data(
        args.data,
        max_rows_per_file=args.max_rows_per_file,
        chunksize=args.chunksize
    )

    validate_state_dimensions(STATE_DIMENSIONS, "training state")
    if states.ndim != 2 or states.shape[1] != STATE_DIM:
        raise ValueError(
            f"Training data must have shape (n, {STATE_DIM}), received {states.shape}"
        )
    if len(states) != len(risks):
        raise ValueError(
            f"Training states and risks length mismatch: {len(states)} != {len(risks)}"
        )

    print(f"Total network records: {len(states):,}")
    print(f"State dimension: {states.shape[1]}")

    split_row = int(len(states) * 0.8)
    if split_row <= args.sequence_length + 1 or len(states) - split_row <= args.sequence_length + 1:
        raise ValueError(
            "Dataset is too small for separate chronological train/validation sequences"
        )

    training_dataset = NetworkSequenceDataset(
        states=states[:split_row],
        risks=risks[:split_row],
        sequence_length=args.sequence_length,
        stride=args.stride
    )

    validation_dataset = NetworkSequenceDataset(
        states=states[split_row:],
        risks=risks[split_row:],
        sequence_length=args.sequence_length,
        stride=args.stride
    )

    target_rate = float(training_dataset.targets.mean())
    print(
        f"Risk target distribution: train min={training_dataset.targets.min():.4f}, "
        f"max={training_dataset.targets.max():.4f}, mean={target_rate:.4f}, "
        f"std={training_dataset.targets.std():.4f} | "
        f"validation mean={validation_dataset.targets.mean():.4f}, "
        f"std={validation_dataset.targets.std():.4f}"
    )

    shuffle_generator = torch.Generator().manual_seed(args.seed)

    train_loader = DataLoader(
        training_dataset,
        batch_size=args.batch_size,
        shuffle=True,
        generator=shuffle_generator
    )

    validation_loader = DataLoader(
        validation_dataset,
        batch_size=args.batch_size,
        shuffle=False
    )

    model = NetworkStateTransitionModel(
        state_dim=STATE_DIM,
        hidden_size=64,
        num_layers=2
    ).to(device)

    optimizer = Adam(
        model.parameters(),
        lr=args.learning_rate
    )

    state_loss_fn = nn.MSELoss()

    negative_weight = 0.5 / max(1.0 - target_rate, 1e-6)
    positive_weight = 0.5 / max(target_rate, 1e-6)

    def risk_loss_fn(predicted, target):
        weights = torch.where(
            target < 0.5,
            torch.full_like(target, negative_weight),
            torch.full_like(target, positive_weight)
        )
        return nn.functional.binary_cross_entropy(
            predicted,
            target,
            weight=weights
        )

    project_root = Path(
        __file__
    ).resolve().parent.parent

    model_directory = project_root / "models"

    model_directory.mkdir(
        exist_ok=True
    )

    model_path = (
        model_directory
        / "network_world_model.pth"
    )

    best_validation_loss = float("inf")
    epochs_without_improvement = 0

    for epoch in range(args.epochs):
        training_metrics = train_epoch(
            model,
            train_loader,
            optimizer,
            state_loss_fn,
            risk_loss_fn,
            device
        )

        validation_metrics = validate_epoch(
            model,
            validation_loader,
            state_loss_fn,
            risk_loss_fn,
            device
        )

        train_predictions, train_targets = collect_risk_diagnostics(
            model,
            train_loader,
            device
        )
        validation_predictions, validation_targets = collect_risk_diagnostics(
            model,
            validation_loader,
            device
        )

        validation_loss = validation_metrics["total_loss"]
        print(
            f"Epoch {epoch + 1}/{args.epochs} | "
            f"Train Loss: {training_metrics['total_loss']:.6f} "
            f"(state={training_metrics['state_loss']:.6f}, risk={training_metrics['risk_loss']:.6f}, "
            f"MAE={training_metrics['state_mae']:.6f}/{training_metrics['risk_mae']:.6f}) | "
            f"Validation Loss: {validation_loss:.6f} "
            f"(state={validation_metrics['state_loss']:.6f}, risk={validation_metrics['risk_loss']:.6f}, "
            f"MAE={validation_metrics['state_mae']:.6f}/{validation_metrics['risk_mae']:.6f}) | "
            f"Risk train mean/std: {train_predictions.mean():.4f}/"
            f"{train_predictions.std():.4f} | "
            f"val mean/std: {validation_predictions.mean():.4f}/"
            f"{validation_predictions.std():.4f} | "
            f"target train/val: {train_targets.mean():.4f}/"
            f"{validation_targets.mean():.4f}"
        )

        if validation_loss < best_validation_loss - args.min_delta:
            best_validation_loss = validation_loss
            epochs_without_improvement = 0

            torch.save(
                {
                    "model_state_dict": model.state_dict(),
                    "model_config": {
                        "state_dim": STATE_DIM,
                        "state_dimensions": list(STATE_DIMENSIONS),
                        "state_scale_hints": STATE_SCALE_HINTS,
                        "preprocessing": {
                            "normalization": "fixed_scale_clip_0_1",
                            "state_dimensions": list(STATE_DIMENSIONS),
                            "state_scale_hints": STATE_SCALE_HINTS,
                            "csv_chunksize": args.chunksize,
                        },
                        "hidden_size": 64,
                        "num_layers": 2
                    },
                    "validation_loss": validation_loss,
                    "epoch": epoch + 1
                    ,"training_config": {
                        "epochs": args.epochs,
                        "batch_size": args.batch_size,
                        "learning_rate": args.learning_rate,
                        "sequence_length": args.sequence_length,
                        "stride": args.stride,
                        "seed": args.seed,
                        "patience": args.patience,
                        "min_delta": args.min_delta,
                    }
                },
                model_path
            )

            print(
                f"Saved best model to: {model_path}"
            )
        else:
            epochs_without_improvement += 1
            if epochs_without_improvement >= args.patience:
                print(
                    f"Early stopping after {epoch + 1} epochs; "
                    f"best validation loss={best_validation_loss:.6f}"
                )
                break

    print("\nTraining complete.")
    print(f"Best validation loss: {best_validation_loss:.6f}")


if __name__ == "__main__":
    main()