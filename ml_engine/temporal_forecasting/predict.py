import argparse

import numpy as np
import pandas as pd
import torch

DEFAULT_MODEL_PATH = "ml-engine/saved_models/temporal_model.pt"


def load_model(model_path: str, device: str = "cpu"):
    model = torch.load(model_path, map_location=device, weights_only=False)
    model.eval()
    return model


def forecast(model, historical_sequence: np.ndarray, horizon: int, device: str = "cpu") -> np.ndarray:
    """
    historical_sequence: 1D array of length sequence_length (or 2D: seq_len x num_features)
    Returns: 1D array of length `horizon` with predicted threat levels in [0, 1]
    """
    if historical_sequence.ndim == 1:
        historical_sequence = historical_sequence[:, np.newaxis]

    x = torch.tensor(historical_sequence, dtype=torch.float32, device=device).unsqueeze(0)

    with torch.no_grad():
        preds = model(x, horizon=horizon)

    return preds.squeeze(0).cpu().numpy()


def main():
    parser = argparse.ArgumentParser(description="Generate a threat-level forecast from a trained model.")
    parser.add_argument("--model", default=DEFAULT_MODEL_PATH)
    parser.add_argument("--series", required=True, help="CSV with a 'threat_level' column")
    parser.add_argument("--sequence-length", type=int, default=48)
    parser.add_argument("--horizon", type=int, default=24)
    args = parser.parse_args()

    device = "cuda" if torch.cuda.is_available() else "cpu"
    model = load_model(args.model, device=device)

    df = pd.read_csv(args.series)
    series = df["threat_level"].to_numpy(dtype=np.float32)

    if len(series) < args.sequence_length:
        raise ValueError(
            f"Series has {len(series)} points, need at least {args.sequence_length}"
        )

    recent_window = series[-args.sequence_length:]
    predictions = forecast(model, recent_window, args.horizon, device=device)

    print("Forecasted threat levels for next", args.horizon, "steps:")
    for i, val in enumerate(predictions, start=1):
        print(f"  t+{i}: {val:.4f}")


if __name__ == "__main__":
    main()