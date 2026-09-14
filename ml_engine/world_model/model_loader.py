from pathlib import Path

import torch

from ml_engine.world_model.state_transition_model import (
    NetworkStateTransitionModel
)


DEFAULT_MODEL_PATH = (
    Path(__file__).resolve().parent.parent.parent
    / "models"
    / "network_world_model.pth"
)


def load_world_model(
    model_path: str | Path | None = None,
    device: str | None = None
):
    model_path = Path(
        model_path or DEFAULT_MODEL_PATH
    )

    if not model_path.exists():
        raise FileNotFoundError(
            f"Trained model not found: {model_path}"
        )

    device = device or (
        "cuda"
        if torch.cuda.is_available()
        else "cpu"
    )

    checkpoint = torch.load(
        model_path,
        map_location=device
    )

    config = checkpoint.get(
        "model_config",
        {}
    )

    model = NetworkStateTransitionModel(
        state_dim=config.get("state_dim", 8),
        hidden_size=config.get("hidden_size", 64),
        num_layers=config.get("num_layers", 2)
    )

    model.load_state_dict(
        checkpoint["model_state_dict"]
    )

    model.to(device)
    model.eval()

    return model, checkpoint