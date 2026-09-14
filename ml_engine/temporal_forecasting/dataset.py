import numpy as np
import torch
from torch.utils.data import Dataset


class ThreatSequenceDataset(Dataset):
    """
    Wraps sliding-window (X, y) arrays for training the LSTM forecaster.
    X: (num_samples, seq_len, num_features)
    y: (num_samples, horizon)
    """

    def __init__(self, X: np.ndarray, y: np.ndarray):
        if X.ndim == 2:
            # (num_samples, seq_len) -> add a feature dimension
            X = X[:, :, np.newaxis]

        self.X = torch.tensor(X, dtype=torch.float32)
        self.y = torch.tensor(y, dtype=torch.float32)

        assert len(self.X) == len(self.y), "X and y must have the same number of samples"

    def __len__(self) -> int:
        return len(self.X)

    def __getitem__(self, idx: int) -> tuple[torch.Tensor, torch.Tensor]:
        return self.X[idx], self.y[idx]


def train_val_split(X: np.ndarray, y: np.ndarray, val_ratio: float = 0.2):
    """Chronological split — no shuffling, since this is time series data."""
    split_idx = int(len(X) * (1 - val_ratio))
    return (X[:split_idx], y[:split_idx]), (X[split_idx:], y[split_idx:])