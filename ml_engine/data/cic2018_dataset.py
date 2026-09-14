from pathlib import Path
from typing import Iterable

import numpy as np
import pandas as pd
import torch
from torch.utils.data import Dataset

from ml_engine.world_model.state_representation import (
    STATE_DIMENSIONS,
    STATE_DIM,
    normalize_raw_features,
    validate_state_dimensions,
)


COLUMN_ALIASES = {
    "flow_rate": [
        "Flow Packets/s",
        "Flow Packets / s",
        "Flow Pkts/s",
    ],
    "syn_flag_ratio": [
        "SYN Flag Count",
        "SYN Flag Cnt",
    ],
    "port_scan_score": [
        "Destination Port",
        "Dst Port",
    ],
    "avg_packet_size": [
        "Average Packet Size",
        "Avg Packet Size",
    ],
    "iat_variance": [
        "Flow IAT Std",
        "Flow IAT Mean",
    ],
    "bytes_asymmetry": [
        "Total Length of Fwd Packets",
        "Total Fwd Packets Length",
    ],
    "unique_dst_ip_count": [
        "Destination IP",
        "Dst IP",
    ],
    "retransmission_rate": [
        "ACK Flag Count",
        "ACK Flag Cnt",
    ],
}


LABEL_ALIASES = [
    "Label",
    "label",
    "Attack",
    "Class",
]


def normalize_column_name(name: str) -> str:
    return " ".join(str(name).strip().split()).lower()


def find_column(columns: Iterable[str], aliases: list[str]) -> str | None:
    normalized = {
        normalize_column_name(column): column
        for column in columns
    }

    for alias in aliases:
        key = normalize_column_name(alias)

        if key in normalized:
            return normalized[key]

    return None


def find_label_column(columns: Iterable[str]) -> str:
    column = find_column(columns, LABEL_ALIASES)

    if column is None:
        raise ValueError(
            f"Could not find a label column. Available columns: {list(columns)}"
        )

    return column


def discover_csv_files(data_path: str | Path) -> list[Path]:
    path = Path(data_path)

    if path.is_file() and path.suffix.lower() == ".csv":
        return [path]

    if not path.exists():
        raise FileNotFoundError(f"Dataset path does not exist: {path}")

    files = sorted(path.rglob("*.csv"))

    if not files:
        raise FileNotFoundError(
            f"No CSV files found inside: {path}"
        )

    return files


def clean_numeric(series: pd.Series) -> pd.Series:
    return pd.to_numeric(
        series,
        errors="coerce"
    ).replace(
        [np.inf, -np.inf],
        np.nan
    )


def safe_minmax(values: np.ndarray) -> np.ndarray:
    minimum = np.nanmin(values, axis=0)
    maximum = np.nanmax(values, axis=0)

    denominator = maximum - minimum
    denominator[denominator == 0] = 1.0

    scaled = (values - minimum) / denominator

    return np.clip(
        np.nan_to_num(
            scaled,
            nan=0.0,
            posinf=1.0,
            neginf=0.0
        ),
        0.0,
        1.0
    )


def label_to_risk(label: str) -> float:
    value = str(label).strip().lower()

    benign_labels = {
        "benign",
        "normal",
        "0",
    }

    if value in benign_labels:
        return 0.0

    return 1.0


def build_state_vectors(
    dataframe: pd.DataFrame
) -> tuple[np.ndarray, np.ndarray]:
    validate_state_dimensions(STATE_DIMENSIONS, "training state")
    dataframe.columns = [
        " ".join(str(column).strip().split())
        for column in dataframe.columns
    ]

    label_column = find_label_column(dataframe.columns)

    def numeric(aliases: list[str], default: float = 0.0) -> np.ndarray:
        column = find_column(dataframe.columns, aliases)
        if column is None:
            return np.full(len(dataframe), default, dtype=np.float32)
        return clean_numeric(dataframe[column]).fillna(default).to_numpy(dtype=np.float32)

    packets = numeric(["Total Fwd Packets", "Tot Fwd Pkts"]) + numeric(
        ["Total Backward Packets", "Tot Bwd Pkts"]
    )
    forward_bytes = numeric(["Total Length of Fwd Packets", "TotLen Fwd Pkts"])
    backward_bytes = numeric(["Total Length of Bwd Packets", "TotLen Bwd Pkts"])
    total_bytes = forward_bytes + backward_bytes
    syn = numeric(COLUMN_ALIASES["syn_flag_ratio"])
    ack = numeric(["ACK Flag Count", "ACK Flag Cnt"])
    source_column = find_column(dataframe.columns, ["Source IP", "Src IP"])
    source_ips = dataframe[source_column].fillna("unknown").astype(str) if source_column else pd.Series(["unknown"] * len(dataframe))
    port_column = find_column(dataframe.columns, COLUMN_ALIASES["port_scan_score"])
    destination_ports = dataframe[port_column].fillna("unknown").astype(str) if port_column else pd.Series(["unknown"] * len(dataframe))
    destination_column = find_column(dataframe.columns, COLUMN_ALIASES["unique_dst_ip_count"])
    destination_ips = dataframe[destination_column].fillna("unknown").astype(str) if destination_column else pd.Series(["unknown"] * len(dataframe))
    grouped = pd.DataFrame({"source": source_ips, "port": destination_ports, "destination": destination_ips})
    port_counts = grouped.groupby("source")["port"].transform("nunique").to_numpy(dtype=np.float32)
    flow_counts = grouped.groupby("source")["source"].transform("size").to_numpy(dtype=np.float32)
    port_scan_scores = np.where(
        flow_counts < 2.0,
        0.0,
        port_counts / np.maximum(flow_counts, 1.0)
    )
    destination_counts = grouped.groupby("source")["destination"].transform("nunique").to_numpy(dtype=np.float32)
    duration = numeric(["Flow Duration"]).clip(min=1.0) / 1_000_000.0
    raw_columns = {
        "flow_rate": packets / duration,
        "syn_flag_ratio": syn / np.maximum(syn + ack, 1.0),
        "port_scan_score": port_scan_scores,
        "avg_packet_size": total_bytes / np.maximum(packets, 1.0),
        "iat_variance": numeric(["Flow IAT Std"]) ** 2,
        "bytes_asymmetry": np.abs(forward_bytes - backward_bytes) / np.maximum(total_bytes, 1.0),
        "unique_dst_ip_count": destination_counts,
        "retransmission_rate": np.zeros(len(dataframe), dtype=np.float32),
    }
    feature_matrix = np.asarray([
        normalize_raw_features({dimension: raw_columns[dimension][row] for dimension in STATE_DIMENSIONS})
        for row in range(len(dataframe))
    ], dtype=np.float32).reshape(len(dataframe), STATE_DIM)

    if feature_matrix.shape != (len(dataframe), STATE_DIM):
        raise ValueError(
            f"Training state matrix must have shape (n, {STATE_DIM}), received {feature_matrix.shape}"
        )

    labels = dataframe[label_column].apply(
        label_to_risk
    ).to_numpy(dtype=np.float32)

    return feature_matrix, labels


def load_cic2018_data(
    data_path: str | Path,
    max_rows_per_file: int | None = None,
    chunksize: int | None = 100_000
) -> tuple[np.ndarray, np.ndarray]:
    csv_files = discover_csv_files(data_path)

    all_states = []
    all_risks = []

    for csv_file in csv_files:
        print(f"Loading: {csv_file}")

        csv_chunks = pd.read_csv(
            csv_file,
            low_memory=False,
            nrows=max_rows_per_file,
            chunksize=chunksize
        ) if chunksize else [pd.read_csv(
            csv_file,
            low_memory=False,
            nrows=max_rows_per_file
        )]

        file_rows = 0
        for dataframe in csv_chunks:
            states, risks = build_state_vectors(dataframe)
            all_states.append(states)
            all_risks.append(risks)
            file_rows += len(states)

        print(
            f"Loaded {file_rows:,} records from {csv_file.name}"
        )

    if not all_states:
        raise RuntimeError("No valid training data was loaded.")

    return (
        np.concatenate(all_states, axis=0),
        np.concatenate(all_risks, axis=0)
    )


class NetworkSequenceDataset(Dataset):
    def __init__(
        self,
        states: np.ndarray,
        risks: np.ndarray,
        sequence_length: int = 20,
        stride: int = 5
    ):
        if len(states) != len(risks):
            raise ValueError(
                "States and risks must have identical lengths."
            )

        if states.ndim != 2 or states.shape[1] != STATE_DIM:
            raise ValueError(
                f"States must have shape (n, {STATE_DIM}), received {states.shape}"
            )

        if len(states) <= sequence_length + 1:
            raise ValueError(
                "Not enough samples to create sequences."
            )

        self.states = states.astype(np.float32)
        self.risks = risks.astype(np.float32)
        self.sequence_length = sequence_length
        self.indices = list(
            range(
                0,
                len(states) - sequence_length - 1,
                stride
            )
        )
        self.targets = np.asarray([
            self.risks[
                start + sequence_length:min(
                    start + 2 * sequence_length,
                    len(self.risks)
                )
            ].mean()
            for start in self.indices
        ], dtype=np.float32)

    def __len__(self):
        return len(self.indices)

    def __getitem__(self, index):
        start = self.indices[index]
        end = start + self.sequence_length

        sequence = self.states[start:end]
        next_state = self.states[end]
        future_risk = self.targets[index]

        return (
            torch.tensor(sequence, dtype=torch.float32),
            torch.tensor(next_state, dtype=torch.float32),
            torch.tensor([future_risk], dtype=torch.float32)
        )