import numpy as np
import pandas as pd


def normalize_numeric_columns(
    df: pd.DataFrame, columns: list[str], method: str = "zscore"
) -> pd.DataFrame:
    """Normalize numeric feature columns in place, returning a copy."""
    df = df.copy()
    for col in columns:
        if col not in df.columns:
            continue
        series = df[col].astype(float)

        if method == "zscore":
            mean, std = series.mean(), series.std()
            df[col] = (series - mean) / (std + 1e-8)
        elif method == "minmax":
            min_val, max_val = series.min(), series.max()
            df[col] = (series - min_val) / (max_val - min_val + 1e-8)
        else:
            raise ValueError(f"Unknown normalization method: {method}")

    return df


def normalize_ip_octets(ip: str) -> tuple[int, int, int, int]:
    """Split an IPv4 address into its 4 octets as ints, useful as a numeric feature."""
    parts = ip.split(".")
    if len(parts) != 4:
        return (0, 0, 0, 0)
    try:
        return tuple(int(p) for p in parts)  # type: ignore
    except ValueError:
        return (0, 0, 0, 0)


def encode_protocol(protocol: str) -> int:
    """Simple ordinal encoding for common protocols."""
    mapping = {"TCP": 1, "UDP": 2, "ICMP": 3, "OTHER": 0}
    return mapping.get(protocol.upper(), 0)


def clip_outliers(df: pd.DataFrame, columns: list[str], lower_pct: float = 0.01, upper_pct: float = 0.99) -> pd.DataFrame:
    """Clip extreme values in numeric columns to reduce the influence of outlier flows."""
    df = df.copy()
    for col in columns:
        if col not in df.columns:
            continue
        lower = df[col].quantile(lower_pct)
        upper = df[col].quantile(upper_pct)
        df[col] = df[col].clip(lower, upper)
    return df