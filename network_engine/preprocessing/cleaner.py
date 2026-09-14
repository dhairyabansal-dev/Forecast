import pandas as pd


def drop_invalid_flows(df: pd.DataFrame) -> pd.DataFrame:
    """Remove flows with missing IPs, zero duration+zero bytes, or malformed ports."""
    df = df.dropna(subset=["src_ip", "dst_ip"])
    df = df[~((df.get("duration_seconds", 0) == 0) & (df.get("total_bytes", 0) == 0))]

    for port_col in ("src_port", "dst_port"):
        if port_col in df.columns:
            df = df[df[port_col].isna() | ((df[port_col] >= 0) & (df[port_col] <= 65535))]

    return df.reset_index(drop=True)


def remove_duplicate_flows(df: pd.DataFrame) -> pd.DataFrame:
    subset = [c for c in ("flow_id",) if c in df.columns]
    if subset:
        return df.drop_duplicates(subset=subset).reset_index(drop=True)
    return df.drop_duplicates().reset_index(drop=True)


def filter_private_ip_noise(df: pd.DataFrame, exclude_localhost: bool = True) -> pd.DataFrame:
    """Optionally strip out loopback/localhost traffic that's rarely relevant for threat detection."""
    if not exclude_localhost:
        return df
    mask = ~(
        df["src_ip"].astype(str).str.startswith("127.")
        | df["dst_ip"].astype(str).str.startswith("127.")
    )
    return df[mask].reset_index(drop=True)


def clean_flows(df: pd.DataFrame) -> pd.DataFrame:
    df = drop_invalid_flows(df)
    df = remove_duplicate_flows(df)
    df = filter_private_ip_noise(df)
    return df