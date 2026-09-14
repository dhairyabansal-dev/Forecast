import csv
from pathlib import Path
from typing import Iterator


ZEEK_CONN_LOG_FIELDS = [
    "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
    "proto", "service", "duration", "orig_bytes", "resp_bytes",
    "conn_state", "orig_pkts", "resp_pkts",
]


class ZeekCollector:
    """
    Parses Zeek's tab-separated conn.log files into flow-like dicts
    compatible with the feature engineering pipeline.
    """

    def __init__(self, log_path: str | Path):
        self.log_path = Path(log_path)

    def _read_tsv_rows(self) -> Iterator[dict]:
        with open(self.log_path, "r", encoding="utf-8") as f:
            fields = ZEEK_CONN_LOG_FIELDS
            for line in f:
                if line.startswith("#"):
                    continue
                values = line.rstrip("\n").split("\t")
                if len(values) < len(fields):
                    continue
                yield dict(zip(fields, values))

    def parse(self) -> list[dict]:
        flows = []
        for row in self._read_tsv_rows():
            try:
                flows.append({
                    "flow_id": row["uid"],
                    "src_ip": row["id.orig_h"],
                    "dst_ip": row["id.resp_h"],
                    "src_port": int(row["id.orig_p"]) if row["id.orig_p"] != "-" else None,
                    "dst_port": int(row["id.resp_p"]) if row["id.resp_p"] != "-" else None,
                    "protocol": row["proto"].upper(),
                    "duration_seconds": float(row["duration"]) if row["duration"] != "-" else 0.0,
                    "src_bytes": int(row["orig_bytes"]) if row["orig_bytes"] != "-" else 0,
                    "dst_bytes": int(row["resp_bytes"]) if row["resp_bytes"] != "-" else 0,
                    "packet_count": (
                        int(row["orig_pkts"] if row["orig_pkts"] != "-" else 0)
                        + int(row["resp_pkts"] if row["resp_pkts"] != "-" else 0)
                    ),
                    "conn_state": row["conn_state"],
                    "timestamp": float(row["ts"]),
                })
            except (ValueError, KeyError):
                continue
        return flows