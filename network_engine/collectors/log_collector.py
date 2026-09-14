import json
from pathlib import Path
from typing import Iterator


class LogCollector:
    """Generic collector for JSON-lines or plain-text network/security logs."""

    def __init__(self, log_path: str | Path):
        self.log_path = Path(log_path)

    def read_jsonl(self) -> Iterator[dict]:
        with open(self.log_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue

    def read_lines(self) -> Iterator[str]:
        with open(self.log_path, "r", encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if stripped:
                    yield stripped

    def tail(self, n: int = 100) -> list[str]:
        """Return the last n lines — useful for a live-ish dashboard feed."""
        with open(self.log_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        return [l.strip() for l in lines[-n:]]