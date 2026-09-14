import hashlib
import json
from typing import Any


def sha256_hexdigest(data: bytes) -> str:
    """Compute SHA-256 hash of raw bytes, returned as hex string."""
    return hashlib.sha256(data).hexdigest()


def hash_string(text: str) -> str:
    """Hash a UTF-8 string with SHA-256."""
    return sha256_hexdigest(text.encode("utf-8"))


def hash_json(payload: dict[str, Any]) -> str:
    """
    Deterministically hash a JSON-serializable dict.
    Keys are sorted so the same logical content always produces the same hash,
    which matters for evidence integrity checks and blockchain anchoring.
    """
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hash_string(canonical)


def hash_file(file_path: str, chunk_size: int = 8192) -> str:
    """Hash a file's contents in chunks without loading it fully into memory."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(chunk_size):
            sha256.update(chunk)
    return sha256.hexdigest()


def verify_hash(data: bytes, expected_hash: str) -> bool:
    """Check whether raw bytes match an expected SHA-256 hash."""
    return sha256_hexdigest(data) == expected_hash


def short_hash(full_hash: str, length: int = 10) -> str:
    """Truncate a hash for display purposes (e.g. in UI evidence lists)."""
    return full_hash[:length]