import uuid
from datetime import datetime, timezone
from typing import Any, Optional


def generate_uuid() -> str:
    """Generate a UUID4 string, used for record IDs across models."""
    return str(uuid.uuid4())


def utc_now() -> datetime:
    """Current UTC timestamp, timezone-aware."""
    return datetime.now(timezone.utc)


def to_iso(dt: Optional[datetime]) -> Optional[str]:
    """Convert a datetime to ISO-8601 string, safely handling None."""
    if dt is None:
        return None
    return dt.isoformat()


def paginate(items: list[Any], page: int = 1, page_size: int = 50) -> dict[str, Any]:
    """
    Simple in-memory pagination helper.
    Returns a dict with items for the requested page plus pagination metadata.
    """
    page = max(page, 1)
    page_size = max(1, min(page_size, 200))

    total = len(items)
    start = (page - 1) * page_size
    end = start + page_size

    return {
        "items": items[start:end],
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": (total + page_size - 1) // page_size if total else 0,
    }


def safe_get(d: dict, *keys: str, default: Any = None) -> Any:
    """
    Safely traverse nested dicts: safe_get(data, "a", "b", "c")
    is equivalent to data.get("a", {}).get("b", {}).get("c", default)
    without raising on missing intermediate keys.
    """
    current = d
    for key in keys:
        if not isinstance(current, dict) or key not in current:
            return default
        current = current[key]
    return current


def clamp(value: float, min_value: float, max_value: float) -> float:
    """Clamp a numeric value between min and max bounds."""
    return max(min_value, min(value, max_value))


def chunk_list(items: list[Any], chunk_size: int) -> list[list[Any]]:
    """Split a list into chunks of a given size — useful for batching packet/flow processing."""
    return [items[i:i + chunk_size] for i in range(0, len(items), chunk_size)]


def normalize_ip_pair(src_ip: str, dst_ip: str) -> tuple[str, str]:
    """
    Return (ip1, ip2) sorted lexicographically, so flow correlation treats
    A->B and B->A traffic as belonging to the same conversation.
    """
    return tuple(sorted([src_ip, dst_ip]))