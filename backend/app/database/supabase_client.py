"""
Supabase client for server-side operations.

Uses the SERVICE_ROLE key (full admin access) — never expose this to the frontend.
The SQLAlchemy engine in connection.py remains the primary database access layer;
this client is for Supabase-specific features (Auth admin, Storage, Realtime, etc.).
"""

from __future__ import annotations

from functools import lru_cache
from typing import TYPE_CHECKING

from app.core.config import settings

if TYPE_CHECKING:
    from supabase import Client


@lru_cache(maxsize=1)
def get_supabase_client() -> "Client":
    """Return a cached Supabase client initialised with the service-role key.

    Raises ``RuntimeError`` if the required environment variables
    (``SUPABASE_URL``, ``SUPABASE_SERVICE_ROLE_KEY``) are not configured.
    """
    if not settings.SUPABASE_URL or not settings.SUPABASE_SERVICE_ROLE_KEY:
        raise RuntimeError(
            "Supabase is not configured. "
            "Set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY in your .env file."
        )

    from supabase import create_client

    return create_client(settings.SUPABASE_URL, settings.SUPABASE_SERVICE_ROLE_KEY)
