import hashlib
import re
import secrets
from datetime import datetime, timedelta, timezone
from typing import Iterable

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from app.core.config import settings

ALGORITHM = "HS256"
COOKIE_NAME = settings.AUTH_COOKIE_NAME
PASSWORD_HASHER = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)
ROLES = {"ADMIN", "DATA_SCIENTIST", "ANALYST", "VIEWER"}


def hash_password(password: str) -> str:
    return PASSWORD_HASHER.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return PASSWORD_HASHER.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def validate_password(password: str) -> list[str]:
    errors: list[str] = []
    if len(password) < 8: errors.append("Password must be at least 8 characters")
    if not re.search(r"[A-Z]", password): errors.append("Password must contain an uppercase character")
    if not re.search(r"[a-z]", password): errors.append("Password must contain a lowercase character")
    if not re.search(r"\d", password): errors.append("Password must contain a number")
    if not re.search(r"[^A-Za-z0-9]", password): errors.append("Password must contain a special character")
    if password.lower() in {"password", "password123", "qwerty123", "admin123", "letmein123", "welcome123"}: errors.append("Password is too common")
    return errors


def create_session_token(user_id: str) -> tuple[str, str, datetime]:
    now = datetime.now(timezone.utc); expires = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES); jti = secrets.token_urlsafe(32)
    token = jwt.encode({"sub": user_id, "jti": jti, "iat": now, "exp": expires}, settings.SECRET_KEY, algorithm=ALGORITHM)
    return token, jti, expires


def decode_session_token(token: str) -> dict | None:
    try: return jwt.decode(token, settings.SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.PyJWTError: return None


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def normalize_email(value: str) -> str:
    return value.strip().lower()


def valid_email(value: str) -> bool:
    return bool(re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", value.strip()))


def role_allowed(role: str, allowed: Iterable[str]) -> bool:
    return role.upper() in {r.upper() for r in allowed}
