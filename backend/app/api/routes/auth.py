import time
from collections import defaultdict, deque
from datetime import datetime, timezone

from fastapi import APIRouter, Cookie, Depends, HTTPException, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import get_current_user, get_db_session, require_roles
from app.core.auth import COOKIE_NAME, ROLES, create_session_token, hash_password, normalize_email, token_digest, validate_password, valid_email, verify_password
from app.core.config import settings
from app.models.user import User, UserSession
from app.schemas.auth import AuthResponse, LoginRequest, RegisterRequest, RoleUpdateRequest, UserResponse
from app.services.audit_service import record_audit
from app.utils.helpers import utc_now

router = APIRouter(prefix="/auth", tags=["Authentication"])

_FAILED_LOGINS: dict[str, deque[float]] = defaultdict(deque)
_MAX_FAILURES = 8
_FAILURE_WINDOW_SECONDS = 15 * 60
_LOCKOUT_SECONDS = 15 * 60


def _key(username: str) -> str:
    return normalize_email(username)


def _blocked(username: str) -> bool:
    now = time.time()
    attempts = _FAILED_LOGINS[_key(username)]
    while attempts and now - attempts[0] > _FAILURE_WINDOW_SECONDS:
        attempts.popleft()
    return len(attempts) >= _MAX_FAILURES and now - attempts[-1] < _LOCKOUT_SECONDS


def _failure(username: str) -> None:
    attempts = _FAILED_LOGINS[_key(username)]
    attempts.append(time.time())


def _clear_failures(username: str) -> None:
    _FAILED_LOGINS.pop(_key(username), None)


def _user_response(user: User) -> UserResponse:
    return UserResponse.model_validate(user, from_attributes=True)


def _set_cookie(response: Response, token: str, expires: datetime) -> None:
    response.set_cookie(
        key=settings.AUTH_COOKIE_NAME,
        value=token,
        expires=expires,
        max_age=max(1, int((expires - datetime.now(timezone.utc)).total_seconds())),
        httponly=True,
        secure=settings.AUTH_COOKIE_SECURE or settings.APP_ENV.lower() in {"production", "prod", "vercel"},
        samesite="lax",
        path="/",
    )


@router.post("/register", response_model=AuthResponse, status_code=201)
async def register(payload: RegisterRequest, response: Response, session: AsyncSession = Depends(get_db_session)):
    email = normalize_email(payload.email)
    if not valid_email(email):
        raise HTTPException(status_code=422, detail="A valid email is required")
    password_errors = validate_password(payload.password)
    if password_errors:
        raise HTTPException(status_code=422, detail=password_errors)

    existing = await session.execute(select(User).where(User.email == email))
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(status_code=409, detail="Unable to register with those credentials")

    user = User(email=email, password_hash=hash_password(payload.password), full_name=payload.full_name.strip(), role="VIEWER")
    session.add(user)
    await session.flush()
    await record_audit(session, action="USER_REGISTRATION", status="SUCCESS", user_id=user.id)

    token, jti, expires = create_session_token(user.id)
    session.add(UserSession(user_id=user.id, jti=jti, token_hash=token_digest(token), expires_at=expires))
    await session.commit()
    _set_cookie(response, token, expires)
    return AuthResponse(user=_user_response(user))


@router.post("/login", response_model=AuthResponse)
async def login(payload: LoginRequest, response: Response, session: AsyncSession = Depends(get_db_session)):
    if _blocked(payload.username):
        raise HTTPException(status_code=429, detail="Too many login attempts. Try again later.")

    email = normalize_email(payload.username)
    result = await session.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()
    if user is None or not verify_password(payload.password, user.password_hash) or not user.is_active:
        _failure(payload.username)
        await record_audit(session, action="LOGIN", status="FAILURE", metadata={"reason": "invalid_credentials"})
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    _clear_failures(payload.username)
    user.last_login_at = utc_now()
    user.updated_at = utc_now()
    token, jti, expires = create_session_token(user.id)
    session.add(UserSession(user_id=user.id, jti=jti, token_hash=token_digest(token), expires_at=expires))
    await record_audit(session, action="LOGIN", status="SUCCESS", user_id=user.id)
    await session.commit()
    _set_cookie(response, token, expires)
    return AuthResponse(user=_user_response(user))


@router.post("/logout", status_code=204)
async def logout(
    response: Response,
    session_cookie: str | None = Cookie(default=None, alias=COOKIE_NAME),
    session: AsyncSession = Depends(get_db_session),
):
    if session_cookie:
        from app.core.auth import decode_session_token
        claims = decode_session_token(session_cookie)
        if claims and claims.get("jti"):
            result = await session.execute(select(UserSession).where(UserSession.jti == claims["jti"]))
            db_session = result.scalar_one_or_none()
            if db_session and db_session.revoked_at is None:
                db_session.revoked_at = utc_now()
                await record_audit(session, action="LOGOUT", status="SUCCESS", user_id=db_session.user_id)
    await session.commit()
    response.delete_cookie(settings.AUTH_COOKIE_NAME, path="/")


@router.get("/me", response_model=UserResponse)
async def me(user: User = Depends(get_current_user)):
    return _user_response(user)


@router.get("/users", response_model=list[UserResponse])
async def list_users(user: User = Depends(require_roles("ADMIN")), session: AsyncSession = Depends(get_db_session)):
    result = await session.execute(select(User).order_by(User.created_at.desc()))
    return [_user_response(item) for item in result.scalars().all()]


@router.patch("/users/{user_id}/role", response_model=UserResponse)
async def change_role(
    user_id: str,
    payload: RoleUpdateRequest,
    admin: User = Depends(require_roles("ADMIN")),
    session: AsyncSession = Depends(get_db_session),
):
    role = payload.role.upper()
    if role not in ROLES:
        raise HTTPException(status_code=422, detail="Invalid role")
    result = await session.execute(select(User).where(User.id == user_id))
    target = result.scalar_one_or_none()
    if target is None:
        raise HTTPException(status_code=404, detail="User not found")
    target.role = role
    target.updated_at = utc_now()
    await record_audit(session, action="ROLE_CHANGE", status="SUCCESS", user_id=admin.id, resource=user_id, metadata={"new_role": role})
    await session.commit()
    return _user_response(target)
