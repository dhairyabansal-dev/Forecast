from datetime import datetime

from pydantic import BaseModel, Field


class RegisterRequest(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=8, max_length=256)
    full_name: str = Field(min_length=1, max_length=200)


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=320)
    password: str = Field(min_length=1, max_length=256)


class UserResponse(BaseModel):
    id: str
    email: str
    full_name: str
    role: str
    is_active: bool
    created_at: datetime
    updated_at: datetime
    last_login_at: datetime | None


class RoleUpdateRequest(BaseModel):
    role: str


class AuthResponse(BaseModel):
    user: UserResponse
    authenticated: bool = True
