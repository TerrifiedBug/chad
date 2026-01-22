from datetime import datetime
from typing import Literal

from pydantic import BaseModel, EmailStr, computed_field

from app.models.user import UserRole


class UserBase(BaseModel):
    email: EmailStr
    role: UserRole = UserRole.VIEWER


class UserCreate(UserBase):
    password: str


class UserUpdate(BaseModel):
    email: EmailStr | None = None
    role: UserRole | None = None
    is_active: bool | None = None


class UserResponse(UserBase):
    id: str  # UUID as string for JSON serialization
    is_active: bool
    created_at: datetime
    has_password: bool = False  # Internal field to compute auth_method

    @computed_field
    @property
    def auth_method(self) -> Literal["local", "sso"]:
        return "local" if self.has_password else "sso"

    class Config:
        from_attributes = True
