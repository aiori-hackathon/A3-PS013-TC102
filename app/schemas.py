"""Pydantic schemas define what API clients may send and receive."""
from typing import Literal
from pydantic import BaseModel, EmailStr, Field

class RegisterRequest(BaseModel):
    display_name: str = Field(min_length=2, max_length=100)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)

class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)

class SettingsRequest(BaseModel):
    max_upload_mb: int = Field(ge=1, le=100)
    alert_threshold: int = Field(ge=2, le=20)
    display_name: str = Field(min_length=2, max_length=100)
    display_timezone: Literal["UTC", "Asia/Kolkata", "Europe/London", "America/New_York"] = "UTC"
