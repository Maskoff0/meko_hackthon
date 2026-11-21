"""Validated configuration and secret loading.

Loads environment variables via python-dotenv and validates them with Pydantic
Settings. No secrets are ever logged or returned in plaintext.
"""
from __future__ import annotations

from functools import lru_cache
from typing import Optional

from pydantic import Field, validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application configuration loaded from environment."""

    # Meko hosted endpoint
    meko_mcp_url: str = Field(default="https://mcp.mekodata.ai/mcp")
    meko_api_key: str
    meko_datapack_id: str

    # Operational bounds
    default_tool_call_budget: int = Field(default=10, ge=1, le=100)
    default_meko_retrieval_budget: int = Field(default=5, ge=1, le=50)
    default_token_budget: int = Field(default=4000, ge=100, le=100000)
    default_wall_clock_deadline_seconds: int = Field(default=60, ge=1, le=600)
    meko_timeout_seconds: float = Field(default=5.0, ge=0.5, le=60.0)
    meko_max_retrieval_content_tokens: int = Field(default=500, ge=0, le=100000)

    # Policy thresholds
    velocity_failed_login_threshold: int = Field(default=5, ge=1)
    velocity_window_seconds: int = Field(default=600, ge=60)
    shadow_mode: bool = Field(default=True, env="SHADOW_MODE")

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False

    @validator("meko_api_key")
    def _non_empty_api_key(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("MEKO_API_KEY must not be empty")
        return v.strip()

    @validator("meko_datapack_id")
    def _non_empty_datapack_id(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("MEKO_DATAPACK_ID must not be empty")
        return v.strip()


@lru_cache()
def get_settings() -> Settings:
    """Return cached Settings instance."""
    return Settings()
