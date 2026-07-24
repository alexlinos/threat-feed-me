"""Pydantic request/response models shared by the API routers."""
from typing import Optional

from pydantic import BaseModel

from threatfeedme.models import ALL_FEEDS, FeedType, REASON_OTHER


class WhitelistRequest(BaseModel):
    ip: str
    reason: str = ""
    added_by: str = "dashboard"
    expires_at: Optional[str] = None
    # ALL_FEEDS ("*") or empty = whitelist from every feed; otherwise a feed name.
    feed_name: Optional[str] = ALL_FEEDS
    reason_code: str = REASON_OTHER


class WhitelistResponse(BaseModel):
    success: bool
    message: str


class FeedRequest(BaseModel):
    name: str
    url: str
    feed_type: str = FeedType.CUSTOM.value
    weight: float = 1.0
    update_interval: int = 3600
    requires_auth: bool = False
    auth_env: Optional[str] = None
    auth_header: str = "Authorization"
    local_file: bool = False
    enabled: bool = True


class SettingsRequest(BaseModel):
    refresh_interval_minutes: int


class ApiKeyRequest(BaseModel):
    # Empty string clears the stored key.
    api_key: str = ""


class IndicatorRequest(BaseModel):
    ip: str
