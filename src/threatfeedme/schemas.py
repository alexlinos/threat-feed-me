"""Pydantic request/response models shared by the API routers."""
from typing import Dict, Optional

from pydantic import BaseModel, Field

from threatfeedme.models import ALL_FEEDS, FeedType, REASON_OTHER


# Caps on free text a client can store: a 900 KB whitelist reason was
# accepted and rendered into every Indicators page (QA, 2026-09-27).
class WhitelistRequest(BaseModel):
    ip: str = Field(max_length=300)
    reason: str = Field("", max_length=500)
    added_by: str = Field("dashboard", max_length=64)
    expires_at: Optional[str] = Field(None, max_length=64)
    # ALL_FEEDS ("*") or empty = whitelist from every feed; otherwise a feed name.
    feed_name: Optional[str] = Field(ALL_FEEDS, max_length=128)
    reason_code: str = Field(REASON_OTHER, max_length=64)


class WhitelistResponse(BaseModel):
    success: bool
    message: str


class FeedRequest(BaseModel):
    name: str
    url: str
    feed_type: str = FeedType.CUSTOM.value
    # Finite and 0-1, as the UI documents: weight=inf reached the scorer,
    # stored confidence_score=inf, and every JSON surface that carried the
    # row (lookup, feed list, TAXII paging) returned 500 (QA, 2026-09-27).
    weight: float = Field(1.0, ge=0.0, le=1.0, allow_inf_nan=False)
    update_interval: int = 3600
    requires_auth: bool = False
    auth_env: Optional[str] = None
    auth_header: str = "Authorization"
    local_file: bool = False
    enabled: bool = True
    # 'ip' (default) or 'domain' — what the feed's lines parse as (D8: feeds
    # declare their kind; domains are never sniffed out of IP feeds).
    indicator_kind: str = "ip"
    # How the URL's body is read: 'list' (one entry per line, CSV, hosts
    # file, URLs) or 'taxii21' (a TAXII 2.1 collection of STIX indicators).
    # Maps to a scraper server-side; a client can never name a scraper
    # directly (the crowdsec_* ones carry integration credentials).
    format: str = "list"
    # A name that already exists is refused (409) unless this is set: adding a
    # feed used to replace a same-named one silently, shipped defaults included.
    overwrite: bool = False


class SettingsRequest(BaseModel):
    # Both optional so a client can update either setting independently.
    refresh_interval_minutes: Optional[int] = None
    retention_max_age_days: Optional[int] = None


class ApiKeyRequest(BaseModel):
    # Empty string clears the stored key.
    api_key: str = ""
    # Multi-credential feeds (auth_env is a comma-separated list, e.g.
    # HoneyDB's id+key pair): {ENV_VAR: value}. Empty value clears that var.
    # When present, takes precedence over api_key.
    keys: Optional[Dict[str, str]] = None


class IndicatorRequest(BaseModel):
    ip: str
