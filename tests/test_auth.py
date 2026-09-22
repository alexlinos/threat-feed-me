"""Dashboard auth rules (v2.4.19)."""
import pytest
from fastapi import HTTPException
from fastapi.security import HTTPBasicCredentials


@pytest.fixture
def auth(monkeypatch):
    """The auth module with its lazily-cached config reset, reading a config
    block we control (config.yaml is baked into the published image, so the
    environment is the lever that must work)."""
    from threatfeedme import auth as mod
    monkeypatch.setattr(mod, "_AUTH_REQUIRED", None)
    # Patch the seam, never core.config: merely READING core.config lazily
    # initializes core from the repo's real config.yaml + ./data DB, which
    # then leaks into every later test (that happened once; don't repeat it).
    monkeypatch.setattr(mod, "_dashboard_config", lambda: {"auth_required": False})
    for var in ("DASHBOARD_USER", "DASHBOARD_PASSWORD"):
        monkeypatch.delenv(var, raising=False)
    return mod


def _creds(user, password):
    return HTTPBasicCredentials(username=user, password=password)


def test_no_credentials_means_open_dashboard(auth):
    assert auth.require_auth(None) is None


def test_setting_both_credentials_turns_auth_on(auth, monkeypatch):
    monkeypatch.setenv("DASHBOARD_USER", "admin")
    monkeypatch.setenv("DASHBOARD_PASSWORD", "s3cret")
    with pytest.raises(HTTPException) as e:
        auth.require_auth(None)
    assert e.value.status_code == 401
    assert auth.require_auth(_creds("admin", "s3cret")) is None


def test_one_credential_alone_does_not_enable_auth(auth, monkeypatch):
    monkeypatch.setenv("DASHBOARD_USER", "admin")
    assert auth.require_auth(None) is None


def test_config_can_force_auth_and_fails_closed_without_creds(auth, monkeypatch):
    monkeypatch.setattr(auth, "_dashboard_config", lambda: {"auth_required": True})
    with pytest.raises(HTTPException) as e:
        auth.require_auth(_creds("admin", "x"))
    assert e.value.status_code == 503


def test_non_ascii_password_is_compared_not_crashed(auth, monkeypatch):
    # compare_digest on non-ASCII str raises TypeError -> every request 500'd
    monkeypatch.setenv("DASHBOARD_USER", "admin")
    monkeypatch.setenv("DASHBOARD_PASSWORD", "pässwörd-ü")
    assert auth.require_auth(_creds("admin", "pässwörd-ü")) is None
    with pytest.raises(HTTPException) as e:
        auth.require_auth(_creds("admin", "passwort"))
    assert e.value.status_code == 401


def test_wrong_username_is_a_plain_401(auth, monkeypatch):
    monkeypatch.setenv("DASHBOARD_USER", "admin")
    monkeypatch.setenv("DASHBOARD_PASSWORD", "s3cret")
    with pytest.raises(HTTPException) as e:
        auth.require_auth(_creds("root", "s3cret"))
    assert e.value.status_code == 401
