"""
Credential policy: which environment variables a feed may use as its API key,
which hosts each key may be sent to, and which names the data-volume .env may
set at startup.

Why this exists (review 2026-09-22): a feed's `auth_env` names an environment
variable whose value is sent as a request header, and it used to be accepted
verbatim from the add-feed API. Anyone who could reach the dashboard (auth is
off by default on a trusted LAN) could add a feed pointing at their own server
with auth_env=UNIFI_PASSWORD — or DASHBOARD_PASSWORD, or any other key — and
the next refresh would hand the secret over. The api-key endpoint would also
write ANY "declared" variable, so auth_env=HTTPS_PROXY turned it into a
persistent proxy injection for every outbound request.

The rule now:
  * A feed key must be either a variable a SHIPPED feed declares
    (OTX_API_KEY, HONEYDB_API_ID, ...) or an operator-defined name with the
    TFM_FEED_ prefix. Nothing else — no DASHBOARD_*, UNIFI_*, *PROXY*.
  * A shipped variable may only be SENT to the host its shipped feed uses, so
    re-pointing alienVault_otx at another server cannot exfiltrate the OTX key.
    TFM_FEED_ keys are the operator's own and may go to any host.
  * The data-volume .env never sets proxy/TLS/interpreter/dashboard variables,
    which neutralizes a .env poisoned before this fix.
"""
import re
from typing import Dict, Iterable, List, Optional, Set
from urllib.parse import urlparse

CUSTOM_KEY_PREFIX = "TFM_FEED_"
_CUSTOM_RE = re.compile(r"TFM_FEED_[A-Z0-9_]+\Z")

# Never settable from the data-volume .env. PROXY anywhere in the name catches
# HTTP(S)_PROXY / ALL_PROXY / NO_PROXY in any case; the rest would let a
# written file change TLS trust, the interpreter, the loader, or the dashboard
# credentials (which must come from the operator's real environment only).
_ENV_FILE_DENY = re.compile(
    r"(?i)(PROXY|^SSL_|^REQUESTS_|^CURL_|^PYTHON|^LD_|^DASHBOARD_|^PATH$|^HOME$|^SHELL$)")


def split_vars(auth_env: Optional[str]) -> List[str]:
    return [v.strip() for v in (auth_env or "").split(",") if v.strip()]


def host_of(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def env_file_may_set(name: str) -> bool:
    """Whether a KEY in the data-volume .env may be applied to os.environ."""
    return not _ENV_FILE_DENY.search(name)


class KeyPolicy:
    """Built from the shipped feed roster (config['feeds']): each declared key
    variable is bound to the host(s) of the shipped feed(s) that declare it."""

    def __init__(self, shipped_feeds: Iterable[dict]):
        self.bound: Dict[str, Set[str]] = {}
        for feed in shipped_feeds or []:
            if not isinstance(feed, dict):
                continue
            host = host_of(feed.get("url") or "")
            for var in split_vars(feed.get("auth_env")):
                if host:
                    self.bound.setdefault(var, set()).add(host)

    @classmethod
    def from_config(cls, config: Optional[Dict]) -> "KeyPolicy":
        return cls((config or {}).get("feeds") or [])

    def allowed_var(self, var: str) -> bool:
        return var in self.bound or bool(_CUSTOM_RE.fullmatch(var))

    def disallowed_reason(self, var: str) -> Optional[str]:
        if self.allowed_var(var):
            return None
        shipped = ", ".join(sorted(self.bound)) or "none"
        return (f"'{var}' can't be used as a feed key. Use a variable a built-in "
                f"feed declares ({shipped}) or a name starting with "
                f"{CUSTOM_KEY_PREFIX} for your own feeds.")

    def may_send(self, var: str, url: str) -> bool:
        """Whether the value of `var` may be sent to `url`'s host."""
        if _CUSTOM_RE.fullmatch(var):
            return True
        hosts = self.bound.get(var)
        return bool(hosts) and host_of(url) in hosts

    def send_refusal(self, var: str, url: str) -> str:
        hosts = ", ".join(sorted(self.bound.get(var, ()))) or "no host"
        return (f"refusing to send {var} to {host_of(url) or url}: that key is "
                f"bound to its built-in feed's host ({hosts})")


def same_origin(a: str, b: str) -> bool:
    """scheme + host + port equality — the boundary credentials must not cross
    on a redirect (an https->http downgrade is an origin change too)."""
    try:
        pa, pb = urlparse(a), urlparse(b)
        return (pa.scheme.lower(), (pa.hostname or "").lower(), pa.port) == \
               (pb.scheme.lower(), (pb.hostname or "").lower(), pb.port)
    except ValueError:
        return False


# Headers safe to carry across an origin change on a redirect. Everything else
# (the feed's auth header, conditional-request validators) stays behind.
CROSS_ORIGIN_SAFE_HEADERS = frozenset({"user-agent", "accept"})
