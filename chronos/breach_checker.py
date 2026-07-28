"""
breach_checker.py — Checks whether a password has appeared in known breaches.

Uses the Have I Been Pwned "Pwned Passwords" API with the k-Anonymity model:
only the first 5 characters of the password's SHA-1 hash are ever sent over
the network, so the plaintext password never leaves the machine and the full
hash is never transmitted either. This is the officially recommended
integration pattern (https://haveibeenpwned.com/API/v3#PwnedPasswords).

No password is ever logged, stored, or transmitted in full.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Optional

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None

HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/{prefix}"
REQUEST_TIMEOUT = 8


@dataclass
class BreachResult:
    checked: bool
    is_breached: Optional[bool]
    times_seen: int
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "checked": self.checked,
            "is_breached": self.is_breached,
            "times_seen": self.times_seen,
            "error": self.error,
        }


def _sha1_upper(password: str) -> str:
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()


def check_password_breach(password: str, timeout: int = REQUEST_TIMEOUT) -> BreachResult:
    """
    Query the HIBP Pwned Passwords range API using k-Anonymity.

    Returns a BreachResult; if the request fails (no internet, API down),
    `checked` is False and `error` explains why — the caller should treat
    this as "unknown", not "safe".
    """
    if requests is None:
        return BreachResult(checked=False, is_breached=None, times_seen=0,
                             error="The 'requests' library is not installed.")

    full_hash = _sha1_upper(password)
    prefix, suffix = full_hash[:5], full_hash[5:]

    try:
        resp = requests.get(
            HIBP_RANGE_URL.format(prefix=prefix),
            timeout=timeout,
            headers={"Add-Padding": "true", "User-Agent": "password-security-auditor"},
        )
        resp.raise_for_status()
    except Exception as exc:  # noqa: BLE001 - surface any network error uniformly
        return BreachResult(checked=False, is_breached=None, times_seen=0, error=str(exc))

    for line in resp.text.splitlines():
        if ":" not in line:
            continue
        line_suffix, count = line.split(":")
        if line_suffix.strip() == suffix:
            return BreachResult(checked=True, is_breached=True, times_seen=int(count))

    return BreachResult(checked=True, is_breached=False, times_seen=0)


def check_batch(passwords: list[str], timeout: int = REQUEST_TIMEOUT) -> dict[str, BreachResult]:
    """Convenience wrapper to check multiple passwords sequentially."""
    return {pwd: check_password_breach(pwd, timeout=timeout) for pwd in passwords}
