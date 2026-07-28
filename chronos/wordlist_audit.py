"""
wordlist_audit.py — Offline password auditing against a local wordlist.

Intended use: auditing YOUR OWN organization's password hashes/exports (with
proper authorization) or personal passwords against known-leaked wordlists
(e.g. rockyou.txt) to flag reused/weak credentials before an attacker does.
This module never contacts the network — everything runs locally.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class WordlistAuditResult:
    total_checked: int
    found_in_wordlist: list[str] = field(default_factory=list)
    not_found: list[str] = field(default_factory=list)
    wordlist_size: int = 0
    seconds_elapsed: float = 0.0

    def to_dict(self) -> dict:
        return {
            "total_checked": self.total_checked,
            "found_count": len(self.found_in_wordlist),
            "found_in_wordlist": self.found_in_wordlist,
            "wordlist_size": self.wordlist_size,
            "seconds_elapsed": round(self.seconds_elapsed, 3),
        }


def load_wordlist(path: str | Path, case_sensitive: bool = False) -> set[str]:
    """
    Load a wordlist file into a set for O(1) membership checks.

    For very large wordlists (rockyou.txt is ~14M lines), a set is still the
    fastest practical approach in pure Python; for repeated large-scale runs
    consider swapping in a Bloom filter (see README 'Future Enhancements').
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Wordlist not found: {path}")

    words: set[str] = set()
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            word = line.rstrip("\n\r")
            if not word:
                continue
            words.add(word if case_sensitive else word.lower())
    return words


def audit_password(password: str, wordlist: set[str], case_sensitive: bool = False) -> bool:
    """Check whether a single password appears verbatim in the wordlist."""
    needle = password if case_sensitive else password.lower()
    return needle in wordlist


def audit_batch(passwords: list[str], wordlist: set[str], case_sensitive: bool = False) -> WordlistAuditResult:
    """Audit a batch of passwords against a preloaded wordlist set."""
    start = time.perf_counter()
    found, not_found = [], []

    for pwd in passwords:
        if audit_password(pwd, wordlist, case_sensitive=case_sensitive):
            found.append(pwd)
        else:
            not_found.append(pwd)

    elapsed = time.perf_counter() - start
    return WordlistAuditResult(
        total_checked=len(passwords),
        found_in_wordlist=found,
        not_found=not_found,
        wordlist_size=len(wordlist),
        seconds_elapsed=elapsed,
    )


def audit_from_file(passwords_path: str | Path, wordlist_path: str | Path,
                     case_sensitive: bool = False) -> WordlistAuditResult:
    """Load passwords (one per line) and a wordlist from disk, then audit."""
    wordlist = load_wordlist(wordlist_path, case_sensitive=case_sensitive)
    with open(passwords_path, "r", encoding="utf-8", errors="ignore") as f:
        passwords = [line.rstrip("\n\r") for line in f if line.strip()]
    return audit_batch(passwords, wordlist, case_sensitive=case_sensitive)
