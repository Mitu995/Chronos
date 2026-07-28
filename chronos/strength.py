"""
strength.py — Entropy-based password strength analysis.

Combines Shannon-entropy estimation with heuristic pattern detection
(keyboard walks, sequential runs, repeated characters, leetspeak-normalized
common-password matches) to produce a 0-100 score and human-readable rating.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
COMMON_PASSWORDS_FILE = DATA_DIR / "common_passwords.txt"

KEYBOARD_ROWS = [
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "1234567890",
]

LEET_MAP = str.maketrans({
    "0": "o", "1": "l", "3": "e", "4": "a",
    "5": "s", "7": "t", "@": "a", "$": "s", "!": "i",
})


@dataclass
class StrengthReport:
    password_length: int
    entropy_bits: float
    pool_size: int
    score: int
    rating: str
    issues: list[str] = field(default_factory=list)
    suggestions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "length": self.password_length,
            "entropy_bits": round(self.entropy_bits, 2),
            "character_pool_size": self.pool_size,
            "score": self.score,
            "rating": self.rating,
            "issues": self.issues,
            "suggestions": self.suggestions,
        }


def _load_common_passwords() -> set[str]:
    if not COMMON_PASSWORDS_FILE.exists():
        return set()
    with open(COMMON_PASSWORDS_FILE, "r", encoding="utf-8", errors="ignore") as f:
        return {line.strip().lower() for line in f if line.strip()}


_COMMON_PASSWORDS_CACHE: set[str] | None = None


def _common_passwords() -> set[str]:
    global _COMMON_PASSWORDS_CACHE
    if _COMMON_PASSWORDS_CACHE is None:
        _COMMON_PASSWORDS_CACHE = _load_common_passwords()
    return _COMMON_PASSWORDS_CACHE


def character_pool_size(password: str) -> int:
    """Estimate the size of the character space the password draws from."""
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"[0-9]", password):
        pool += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        pool += 33  # common printable special characters
    return pool or 1


def calculate_entropy(password: str) -> float:
    """Shannon-style entropy estimate: length * log2(pool_size)."""
    pool = character_pool_size(password)
    if not password:
        return 0.0
    return len(password) * math.log2(pool)


def _has_sequential_run(password: str, run_length: int = 3) -> bool:
    lowered = password.lower()
    for i in range(len(lowered) - run_length + 1):
        window = lowered[i:i + run_length]
        if all(ord(window[j + 1]) - ord(window[j]) == 1 for j in range(len(window) - 1)):
            return True
        if all(ord(window[j]) - ord(window[j + 1]) == 1 for j in range(len(window) - 1)):
            return True
    return False


def _has_keyboard_walk(password: str, run_length: int = 4) -> bool:
    lowered = password.lower()
    for row in KEYBOARD_ROWS:
        for i in range(len(row) - run_length + 1):
            chunk = row[i:i + run_length]
            if chunk in lowered or chunk[::-1] in lowered:
                return True
    return False


def _has_repeated_chars(password: str, run_length: int = 3) -> bool:
    return bool(re.search(r"(.)\1{" + str(run_length - 1) + r",}", password))


def _matches_common_password(password: str) -> bool:
    normalized = password.lower().translate(LEET_MAP)
    common = _common_passwords()
    return password.lower() in common or normalized in common


def detect_patterns(password: str) -> list[str]:
    """Return a list of human-readable weakness flags."""
    issues = []
    if len(password) < 8:
        issues.append("Password is shorter than 8 characters.")
    if _has_sequential_run(password):
        issues.append("Contains a sequential character run (e.g. 'abc', '321').")
    if _has_keyboard_walk(password):
        issues.append("Contains a keyboard-adjacent pattern (e.g. 'qwerty', 'asdf').")
    if _has_repeated_chars(password):
        issues.append("Contains 3+ repeated characters in a row (e.g. 'aaa').")
    if _matches_common_password(password):
        issues.append("Matches a known common password (including leetspeak variants).")
    if not re.search(r"[A-Z]", password):
        issues.append("No uppercase letters.")
    if not re.search(r"[a-z]", password):
        issues.append("No lowercase letters.")
    if not re.search(r"[0-9]", password):
        issues.append("No digits.")
    if not re.search(r"[^a-zA-Z0-9]", password):
        issues.append("No special characters.")
    return issues


def _score_from_entropy(entropy: float) -> int:
    """Map entropy bits to a 0-100 baseline score."""
    # ~28 bits -> weak, ~60 bits -> strong, ~80+ -> very strong
    return max(0, min(100, round((entropy / 80) * 100)))


def _rating_from_score(score: int) -> str:
    if score < 20:
        return "Very Weak"
    if score < 40:
        return "Weak"
    if score < 60:
        return "Fair"
    if score < 80:
        return "Strong"
    return "Very Strong"


def score_password(password: str) -> StrengthReport:
    """Run the full strength analysis pipeline for a single password."""
    entropy = calculate_entropy(password)
    pool = character_pool_size(password)
    issues = detect_patterns(password)

    score = _score_from_entropy(entropy)
    # Penalize each detected issue; heavier penalty for common-password matches
    for issue in issues:
        score -= 15 if "common password" in issue else 8
    score = max(0, min(100, score))

    rating = _rating_from_score(score)

    suggestions = []
    if len(password) < 12:
        suggestions.append("Use at least 12-16 characters; length matters more than symbol substitution.")
    if "No special characters." in issues:
        suggestions.append("Add special characters (e.g. !, #, %, *).")
    if "No uppercase letters." in issues or "No lowercase letters." in issues:
        suggestions.append("Mix uppercase and lowercase letters.")
    if any("common password" in i for i in issues):
        suggestions.append("Avoid dictionary words or their leetspeak variants; consider a passphrase instead.")
    if any("keyboard-adjacent" in i or "sequential" in i for i in issues):
        suggestions.append("Avoid keyboard walks and sequential runs.")
    if not suggestions:
        suggestions.append("Looks solid — consider a password manager to keep it unique per account.")

    return StrengthReport(
        password_length=len(password),
        entropy_bits=entropy,
        pool_size=pool,
        score=score,
        rating=rating,
        issues=issues,
        suggestions=suggestions,
    )
