"""
hash_identifier.py — Heuristic identification of hash/digest types.

Identification is inherently ambiguous for fixed-length hex digests (e.g. a
32-char hex string could be MD5, NTLM, or MD4), so this module returns a
ranked list of candidates with confidence levels rather than a single
"answer" — the same approach tools like hashid/hash-identifier take.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

HEX32 = re.compile(r"^[a-fA-F0-9]{32}$")
HEX40 = re.compile(r"^[a-fA-F0-9]{40}$")
HEX56 = re.compile(r"^[a-fA-F0-9]{56}$")
HEX64 = re.compile(r"^[a-fA-F0-9]{64}$")
HEX96 = re.compile(r"^[a-fA-F0-9]{96}$")
HEX128 = re.compile(r"^[a-fA-F0-9]{128}$")


@dataclass
class HashCandidate:
    name: str
    confidence: str  # "High" | "Medium" | "Low"
    notes: str = ""


# Ordered rules: (matcher, list_of_candidates)
_RULES: list[tuple[re.Pattern, list[HashCandidate]]] = [
    (re.compile(r"^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$"), [
        HashCandidate("bcrypt", "High", "Salted, adaptive — cannot be cracked with a plain lookup table."),
    ]),
    (re.compile(r"^\$6\$"), [HashCandidate("SHA-512 crypt (Unix /etc/shadow)", "High")]),
    (re.compile(r"^\$5\$"), [HashCandidate("SHA-256 crypt (Unix /etc/shadow)", "High")]),
    (re.compile(r"^\$1\$"), [HashCandidate("MD5 crypt (Unix /etc/shadow, legacy)", "High")]),
    (re.compile(r"^\$argon2(id|i|d)\$"), [HashCandidate("Argon2", "High", "Modern, memory-hard KDF.")]),
    (re.compile(r"^\$pbkdf2"), [HashCandidate("PBKDF2 (Django/passlib style)", "High")]),
    (re.compile(r"^\$P\$"), [HashCandidate("phpBB3 / WordPress (phpass)", "High")]),
    (re.compile(r"^0x0100[a-fA-F0-9]{48}$"), [HashCandidate("MSSQL 2000/2005", "Medium")]),
    (re.compile(r"^[a-fA-F0-9]{32}:[a-fA-F0-9]{2,}$"), [HashCandidate("Salted MD5 (hash:salt format)", "Medium")]),
]


def identify_hash(value: str) -> list[HashCandidate]:
    """Return a ranked list of plausible hash-type candidates for `value`."""
    value = value.strip()

    for pattern, candidates in _RULES:
        if pattern.match(value):
            return candidates

    if HEX32.match(value):
        return [
            HashCandidate("MD5", "Medium", "32 hex chars — also matches NTLM/MD4 by length alone."),
            HashCandidate("NTLM", "Medium", "Common in Windows/Active Directory dumps."),
            HashCandidate("MD4", "Low"),
        ]
    if HEX40.match(value):
        return [
            HashCandidate("SHA-1", "Medium", "40 hex chars."),
            HashCandidate("MySQL 5.x (SHA1(SHA1(pw)))", "Low"),
        ]
    if HEX56.match(value):
        return [HashCandidate("SHA-224", "Medium")]
    if HEX64.match(value):
        return [
            HashCandidate("SHA-256", "Medium"),
            HashCandidate("SHA3-256", "Low"),
        ]
    if HEX96.match(value):
        return [HashCandidate("SHA-384", "Medium")]
    if HEX128.match(value):
        return [
            HashCandidate("SHA-512", "Medium"),
            HashCandidate("SHA3-512", "Low"),
            HashCandidate("Whirlpool", "Low"),
        ]

    return [HashCandidate("Unknown", "Low", "Does not match any known fixed pattern or hex length.")]
