"""
crack_time.py — Estimates time-to-crack under realistic attacker scenarios.

Rather than reporting entropy in the abstract, this module converts entropy
into a *time* figure by combining it with:
  1. The target's hash type (a bcrypt hash survives orders of magnitude
     longer than an unsalted MD5 hash at the same password entropy).
  2. An attacker scenario (rate-limited login form vs. a single offline GPU
     vs. a distributed GPU cluster).

Hash-rate figures are round, order-of-magnitude approximations based on
publicly published hashcat benchmark classes for a modern high-end consumer
GPU. They are for illustrative risk communication only — NOT a precision
benchmark, and this module performs no actual hashing or cracking of
anything. It only does arithmetic on a number the caller already computed
(bits of entropy) against a public rate table.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

# Approximate guesses/second for a *single* modern high-end consumer GPU,
# order-of-magnitude figures based on publicly documented hashcat benchmark
# classes. Real-world throughput varies by hardware, mode, and rules used.
GPU_HASH_RATES: dict[str, float] = {
    "MD5": 2e10,
    "NTLM": 3e10,
    "SHA-1": 6e9,
    "SHA-256": 2.5e9,
    "SHA-384": 1e9,
    "SHA-512": 1e9,
    "SHA3-256": 1e9,
    "SHA3-512": 5e8,
    "MD4": 2e10,
    "MySQL 5.x (SHA1(SHA1(pw)))": 6e9,
    "Whirlpool": 3e8,
    "Unix SHA-512 crypt": 2e4,
    "SHA-512 crypt (Unix /etc/shadow)": 2e4,
    "SHA-256 crypt (Unix /etc/shadow)": 3e4,
    "MD5 crypt (Unix /etc/shadow, legacy)": 5e5,
    "phpBB3 / WordPress (phpass)": 4e5,
    "PBKDF2 (Django/passlib style)": 5e3,
    "bcrypt": 5e4,
    "Argon2": 5.0,
    "Unknown": 2.5e9,  # conservative fallback: assume a fast, unsalted hash
}

# Scenario multipliers / overrides applied on top of the base GPU rate.
SCENARIOS = {
    "online_throttled": {
        "label": "Online, rate-limited login (~10 attempts/sec)",
        "fixed_rate": 10.0,  # hash type is irrelevant behind a login form
    },
    "offline_single_gpu": {
        "label": "Offline attack, single high-end GPU",
        "multiplier": 1.0,
    },
    "offline_gpu_cluster": {
        "label": "Offline attack, 100-GPU cluster",
        "multiplier": 100.0,
    },
}


@dataclass
class CrackTimeEstimate:
    scenario: str
    scenario_label: str
    hash_type: str
    guesses_per_second: float
    seconds_to_crack: float
    human_readable: str

    def to_dict(self) -> dict:
        return {
            "scenario": self.scenario,
            "scenario_label": self.scenario_label,
            "hash_type": self.hash_type,
            "guesses_per_second": self.guesses_per_second,
            "seconds_to_crack": self.seconds_to_crack,
            "human_readable": self.human_readable,
        }


def _humanize_seconds(seconds: float) -> str:
    if seconds < 1:
        return "instantly"
    units = [
        ("centuries", 60 * 60 * 24 * 365 * 100),
        ("years", 60 * 60 * 24 * 365),
        ("days", 60 * 60 * 24),
        ("hours", 60 * 60),
        ("minutes", 60),
        ("seconds", 1),
    ]
    for name, size in units:
        if seconds >= size:
            value = seconds / size
            if name == "centuries" and value > 1000:
                return f"{value:,.0f} centuries (effectively uncrackable)"
            return f"{value:,.1f} {name}"
    return f"{seconds:.2f} seconds"


def estimate_crack_time(
    entropy_bits: float,
    hash_type: str = "Unknown",
    scenario: str = "offline_single_gpu",
) -> CrackTimeEstimate:
    """
    Estimate time-to-crack for a password of given entropy under a scenario.

    Uses the average-case assumption that an attacker finds the password
    after searching half the keyspace: guesses = 2^entropy / 2.
    """
    if scenario not in SCENARIOS:
        raise ValueError(f"Unknown scenario '{scenario}'. Valid: {list(SCENARIOS)}")

    scenario_cfg = SCENARIOS[scenario]
    if "fixed_rate" in scenario_cfg:
        rate = scenario_cfg["fixed_rate"]
    else:
        base_rate = GPU_HASH_RATES.get(hash_type, GPU_HASH_RATES["Unknown"])
        rate = base_rate * scenario_cfg["multiplier"]

    guesses = (2 ** entropy_bits) / 2
    seconds = guesses / rate

    return CrackTimeEstimate(
        scenario=scenario,
        scenario_label=scenario_cfg["label"],
        hash_type=hash_type,
        guesses_per_second=rate,
        seconds_to_crack=seconds,
        human_readable=_humanize_seconds(seconds),
    )


def estimate_all_scenarios(entropy_bits: float, hash_type: str = "Unknown") -> list[CrackTimeEstimate]:
    """Convenience helper: estimate crack time across all defined scenarios."""
    return [estimate_crack_time(entropy_bits, hash_type, scenario) for scenario in SCENARIOS]
