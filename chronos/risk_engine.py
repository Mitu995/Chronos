"""
risk_engine.py — Composite Password Risk Score (CPRS).

CPRS fuses four independent signals into a single, documented 0-100 risk
score (higher = riskier). This is deliberately NOT just "invert the strength
score" — a password can have decent entropy but still be catastrophically
risky if it was breached, or fine on paper but non-compliant with policy.
Fusing the signals produces a more decision-useful number than any one
signal alone.

    CPRS = 0.30 * StrengthRisk
         + 0.30 * BreachRisk
         + 0.15 * PolicyRisk
         + 0.25 * CrackTimeRisk

Weight rationale:
  - StrengthRisk (30%): entropy/pattern-based, always available, no network
    call required — the baseline signal.
  - BreachRisk (30%): weighted equally with strength because a breached
    password is a near-certain compromise regardless of how "strong" it
    looks in isolation (real people reuse strong-looking passwords).
  - PolicyRisk (15%): lower weight because policy violations are often
    about organizational compliance rather than raw crackability.
  - CrackTimeRisk (25%): translates entropy into a concrete adversarial
    time-to-compromise, which strength scoring alone does not communicate.

Sub-score derivations:
  - StrengthRisk = 100 - strength_score (from strength.score_password)
  - BreachRisk   = 100 if breached, 0 if confirmed clean, 20 if unknown
                    (network unavailable — treated as residual uncertainty,
                    not as "safe")
  - PolicyRisk   = min(100, violations_count * 25)
  - CrackTimeRisk: bucketed from the offline_single_gpu crack-time estimate
                    (a conservative, hash-agnostic middle-ground scenario)

Risk levels:
    0-19   Minimal
    20-39  Low
    40-59  Medium
    60-79  High
    80-100 Critical
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from . import crack_time as crack_time_mod
from . import policy_checker
from . import strength as strength_mod
from .breach_checker import BreachResult

WEIGHTS = {
    "strength": 0.30,
    "breach": 0.30,
    "policy": 0.15,
    "crack_time": 0.25,
}

_CRACK_TIME_BUCKETS = [
    # (seconds_upper_bound, risk_points)
    (60 * 60, 100),                 # under an hour
    (60 * 60 * 24, 90),             # under a day
    (60 * 60 * 24 * 30, 70),        # under a month
    (60 * 60 * 24 * 365, 50),       # under a year
    (60 * 60 * 24 * 365 * 10, 25),  # under a decade
    (60 * 60 * 24 * 365 * 100, 10),  # under a century
]


@dataclass
class RiskReport:
    cprs: int
    risk_level: str
    strength_risk: float
    breach_risk: float
    policy_risk: float
    crack_time_risk: float
    strength_report: strength_mod.StrengthReport
    policy_result: policy_checker.PolicyResult
    breach_result: Optional[BreachResult]
    crack_time_estimate: crack_time_mod.CrackTimeEstimate
    contributing_factors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "cprs": self.cprs,
            "risk_level": self.risk_level,
            "breakdown": {
                "strength_risk": round(self.strength_risk, 1),
                "breach_risk": round(self.breach_risk, 1),
                "policy_risk": round(self.policy_risk, 1),
                "crack_time_risk": round(self.crack_time_risk, 1),
            },
            "weights": WEIGHTS,
            "strength": self.strength_report.to_dict(),
            "policy": self.policy_result.to_dict(),
            "breach": self.breach_result.to_dict() if self.breach_result else None,
            "crack_time_estimate": self.crack_time_estimate.to_dict(),
            "contributing_factors": self.contributing_factors,
        }


def _crack_time_risk(seconds: float) -> float:
    for upper_bound, points in _CRACK_TIME_BUCKETS:
        if seconds < upper_bound:
            return points
    return 0.0


def _risk_level(cprs: int) -> str:
    if cprs >= 80:
        return "Critical"
    if cprs >= 60:
        return "High"
    if cprs >= 40:
        return "Medium"
    if cprs >= 20:
        return "Low"
    return "Minimal"


def compute_risk_score(
    password: str,
    policy: policy_checker.PasswordPolicy = policy_checker.NIST_800_63B,
    breach_result: Optional[BreachResult] = None,
    hash_type: str = "Unknown",
) -> RiskReport:
    """
    Compute the Composite Password Risk Score for a single password.

    `breach_result` is optional and caller-supplied so this function never
    makes a network call itself — callers decide whether to run the (online)
    breach check and pass the result in, keeping this module offline-safe
    and independently testable.
    """
    strength_report = strength_mod.score_password(password)
    policy_result = policy_checker.check(password, policy)
    crack_estimate = crack_time_mod.estimate_crack_time(
        strength_report.entropy_bits, hash_type=hash_type, scenario="offline_single_gpu"
    )

    strength_risk = 100 - strength_report.score

    if breach_result is None or not breach_result.checked:
        breach_risk = 20.0  # unknown -> residual uncertainty, not "safe"
    elif breach_result.is_breached:
        breach_risk = 100.0
    else:
        breach_risk = 0.0

    policy_risk = min(100.0, len(policy_result.violations) * 25.0)
    crack_risk = _crack_time_risk(crack_estimate.seconds_to_crack)

    cprs = (
        WEIGHTS["strength"] * strength_risk
        + WEIGHTS["breach"] * breach_risk
        + WEIGHTS["policy"] * policy_risk
        + WEIGHTS["crack_time"] * crack_risk
    )
    cprs = round(max(0.0, min(100.0, cprs)))

    factors = []
    if breach_risk == 100.0:
        factors.append("Password found in known breach data — treat as fully compromised.")
    if strength_risk > 60:
        factors.append("Low entropy / weak composition drives most of the risk.")
    if policy_risk > 0:
        factors.append(f"{len(policy_result.violations)} policy violation(s) detected.")
    if crack_risk >= 70:
        factors.append(f"Estimated crackable in {crack_estimate.human_readable} under an offline single-GPU attack.")
    if not factors:
        factors.append("No significant risk factors detected across strength, breach, policy, or crack-time signals.")

    return RiskReport(
        cprs=cprs,
        risk_level=_risk_level(cprs),
        strength_risk=strength_risk,
        breach_risk=breach_risk,
        policy_risk=policy_risk,
        crack_time_risk=crack_risk,
        strength_report=strength_report,
        policy_result=policy_result,
        breach_result=breach_result,
        crack_time_estimate=crack_estimate,
        contributing_factors=factors,
    )
