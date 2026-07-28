"""
policy_checker.py — Configurable password policy compliance checking.

Ships with two presets:
  - "nist800_63b": modern NIST SP 800-63B guidance (length over complexity,
    no forced periodic rotation, no composition rules, but blocks known
    breached/common passwords).
  - "legacy_complexity": traditional composition-rule policy (upper/lower/
    digit/special + min length) for organizations still on older standards.

Custom policies can be built directly via the PasswordPolicy dataclass.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .strength import _matches_common_password  # reuse common-password check


@dataclass
class PasswordPolicy:
    name: str = "custom"
    min_length: int = 8
    max_length: Optional[int] = 64
    require_upper: bool = False
    require_lower: bool = False
    require_digit: bool = False
    require_special: bool = False
    max_repeated_chars: Optional[int] = 3  # None disables this check
    block_common_passwords: bool = True
    forbidden_substrings: list[str] = field(default_factory=list)  # e.g. username, company name


@dataclass
class PolicyResult:
    compliant: bool
    violations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"compliant": self.compliant, "violations": self.violations}


NIST_800_63B = PasswordPolicy(
    name="nist800_63b",
    min_length=8,
    max_length=64,
    require_upper=False,
    require_lower=False,
    require_digit=False,
    require_special=False,
    max_repeated_chars=None,
    block_common_passwords=True,
)

LEGACY_COMPLEXITY = PasswordPolicy(
    name="legacy_complexity",
    min_length=8,
    max_length=64,
    require_upper=True,
    require_lower=True,
    require_digit=True,
    require_special=True,
    max_repeated_chars=3,
    block_common_passwords=True,
)

PRESETS = {
    "nist800_63b": NIST_800_63B,
    "legacy_complexity": LEGACY_COMPLEXITY,
}


def check(password: str, policy: PasswordPolicy, context_terms: Optional[list[str]] = None) -> PolicyResult:
    """
    Evaluate a password against a policy.

    `context_terms` lets callers pass in things like username, email local
    part, or company name at check-time without baking them into the policy
    object itself.
    """
    violations = []

    if len(password) < policy.min_length:
        violations.append(f"Shorter than minimum length ({policy.min_length}).")
    if policy.max_length and len(password) > policy.max_length:
        violations.append(f"Longer than maximum length ({policy.max_length}).")
    if policy.require_upper and not any(c.isupper() for c in password):
        violations.append("Missing required uppercase letter.")
    if policy.require_lower and not any(c.islower() for c in password):
        violations.append("Missing required lowercase letter.")
    if policy.require_digit and not any(c.isdigit() for c in password):
        violations.append("Missing required digit.")
    if policy.require_special and password.isalnum():
        violations.append("Missing required special character.")

    if policy.max_repeated_chars:
        run = 1
        for i in range(1, len(password)):
            run = run + 1 if password[i] == password[i - 1] else 1
            if run > policy.max_repeated_chars:
                violations.append(
                    f"Contains more than {policy.max_repeated_chars} repeated characters in a row."
                )
                break

    if policy.block_common_passwords and _matches_common_password(password):
        violations.append("Matches a known common/breached-pattern password.")

    all_forbidden = list(policy.forbidden_substrings) + list(context_terms or [])
    lowered = password.lower()
    for term in all_forbidden:
        if term and term.lower() in lowered:
            violations.append(f"Contains forbidden/contextual substring: '{term}'.")

    return PolicyResult(compliant=not violations, violations=violations)
