"""
Chronos — Password Risk & Crack-Time Intelligence Engine
==========================================================
A modular, offline-first password auditing toolkit that fuses strength,
breach status, policy compliance, and adversarial crack-time modeling into
a single Composite Password Risk Score (CPRS), plus organization-wide
batch auditing with HTML risk reports.

Modules:
    strength         - Entropy-based password strength scoring
    breach_checker   - k-Anonymity breach lookup (Have I Been Pwned API)
    hash_identifier  - Heuristic hash-type identification
    wordlist_audit   - Offline dictionary/wordlist auditing
    policy_checker   - Configurable password policy compliance (NIST 800-63B preset)
    crack_time       - Time-to-crack estimation across attacker scenarios
    risk_engine      - Composite Password Risk Score (CPRS) fusion engine
    report           - Organization-wide batch audit and HTML report generation

Author: SM Moniruzzaman
License: MIT
"""

__version__ = "2.0.0"
__author__ = "SM Moniruzzaman"
