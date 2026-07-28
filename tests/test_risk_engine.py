from chronos.breach_checker import BreachResult
from chronos.policy_checker import LEGACY_COMPLEXITY, NIST_800_63B
from chronos.risk_engine import compute_risk_score


def test_weak_common_password_scores_high_risk():
    report = compute_risk_score("password", policy=NIST_800_63B)
    assert report.cprs >= 60
    assert report.risk_level in ("High", "Critical")


def test_strong_unique_password_scores_low_risk():
    report = compute_risk_score("Xk7#mQ2vRt9!pL4zVh8&", policy=NIST_800_63B)
    assert report.cprs <= 30
    assert report.risk_level in ("Minimal", "Low")


def test_confirmed_breach_pushes_risk_up_even_for_decent_strength():
    breached = BreachResult(checked=True, is_breached=True, times_seen=500000)
    report_breached = compute_risk_score("Summer2024!", policy=NIST_800_63B, breach_result=breached)

    clean = BreachResult(checked=True, is_breached=False, times_seen=0)
    report_clean = compute_risk_score("Summer2024!", policy=NIST_800_63B, breach_result=clean)

    assert report_breached.cprs > report_clean.cprs
    assert report_breached.breach_risk == 100.0
    assert report_clean.breach_risk == 0.0


def test_unknown_breach_status_is_not_treated_as_safe():
    report = compute_risk_score("Xk7#mQ2vRt9!pL4zVh8&", policy=NIST_800_63B, breach_result=None)
    assert report.breach_risk == 20.0  # residual uncertainty, not zero


def test_policy_violations_increase_policy_risk():
    report = compute_risk_score("alllowercase", policy=LEGACY_COMPLEXITY)
    assert report.policy_risk > 0
    assert len(report.policy_result.violations) > 0


def test_slower_hash_type_lowers_crack_time_risk():
    md5_report = compute_risk_score("Xk7#mQ2vRt9", policy=NIST_800_63B, hash_type="MD5")
    bcrypt_report = compute_risk_score("Xk7#mQ2vRt9", policy=NIST_800_63B, hash_type="bcrypt")
    assert bcrypt_report.crack_time_risk <= md5_report.crack_time_risk


def test_contributing_factors_non_empty():
    report = compute_risk_score("password", policy=NIST_800_63B)
    assert len(report.contributing_factors) > 0


def test_to_dict_serializes_cleanly():
    report = compute_risk_score("Test1234!", policy=NIST_800_63B)
    d = report.to_dict()
    assert "cprs" in d and "breakdown" in d and "crack_time_estimate" in d
