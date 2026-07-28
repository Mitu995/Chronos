from chronos.policy_checker import NIST_800_63B
from chronos.report import render_html, run_batch_audit


def test_batch_audit_computes_average():
    entries = [("alice", "password"), ("bob", "Xk7#mQ2vRt9!pL4zVh8&")]
    result = run_batch_audit(entries, policy=NIST_800_63B)
    assert result.total_entries == 2
    assert 0 <= result.average_cprs <= 100


def test_batch_audit_detects_password_reuse():
    entries = [("alice", "Summer2024!"), ("bob", "Summer2024!"), ("carol", "Xk7#mQ2vRt9!pL4zVh8&")]
    result = run_batch_audit(entries, policy=NIST_800_63B)
    assert "Summer2024!" in result.reused_passwords
    assert set(result.reused_passwords["Summer2024!"]) == {"alice", "bob"}


def test_batch_audit_no_reuse_when_all_unique():
    entries = [("alice", "Xk7#mQ2vRt9!pL4zVh8&"), ("bob", "Zp9$wLq4Ry7!nT2b")]
    result = run_batch_audit(entries, policy=NIST_800_63B)
    assert result.reused_passwords == {}


def test_worst_offenders_sorted_descending():
    entries = [
        ("alice", "Xk7#mQ2vRt9!pL4zVh8&"),
        ("bob", "password"),
        ("carol", "Summer2024!"),
    ]
    result = run_batch_audit(entries, policy=NIST_800_63B, top_n_worst=3)
    scores = [e.risk_report.cprs for e in result.worst_offenders]
    assert scores == sorted(scores, reverse=True)


def test_risk_distribution_sums_to_total():
    entries = [("a", "password"), ("b", "Xk7#mQ2vRt9!pL4zVh8&"), ("c", "Summer2024!")]
    result = run_batch_audit(entries, policy=NIST_800_63B)
    assert sum(result.risk_distribution.values()) == result.total_entries


def test_render_html_produces_valid_looking_document():
    entries = [("alice", "password"), ("bob", "Summer2024!")]
    result = run_batch_audit(entries, policy=NIST_800_63B)
    html = render_html(result)
    assert html.strip().startswith("<!DOCTYPE html>")
    assert "Chronos" in html
    assert "alice" in html  # appears in the worst-offenders table
