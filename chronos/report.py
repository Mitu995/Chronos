"""
report.py — Organization-wide batch password audit with HTML report export.

Takes a list of (identifier, password) pairs — e.g. exported from an internal
password manager, or a scoped HR/IT export under signed authorization — and
produces an aggregate risk report: score distribution, password reuse
clusters (a top VAPT finding: the same password across multiple accounts),
and the highest-risk entries, rendered as a single self-contained HTML file.

Everything in this module runs offline. Breach checking is intentionally
NOT performed automatically here to keep bulk audits network-free and safe
to run against sensitive internal exports; callers may pass in pre-computed
breach results per password if they've explicitly opted into that.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from . import policy_checker, risk_engine
from .breach_checker import BreachResult


@dataclass
class BatchEntry:
    identifier: str
    password: str
    risk_report: risk_engine.RiskReport


@dataclass
class BatchAuditResult:
    generated_at: str
    total_entries: int
    average_cprs: float
    risk_distribution: dict[str, int]
    reused_passwords: dict[str, list[str]]  # password -> list of identifiers (redacted in report)
    top_issues: list[tuple[str, int]]
    worst_offenders: list[BatchEntry]
    entries: list[BatchEntry] = field(default_factory=list)


def run_batch_audit(
    entries: list[tuple[str, str]],
    policy: policy_checker.PasswordPolicy = policy_checker.NIST_800_63B,
    breach_results: Optional[dict[str, BreachResult]] = None,
    top_n_worst: int = 10,
) -> BatchAuditResult:
    """
    Run CPRS scoring across a batch of (identifier, password) pairs.

    `breach_results`, if provided, maps password -> BreachResult so bulk
    runs can optionally incorporate pre-fetched breach data without this
    function making any network calls itself.
    """
    breach_results = breach_results or {}
    scored: list[BatchEntry] = []
    issue_counter: Counter[str] = Counter()
    password_to_identifiers: dict[str, list[str]] = defaultdict(list)

    for identifier, password in entries:
        breach_result = breach_results.get(password)
        risk_report = risk_engine.compute_risk_score(password, policy=policy, breach_result=breach_result)
        scored.append(BatchEntry(identifier=identifier, password=password, risk_report=risk_report))

        password_to_identifiers[password].append(identifier)
        for issue in risk_report.strength_report.issues:
            issue_counter[issue] += 1
        for violation in risk_report.policy_result.violations:
            issue_counter[violation] += 1

    total = len(scored)
    avg_cprs = sum(e.risk_report.cprs for e in scored) / total if total else 0.0

    distribution = {"Minimal": 0, "Low": 0, "Medium": 0, "High": 0, "Critical": 0}
    for e in scored:
        distribution[e.risk_report.risk_level] += 1

    reused = {pwd: ids for pwd, ids in password_to_identifiers.items() if len(ids) > 1}

    worst = sorted(scored, key=lambda e: e.risk_report.cprs, reverse=True)[:top_n_worst]

    return BatchAuditResult(
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        total_entries=total,
        average_cprs=round(avg_cprs, 1),
        risk_distribution=distribution,
        reused_passwords=reused,
        top_issues=issue_counter.most_common(10),
        worst_offenders=worst,
        entries=scored,
    )


_RISK_COLORS = {
    "Minimal": "#2e7d32",
    "Low": "#558b2f",
    "Medium": "#f9a825",
    "High": "#e65100",
    "Critical": "#c62828",
}


def _bar(label: str, count: int, total: int, color: str) -> str:
    pct = (count / total * 100) if total else 0
    return f"""
    <div class="bar-row">
      <span class="bar-label">{label}</span>
      <div class="bar-track"><div class="bar-fill" style="width:{pct:.1f}%;background:{color}"></div></div>
      <span class="bar-count">{count}</span>
    </div>"""


def render_html(result: BatchAuditResult, title: str = "Chronos Password Risk Report") -> str:
    """Render a BatchAuditResult as a single self-contained HTML report."""
    dist_bars = "".join(
        _bar(level, count, result.total_entries, _RISK_COLORS[level])
        for level, count in result.risk_distribution.items()
    )

    reuse_rows = ""
    for pwd, ids in sorted(result.reused_passwords.items(), key=lambda kv: -len(kv[1]))[:15]:
        masked = pwd[0] + "*" * max(1, len(pwd) - 2) + pwd[-1] if len(pwd) > 2 else "*" * len(pwd)
        reuse_rows += f"<tr><td>{masked}</td><td>{len(ids)}</td><td>{', '.join(ids)}</td></tr>"
    reuse_section = (
        f"<table><tr><th>Password (masked)</th><th># Accounts</th><th>Identifiers</th></tr>{reuse_rows}</table>"
        if result.reused_passwords else "<p class='muted'>No password reuse detected across accounts.</p>"
    )

    issues_rows = "".join(f"<tr><td>{issue}</td><td>{count}</td></tr>" for issue, count in result.top_issues)

    worst_rows = ""
    for e in result.worst_offenders:
        color = _RISK_COLORS[e.risk_report.risk_level]
        worst_rows += (
            f"<tr><td>{e.identifier}</td>"
            f"<td><span class='badge' style='background:{color}'>{e.risk_report.cprs}</span></td>"
            f"<td>{e.risk_report.risk_level}</td>"
            f"<td>{e.risk_report.crack_time_estimate.human_readable}</td></tr>"
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{title}</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; background:#0f1115; color:#e6e6e6; margin:0; padding:40px; }}
  .container {{ max-width: 960px; margin: 0 auto; }}
  h1 {{ font-size: 26px; margin-bottom: 4px; }}
  .subtitle {{ color:#9aa0a6; margin-top:0; margin-bottom: 32px; }}
  .summary {{ display:flex; gap:20px; margin-bottom: 32px; flex-wrap: wrap; }}
  .card {{ background:#1a1d24; border-radius:10px; padding:18px 24px; flex:1; min-width:160px; }}
  .card .value {{ font-size:28px; font-weight:700; }}
  .card .label {{ color:#9aa0a6; font-size:13px; text-transform:uppercase; letter-spacing:0.04em; }}
  section {{ margin-bottom: 36px; }}
  h2 {{ font-size:18px; border-bottom:1px solid #2a2d35; padding-bottom:8px; }}
  .bar-row {{ display:flex; align-items:center; gap:12px; margin:8px 0; }}
  .bar-label {{ width:80px; font-size:13px; color:#c7c9cd; }}
  .bar-track {{ flex:1; background:#22252c; border-radius:6px; height:18px; overflow:hidden; }}
  .bar-fill {{ height:100%; border-radius:6px; }}
  .bar-count {{ width:30px; text-align:right; font-size:13px; color:#c7c9cd; }}
  table {{ width:100%; border-collapse: collapse; font-size:14px; }}
  th, td {{ text-align:left; padding:8px 10px; border-bottom:1px solid #22252c; }}
  th {{ color:#9aa0a6; font-weight:600; text-transform:uppercase; font-size:12px; }}
  .badge {{ padding:3px 10px; border-radius:20px; font-weight:700; font-size:13px; }}
  .muted {{ color:#9aa0a6; }}
  footer {{ color:#5f6368; font-size:12px; margin-top:40px; }}
</style>
</head>
<body>
<div class="container">
  <h1>{title}</h1>
  <p class="subtitle">Generated {result.generated_at} · {result.total_entries} accounts audited</p>

  <div class="summary">
    <div class="card"><div class="value">{result.average_cprs}</div><div class="label">Avg. CPRS</div></div>
    <div class="card"><div class="value">{len(result.reused_passwords)}</div><div class="label">Reused Passwords</div></div>
    <div class="card"><div class="value">{result.risk_distribution['Critical'] + result.risk_distribution['High']}</div><div class="label">High/Critical Accounts</div></div>
  </div>

  <section>
    <h2>Risk Distribution</h2>
    {dist_bars}
  </section>

  <section>
    <h2>Password Reuse Across Accounts</h2>
    {reuse_section}
  </section>

  <section>
    <h2>Most Common Issues</h2>
    <table><tr><th>Issue</th><th>Occurrences</th></tr>{issues_rows}</table>
  </section>

  <section>
    <h2>Highest-Risk Accounts</h2>
    <table><tr><th>Identifier</th><th>CPRS</th><th>Level</th><th>Est. Crack Time (offline GPU)</th></tr>{worst_rows}</table>
  </section>

  <footer>Generated by Chronos — Password Risk &amp; Crack-Time Intelligence Engine. For authorized security assessments only.</footer>
</div>
</body>
</html>"""
