"""
cli.py — Command-line interface for Chronos (Password Risk & Crack-Time Intelligence Engine).

Subcommands:
    strength   Score a password's strength (entropy + pattern heuristics)
    breach     Check a password against HIBP's Pwned Passwords (k-Anonymity)
    hashid     Identify the likely type of a hash/digest string
    wordlist   Audit password(s) against a local wordlist file
    policy     Check a password against a policy preset or custom rules
    audit      Run the full pipeline (strength + breach + policy) at once
"""

from __future__ import annotations

import argparse
import csv
import getpass
import json
import sys
from pathlib import Path

from . import (
    breach_checker,
    crack_time,
    hash_identifier,
    policy_checker,
    report,
    risk_engine,
    strength,
    wordlist_audit,
)

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    _COLOR = True
except ImportError:  # pragma: no cover
    _COLOR = False

    class _NoColor:
        def __getattr__(self, _):
            return ""
    Fore = Style = _NoColor()


RATING_COLOR = {
    "Very Weak": Fore.RED,
    "Weak": Fore.RED,
    "Fair": Fore.YELLOW,
    "Strong": Fore.GREEN,
    "Very Strong": Fore.GREEN,
}


def _prompt_password(label: str = "Password") -> str:
    return getpass.getpass(f"{label}: ")


def _print_json(data: dict) -> None:
    print(json.dumps(data, indent=2))


def _write_csv(rows: list[dict], path: str) -> None:
    if not rows:
        return
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


# --------------------------------------------------------------------------
# Subcommand handlers
# --------------------------------------------------------------------------

def cmd_strength(args: argparse.Namespace) -> None:
    pwd = args.password or _prompt_password()
    report = strength.score_password(pwd)

    if args.json:
        _print_json(report.to_dict())
        return

    color = RATING_COLOR.get(report.rating, "")
    print(f"\n{Style.BRIGHT}Password Strength Report{Style.RESET_ALL}")
    print(f"  Length        : {report.password_length}")
    print(f"  Entropy       : {report.entropy_bits:.1f} bits")
    print(f"  Score         : {report.score}/100")
    print(f"  Rating        : {color}{report.rating}{Style.RESET_ALL}")
    if report.issues:
        print(f"\n  {Fore.YELLOW}Issues:{Style.RESET_ALL}")
        for issue in report.issues:
            print(f"    - {issue}")
    print(f"\n  Suggestions:")
    for s in report.suggestions:
        print(f"    - {s}")
    print()


def cmd_breach(args: argparse.Namespace) -> None:
    pwd = args.password or _prompt_password()
    result = breach_checker.check_password_breach(pwd)

    if args.json:
        _print_json(result.to_dict())
        return

    print()
    if not result.checked:
        print(f"{Fore.YELLOW}Could not check breach status: {result.error}{Style.RESET_ALL}")
    elif result.is_breached:
        print(f"{Fore.RED}⚠ This password has appeared in {result.times_seen:,} known breaches.{Style.RESET_ALL}")
        print("  Do not use it for any account.")
    else:
        print(f"{Fore.GREEN}✓ Not found in the Pwned Passwords database.{Style.RESET_ALL}")
    print()


def cmd_hashid(args: argparse.Namespace) -> None:
    candidates = hash_identifier.identify_hash(args.hash_value)

    if args.json:
        _print_json({"input": args.hash_value,
                      "candidates": [c.__dict__ for c in candidates]})
        return

    print(f"\n{Style.BRIGHT}Hash Identification{Style.RESET_ALL}")
    print(f"  Input : {args.hash_value}")
    print(f"  Length: {len(args.hash_value)} chars\n")
    for c in candidates:
        print(f"  [{c.confidence:6}] {c.name}" + (f"  — {c.notes}" if c.notes else ""))
    print()


def cmd_wordlist(args: argparse.Namespace) -> None:
    wl = wordlist_audit.load_wordlist(args.wordlist, case_sensitive=args.case_sensitive)

    if args.passwords_file:
        with open(args.passwords_file, "r", encoding="utf-8", errors="ignore") as f:
            passwords = [line.rstrip("\n\r") for line in f if line.strip()]
    else:
        passwords = [args.password or _prompt_password()]

    result = wordlist_audit.audit_batch(passwords, wl, case_sensitive=args.case_sensitive)

    if args.json:
        _print_json(result.to_dict())
        return

    print(f"\n{Style.BRIGHT}Wordlist Audit{Style.RESET_ALL}")
    print(f"  Wordlist size : {result.wordlist_size:,} entries")
    print(f"  Checked       : {result.total_checked}")
    print(f"  Found         : {len(result.found_in_wordlist)}")
    print(f"  Time          : {result.seconds_elapsed:.3f}s")
    if result.found_in_wordlist:
        print(f"\n  {Fore.RED}Passwords found in wordlist:{Style.RESET_ALL}")
        for p in result.found_in_wordlist:
            print(f"    - {p}")
    print()

    if args.csv:
        rows = [{"password": p, "found_in_wordlist": p in result.found_in_wordlist} for p in passwords]
        _write_csv(rows, args.csv)
        print(f"CSV report written to {args.csv}")


def cmd_policy(args: argparse.Namespace) -> None:
    pwd = args.password or _prompt_password()
    policy = policy_checker.PRESETS.get(args.preset, policy_checker.NIST_800_63B)
    context_terms = args.context.split(",") if args.context else []
    result = policy_checker.check(pwd, policy, context_terms=context_terms)

    if args.json:
        _print_json({"policy": policy.name, **result.to_dict()})
        return

    print(f"\n{Style.BRIGHT}Policy Compliance ({policy.name}){Style.RESET_ALL}")
    if result.compliant:
        print(f"  {Fore.GREEN}✓ Compliant{Style.RESET_ALL}")
    else:
        print(f"  {Fore.RED}✗ Non-compliant{Style.RESET_ALL}")
        for v in result.violations:
            print(f"    - {v}")
    print()


def cmd_audit(args: argparse.Namespace) -> None:
    """Full pipeline: strength + policy, and breach if --online is set."""
    pwd = args.password or _prompt_password()

    strength_report = strength.score_password(pwd)
    policy = policy_checker.PRESETS.get(args.preset, policy_checker.NIST_800_63B)
    policy_result = policy_checker.check(pwd, policy)

    breach_result = None
    if args.online:
        breach_result = breach_checker.check_password_breach(pwd)

    wl_result = None
    if args.wordlist:
        wl = wordlist_audit.load_wordlist(args.wordlist)
        wl_result = wordlist_audit.audit_password(pwd, wl)

    if args.json:
        out = {
            "strength": strength_report.to_dict(),
            "policy": {"preset": policy.name, **policy_result.to_dict()},
        }
        if breach_result:
            out["breach"] = breach_result.to_dict()
        if args.wordlist:
            out["found_in_wordlist"] = wl_result
        _print_json(out)
        return

    color = RATING_COLOR.get(strength_report.rating, "")
    print(f"\n{Style.BRIGHT}=== Full Password Audit ==={Style.RESET_ALL}")
    print(f"\n[Strength]  Score: {strength_report.score}/100  "
          f"Rating: {color}{strength_report.rating}{Style.RESET_ALL}  "
          f"Entropy: {strength_report.entropy_bits:.1f} bits")
    for issue in strength_report.issues:
        print(f"    - {issue}")

    print(f"\n[Policy: {policy.name}]  ", end="")
    print(f"{Fore.GREEN}Compliant{Style.RESET_ALL}" if policy_result.compliant
          else f"{Fore.RED}Non-compliant{Style.RESET_ALL}")
    for v in policy_result.violations:
        print(f"    - {v}")

    if breach_result:
        print(f"\n[Breach Check]  ", end="")
        if not breach_result.checked:
            print(f"{Fore.YELLOW}Unknown ({breach_result.error}){Style.RESET_ALL}")
        elif breach_result.is_breached:
            print(f"{Fore.RED}Found in {breach_result.times_seen:,} breaches{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}Not found{Style.RESET_ALL}")

    if args.wordlist:
        print(f"\n[Wordlist: {Path(args.wordlist).name}]  ", end="")
        print(f"{Fore.RED}Found{Style.RESET_ALL}" if wl_result else f"{Fore.GREEN}Not found{Style.RESET_ALL}")

    print()


def cmd_risk(args: argparse.Namespace) -> None:
    """Full Composite Password Risk Score (CPRS): strength + policy + crack-time, optional breach."""
    pwd = args.password or _prompt_password()
    policy = policy_checker.PRESETS.get(args.preset, policy_checker.NIST_800_63B)

    breach_result = breach_checker.check_password_breach(pwd) if args.online else None
    risk_report = risk_engine.compute_risk_score(
        pwd, policy=policy, breach_result=breach_result, hash_type=args.hash_type
    )

    if args.json:
        _print_json(risk_report.to_dict())
        return

    color = RATING_COLOR.get(
        {"Minimal": "Very Strong", "Low": "Strong", "Medium": "Fair",
         "High": "Weak", "Critical": "Very Weak"}[risk_report.risk_level], ""
    )
    print(f"\n{Style.BRIGHT}=== Chronos Risk Score (CPRS) ==={Style.RESET_ALL}")
    print(f"\n  CPRS Score : {risk_report.cprs}/100")
    print(f"  Risk Level : {color}{risk_report.risk_level}{Style.RESET_ALL}")
    print(f"\n  Breakdown:")
    print(f"    Strength risk    : {risk_report.strength_risk:.0f}/100  (weight 30%)")
    print(f"    Breach risk      : {risk_report.breach_risk:.0f}/100  (weight 30%)")
    print(f"    Policy risk      : {risk_report.policy_risk:.0f}/100  (weight 15%)")
    print(f"    Crack-time risk  : {risk_report.crack_time_risk:.0f}/100  (weight 25%)")
    print(f"\n  Estimated crack time (offline, single GPU, hash type: {args.hash_type}):")
    print(f"    {risk_report.crack_time_estimate.human_readable}")
    print(f"\n  Contributing factors:")
    for f in risk_report.contributing_factors:
        print(f"    - {f}")
    print()


def cmd_cracktime(args: argparse.Namespace) -> None:
    pwd = args.password or _prompt_password()
    report_ = strength.score_password(pwd)
    estimates = crack_time.estimate_all_scenarios(report_.entropy_bits, hash_type=args.hash_type)

    if args.json:
        _print_json({"entropy_bits": round(report_.entropy_bits, 2),
                      "hash_type": args.hash_type,
                      "estimates": [e.to_dict() for e in estimates]})
        return

    print(f"\n{Style.BRIGHT}Crack-Time Estimate{Style.RESET_ALL}  (entropy: {report_.entropy_bits:.1f} bits, "
          f"hash type: {args.hash_type})\n")
    for e in estimates:
        print(f"  {e.scenario_label}")
        print(f"    -> {Style.BRIGHT}{e.human_readable}{Style.RESET_ALL}\n")


def cmd_org_audit(args: argparse.Namespace) -> None:
    entries: list[tuple[str, str]] = []
    with open(args.input_file, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.rstrip("\n\r")
            if not line:
                continue
            if ":" in line:
                identifier, pwd = line.split(":", 1)
            else:
                identifier, pwd = line, line  # fallback: no identifier column supplied
            entries.append((identifier, pwd))

    policy = policy_checker.PRESETS.get(args.preset, policy_checker.NIST_800_63B)
    result = report.run_batch_audit(entries, policy=policy, top_n_worst=args.top_n)

    if args.json:
        _print_json({
            "generated_at": result.generated_at,
            "total_entries": result.total_entries,
            "average_cprs": result.average_cprs,
            "risk_distribution": result.risk_distribution,
            "reused_password_count": len(result.reused_passwords),
            "top_issues": result.top_issues,
        })
    else:
        print(f"\n{Style.BRIGHT}Batch Audit Summary{Style.RESET_ALL}")
        print(f"  Accounts audited : {result.total_entries}")
        print(f"  Average CPRS     : {result.average_cprs}")
        print(f"  Reused passwords : {len(result.reused_passwords)}")
        print(f"  Risk distribution: {result.risk_distribution}")

    if args.html:
        html = report.render_html(result)
        with open(args.html, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"\nHTML report written to {args.html}")


# --------------------------------------------------------------------------
# Argument parsing
# --------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="chronos",
        description="Chronos — Password Risk & Crack-Time Intelligence Engine. Composite risk "
                     "scoring (CPRS), crack-time estimation, breach/hash/wordlist/policy auditing, "
                     "and organization-wide HTML risk reporting.",
        epilog="Examples:\n"
               "  chronos strength\n"
               "  chronos risk --online\n"
               "  chronos cracktime --hash-type bcrypt\n"
               "  chronos breach --json\n"
               "  chronos hashid -H 5f4dcc3b5aa765d61d8327deb882cf99\n"
               "  chronos wordlist -w rockyou.txt -f exported_passwords.txt --csv report.csv\n"
               "  chronos policy --preset legacy_complexity\n"
               "  chronos org-audit -i accounts.txt --html risk_report.html\n"
               "  chronos audit --online --wordlist rockyou.txt\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    common_pwd = dict(help="Password to check (omit to be prompted securely, recommended).")

    p_strength = sub.add_parser("strength", help="Analyze password strength.")
    p_strength.add_argument("-p", "--password", **common_pwd)
    p_strength.add_argument("--json", action="store_true", help="Output as JSON.")
    p_strength.set_defaults(func=cmd_strength)

    p_breach = sub.add_parser("breach", help="Check password against known breaches (HIBP, k-Anonymity).")
    p_breach.add_argument("-p", "--password", **common_pwd)
    p_breach.add_argument("--json", action="store_true", help="Output as JSON.")
    p_breach.set_defaults(func=cmd_breach)

    p_hashid = sub.add_parser("hashid", help="Identify the likely type of a hash string.")
    p_hashid.add_argument("-H", "--hash-value", required=True, help="Hash string to identify.")
    p_hashid.add_argument("--json", action="store_true", help="Output as JSON.")
    p_hashid.set_defaults(func=cmd_hashid)

    p_wordlist = sub.add_parser("wordlist", help="Audit password(s) against a local wordlist.")
    p_wordlist.add_argument("-w", "--wordlist", required=True, help="Path to wordlist file.")
    p_wordlist.add_argument("-p", "--password", help="Single password to check.")
    p_wordlist.add_argument("-f", "--passwords-file", help="File with one password per line (batch mode).")
    p_wordlist.add_argument("--case-sensitive", action="store_true")
    p_wordlist.add_argument("--csv", help="Write batch results to this CSV path.")
    p_wordlist.add_argument("--json", action="store_true", help="Output as JSON.")
    p_wordlist.set_defaults(func=cmd_wordlist)

    p_policy = sub.add_parser("policy", help="Check password against a policy.")
    p_policy.add_argument("-p", "--password", **common_pwd)
    p_policy.add_argument("--preset", choices=list(policy_checker.PRESETS.keys()),
                           default="nist800_63b", help="Policy preset to use.")
    p_policy.add_argument("--context", help="Comma-separated forbidden terms (e.g. username,company).")
    p_policy.add_argument("--json", action="store_true", help="Output as JSON.")
    p_policy.set_defaults(func=cmd_policy)

    p_risk = sub.add_parser("risk", help="Composite Password Risk Score (CPRS) — strength + policy + crack-time (+breach).")
    p_risk.add_argument("-p", "--password", **common_pwd)
    p_risk.add_argument("--preset", choices=list(policy_checker.PRESETS.keys()), default="nist800_63b")
    p_risk.add_argument("--online", action="store_true", help="Also run the breach check (network required).")
    p_risk.add_argument("--hash-type", default="Unknown",
                         help="Target hash type for crack-time modeling (e.g. bcrypt, MD5, SHA-256).")
    p_risk.add_argument("--json", action="store_true", help="Output as JSON.")
    p_risk.set_defaults(func=cmd_risk)

    p_cracktime = sub.add_parser("cracktime", help="Estimate time-to-crack across attacker scenarios.")
    p_cracktime.add_argument("-p", "--password", **common_pwd)
    p_cracktime.add_argument("--hash-type", default="Unknown",
                              help="Target hash type (e.g. bcrypt, MD5, SHA-256, NTLM, Argon2).")
    p_cracktime.add_argument("--json", action="store_true", help="Output as JSON.")
    p_cracktime.set_defaults(func=cmd_cracktime)

    p_org = sub.add_parser("org-audit", help="Batch-audit accounts and generate an HTML risk report.")
    p_org.add_argument("-i", "--input-file", required=True,
                        help="File with 'identifier:password' per line (or just passwords).")
    p_org.add_argument("--preset", choices=list(policy_checker.PRESETS.keys()), default="nist800_63b")
    p_org.add_argument("--top-n", type=int, default=10, help="Number of highest-risk accounts to list.")
    p_org.add_argument("--html", help="Path to write the HTML report to.")
    p_org.add_argument("--json", action="store_true", help="Also print a JSON summary.")
    p_org.set_defaults(func=cmd_org_audit)

    p_audit = sub.add_parser("audit", help="Run the full audit pipeline.")
    p_audit.add_argument("-p", "--password", **common_pwd)
    p_audit.add_argument("--preset", choices=list(policy_checker.PRESETS.keys()), default="nist800_63b")
    p_audit.add_argument("--online", action="store_true", help="Also run the breach check (network required).")
    p_audit.add_argument("--wordlist", help="Also check against this local wordlist file.")
    p_audit.add_argument("--json", action="store_true", help="Output as JSON.")
    p_audit.set_defaults(func=cmd_audit)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        args.func(args)
    except FileNotFoundError as e:
        print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nAborted.")
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
