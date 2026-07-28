# Chronos — Password Risk & Crack-Time Intelligence Engine

Most password checkers tell you a password is "strong" or "weak." Chronos
goes further: it fuses strength, breach status, policy compliance, and
adversarial crack-time modeling into a single, formally weighted **Composite
Password Risk Score (CPRS)** — and can run that scoring across an entire
organization's password export to produce a VAPT-style HTML risk report.

## Why Chronos is different

Most GitHub password tools do exactly one thing: check strength, or check
breaches, or identify a hash. Chronos treats those as *signals* feeding a
single decision-useful number, and adds two capabilities that standalone
checkers don't have:

1. **Time, not just a score.** A "72/100 strength score" doesn't tell you
   anything actionable. "Crackable in 4 hours on a single GPU if this is an
   unsalted MD5 hash, but 400 years if it's bcrypt" does. Chronos models
   crack time across three attacker scenarios (rate-limited login, single
   offline GPU, GPU cluster) and across hash type, because the same password
   entropy means wildly different things depending on how it's stored.

2. **Organization-scale reporting.** Auditing one password at a time doesn't
   scale to a real engagement. Chronos's `org-audit` command takes an
   `identifier:password` export and produces a single self-contained HTML
   report: risk distribution, password-reuse clusters across accounts (a
   top real-world VAPT finding), the most common weaknesses, and the
   highest-risk accounts — the kind of deliverable a client actually reads.

## The CPRS Methodology

```
CPRS = 0.30 x StrengthRisk + 0.30 x BreachRisk + 0.15 x PolicyRisk + 0.25 x CrackTimeRisk
```

| Signal | Weight | Derivation | Rationale |
|---|---|---|---|
| **StrengthRisk** | 30% | `100 - entropy/pattern score` | Always available offline; the baseline signal. |
| **BreachRisk** | 30% | `100` if breached, `0` if confirmed clean, `20` if unchecked | Weighted equally with strength: a breached password is a near-certain compromise regardless of how strong it looks in isolation — real people reuse strong-looking passwords across accounts. Unknown status is treated as residual risk, never as "safe." |
| **PolicyRisk** | 15% | `min(100, violations x 25)` | Lower weight — policy violations are often about organizational compliance rather than raw crackability. |
| **CrackTimeRisk** | 25% | Bucketed from estimated offline single-GPU crack time (<1hr=100 ... >100yr=0) | Converts an abstract entropy number into a concrete adversarial time-to-compromise. |

Final score maps to five risk levels: **Minimal (0-19) -> Low (20-39) -> Medium
(40-59) -> High (60-79) -> Critical (80-100)**.

This isn't presented as a solved research problem — the weights are a
reasoned starting point, not empirically fitted against a labeled breach
dataset (see *Future Enhancements*). But it's a documented, falsifiable
methodology rather than a black-box score, which is the point.

## Features

| Module | What it does |
|---|---|
| **Risk Engine (CPRS)** | Composite 0-100 risk score fusing strength, breach, policy, and crack-time signals with a documented weighted formula. |
| **Crack-Time Estimator** | Converts entropy + hash type into human-readable time-to-crack across 3 attacker scenarios, using published order-of-magnitude hash-rate benchmarks. |
| **Password Strength Analyzer** | Entropy scoring + heuristic pattern detection (keyboard walks, sequential runs, repeated characters, leetspeak-normalized common-password matching). |
| **Breach Checker** | HaveIBeenPwned Pwned Passwords lookup via k-Anonymity — only a 5-character hash prefix ever leaves the machine. |
| **Hash Identifier** | Heuristic hash-type identification (MD5, SHA-1/256/384/512, NTLM, bcrypt, Argon2, PBKDF2, Unix crypt variants, phpass) with ranked confidence. |
| **Offline Wordlist Audit** | Checks passwords against a local wordlist (e.g. `rockyou.txt`) — fully offline. |
| **Policy Checker** | NIST SP 800-63B and legacy-complexity presets, plus custom policies. |
| **Org-Audit HTML Reporting** | Batch-scores an `identifier:password` export and renders a self-contained HTML report: risk distribution, password-reuse clusters, top issues, highest-risk accounts. |

## Installation

```bash
git clone https://github.com/<your-username>/chronos.git
cd chronos
pip install -r requirements.txt
pip install -e .          # installs the `chronos` command
```

## Usage

```bash
# Full composite risk score for one password
chronos risk --online --hash-type bcrypt

# Just the crack-time breakdown across attacker scenarios
chronos cracktime --hash-type MD5

# Strength, breach, hash-id, wordlist, and policy still work standalone
chronos strength -p "P@ssw0rd"
chronos breach
chronos hashid -H 5f4dcc3b5aa765d61d8327deb882cf99
chronos wordlist -w rockyou.txt -f exported_passwords.txt --csv report.csv
chronos policy --preset nist800_63b

# Organization-wide batch audit -> HTML report
# accounts.txt format: one "identifier:password" per line
chronos org-audit -i accounts.txt --html risk_report.html

# Legacy full pipeline (strength + policy + optional breach/wordlist)
chronos audit --online --wordlist rockyou.txt
```

Every subcommand supports `--json` for scripting/report integration.

### Example: `chronos risk`

```
=== Chronos Risk Score (CPRS) ===

  CPRS Score : 78/100
  Risk Level : High

  Breakdown:
    Strength risk    : 65/100  (weight 30%)
    Breach risk      : 100/100  (weight 30%)
    Policy risk      : 0/100  (weight 15%)
    Crack-time risk  : 70/100  (weight 25%)

  Estimated crack time (offline, single GPU, hash type: MD5):
    2.3 days

  Contributing factors:
    - Password found in known breach data - treat as fully compromised.
    - Estimated crackable in 2.3 days under an offline single-GPU attack.
```

## Full Command Reference

Every subcommand accepts `-p/--password` (omit it to be prompted securely
via `getpass` instead of typing it in plaintext) and `--json` for
machine-readable output.

| Command | Required flags | Optional flags | Purpose |
|---|---|---|---|
| `strength` | — | `-p`, `--json` | Entropy + pattern-based strength score. |
| `breach` | — | `-p`, `--json` | HIBP k-Anonymity breach lookup (network required). |
| `hashid` | `-H/--hash-value` | `--json` | Identify likely hash type from a hash string. |
| `wordlist` | `-w/--wordlist` | `-p`, `-f/--passwords-file`, `--case-sensitive`, `--csv`, `--json` | Offline wordlist audit, single or batch. |
| `policy` | — | `-p`, `--preset {nist800_63b,legacy_complexity}`, `--context`, `--json` | Policy compliance check. |
| `risk` | — | `-p`, `--preset`, `--online`, `--hash-type`, `--json` | Composite Password Risk Score (CPRS). |
| `cracktime` | — | `-p`, `--hash-type`, `--json` | Time-to-crack across 3 attacker scenarios. |
| `org-audit` | `-i/--input-file` | `--preset`, `--top-n`, `--html`, `--json` | Batch-score an account export, optional HTML report. |
| `audit` | — | `-p`, `--preset`, `--online`, `--wordlist`, `--json` | Legacy full pipeline (strength + policy + optional breach/wordlist). |

### `chronos strength`
```
usage: chronos strength [-h] [-p PASSWORD] [--json]
```

### `chronos breach`
```
usage: chronos breach [-h] [-p PASSWORD] [--json]
```

### `chronos hashid`
```
usage: chronos hashid [-h] -H HASH_VALUE [--json]
```

### `chronos wordlist`
```
usage: chronos wordlist [-h] -w WORDLIST [-p PASSWORD] [-f PASSWORDS_FILE]
                         [--case-sensitive] [--csv CSV] [--json]
```

### `chronos policy`
```
usage: chronos policy [-h] [-p PASSWORD]
                       [--preset {nist800_63b,legacy_complexity}]
                       [--context CONTEXT] [--json]
```
`--context` takes a comma-separated list of forbidden terms to check for
(e.g. `--context "acmecorp,jdoe"` flags passwords containing the company
name or username).

### `chronos risk`
```
usage: chronos risk [-h] [-p PASSWORD]
                     [--preset {nist800_63b,legacy_complexity}] [--online]
                     [--hash-type HASH_TYPE] [--json]
```
`--online` additionally runs the HIBP breach check (network required);
without it, breach status is treated as "unknown" and contributes a fixed
residual risk (see the CPRS methodology above). `--hash-type` feeds the
crack-time sub-score — use whatever `chronos hashid` identified for the
target hash (e.g. `bcrypt`, `MD5`, `SHA-256`, `NTLM`, `Argon2`).

### `chronos cracktime`
```
usage: chronos cracktime [-h] [-p PASSWORD] [--hash-type HASH_TYPE] [--json]
```

### `chronos org-audit`
```
usage: chronos org-audit [-h] -i INPUT_FILE
                          [--preset {nist800_63b,legacy_complexity}]
                          [--top-n TOP_N] [--html HTML] [--json]
```
`-i/--input-file` expects one `identifier:password` pair per line (a bare
password per line also works, with the password reused as its own
identifier). `--top-n` controls how many highest-risk accounts appear in
the report's "Highest-Risk Accounts" table (default 10). `--html` writes
the full report; omit it to only print the terminal summary.

### `chronos audit`
```
usage: chronos audit [-h] [-p PASSWORD]
                      [--preset {nist800_63b,legacy_complexity}] [--online]
                      [--wordlist WORDLIST] [--json]
```

## Running tests

```bash
pip install pytest
pytest tests/ -v
```
49 tests covering entropy calculation, pattern detection, hash-type rules,
crack-time modeling across scenarios and hash types, CPRS fusion logic
(including breach/unknown-status edge cases), and batch-audit reuse
detection.

## Ethical use

Chronos is intended for auditing passwords you own or are explicitly
authorized to assess — your own accounts, or an organization's exported
password data under a signed engagement scope. The breach-check module only
ever transmits a 5-character hash prefix, never the password. The
wordlist-audit and org-audit modules run entirely offline by default.
Crack-time figures are illustrative, order-of-magnitude estimates for risk
communication, not a precision benchmarking tool.

## Future enhancements

- Empirically calibrate CPRS weights against a labeled breach/crack-time
  dataset instead of the current reasoned-default weights.
- Bloom-filter backend for `wordlist_audit` to handle multi-GB wordlists
  with constant memory.
- Passphrase-aware entropy model (dictionary-word-based, a la `zxcvbn`) as
  an alternative scoring mode.
- PDF export alongside the existing HTML/JSON/CSV output.
- Optional REST API wrapper (FastAPI) around the same core modules.

## License

MIT
