from chronos.policy_checker import (
    LEGACY_COMPLEXITY,
    NIST_800_63B,
    PasswordPolicy,
    check,
)


def test_nist_policy_allows_long_simple_password():
    result = check("correct horse battery staple 42", NIST_800_63B)
    assert result.compliant


def test_nist_policy_blocks_short_password():
    result = check("abc123", NIST_800_63B)
    assert not result.compliant
    assert any("Shorter than minimum length" in v for v in result.violations)


def test_legacy_policy_requires_complexity():
    result = check("alllowercase", LEGACY_COMPLEXITY)
    assert not result.compliant
    assert any("uppercase" in v for v in result.violations)
    assert any("digit" in v for v in result.violations)
    assert any("special" in v for v in result.violations)


def test_legacy_policy_passes_with_all_classes():
    result = check("Str0ng!Pass", LEGACY_COMPLEXITY)
    assert result.compliant


def test_context_terms_are_blocked():
    policy = PasswordPolicy(name="custom", min_length=4)
    result = check("mitu995rocks", policy, context_terms=["mitu995"])
    assert not result.compliant
    assert any("forbidden/contextual substring" in v for v in result.violations)


def test_max_repeated_chars():
    policy = PasswordPolicy(name="custom", min_length=1, max_repeated_chars=2)
    result = check("aaabbb", policy)
    assert not result.compliant
