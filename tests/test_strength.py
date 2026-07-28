from chronos.strength import (
    calculate_entropy,
    character_pool_size,
    detect_patterns,
    score_password,
)


def test_weak_password_scores_low():
    report = score_password("password")
    assert report.rating in ("Very Weak", "Weak")
    assert "Matches a known common password (including leetspeak variants)." in report.issues


def test_strong_password_scores_high():
    report = score_password("Tr0ub4dor&3xQzL9!vP")
    assert report.score > 60
    assert report.rating in ("Strong", "Very Strong")


def test_character_pool_size_all_classes():
    assert character_pool_size("Ab1!") == 26 + 26 + 10 + 33


def test_character_pool_size_lower_only():
    assert character_pool_size("abcdef") == 26


def test_entropy_increases_with_length():
    short = calculate_entropy("abc123")
    long = calculate_entropy("abc123abc123abc123")
    assert long > short


def test_detects_sequential_run():
    assert any("sequential" in i for i in detect_patterns("myabc123pass"))


def test_detects_keyboard_walk():
    assert any("keyboard-adjacent" in i for i in detect_patterns("qwerty99"))


def test_detects_repeated_chars():
    assert any("repeated characters" in i for i in detect_patterns("passsss1"))


def test_leetspeak_common_password_detected():
    report = score_password("P@ssw0rd")
    assert any("common password" in i for i in report.issues)
