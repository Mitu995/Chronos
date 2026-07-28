import tempfile
from pathlib import Path

from chronos.wordlist_audit import audit_batch, audit_password, load_wordlist


def _make_wordlist(words):
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    tmp.write("\n".join(words))
    tmp.close()
    return Path(tmp.name)


def test_load_wordlist_lowercases_by_default():
    path = _make_wordlist(["Password1", "Summer2024"])
    wl = load_wordlist(path)
    assert "password1" in wl
    assert "Password1" not in wl


def test_audit_password_found():
    path = _make_wordlist(["password1", "letmein"])
    wl = load_wordlist(path)
    assert audit_password("password1", wl) is True
    assert audit_password("notinlist", wl) is False


def test_audit_batch_counts_correctly():
    path = _make_wordlist(["password1", "letmein", "qwerty"])
    wl = load_wordlist(path)
    result = audit_batch(["password1", "unique_one", "qwerty"], wl)
    assert result.total_checked == 3
    assert len(result.found_in_wordlist) == 2
    assert "unique_one" in result.not_found


def test_case_sensitive_mode():
    path = _make_wordlist(["Password1"])
    wl = load_wordlist(path, case_sensitive=True)
    assert audit_password("Password1", wl, case_sensitive=True) is True
    assert audit_password("password1", wl, case_sensitive=True) is False
