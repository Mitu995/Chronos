from chronos.hash_identifier import identify_hash


def test_identifies_md5_by_length():
    candidates = identify_hash("5f4dcc3b5aa765d61d8327deb882cf99")  # md5("password")
    names = [c.name for c in candidates]
    assert "MD5" in names


def test_identifies_sha1_by_length():
    candidates = identify_hash("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8")  # sha1("password")
    names = [c.name for c in candidates]
    assert "SHA-1" in names


def test_identifies_sha256_by_length():
    candidates = identify_hash("5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8")
    names = [c.name for c in candidates]
    assert "SHA-256" in names


def test_identifies_bcrypt():
    candidates = identify_hash("$2b$12$KIXQ0G9z8yF1p3W1a2b3c4dOeXjklMnopQRstuVWXyzABCDEfghij")
    assert candidates[0].name == "bcrypt"
    assert candidates[0].confidence == "High"


def test_unknown_format_returns_low_confidence():
    candidates = identify_hash("not-a-real-hash")
    assert candidates[0].name == "Unknown"
