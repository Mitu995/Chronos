from unittest.mock import MagicMock, patch

from chronos.breach_checker import _sha1_upper, check_password_breach


def test_sha1_upper_matches_known_hash():
    assert _sha1_upper("password") == "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"


@patch("chronos.breach_checker.requests")
def test_check_password_breach_found(mock_requests):
    full_hash = _sha1_upper("password")
    suffix = full_hash[5:]
    mock_response = MagicMock()
    mock_response.text = f"{suffix}:3861493\nAAAAA:10"
    mock_response.raise_for_status = MagicMock()
    mock_requests.get.return_value = mock_response

    result = check_password_breach("password")
    assert result.checked is True
    assert result.is_breached is True
    assert result.times_seen == 3861493


@patch("chronos.breach_checker.requests")
def test_check_password_breach_not_found(mock_requests):
    mock_response = MagicMock()
    mock_response.text = "AAAAA:10\nBBBBB:20"
    mock_response.raise_for_status = MagicMock()
    mock_requests.get.return_value = mock_response

    result = check_password_breach("a-very-unique-passphrase-42!")
    assert result.checked is True
    assert result.is_breached is False


@patch("chronos.breach_checker.requests")
def test_check_password_breach_network_error(mock_requests):
    mock_requests.get.side_effect = ConnectionError("no internet")

    result = check_password_breach("anything")
    assert result.checked is False
    assert result.is_breached is None
    assert "no internet" in result.error
