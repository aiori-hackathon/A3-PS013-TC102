"""Password and token security regression tests."""
import pytest
from app.security import hash_password, verify_password, create_access_token, decode_access_token


def test_password_hash_is_salted_and_verifies():
    first = hash_password("Example-Pass-123!")
    second = hash_password("Example-Pass-123!")
    assert first != second
    assert verify_password("Example-Pass-123!", first)
    assert not verify_password("wrong-password", first)


def test_malformed_password_hash_fails_closed():
    assert not verify_password("password", "not-a-valid-hash")


def test_access_token_round_trip():
    token = create_access_token(42)
    assert decode_access_token(token) == 42


def test_invalid_token_is_rejected():
    with pytest.raises(Exception):
        decode_access_token("not-a-token")


def test_csv_formula_prefix_is_neutralized():
    from app.main import safe_csv_cell
    assert safe_csv_cell("=HYPERLINK(\"https://example.invalid\")").startswith("'")
    assert safe_csv_cell("  @SUM(A1:A2)").startswith("'")
    assert safe_csv_cell("normal log text") == "normal log text"
