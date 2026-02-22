"""
tests/test_interactsh.py — Unit tests for InteractshClient pure methods.

Network-dependent methods (register, poll, aclose) are not tested here.
Only interaction_host and interaction_test_id are exercised — they are
pure string-manipulation methods that work without a registered client.
"""
from Interactsh import InteractshClient


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def registered_client(domain: str = "oast.live") -> InteractshClient:
    """Return an InteractshClient with registration state set manually.

    This avoids any network calls while allowing interaction_host to work.
    The correlation_id is exactly 20 lowercase alphanumeric characters to
    match the production format.
    """
    client = InteractshClient(f"https://{domain}")
    client._registered = True
    client.correlation_id = "abcde12345fghij67890"  # exactly 20 chars
    return client


# ---------------------------------------------------------------------------
# interaction_host
# ---------------------------------------------------------------------------


class TestInteractionHost:
    def test_returns_empty_string_when_not_registered(self):
        client = InteractshClient("https://oast.live")
        # _registered defaults to False; correlation_id is None
        assert client.interaction_host("abc") == ""

    def test_format_corrid_plus_nonce_dot_domain(self):
        client = registered_client()
        nonce = "a" * InteractshClient.NONCE_LENGTH  # exactly 13 chars
        host = client.interaction_host(nonce)
        expected = f"abcde12345fghij67890{nonce}.oast.live"
        assert host == expected

    def test_short_test_id_padded_with_zeros(self):
        client = registered_client()
        host = client.interaction_host("abc")
        # Extract the nonce portion (after 20-char corr_id, before first dot)
        first_label = host.split(".")[0]
        nonce = first_label[20:]
        assert len(nonce) == InteractshClient.NONCE_LENGTH
        assert nonce == "abc" + "0" * (InteractshClient.NONCE_LENGTH - 3)

    def test_long_test_id_truncated_to_nonce_length(self):
        client = registered_client()
        long_id = "z" * 50
        host = client.interaction_host(long_id)
        first_label = host.split(".")[0]
        nonce = first_label[20:]
        assert len(nonce) == InteractshClient.NONCE_LENGTH
        assert nonce == "z" * InteractshClient.NONCE_LENGTH

    def test_empty_test_id_padded_fully(self):
        client = registered_client()
        host = client.interaction_host("")
        first_label = host.split(".")[0]
        nonce = first_label[20:]
        assert nonce == "0" * InteractshClient.NONCE_LENGTH

    def test_domain_preserved_in_host(self):
        client = registered_client(domain="interact.sh")
        host = client.interaction_host("abc")
        assert host.endswith(".interact.sh")

    def test_correlation_id_is_prefix_of_first_label(self):
        client = registered_client()
        host = client.interaction_host("abc")
        first_label = host.split(".")[0]
        assert first_label.startswith("abcde12345fghij67890")

    def test_total_first_label_length(self):
        # corr_id (20) + nonce (NONCE_LENGTH) = 33 by design
        client = registered_client()
        host = client.interaction_host("abc")
        first_label = host.split(".")[0]
        assert len(first_label) == 20 + InteractshClient.NONCE_LENGTH


# ---------------------------------------------------------------------------
# interaction_test_id
# ---------------------------------------------------------------------------


class TestInteractionTestId:
    def test_exact_length_returned_unchanged(self):
        client = InteractshClient("https://oast.live")
        exact = "a" * InteractshClient.NONCE_LENGTH
        assert client.interaction_test_id(exact) == exact

    def test_short_id_padded_with_zeros(self):
        client = InteractshClient("https://oast.live")
        result = client.interaction_test_id("abc")
        assert len(result) == InteractshClient.NONCE_LENGTH
        assert result == "abc" + "0" * (InteractshClient.NONCE_LENGTH - 3)

    def test_long_id_truncated(self):
        client = InteractshClient("https://oast.live")
        result = client.interaction_test_id("x" * 50)
        assert len(result) == InteractshClient.NONCE_LENGTH
        assert result == "x" * InteractshClient.NONCE_LENGTH

    def test_empty_id_is_all_zeros(self):
        client = InteractshClient("https://oast.live")
        result = client.interaction_test_id("")
        assert result == "0" * InteractshClient.NONCE_LENGTH

    def test_nonce_length_constant_is_13(self):
        assert InteractshClient.NONCE_LENGTH == 13

    def test_result_matches_nonce_in_interaction_host(self):
        # The nonce portion of interaction_host must equal interaction_test_id
        client = registered_client()
        test_id = "mytest"
        host = client.interaction_host(test_id)
        nonce_in_host = host.split(".")[0][20:]
        assert nonce_in_host == client.interaction_test_id(test_id)
