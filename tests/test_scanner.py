"""Basic unit tests for SSRFProbe scanner and payload logic."""

import pytest
from ssrfprobe.payloads import generate_bypass_payloads
from ssrfprobe.scanner import SSRFScanner


def test_payload_generation():
    """Verify default payload lists and collaborator injection."""
    payloads_default = generate_bypass_payloads()
    assert "http://127.0.0.1" in payloads_default
    assert "http://2130706433" in payloads_default

    collab_domain = "interact.sh"
    payloads_collab = generate_bypass_payloads(collaborator_url=collab_domain)
    assert any(collab_domain in p for p in payloads_collab)


def test_url_parameter_injection():
    """Test query-string parameter injection behavior."""
    scanner = SSRFScanner()
    test_url = "https://example.com/api?endpoint=test"
    injected = scanner._inject_params(test_url, "http://127.0.0.1")

    assert len(injected) > 0
    assert "endpoint=http%3A%2F%2F127.0.0.1" in injected[0] or "endpoint=http://127.0.0.1" in injected[0]
