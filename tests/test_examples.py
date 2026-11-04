"""Regression tests: the example emails keep their expected verdicts and key signals."""
from pathlib import Path

import pytest

from phishsentinel import analyze_signals, rule_logodds, sigmoid

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
CASES = {
    "benign_order_update.eml": (False, {"fully_authenticated", "links_to_known_brands_only"}),
    "benign_thread_reply.eml": (False, {"reply_thread_context"}),
    "suspicious_masked_link.eml": (True, {"link_text_mismatch", "raw_ip_link", "non_standard_port", "spf_fail"}),
    "suspicious_fake_reply.eml": (True, {"fake_reply_subject", "address_in_display_name", "reply_to_mismatch", "secrecy"}),
    "suspicious_attachment.eml": (True, {"executable_attachment", "double_extension"}),
}


@pytest.mark.parametrize("name", sorted(CASES))
def test_example_verdict_and_signals(name):
    suspicious, expected = CASES[name]
    _, signals = analyze_signals((EXAMPLES / name).read_text())
    risk = sigmoid(rule_logodds(signals) - 1.0)
    assert (risk >= 0.8) if suspicious else (risk < 0.5)
    assert expected <= {s["name"] for s in signals}


def test_every_example_is_covered():
    assert {p.name for p in EXAMPLES.glob("*.eml")} == set(CASES)
