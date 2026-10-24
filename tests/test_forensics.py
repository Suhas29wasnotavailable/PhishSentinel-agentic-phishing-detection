from phishsentinel import analyze_signals, brand_lookalike, rule_logodds, sigmoid


def names(text):
    return {s["name"] for s in analyze_signals(text)[1]}


def test_typosquat_and_brand_in_domain_are_detected():
    assert brand_lookalike("paypa1.com") == ("paypal", "typosquat")
    assert brand_lookalike("secure-microsoft-login.com")[0] == "microsoft"


def test_real_brand_domains_are_not_lookalikes():
    assert brand_lookalike("www.paypal.com") is None
    assert brand_lookalike("login.microsoftonline.com") is None


def test_raw_ip_link_is_flagged():
    assert "raw_ip_link" in names("visit http://192.0.2.10/page today")


def test_links_only_to_known_brands_is_negative_evidence():
    _, signals = analyze_signals("your receipt is at https://www.amazon.com/orders")
    trust = [s for s in signals if s["name"] == "links_to_known_brands_only"]
    assert trust and trust[0]["weight"] < 0


def test_unicode_obfuscation_signal():
    assert "unicode_obfuscation" in names("plеase re​view")


def test_reply_thread_context_lowers_risk():
    _, signals = analyze_signals("-----Original Message-----\nsee notes from the meeting")
    assert rule_logodds(signals) < 0


def test_header_mismatch_signals():
    raw = ("From: Example Support <help@example.com>\nTo: user@example.org\nSubject: Hello\n"
           "Reply-To: other@elsewhere.net\n"
           "Authentication-Results: mx.example.org; spf=fail; dkim=none; dmarc=fail\n\nHello.")
    found = names(raw)
    assert {"reply_to_mismatch", "spf_fail", "dmarc_fail"} <= found


def test_content_signals_carry_highlight_spans():
    e, signals = analyze_signals("Please click here to continue")
    cta = next(s for s in signals if s["name"] == "call_to_action")
    a, b = cta["spans"][0]
    assert e["norm"][a:b].lower() == "click here"


def test_sigmoid_is_a_probability():
    assert sigmoid(0) == 0.5
    assert 0 < sigmoid(-20) < sigmoid(20) < 1
