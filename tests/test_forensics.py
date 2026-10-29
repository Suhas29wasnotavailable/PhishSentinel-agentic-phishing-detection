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


def html_email(anchor):
    return ("From: Example Sender <news@example.com>\nTo: user@example.org\nSubject: Notice\n"
            f"Content-Type: text/html; charset=utf-8\n\n<p>Sign in at {anchor}</p>")


def test_link_text_showing_another_domain_is_flagged():
    found = names(html_email('<a href="http://example-login.xyz/a">www.paypal.com</a>'))
    assert "link_text_mismatch" in found


def test_link_text_matching_its_target_is_not_flagged():
    found = names(html_email('<a href="https://www.paypal.com/signin">paypal.com</a>'))
    assert "link_text_mismatch" not in found
    assert "link_text_mismatch" not in names(html_email('<a href="http://example.org/x">here</a>'))


def sender(addr):
    return f"From: Support <{addr}>\nTo: user@example.org\nSubject: Hello\n\nHello."


def test_lookalike_sender_domain_is_flagged():
    assert "sender_domain_typosquat" in names(sender("help@paypa1.com"))


def test_genuine_sender_domain_is_not_flagged():
    assert not any(n.startswith("sender_domain_") for n in names(sender("help@paypal.com")))


def test_url_trick_signals():
    found = names("a http://xn--pypal-4ve.com/x b https://bit.ly/abc c http://user@example.org/login")
    assert {"punycode_domain", "url_shortener", "at_symbol_in_url"} <= found


def test_oauth_consent_link_to_unknown_app_is_flagged():
    link = "https://login.microsoftonline.com/common/oauth2/authorize?scope=Mail.Read&redirect_uri=https://example-app.xyz/cb"
    assert "oauth_consent_abuse" in names(link)


def test_many_links_signal():
    assert "many_links" in names(" ".join(f"https://site{i}.example.org" for i in range(6)))


def test_executive_title_on_free_mail():
    raw = "From: CFO Office <cfo.office@gmail.com>\nTo: user@example.org\nSubject: Quick task\n\nAre you at your desk?"
    assert "executive_on_freemail" in names(raw)


def test_risky_attachments_are_flagged():
    raw = ("From: Example Sender <news@example.com>\nTo: user@example.org\nSubject: Files\n"
           "MIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=XX\n\n"
           "--XX\nContent-Type: text/plain\n\nSee attached.\n"
           "--XX\nContent-Type: application/octet-stream\nContent-Disposition: attachment; filename=\"invoice.pdf.exe\"\n\nAAAA\n"
           "--XX\nContent-Type: application/octet-stream\nContent-Disposition: attachment; filename=\"report.docm\"\n\nAAAA\n"
           "--XX--\n")
    e, signals = analyze_signals(raw)
    assert [a["filename"] for a in e["attachments"]] == ["invoice.pdf.exe", "report.docm"]
    assert {"executable_attachment", "double_extension", "risky_container"} <= {s["name"] for s in signals}


def test_reply_to_on_a_subdomain_of_the_sender_is_not_a_mismatch():
    raw = ("From: Example Support <help@example.com>\nTo: user@example.org\nSubject: Hello\n"
           "Reply-To: tickets@support.example.com\n\nHello.")
    assert "reply_to_mismatch" not in names(raw)


def test_lookalike_under_a_country_suffix():
    assert brand_lookalike("paypa1.com.sg") == ("paypal", "typosquat")


def test_form_asking_for_a_password_inside_the_email_is_flagged():
    form = ('<form action="http://example-login.xyz/post"><input name="u">'
            '<input type="password" name="p"><button>Sign in</button></form>')
    e, signals = analyze_signals(html_email(form))
    assert e["forms"] == [{"action": "http://example-login.xyz/post", "password": True}]
    assert "embedded_password_form" in {s["name"] for s in signals}


def test_form_without_password_is_weaker_evidence():
    found = names(html_email('<form action="https://example.org/survey"><input name="q"></form>'))
    assert "embedded_form" in found and "embedded_password_form" not in found


def test_punycode_homoglyph_domain_is_matched_to_the_brand():
    assert brand_lookalike("xn--pypal-4ve.com") == ("paypal", "typosquat")
    found = names("sign in at https://xn--pypal-4ve.com/login")
    assert {"punycode_domain", "brand_lookalike_typosquat"} <= found
