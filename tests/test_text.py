from phishsentinel import normalize, normalize_with_map, extract_urls, parse_input, registered_domain


def test_zero_width_and_homoglyphs_are_removed():
    norm, _, stats = normalize_with_map("vеrify ac​count")
    assert norm == "verify account"
    assert stats == {"zero_width": 1, "homoglyphs": 1}


def test_index_map_points_back_to_original_characters():
    original = "ab​cd"
    norm, idx, _ = normalize_with_map(original)
    assert norm == "abcd"
    assert [original[i] for i in idx] == list("abcd")


def test_plain_text_is_unchanged():
    assert normalize("hello world") == "hello world"


def test_registered_domain_handles_multi_part_tlds():
    assert registered_domain("login.secure.example.com") == "example.com"
    assert registered_domain("mail.example.co.uk") == "example.co.uk"


def test_extracts_standard_and_spaced_urls():
    urls = extract_urls("see https://a.example.com/x and www . spaced-site . biz / page")
    assert [u["url"] for u in urls] == ["https://a.example.com/x", "www.spaced-site.biz/page"]
    assert urls[1]["domain"] == "spaced-site.biz"


def test_body_only_input_has_no_headers():
    parsed = parse_input("just a short body with no headers at all")
    assert parsed["headers"] is None
    assert parsed["urls"] == []


def test_raw_email_headers_are_parsed():
    raw = ("From: Example Sender <news@example.com>\nTo: user@example.org\nSubject: Monthly update\n"
           "Authentication-Results: mx.example.org; spf=pass; dkim=pass; dmarc=pass\n\nHello there.")
    h = parse_input(raw)["headers"]
    assert h["from_addr"] == "news@example.com"
    assert (h["spf"], h["dkim"], h["dmarc"]) == ("pass", "pass", "pass")
