from phishsentinel import defang, extract_iocs, parse_input


def test_defang_urls_and_addresses():
    assert defang("http://a.example.com/x.php") == "hxxp://a[.]example[.]com/x.php"
    assert defang("https://192.0.2.10") == "hxxps://192[.]0[.]2[.]10"
    assert defang("user@example.com") == "user@example[.]com"


def test_extract_iocs_from_raw_email():
    raw = ("From: Example Support <help@example.com>\nTo: user@example.org\nSubject: Notice\n"
           "Reply-To: other@elsewhere.net\n\nOpen http://192.0.2.10/doc or http://192.0.2.10/doc again, "
           "or https://files.example.org/a")
    iocs = extract_iocs(parse_input(raw))
    assert iocs["urls"] == ["hxxp://192[.]0[.]2[.]10/doc", "hxxps://files[.]example[.]org/a"]
    assert iocs["ips"] == ["192[.]0[.]2[.]10"]
    assert iocs["senders"] == ["help@example[.]com", "other@elsewhere[.]net"]
    assert iocs["domains"] == ["192[.]0[.]2[.]10", "example[.]org"]
