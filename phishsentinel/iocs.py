"""Indicators of compromise from a parsed email, defanged so they can be pasted into tickets and chats safely."""
import re


def defang(indicator):
    """http://a.example.com/x -> hxxp://a[.]example[.]com/x ; user@example.com -> user@example[.]com"""
    s = re.sub(r"(?i)^http", "hxxp", indicator)
    head, sep, rest = s.partition("://")
    if not sep:
        head, rest = "", s
    host, slash, path = rest.partition("/")
    return f"{head}{sep}{host.replace('.', '[.]')}{slash}{path}"


def extract_iocs(email, defanged=True):
    f = defang if defanged else (lambda x: x)
    urls = [u["url"] for u in email["urls"]] + [a["href"] for a in email.get("anchors", []) if "//" in a["href"]]
    hosts = [u["host"] for u in email["urls"]]
    h = email["headers"] or {}
    return {
        "urls": [f(u) for u in dict.fromkeys(urls)],
        "domains": [f(d) for d in dict.fromkeys(u["domain"] for u in email["urls"])],
        "ips": [f(x) for x in dict.fromkeys(x for x in hosts if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", x))],
        "senders": [f(a) for a in dict.fromkeys(a for a in (h.get("from_addr"), h.get("reply_to"), h.get("return_path")) if a)],
        "attachments": [{"filename": a["filename"], "sha256": a["sha256"]} for a in email["attachments"]],
    }
