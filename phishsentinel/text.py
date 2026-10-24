"""Email parsing, Unicode normalisation and URL extraction (the Parser agent)."""
import hashlib
import re
import unicodedata
from email import message_from_string, policy
from email.utils import parseaddr
from urllib.parse import urlparse


ZW_RE = re.compile("[\u200b\u200c\u200d\u2060\ufeff\u00ad]")
CONFUSABLES = {  # Cyrillic / Greek look-alikes → Latin
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "һ": "h",
    "ӏ": "l", "ԛ": "q", "ԝ": "w", "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C",
    "Т": "T", "Х": "X", "ο": "o", "α": "a", "ν": "v", "ρ": "p", "τ": "t", "ι": "i", "κ": "k", "Ο": "O", "Α": "A", "Ε": "E",
}

def normalize_with_map(s):
    """Return (normalised_text, index_map, stats). index_map[i] = position in the original string."""
    out, idx, zw, glyph = [], [], 0, 0
    for i, ch in enumerate(s):
        if ZW_RE.match(ch):
            zw += 1
            continue
        n = unicodedata.normalize("NFKC", ch)
        mapped = "".join(CONFUSABLES.get(c, c) for c in n)
        if mapped != ch and ch in CONFUSABLES:
            glyph += 1
        for c in mapped:
            out.append(c); idx.append(i)
    return "".join(out), idx, {"zero_width": zw, "homoglyphs": glyph}

def normalize(s):
    return normalize_with_map(s)[0]

URL_RE = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"')\]]+")
SPACED_URL_RE = re.compile(r"(?i)\b(?:https?\s*:\s*/\s*/\s*|www\s*\.\s*)[a-z0-9-]+(?:\s*\.\s*[a-z0-9-]+)+(?:\s*/\s*[\w\-.?=&%~]+)*")
MULTI_TLDS = {"co.uk", "co.in", "com.au", "net.in", "org.in", "co.jp", "com.br"}

def registered_domain(host):
    parts = (host or "").lower().strip(".").split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in MULTI_TLDS:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])

def extract_urls(norm_text):
    found, seen = [], set()
    for rx in (URL_RE, SPACED_URL_RE):
        for m in rx.finditer(norm_text):
            if any(a <= m.start() < b for a, b in seen):
                continue
            url = re.sub(r"\s+", "", m.group(0)).rstrip(".,;")
            full = url if url.lower().startswith("http") else "http://" + url
            host = (urlparse(full).hostname or "").lower()
            if "." not in host:
                continue
            seen.add((m.start(), m.end()))
            found.append({"url": url, "host": host, "domain": registered_domain(host),
                          "scheme": urlparse(full).scheme if url.lower().startswith("http") else "", "span": (m.start(), m.end())})
    return found

def looks_like_raw_email(s):
    head = s[:3000]
    return bool(re.search(r"(?im)^from:\s.+$", head) and re.search(r"(?im)^(subject|to|received|message-id):\s", head))

def parse_input(raw):
    headers, attachments, body = None, [], raw
    if looks_like_raw_email(raw):
        msg = message_from_string(raw, policy=policy.default)
        from_name, from_addr = parseaddr(str(msg.get("From", "")))
        auth = str(msg.get("Authentication-Results", "") or "")
        res = lambda k: (re.search(rf"{k}=(\w+)", auth).group(1).lower() if re.search(rf"{k}=(\w+)", auth) else "none")
        headers = {"from_name": from_name, "from_addr": from_addr.lower(), "subject": str(msg.get("Subject", "")),
                   "reply_to": parseaddr(str(msg.get("Reply-To", "") or ""))[1].lower(),
                   "return_path": parseaddr(str(msg.get("Return-Path", "") or ""))[1].lower(),
                   "spf": res("spf"), "dkim": res("dkim"), "dmarc": res("dmarc"), "has_auth_header": bool(auth)}
        texts, htmls = [], []
        for part in msg.walk():
            if part.is_multipart():
                continue
            if part.get_filename() or part.get_content_disposition() == "attachment":
                data = part.get_payload(decode=True) or b""
                attachments.append({"filename": part.get_filename() or "unnamed", "size": len(data),
                                    "sha256": hashlib.sha256(data).hexdigest()})
            elif part.get_content_type() == "text/plain":
                texts.append(part.get_content())
            elif part.get_content_type() == "text/html":
                htmls.append(re.sub(r"<[^>]+>", " ", part.get_content()))
        body = "\n".join(texts) or "\n".join(htmls)
        if headers["subject"]:
            body = headers["subject"] + "\n\n" + body
    norm, idx, obf = normalize_with_map(body)
    return {"body": body, "norm": norm, "idx": idx, "obfuscation": obf, "headers": headers,
            "attachments": attachments, "urls": extract_urls(norm)}
