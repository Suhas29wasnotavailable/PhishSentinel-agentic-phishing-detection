"""Deterministic forensic tool agents: header, URL and content signals in log-odds."""
import math
import re
from urllib.parse import urlparse, parse_qs

from .text import normalize, registered_domain


BRANDS = {"paypal": ["paypal.com"], "microsoft": ["microsoft.com", "microsoftonline.com", "office.com", "live.com", "outlook.com"],
          "apple": ["apple.com", "icloud.com"], "amazon": ["amazon.com", "amazon.in", "amazon.co.uk"], "netflix": ["netflix.com"],
          "google": ["google.com", "gmail.com", "youtube.com"], "ebay": ["ebay.com"], "docusign": ["docusign.com", "docusign.net"],
          "dhl": ["dhl.com"], "fedex": ["fedex.com"], "chase": ["chase.com"], "wellsfargo": ["wellsfargo.com"],
          "bankofamerica": ["bankofamerica.com"], "citibank": ["citi.com", "citibank.com"], "hdfc": ["hdfcbank.com"], "linkedin": ["linkedin.com"]}
LEGIT_DOMAINS = {d for ds in BRANDS.values() for d in ds}
SHORTENERS = {"bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc"}
RISKY_TLDS = {"xyz", "top", "club", "icu", "buzz", "live", "info", "biz", "ru", "cn", "tk", "ml", "ga", "cf", "gq", "zip", "mov", "online", "site", "shop"}
FREEMAIL = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "protonmail.com", "aol.com", "mail.ru"}
RISKY_EXT = {"exe", "scr", "js", "vbs", "bat", "cmd", "ps1", "jar", "msi", "hta", "lnk"}

def levenshtein(a, b):
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]

def skeleton(label):
    s = normalize(label.lower())
    for a, b in [("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"), ("3", "e"), ("5", "s"), ("$", "s")]:
        s = s.replace(a, b)
    return s

def brand_lookalike(host):
    """Return (brand, kind) if host imitates a brand without belonging to it."""
    dom = registered_domain(host)
    if dom in LEGIT_DOMAINS:
        return None
    label = skeleton(dom.split(".")[0])
    for brand in BRANDS:
        if label == brand or (len(brand) >= 5 and levenshtein(label, brand) <= 1):
            return brand, "typosquat"
        if len(brand) >= 4 and brand in label.replace("-", ""):
            return brand, "brand-in-domain"
        if any(brand == skeleton(part) for part in host.split(".")[:-2]):
            return brand, "brand-in-subdomain"
    return None

def sig(sid, agent, name, weight, evidence, mitre=None, spans=None, category=None):
    return {"id": sid, "agent": agent, "name": name, "weight": round(weight, 2), "evidence": evidence,
            "mitre": mitre, "spans": spans or [], "category": category or name}

def header_forensics(e):
    h = e["headers"]
    if not h:
        return []
    out, fdom = [], h["from_addr"].split("@")[-1]
    if h["has_auth_header"]:
        for k, w in [("spf", 1.0), ("dkim", 0.6), ("dmarc", 1.3)]:
            if h[k] in ("fail", "softfail", "none", "permerror"):
                out.append(sig(f"H-{k}", "Header", f"{k}_{h[k]}", w * (0.5 if h[k] in ("softfail", "none") else 1), f"{k.upper()}={h[k]}", "T1566"))
        if all(h[k] == "pass" for k in ("spf", "dkim", "dmarc")):
            out.append(sig("H-auth", "Header", "fully_authenticated", -0.8, f"SPF/DKIM/DMARC pass for {fdom}"))
    if h["reply_to"] and h["reply_to"].split("@")[-1] != fdom:
        out.append(sig("H-reply", "Header", "reply_to_mismatch", 1.4, f"Reply-To {h['reply_to']} ≠ From domain {fdom}", "T1656"))
    if h["return_path"] and registered_domain(h["return_path"].split("@")[-1]) != registered_domain(fdom):
        out.append(sig("H-rpath", "Header", "return_path_mismatch", 0.5, f"Return-Path {h['return_path']}"))
    disp = skeleton(h["from_name"].replace(" ", ""))
    for brand, doms in BRANDS.items():
        if brand in disp and registered_domain(fdom) not in doms:
            out.append(sig("H-spoof", "Header", "display_name_spoof", 2.0, f"Display name '{h['from_name']}' but sent from {fdom}", "T1656"))
            break
    if fdom in FREEMAIL and re.search(r"(?i)\b(ceo|cfo|director|president|payroll|accounts)\b", h["from_name"]):
        out.append(sig("H-free", "Header", "executive_on_freemail", 1.5, f"Executive title on free-mail domain {fdom}", "T1656"))
    for a in e["attachments"]:
        parts = a["filename"].lower().split(".")
        if parts[-1] in RISKY_EXT:
            out.append(sig("A-exe", "Header", "executable_attachment", 3.0, a["filename"], "T1566.001"))
        if len(parts) >= 3 and parts[-2] in {"pdf", "doc", "docx", "xls", "jpg", "txt"}:
            out.append(sig("A-dbl", "Header", "double_extension", 2.5, a["filename"], "T1036.007"))
        if parts[-1] in {"docm", "xlsm", "html", "htm", "iso", "img"}:
            out.append(sig("A-risky", "Header", "risky_container", 1.5, a["filename"], "T1566.001"))
    return out

def url_intel(e):
    out, urls = [], e["urls"]
    for u in urls:
        host, sp = u["host"], [u["span"]]
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
            out.append(sig("U-ip", "URL", "raw_ip_link", 2.0, u["url"], "T1566.002", sp, "url"))
        if u["domain"] in SHORTENERS:
            out.append(sig("U-short", "URL", "url_shortener", 0.8, u["url"], "T1566.002", sp, "url"))
        if host.split(".")[-1] in RISKY_TLDS:
            out.append(sig("U-tld", "URL", "risky_tld", 0.7, f".{host.split('.')[-1]} in {host}", "T1583.001", sp, "url"))
        if host.startswith("xn--") or ".xn--" in host:
            out.append(sig("U-puny", "URL", "punycode_domain", 2.5, host, "T1583.001", sp, "url"))
        la = brand_lookalike(host)
        if la:
            out.append(sig("U-look", "URL", f"brand_lookalike_{la[1]}", 2.2, f"{host} imitates {la[0]}", "T1583.001", sp, "url"))
        if "@" in u["url"].split("//")[-1].split("/")[0]:
            out.append(sig("U-at", "URL", "at_symbol_in_url", 1.5, u["url"], "T1566.002", sp, "url"))
        q = parse_qs(urlparse(u["url"] if u["url"].startswith("http") else "http://" + u["url"]).query)
        if "redirect_uri" in q and "scope" in q:
            redir = registered_domain(urlparse(q["redirect_uri"][0]).hostname or "")
            if redir not in LEGIT_DOMAINS:
                out.append(sig("U-oauth", "URL", "oauth_consent_abuse", 2.5, f"OAuth grant ({q['scope'][0][:60]}) redirecting to {redir}", "T1528", sp, "url"))
    for a in e.get("anchors", []):
        shown = re.search(r"(?i)\b(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,})\b", a["text"])
        target = urlparse(a["href"] if "//" in a["href"] else "http://" + a["href"]).hostname or ""
        if shown and target and registered_domain(shown.group(1)) != registered_domain(target):
            out.append(sig("U-mask", "URL", "link_text_mismatch", 2.0,
                           f"link text shows {shown.group(1)} but points to {target}", "T1566.002", [], "url"))
    if len(urls) >= 6:
        out.append(sig("U-many", "URL", "many_links", 0.3, f"{len(urls)} links in message", None))
    if urls and all(u["domain"] in LEGIT_DOMAINS for u in urls):
        out.append(sig("U-trust", "URL", "links_to_known_brands_only", -0.6, ", ".join(sorted({u['domain'] for u in urls}))))
    return out

CONTENT_RULES = [  # (id, name, log-odds weight, MITRE, patterns)
    ("C-urg", "urgency", 0.5, "T1566", [r"\b(urgent(ly)?|immediately|act now|right away|within \d+ (hours?|days?)|expires? (today|soon)|final notice|last chance|limited time)\b"]),
    ("C-thr", "threat", 0.7, "T1566", [r"\b(suspend(ed)?|locked|terminat(e|ed|ion)|deactivat(e|ed)|legal action|closed permanently)\b"]),
    ("C-cred", "credential_request", 1.2, "T1598", [r"\b(verify|confirm|update|validate) (your )?(account|identity|password|login|details|information|billing)\b",
                                                   r"\b(password|pin number|otp|social security|credit card (number|details)|bank account (number|details))\b"]),
    ("C-fin", "financial_lure", 0.6, "T1656", [r"\b(wire transfer|western union|money ?gram|gift cards?|bitcoin|investment opportunity|stock (alert|pick|profile)|beneficiary|inheritance|next of kin)\b"]),
    ("C-rew", "reward_lure", 0.8, "T1566", [r"\b(congratulations|you (have )?won|winner|prize|lottery|free (gift|offer|trial)|claim your|selected to receive|million (dollars|usd))\b"]),
    ("C-cta", "call_to_action", 0.6, "T1204.001", [r"\b(click (here|below|the link|this link)|visit (our|this) (site|website)|order now|buy now|sign up now|call now)\b"]),
    ("C-sec", "secrecy", 0.6, "T1656", [r"\b(keep (this|it) (between us|private|secret)|discreet(ly)?|do not (tell|share|disclose) (this|anyone))\b"]),
    ("C-gen", "generic_greeting", 0.3, "T1566", [r"\b(dear (customer|user|friend|sir|madam|valued|member|beneficiary|account holder))\b"]),
    ("C-bulk", "bulk_mail_footer", 0.4, "T1566", [r"\b(unsubscribe|remove me|opt[- ]?out|to be removed)\b"]),
    ("C-thread", "reply_thread_context", -0.7, None, [r"(-{3,}\s*original message|forwarded by|\bre\s*:\s|\bfw\s*:\s|wrote\s*:)"]),
]

def content_forensics(e):
    out, text = [], e["norm"]
    for sid, name, w, mitre, pats in CONTENT_RULES:
        spans = [(m.start(), m.end()) for p in pats for m in re.finditer(p, text, flags=re.I)]
        if spans:
            snippet = ", ".join(sorted({text[a:b].lower() for a, b in spans})[:4])
            out.append(sig(sid, "Content", name, w, f"“{snippet}”", mitre, spans[:12], name))
    obf = e["obfuscation"]
    if obf["zero_width"] or obf["homoglyphs"]:
        out.append(sig("O-evasion", "Content", "unicode_obfuscation", 1.5,
                       f"{obf['homoglyphs']} homoglyph(s), {obf['zero_width']} zero-width char(s)", "T1027", [], "obfuscation"))
    return out


def rule_logodds(signals):
    return float(sum(s["weight"] for s in signals))


def sigmoid(x):
    return 1 / (1 + math.exp(-x))


def analyze_signals(raw):
    """Run the parser and every tool agent; return (parsed_email, signals)."""
    from .text import parse_input
    e = parse_input(raw)
    return e, header_forensics(e) + url_intel(e) + content_forensics(e)
