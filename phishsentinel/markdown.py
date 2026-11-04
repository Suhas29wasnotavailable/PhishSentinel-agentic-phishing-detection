"""Markdown triage note for pasting into a ticket, wiki or chat."""
import re

from .iocs import defang, extract_iocs
from .mitre import technique_name, technique_url


def cell(text):
    return str(text).replace("|", "\\|").replace("\n", " ")


def defang_text(text):
    """Defang every URL inside free text, so a pasted note has no live links to the attacker."""
    return re.sub(r"(?i)\b(?:https?://|www\.)[^\s<>\"')\]]+", lambda m: defang(m.group(0)), text)


def triage_markdown(email, signals, lo, risk, title="Email triage"):
    h = email["headers"] or {}
    lines = [f"## {title}", "",
             f"**Rule-engine risk:** {risk:.2f} (log-odds {lo:+.1f})  ",
             f"**Subject:** {cell(h.get('subject') or '-')}  ",
             f"**From:** {cell(h.get('from_addr') or '-')}", ""]
    if signals:
        lines += ["| Weight | Agent | Signal | Evidence | ATT&CK |", "|---:|---|---|---|---|"]
        for s in sorted(signals, key=lambda s: -abs(s["weight"])):
            mitre = f"[{s['mitre']}]({technique_url(s['mitre'])}) {technique_name(s['mitre'])}" if s["mitre"] else ""
            lines.append(f"| {s['weight']:+.1f} | {s['agent']} | `{s['name']}` | {cell(defang_text(s['evidence'][:90]))} | {mitre} |")
    else:
        lines.append("_No deterministic signals._")
    iocs = extract_iocs(email)
    found = [(k, v) for k, vs in iocs.items() for v in vs]
    if found:
        lines += ["", "**Indicators (defanged):**", ""]
        for kind, v in found:
            lines.append(f"- {kind}: `{v['sha256']}` {cell(v['filename'])}" if kind == "attachments" else f"- {kind}: `{v}`")
    return "\n".join(lines) + "\n"
