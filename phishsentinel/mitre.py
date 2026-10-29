"""Names of the MITRE ATT&CK techniques the forensic signals map to."""

TECHNIQUES = {
    "T1027": "Obfuscated Files or Information",
    "T1036.007": "Masquerading: Double File Extension",
    "T1204.001": "User Execution: Malicious Link",
    "T1528": "Steal Application Access Token",
    "T1566": "Phishing",
    "T1566.001": "Phishing: Spearphishing Attachment",
    "T1566.002": "Phishing: Spearphishing Link",
    "T1583.001": "Acquire Infrastructure: Domains",
    "T1598": "Phishing for Information",
    "T1598.003": "Phishing for Information: Spearphishing Link",
    "T1656": "Impersonation",
}


def technique_name(tid):
    return TECHNIQUES.get(tid, "")


def technique_url(tid):
    return f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"
