"""Command-line evidence ledger: python -m phishsentinel FILE (or pipe text on stdin)."""
import argparse
import json
import sys

from .forensics import analyze_signals, rule_logodds, sigmoid


def main(argv=None):
    ap = argparse.ArgumentParser(prog="phishsentinel", description="Deterministic phishing evidence ledger for one email.")
    ap.add_argument("file", nargs="?", help="email file (plain text or raw MIME); reads stdin if omitted")
    ap.add_argument("--json", action="store_true", help="print signals as JSON")
    args = ap.parse_args(argv)

    raw = open(args.file, encoding="utf-8", errors="replace").read() if args.file else sys.stdin.read()
    email, signals = analyze_signals(raw)
    lo = rule_logodds(signals)
    risk = sigmoid(lo - 1.0)

    if args.json:
        print(json.dumps({"rule_logodds": lo, "rule_risk": risk, "urls": [u["url"] for u in email["urls"]],
                          "signals": [{k: s[k] for k in ("agent", "name", "weight", "evidence", "mitre")} for s in signals]}, indent=2))
        return 0
    print(f"Rule-engine risk: {risk:.2f}  (log-odds {lo:+.1f})  ·  headers: {'yes' if email['headers'] else 'no'}  ·  URLs: {len(email['urls'])}")
    for s in sorted(signals, key=lambda s: -abs(s["weight"])):
        print(f"  [{s['weight']:+.1f}] {s['agent']:<8} {s['name']:<32} {s['evidence'][:70]}")
    if not signals:
        print("  no deterministic signals")
    return 0


if __name__ == "__main__":
    sys.exit(main())
