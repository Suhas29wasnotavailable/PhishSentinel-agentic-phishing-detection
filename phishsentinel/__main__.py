"""Command-line evidence ledger: python -m phishsentinel FILE [FILE ...] (or pipe text on stdin)."""
import argparse
import json
import sys

from .forensics import analyze_signals, rule_logodds, sigmoid


def report(raw):
    email, signals = analyze_signals(raw)
    lo = rule_logodds(signals)
    return email, signals, lo, sigmoid(lo - 1.0)


def as_json(email, signals, lo, risk, **extra):
    return {**extra, "rule_logodds": lo, "rule_risk": risk, "urls": [u["url"] for u in email["urls"]],
            "signals": [{k: s[k] for k in ("agent", "name", "weight", "evidence", "mitre")} for s in signals]}


def batch(paths, args):
    """Several files: one summary line (or one JSON line) per email, riskiest first."""
    rows = []
    for path in paths:
        with open(path, encoding="utf-8", errors="replace") as f:
            rows.append((path, *report(f.read())))
    rows.sort(key=lambda r: -r[4])
    for path, email, signals, lo, risk in rows:
        if args.json:
            print(json.dumps(as_json(email, signals, lo, risk, file=path)))
        else:
            top = max(signals, key=lambda s: s["weight"])["name"] if signals else "-"
            print(f"{risk:.2f}  {top:<32} {path}")
    flagged = args.fail_above is not None and any(r[4] >= args.fail_above for r in rows)
    return 2 if flagged else 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="phishsentinel", description="Deterministic phishing evidence ledger for emails.")
    ap.add_argument("files", nargs="*", metavar="FILE",
                    help="email file(s), plain text or raw MIME; reads stdin if omitted. Several files give a ranked summary")
    ap.add_argument("--json", action="store_true", help="print signals as JSON (JSON lines for several files)")
    ap.add_argument("--fail-above", type=float, metavar="RISK",
                    help="exit with code 2 if the rule-engine risk is at or above RISK (0-1), for mail-filter hooks")
    args = ap.parse_args(argv)

    if len(args.files) > 1:
        return batch(args.files, args)
    raw = open(args.files[0], encoding="utf-8", errors="replace").read() if args.files else sys.stdin.read()
    email, signals, lo, risk = report(raw)
    flagged = args.fail_above is not None and risk >= args.fail_above

    if args.json:
        print(json.dumps(as_json(email, signals, lo, risk), indent=2))
        return 2 if flagged else 0
    print(f"Rule-engine risk: {risk:.2f}  (log-odds {lo:+.1f})  ·  headers: {'yes' if email['headers'] else 'no'}  ·  URLs: {len(email['urls'])}")
    for s in sorted(signals, key=lambda s: -abs(s["weight"])):
        print(f"  [{s['weight']:+.1f}] {s['agent']:<8} {s['name']:<32} {s['evidence'][:70]}")
    if not signals:
        print("  no deterministic signals")
    return 2 if flagged else 0


if __name__ == "__main__":
    sys.exit(main())
