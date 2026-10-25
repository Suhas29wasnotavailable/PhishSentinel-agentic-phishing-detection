# Changelog

## 0.2.0 – 2026-10-25
### Added
- `link_text_mismatch` signal: HTML links whose visible text shows a different domain from the real target.
- `sender_domain_typosquat` / `sender_domain_brand-in-domain` signals for look-alike From domains.
- CLI batch mode: several files give a riskiest-first summary (or JSON lines with `--json`).
- CLI `--fail-above RISK` returns exit code 2 for mail-filter hooks.
- Tests for the CLI and for every URL, header and attachment signal; CI reports coverage and runs on Python 3.13.

### Fixed
- HTML-only emails lost their link targets when tags were stripped. `href` URLs are now kept, `<script>`/`<style>` blocks are dropped and HTML entities are unescaped.

## 0.1.0 – 2026-10-24
- Deterministic core extracted from the notebook: parser, Unicode normalisation, header/URL/content forensics and the `phishsentinel` CLI.
