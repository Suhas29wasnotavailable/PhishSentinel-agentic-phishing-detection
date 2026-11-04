# Example emails

Small hand-written emails for trying the CLI and for regression tests (`tests/test_examples.py`).
Every domain and address uses reserved example names (`example.*`) or documentation IP ranges, and the attachment holds no real content.

| File | Expected | What it shows |
|---|---|---|
| `benign_order_update.eml` | low risk | Fully authenticated, links only to the sender's brand |
| `benign_thread_reply.eml` | low risk | Real reply with In-Reply-To and quoted text |
| `suspicious_masked_link.eml` | high risk | SPF/DMARC fail, link text shows paypal.com but points to an IP on port 8080 |
| `suspicious_fake_reply.eml` | high risk | "RE:" with no thread, address in display name, Reply-To elsewhere, wire transfer and secrecy |
| `suspicious_attachment.eml` | high risk | `.pdf.exe` double-extension executable |

```bash
phishsentinel examples/             # ranked summary
phishsentinel examples/suspicious_masked_link.eml --markdown
```
