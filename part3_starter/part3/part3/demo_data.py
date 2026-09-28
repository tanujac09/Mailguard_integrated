"""Synthetic, fictional test data (documentation IP ranges, invented domains). Replace with real Part 1/2 output later."""
import hashlib, json, random
from datetime import datetime, timedelta

BODY = ("Dear customer your invoice INV-{n} is overdue. Please verify your payment details immediately using the secure link "
        "below to avoid suspension of services. {extra} Regards accounts department")
EXTRAS = ["Contact us if you have questions.", "This is your final reminder.", "Ignore this if already paid.", "Thank you for your business."]
ATT_HASH = hashlib.sha256(b"fake-invoice.zip").hexdigest()

def _bundle(i, when, from_addr, ip, asn, body, urls, atts, spf="fail", dmarc="fail", lookalike=None, subject="Invoice"):
    raw = ("Message-ID: <%d@demo>\nFrom: %s\nDate: %s\n\n%s\n" % (i, from_addr, when, body)).encode()
    return {
        "bundle_version": "0.1",
        "artifact": {"filename": "email_%03d.eml" % i, "sha256": hashlib.sha256(raw).hexdigest(), "size_bytes": len(raw),
                     "collected_at": when, "source": "demo"},
        "email": {"message_id": "<%d@demo>" % i, "received_at": when, "subject": subject, "from_addr": from_addr, "body_norm": body},
        "part1": {"spf": spf, "dkim": "none", "dmarc": dmarc, "trust_boundary_ip": ip, "lookalike_of": lookalike},
        "part2": {"asn": asn, "asn_org": "ExampleNet", "urls": urls, "attachments": atts, "risk_score": 0.9 if lookalike else 0.1},
    }, raw

def make_demo(seed=7):
    rnd = random.Random(seed); base = datetime(2026, 9, 19, 9, 0, 0); out = []
    senders = ["accounts@example-pay.net", "billing@examp1e-pay.net", "accounts@example-payments.net"]
    for n in range(15):                                   # the campaign
        when = (base + timedelta(minutes=rnd.randint(0, 40))).strftime("%Y-%m-%dT%H:%M:%SZ")
        ip = "203.0.113.45" if n < 6 else "203.0.113.%d" % (60 + n)
        dom = "pay-verify.example" if n < 11 else "pay-verify2.example"
        urls = [{"url": "https://track.mailer.example/r?id=%d" % n, "final_url": "https://%s/inv?id=%d" % (dom, 8800 + n), "final_domain": dom}]
        atts = [{"filename": "invoice.zip", "sha256": ATT_HASH}] if n < 9 else []
        out.append(_bundle(100 + n, when, senders[n % 3], ip, 64500, BODY.format(n=88000 + n, extra=EXTRAS[n % 4]), urls, atts,
                           lookalike="example-supplier.com"))
    for n in range(3):                                    # decoys: same shared-hosting IP, unrelated content
        when = (base + timedelta(minutes=10 * n)).strftime("%Y-%m-%dT%H:%M:%SZ")
        body = "Weekly bakery newsletter number %d fresh sourdough and seasonal pastries are available this weekend at the shop" % n
        out.append(_bundle(200 + n, when, "hello@sweetbakery%d.example" % n, "203.0.113.45", 64500, body,
                           [{"url": "https://sweetbakery%d.example/menu" % n, "final_url": "https://sweetbakery%d.example/menu" % n,
                             "final_domain": "sweetbakery%d.example" % n}], [], spf="pass", dmarc="pass", subject="Newsletter"))
    for n in range(5):                                    # benign mail elsewhere
        when = (base + timedelta(hours=1 + n)).strftime("%Y-%m-%dT%H:%M:%SZ")
        out.append(_bundle(300 + n, when, "person%d@company%d.example" % (n, n), "198.51.100.%d" % (10 + n), 64501 + n,
                           "Meeting notes for project %d attached please review before the call tomorrow morning thanks" % n,
                           [], [], spf="pass", dmarc="pass", subject="Notes"))
    return out
