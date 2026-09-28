"""
Turns raw .eml bytes into the structured pieces every downstream module
needs: headers (including the full Received: chain, in file order),
body text/html, links found in the body, and attachments with hashes.
"""
import hashlib
import re
from email import policy
from email.parser import BytesParser
from dataclasses import dataclass, field
from typing import List, Optional
#from bridge import send_to_part3

@dataclass
class Attachment:
    filename: str
    content_type: str
    sha256: str
    size: int


@dataclass
class ParsedEmail:
    raw_bytes: bytes
    sha256: str
    subject: Optional[str]
    from_header: Optional[str]
    from_domain: Optional[str]
    reply_to: Optional[str]
    return_path: Optional[str]
    date_header: Optional[str]
    message_id: Optional[str]
    received_chain: List[str] = field(default_factory=list)  # file order: newest hop first
    body_text: str = ""
    body_html: str = ""
    links: List[dict] = field(default_factory=list)  # {anchor_text, href}
    attachments: List[Attachment] = field(default_factory=list)
    raw_header_block: str = ""


def _extract_domain(addr: Optional[str]) -> Optional[str]:
    if not addr:
        return None
    match = re.search(r"@([A-Za-z0-9.-]+)", addr)
    return match.group(1).lower() if match else None


def _extract_links_from_html(html: str) -> List[dict]:
    links = []
    for m in re.finditer(r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', html, re.IGNORECASE | re.DOTALL):
        href = m.group(1).strip()
        anchor_text = re.sub(r"<[^>]+>", "", m.group(2)).strip()
        links.append({"href": href, "anchor_text": anchor_text})
    return links


def _extract_links_from_text(text: str) -> List[dict]:
    links = []
    for m in re.finditer(r"https?://[^\s<>\")]+", text):
        links.append({"href": m.group(0), "anchor_text": m.group(0)})
    return links


def parse_eml(raw_bytes: bytes, filename: str = "upload.eml") -> ParsedEmail:
    msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)

    sha256 = hashlib.sha256(raw_bytes).hexdigest()

    from_header = msg.get("From")
    from_domain = _extract_domain(from_header)
    reply_to = msg.get("Reply-To")
    return_path = msg.get("Return-Path")
    date_header = msg.get("Date")
    message_id = msg.get("Message-ID")
    subject = msg.get("Subject")

    # get_all preserves file order: the FIRST Received header in the raw
    # file is the MOST RECENT hop (added last, closest to the recipient).
    # The LAST one in this list is the EARLIEST / original hop.
    received_chain = msg.get_all("Received") or []

    body_text = ""
    body_html = ""
    attachments: List[Attachment] = []

    if msg.is_multipart():
        for part in msg.walk():
            content_disposition = str(part.get("Content-Disposition") or "")
            content_type = part.get_content_type()

            if "attachment" in content_disposition or part.get_filename():
                try:
                    payload = part.get_payload(decode=True) or b""
                except Exception:
                    payload = b""
                attachments.append(
                    Attachment(
                        filename=part.get_filename() or "unnamed",
                        content_type=content_type,
                        sha256=hashlib.sha256(payload).hexdigest(),
                        size=len(payload),
                    )
                )
            elif content_type == "text/plain" and not body_text:
                try:
                    body_text = part.get_content()
                except Exception:
                    body_text = ""
            elif content_type == "text/html" and not body_html:
                try:
                    body_html = part.get_content()
                except Exception:
                    body_html = ""
    else:
        content_type = msg.get_content_type()
        try:
            content = msg.get_content()
        except Exception:
            content = ""
        if content_type == "text/html":
            body_html = content
        else:
            body_text = content

    links = []
    if body_html:
        links.extend(_extract_links_from_html(body_html))
    if body_text:
        links.extend(_extract_links_from_text(body_text))

    # raw header block (everything before the first blank line) - handy for
    # the analyst's "raw evidence" panel
    raw_text = raw_bytes.decode("utf-8", errors="replace")
    raw_header_block = raw_text.split("\n\n", 1)[0]

    return ParsedEmail(
        raw_bytes=raw_bytes,
        sha256=sha256,
        subject=subject,
        from_header=from_header,
        from_domain=from_domain,
        reply_to=reply_to,
        return_path=return_path,
        date_header=date_header,
        message_id=message_id,
        received_chain=received_chain,
        body_text=body_text,
        body_html=body_html,
        links=links,
        attachments=attachments,
        raw_header_block=raw_header_block,
    )
