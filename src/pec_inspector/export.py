"""Readable export of a message: decoded text/HTML body and every attachment, in plain files.

Layout, one folder per message::

    <root>/<n>_<subject>/
        message.txt          headers + body of the original message, decoded (HTML converted to text if needed)
        message.html         the HTML body, if any (remote content is blocked by a Content-Security-Policy tag)
        attachments/         every attachment of the original message; for .p7m the signed content as well
        pec/                 certification parts: daticert.xml, smime.p7s, the PEC wrapper text, the raw envelope

For messages without an enclosed original (receipts) ``message.txt`` holds the receipt text itself.
Attachment names come from the sender and are sanitised, so nothing can be written outside the folder.
"""
from __future__ import annotations

import re
from html.parser import HTMLParser
from pathlib import Path
from typing import List, Optional, Tuple

from . import pki

CSP_META = ('<meta http-equiv="Content-Security-Policy" '
            'content="default-src \'none\'; img-src data:; style-src \'unsafe-inline\'">\n')

_BLOCK_TAGS = {"p", "div", "br", "tr", "li", "h1", "h2", "h3", "h4", "h5", "h6", "table", "ul", "ol", "blockquote", "pre"}


class _TextExtractor(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts: List[str] = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self._skip += 1
        elif tag in _BLOCK_TAGS:
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip:
            self._skip -= 1
        elif tag in _BLOCK_TAGS:
            self.parts.append("\n")

    def handle_data(self, data):
        if not self._skip:
            self.parts.append(data)


def html_to_text(source: str) -> str:
    parser = _TextExtractor()
    parser.feed(source)
    parser.close()
    text = re.sub(r"[ \t\r\f\v]+", " ", "".join(parser.parts))
    return re.sub(r"\n\s*\n\s*\n+", "\n\n", text).strip() + "\n"


def slug(text: str, limit: int = 60) -> str:
    return re.sub(r"[^\w.-]+", "_", text or "").strip("_.")[:limit] or "message"


def _unique(directory: Path, name: str) -> Path:
    target = directory / name
    stem, suffix, counter = target.stem, target.suffix, 1
    while target.exists():
        counter += 1
        target = directory / f"{stem}_{counter}{suffix}"
    return target


def _decode(part) -> str:
    payload = part.get_payload(decode=True) or b""
    for charset in (part.get_content_charset(), "utf-8", "latin-1"):
        try:
            return payload.decode(charset or "utf-8")
        except (LookupError, UnicodeDecodeError):
            continue
    return payload.decode("utf-8", "replace")


def _headers(message) -> str:
    lines = []
    for name in ("From", "To", "Cc", "Date", "Subject", "Message-ID"):
        if message.get(name):
            lines.append(f"{name}: {' '.join(str(message[name]).split())}")
    return "\n".join(lines)


def read_parts(msg) -> dict:
    """Split a PEC/REM message into what a reader wants: ``main`` (the original message, or ``msg`` itself),
    ``body_text``, ``body_html``, ``attachments`` and ``pec_files`` as ``(name, bytes)`` lists, ``wrapper`` (the text of
    the PEC envelope, empty if there is no enclosed original)."""
    original = []                         # at most one enclosed original message
    texts = {0: [], 1: []}                # level 0 = PEC wrapper, 1 = original message
    htmls = {0: [], 1: []}
    attachments: List[Tuple[str, bytes]] = []
    pec_files: List[Tuple[str, bytes]] = []

    def walk(part, level):
        content_type, filename = part.get_content_type(), part.get_filename()
        if content_type == "message/rfc822":
            inner = part.get_payload(0)
            if level == 0 and not original:
                original.append(inner)
                walk(inner, 1)
            else:                         # a forwarded message inside the original: keep it as an attachment
                attachments.append((pki.safe_filename(filename or "message") + ("" if (filename or "").lower().endswith(".eml") else ".eml"),
                                    inner.as_bytes()))
        elif part.is_multipart():
            for sub in part.iter_parts():
                walk(sub, level)
        elif filename:
            payload = part.get_payload(decode=True)
            if payload is not None:
                (pec_files if level == 0 else attachments).append((pki.safe_filename(filename), payload))
        elif content_type == "text/plain":
            texts[min(level, 1)].append(_decode(part))
        elif content_type == "text/html":
            htmls[min(level, 1)].append(_decode(part))

    walk(msg, 0)
    if not original:                      # no PEC envelope (e.g. a copy in Sent): files are real attachments, except
        kept = []                         # the certification parts of a receipt
        for name, data in pec_files:
            (kept if name.lower() in ("daticert.xml", "smime.p7s") else attachments).append((name, data))
        pec_files[:] = kept

    main, body_level = (original[0], 1) if original else (msg, 0)
    body_html = "\n".join(htmls[body_level])
    body_text = "\n".join(texts[body_level]).strip() or (html_to_text(body_html) if body_html else "")
    return {"main": main, "body_text": body_text, "body_html": body_html, "attachments": attachments,
            "pec_files": pec_files, "wrapper": "\n".join(texts[0]).strip() if original else ""}


def export_message(num: str, msg, root, raw: Optional[bytes] = None) -> Tuple[Path, int]:
    """Write the readable export of ``msg`` (an ``email.message.EmailMessage``) under ``root``.
    Returns ``(message folder, number of attachments written)``."""
    folder = Path(root) / f"{num}_{slug(str(msg['Subject'] or ''))}"
    attachments_dir, pec_dir = folder / "attachments", folder / "pec"
    folder.mkdir(parents=True, exist_ok=True)

    parts = read_parts(msg)
    main, body_text, body_html = parts["main"], parts["body_text"], parts["body_html"]
    attachments, pec_files = parts["attachments"], parts["pec_files"]
    (folder / "message.txt").write_text(_headers(main) + "\n\n" + body_text.strip() + "\n", encoding="utf-8")
    if body_html:
        (folder / "message.html").write_text(CSP_META + body_html, encoding="utf-8")

    written = 0
    if attachments:
        attachments_dir.mkdir(exist_ok=True)
    for name, data in attachments:
        _unique(attachments_dir, name).write_bytes(data)
        written += 1
        if name.lower().endswith(".p7m"):             # also provide the signed content in the clear
            target = _unique(attachments_dir, pki.safe_filename(name[:-4] or name + ".content"))
            ok, _ = pki.cms_verify(pki.to_der(data), None, str(target))
            if ok:
                written += 1
            else:
                target.unlink(missing_ok=True)

    wrapper = parts["wrapper"]
    if pec_files or wrapper or raw is not None:
        pec_dir.mkdir(exist_ok=True)
        for name, data in pec_files:
            _unique(pec_dir, name).write_bytes(data)
        if wrapper:
            (pec_dir / "envelope.txt").write_text(wrapper + "\n", encoding="utf-8")
        if raw is not None:
            (pec_dir / "envelope.eml").write_bytes(raw)
    return folder, written
