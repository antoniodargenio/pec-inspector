"""Export a whole conversation (see :mod:`threads`) as one A4 PDF, messages in chronological order.

Needs the optional dependency ``reportlab`` (``pip install "pec-inspector[pdf]"``). The standard PDF fonts are
used, so text outside Latin-1/WinAnsi (e.g. Cyrillic, CJK) is not rendered. Attachments are only listed, not embedded.
"""
from __future__ import annotations

import email
import hashlib
import io
from email import policy
from pathlib import Path
from typing import Dict
from xml.sax.saxutils import escape

from . import export

MAX_BODY_CHARS = 20000          # a very long body is cut, with a note, to keep the PDF readable

A4_W, A4_H = 595.2756, 841.8898        # points

ROLE_LABELS = {"sent": "SENT", "received": "RECEIVED", "receipt": "RECEIPT", "message": "MESSAGE"}


class PdfUnavailable(RuntimeError):
    pass


def available() -> bool:
    """True if reportlab can really be imported (it is installed but refuses to load on Python < 3.10)."""
    try:
        import reportlab.platypus  # noqa: F401
    except ImportError:
        return False
    return True


def _paragraph_text(text: str) -> str:
    return escape(text).replace("\r", "").replace("\n", "<br/>")


def write_thread_pdf(thread: dict, reports: Dict[str, dict], path) -> Path:
    """Write ``thread`` to ``path`` and return it. ``reports`` maps message id -> message report (for the raw files)."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import HRFlowable, KeepTogether, Paragraph, SimpleDocTemplate, Spacer
    except ImportError as exc:
        raise PdfUnavailable('PDF export needs reportlab: pip install "pec-inspector[pdf]"') from exc

    styles = getSampleStyleSheet()
    title = ParagraphStyle("t", parent=styles["Title"], fontSize=16, leading=20, alignment=0)
    meta = ParagraphStyle("m", parent=styles["Normal"], fontSize=9, leading=12, textColor=colors.HexColor("#444444"))
    head = ParagraphStyle("h", parent=styles["Heading3"], fontSize=11, leading=14, spaceBefore=10, spaceAfter=2)
    body = ParagraphStyle("b", parent=styles["Normal"], fontSize=9.5, leading=12.5)
    small = ParagraphStyle("s", parent=meta, fontSize=8.5, leading=11)

    subject = thread["subject"] or "(no subject)"
    counts = thread["counts"]
    story = [Paragraph(_paragraph_text(subject), title),
             Paragraph(_paragraph_text(
                 f"Conversation {thread['id']} - {len(thread['messages'])} messages: {counts['sent']} sent, "
                 f"{counts['received']} received, {counts['receipts']} receipts"
                 + (f" ({', '.join(thread['receipts'])})" if thread["receipts"] else "")), meta),
             Paragraph(_paragraph_text(f"From {thread['first_date']} to {thread['last_date']}"), meta),
             Spacer(1, 4), HRFlowable(width="100%", color=colors.grey)]

    embedded: list = []                  # attachments to append at the end, each distinct file once
    seen: dict = {}
    try:
        import pypdf  # noqa: F401
        pypdf_ok = True
    except ImportError:
        pypdf_ok = False

    for number, entry in enumerate(thread["messages"], 1):
        label = ROLE_LABELS.get(entry["role"], entry["role"].upper())
        if entry["receipt"]:
            label += f" - {entry['receipt']}"
        lines = [f"Date: {entry['date']}", f"From: {entry['from']}", f"To: {entry['to']}", f"Subject: {entry['subject']}"]
        block = [Paragraph(_paragraph_text(f"{number}. {label}"), head),
                 Paragraph(_paragraph_text("\n".join(lines)), meta), Spacer(1, 4)]
        text, names = "", []
        report = reports.get(entry["id"]) or {}
        eml = (report.get("files") or {}).get("envelope_eml")
        if eml and Path(eml).is_file():
            parts = export.read_parts(email.message_from_bytes(Path(eml).read_bytes(), policy=policy.default))
            text = parts["body_text"] or parts["wrapper"]
            for name, data in parts["attachments"]:
                digest = hashlib.sha256(data).hexdigest()
                if digest in seen:
                    names.append(f"{name} (same file as attachment {seen[digest]})")
                    continue
                kind = _kind(data)
                if kind and pypdf_ok:
                    embedded.append({"name": name, "data": data, "kind": kind, "message": number})
                    seen[digest] = f"{len(embedded)}"
                    names.append(f"{name} (embedded as attachment {len(embedded)})")
                else:
                    seen[digest] = name
                    names.append(f"{name} (not embedded: " + ("unsupported format" if pypdf_ok else "pypdf missing") + ")")
        if len(text) > MAX_BODY_CHARS:
            text = text[:MAX_BODY_CHARS] + "\n[... text truncated ...]"
        block.append(Paragraph(_paragraph_text(text.strip() or "(no text)"), body))
        if names:
            block += [Spacer(1, 3), Paragraph(_paragraph_text("Attachments: " + ", ".join(names)), small)]
        story += [KeepTogether(block[:3]), *block[3:], Spacer(1, 6), HRFlowable(width="100%", color=colors.lightgrey)]

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.grey)
        canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, f"page {doc.page}")
        canvas.restoreState()

    path = Path(path)
    SimpleDocTemplate(str(path), pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=16 * mm,
                      bottomMargin=18 * mm, title=subject, author="pec-inspector").build(
        story, onFirstPage=footer, onLaterPages=footer)
    if embedded:
        _append_attachments(path, embedded, thread)
    return path


def _kind(data: bytes):
    if data[:1024].lstrip().startswith(b"%PDF"):
        return "pdf"
    if data[:4] == b"\x89PNG" or data[:3] == b"\xff\xd8\xff":
        return "image"
    return None


def _single_page(draw) -> bytes:
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas
    buffer = io.BytesIO()
    page = canvas.Canvas(buffer, pagesize=A4)
    draw(page)
    page.showPage()
    page.save()
    return buffer.getvalue()


def _cover(number: int, item: dict, note: str = "") -> bytes:
    def draw(page):
        page.setFont("Helvetica-Bold", 16)
        page.drawString(60, A4_H - 120, f"Attachment {number}")
        page.setFont("Helvetica", 11)
        page.drawString(60, A4_H - 145, item["name"][:90])
        page.drawString(60, A4_H - 163, f"from message {item['message']} of the conversation")
        if note:
            page.setFillColorRGB(0.6, 0, 0)
            page.drawString(60, A4_H - 190, note[:100])
    return _single_page(draw)


def _image_page(data: bytes) -> bytes:
    from reportlab.lib.utils import ImageReader

    def draw(page):
        image = ImageReader(io.BytesIO(data))
        w, h = image.getSize()
        margin = 28
        scale = min((A4_W - 2 * margin) / w, (A4_H - 2 * margin) / h)
        page.drawImage(image, (A4_W - w * scale) / 2, (A4_H - h * scale) / 2, w * scale, h * scale)
    return _single_page(draw)


def _fit_to_a4(page):
    """A new A4 page carrying ``page`` scaled to fit and centred."""
    from pypdf import PageObject, Transformation
    page.transfer_rotation_to_content()
    left, bottom = float(page.mediabox.left), float(page.mediabox.bottom)
    width, height = float(page.mediabox.width), float(page.mediabox.height)
    scale = min(A4_W / width, A4_H / height)
    blank = PageObject.create_blank_page(width=A4_W, height=A4_H)
    blank.merge_transformed_page(page, Transformation().translate(-left, -bottom).scale(scale)
                                 .translate((A4_W - width * scale) / 2, (A4_H - height * scale) / 2))
    return blank


def _append_attachments(path: Path, embedded: list, thread: dict) -> None:
    """Append the attachments after the messages: a cover page, then the pages of each file scaled to A4."""
    from pypdf import PdfReader, PdfWriter
    writer = PdfWriter()
    for page in PdfReader(str(path)).pages:
        writer.add_page(page)
    for number, item in enumerate(embedded, 1):
        try:
            if item["kind"] == "pdf":
                reader = PdfReader(io.BytesIO(item["data"]))
                if reader.is_encrypted and not reader.decrypt(""):
                    raise ValueError("password-protected PDF")
                pages = [_fit_to_a4(page) for page in reader.pages]
            else:
                pages = list(PdfReader(io.BytesIO(_image_page(item["data"]))).pages)
            note = ""
        except Exception as exc:                          # corrupt or unsupported attachment: say so, keep going
            pages, note = [], f"cannot be embedded: {exc}"
        cover = PdfReader(io.BytesIO(_cover(number, item, note))).pages[0]
        writer.add_page(cover)
        writer.add_outline_item(f"Attachment {number}: {item['name']}", len(writer.pages) - 1)
        for page in pages:
            writer.add_page(page)
    with open(path, "wb") as handle:
        writer.write(handle)
