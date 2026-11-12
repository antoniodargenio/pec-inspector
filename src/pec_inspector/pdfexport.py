"""Export a whole conversation (see :mod:`threads`) as one A4 PDF, messages in chronological order.

Needs the optional dependency ``reportlab`` (``pip install "pec-inspector[pdf]"``). The standard PDF fonts are
used, so text outside Latin-1/WinAnsi (e.g. Cyrillic, CJK) is not rendered. Attachments are only listed, not embedded.
"""
from __future__ import annotations

import email
from email import policy
from pathlib import Path
from typing import Dict
from xml.sax.saxutils import escape

from . import export

MAX_BODY_CHARS = 20000          # a very long body is cut, with a note, to keep the PDF readable

ROLE_LABELS = {"sent": "INVIATO", "received": "RICEVUTO", "receipt": "RICEVUTA", "message": "MESSAGGIO"}


class PdfUnavailable(RuntimeError):
    pass


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

    subject = thread["subject"] or "(senza oggetto)"
    counts = thread["counts"]
    story = [Paragraph(_paragraph_text(subject), title),
             Paragraph(_paragraph_text(
                 f"Conversazione {thread['id']} - {len(thread['messages'])} messaggi: {counts['sent']} inviati, "
                 f"{counts['received']} ricevuti, {counts['receipts']} ricevute"
                 + (f" ({', '.join(thread['receipts'])})" if thread["receipts"] else "")), meta),
             Paragraph(_paragraph_text(f"Dal {thread['first_date']} al {thread['last_date']}"), meta),
             Spacer(1, 4), HRFlowable(width="100%", color=colors.grey)]

    for number, entry in enumerate(thread["messages"], 1):
        label = ROLE_LABELS.get(entry["role"], entry["role"].upper())
        if entry["receipt"]:
            label += f" - {entry['receipt']}"
        lines = [f"Data: {entry['date']}", f"Da: {entry['from']}", f"A: {entry['to']}", f"Oggetto: {entry['subject']}"]
        block = [Paragraph(_paragraph_text(f"{number}. {label}"), head),
                 Paragraph(_paragraph_text("\n".join(lines)), meta), Spacer(1, 4)]
        text, names = "", []
        report = reports.get(entry["id"]) or {}
        eml = (report.get("files") or {}).get("envelope_eml")
        if eml and Path(eml).is_file():
            parts = export.read_parts(email.message_from_bytes(Path(eml).read_bytes(), policy=policy.default))
            text = parts["body_text"] or parts["wrapper"]
            names = [name for name, _ in parts["attachments"]]
        if len(text) > MAX_BODY_CHARS:
            text = text[:MAX_BODY_CHARS] + "\n[... testo troncato ...]"
        block.append(Paragraph(_paragraph_text(text.strip() or "(nessun testo)"), body))
        if names:
            block += [Spacer(1, 3), Paragraph(_paragraph_text("Allegati: " + ", ".join(names)), small)]
        story += [KeepTogether(block[:3]), *block[3:], Spacer(1, 6), HRFlowable(width="100%", color=colors.lightgrey)]

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.grey)
        canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, f"pagina {doc.page}")
        canvas.restoreState()

    path = Path(path)
    SimpleDocTemplate(str(path), pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=16 * mm,
                      bottomMargin=18 * mm, title=subject, author="pec-inspector").build(
        story, onFirstPage=footer, onLaterPages=footer)
    return path
