"""Group the processed messages into conversations: what was sent, what was received and the receipts.

Messages are linked through the ``Message-ID`` of the *original* message, which is carried by

* the original itself (a copy in the Sent folder, or the ``postacert.eml`` enclosed in a PEC envelope),
* every PEC receipt (``X-Riferimento-Message-ID`` header, ``<msgid>`` of ``daticert.xml``),

and through the ``In-Reply-To`` / ``References`` headers of the original, so that replies join the
conversation they answer. Nothing is guessed from subjects: two messages are in the same conversation only if
they share at least one of these identifiers.
"""
from __future__ import annotations

from datetime import datetime, timezone
from email.utils import getaddresses, parsedate_to_datetime
from typing import Dict, Iterable, List, Optional

from . import formats

_MIN = datetime.min.replace(tzinfo=timezone.utc)
_PREFIXES = ("posta certificata:", "accettazione:", "consegna:", "avvenuta consegna:", "mancata consegna:",
             "presa in carico:", "non accettazione:", "preavviso di errore consegna:", "avviso di mancata consegna:",
             "anomalia messaggio:", "re:", "r:", "fwd:", "fw:", "i:")


def ids_in(value) -> List[str]:
    """All message ids in a ``References`` / ``In-Reply-To`` style value (``<a@x> <b@y>``), normalised."""
    out = []
    for token in str(value or "").replace(",", " ").split():
        token = formats.normalize_id(token)
        if token:
            out.append(token)
    return out


def threading_info(own_id: str, original_id: str, daticert_id: str, reference_id: str, references: Iterable[str]) -> dict:
    """The ``threading`` block of a message report. ``original_id`` is the id of the enclosed original message (if any);
    when the message carries no original, the id named by the receipt (``X-Riferimento-Message-ID`` /
    ``daticert.xml``) or, as a last resort, the message's own id identifies the conversation."""
    own = formats.normalize_id(own_id)
    key = (formats.normalize_id(original_id) or formats.normalize_id(reference_id)
           or formats.normalize_id(daticert_id) or own)
    refs = [r for r in dict.fromkeys(references) if r and r != key]
    return {"message_id": own or None, "original_message_id": key or None, "references": refs}


def _when(value: str) -> datetime:
    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError):
        return _MIN
    if parsed is None:
        return _MIN
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def receipt_type(report: dict) -> Optional[str]:
    """Name of the receipt (``accettazione``, ``avvenuta-consegna``, ... or the REM event) if the message is one."""
    x_receipt = (report.get("headers") or {}).get("x_ricevuta")
    if x_receipt:
        return x_receipt
    daticert = report.get("daticert") or {}
    if daticert.get("type") in formats.RECEIPT_TYPES:
        return daticert["type"]
    rem = report.get("rem") or {}
    if "receipt" in rem.get("REM-MessageType", ""):
        event = rem.get("REM-EventIdentifier", "")
        return event[len(formats.EVENT_URI):] if event.startswith(formats.EVENT_URI) else (event or "receipt")
    for evidence in report.get("evidence") or []:
        if evidence.get("event"):
            return evidence["event"].rsplit("/", 1)[-1]
    return None


def _addresses(value: str) -> set:
    return {a.lower() for _, a in getaddresses([value or ""]) if a}


def role(report: dict, address: Optional[str]) -> str:
    """``receipt``, ``sent`` (the mailbox is the sender), ``received`` or ``message`` (not determinable)."""
    if receipt_type(report):
        return "receipt"
    if not address:
        return "message"
    original = report.get("original_message") or {}
    sender = _addresses(original.get("from") or report.get("from"))
    return "sent" if address.lower() in sender else "received"


def _clean_subject(subject: str) -> str:
    text = " ".join((subject or "").split())
    changed = True
    while changed:
        changed = False
        for prefix in _PREFIXES:
            if text.lower().startswith(prefix):
                text, changed = text[len(prefix):].strip(), True
    return text


def build_threads(reports: List[dict], address: Optional[str] = None) -> List[dict]:
    """Conversations, oldest first; each lists its messages in chronological order."""
    parent = list(range(len(reports)))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    owner: Dict[str, int] = {}
    for index, report in enumerate(reports):
        info = report.get("threading") or {}
        keys = [info.get("original_message_id")] + list(info.get("references") or [])
        for key in filter(None, keys):
            if key in owner:
                parent[find(index)] = find(owner[key])
            else:
                owner[key] = index

    groups: Dict[int, List[int]] = {}
    for index in range(len(reports)):
        groups.setdefault(find(index), []).append(index)

    threads = []
    for members in groups.values():
        entries = []
        for index in members:
            report = reports[index]
            original = report.get("original_message") or {}
            entries.append({
                "id": report["id"], "folder": report.get("folder"), "role": role(report, address),
                "receipt": receipt_type(report), "kind": report.get("kind"),
                "date": report.get("date") or "",
                "from": original.get("from") or report.get("from") or "",
                "to": original.get("to") or report.get("to") or "",
                "subject": original.get("subject") or report.get("subject") or "",
                "_when": _when(report.get("date") or ""), "_order": index,
            })
        entries.sort(key=lambda e: (e["_when"], e["_order"]))
        non_receipts = [e for e in entries if e["role"] != "receipt"]
        subject = _clean_subject((non_receipts or entries)[0]["subject"])
        receipts = sorted({e["receipt"] for e in entries if e["receipt"]})
        threads.append({
            "subject": subject,
            "first_date": entries[0]["date"], "last_date": entries[-1]["date"],
            "counts": {"sent": sum(e["role"] == "sent" for e in entries),
                       "received": sum(e["role"] == "received" for e in entries),
                       "receipts": sum(e["role"] == "receipt" for e in entries),
                       "other": sum(e["role"] == "message" for e in entries)},
            "receipts": receipts,
            "messages": entries, "_start": (entries[0]["_when"], entries[0]["_order"]),
        })
    threads.sort(key=lambda t: t["_start"])
    for number, thread in enumerate(threads, 1):
        thread.pop("_start")
        thread["id"] = f"t{number}"
        for entry in thread["messages"]:
            entry.pop("_when")
            entry.pop("_order")
    return [{"id": t["id"], **{k: v for k, v in t.items() if k != "id"}} for t in threads]


def thread_lines(threads: List[dict]) -> List[str]:
    lines = [f"\n=== CONVERSATIONS ({len(threads)})"]
    for thread in threads:
        counts = thread["counts"]
        lines.append(f"\n[{thread['id']}] {thread['subject'] or '(no subject)'}")
        lines.append(f"    {len(thread['messages'])} messages: {counts['sent']} sent, {counts['received']} received, "
                     f"{counts['receipts']} receipts" + (f", {counts['other']} other" if counts["other"] else "")
                     + (f" | receipts: {', '.join(thread['receipts'])}" if thread["receipts"] else ""))
        for entry in thread["messages"]:
            label = entry["role"] + (f" ({entry['receipt']})" if entry["receipt"] else "")
            where = f" [{entry['folder']}]" if entry.get("folder") else ""
            lines.append(f"    {entry['date']}  {label:<30} msg {entry['id']}{where}  {entry['from']} -> {entry['to']}")
    return lines
