"""Signature, certificate-chain and revocation checks.

* S/MIME signature of the PEC envelope (``smime.p7s``)
* digital signatures on the original attachments: CAdES ``.p7m`` (enveloping), detached ``.p7s``,
  PAdES signatures inside PDFs (found through ``/ByteRange``); XMLDSig/XAdES is only detected
* certificate validity at the date of the message
* trust chain against PEM roots given with ``--ca`` (the PEC provider signer chains to the AgID CA; qualified
  signers chain to their own trust service provider, whose root you have to supply)
* revocation: OCSP (through ``openssl ocsp``) and CRL, for every certificate of the chain except the root

Signature *integrity* is checked with the ``openssl`` command line (``cryptography`` has no CMS verifier);
trust is evaluated separately with ``cryptography``.

Every check returns plain ``dict``/``list`` data (JSON-serialisable); the ``*_lines`` functions render the same
data as the human-readable text report.
"""
from __future__ import annotations

import base64
import os
import re
import subprocess
import tempfile
import warnings
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Dict, List, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import AuthorityInformationAccessOID
from cryptography.x509.verification import ExtensionPolicy, PolicyBuilder, Store

from . import netsafe

# PEC provider S/MIME blobs are often BER, not DER: cryptography reads them anyway (harmless warning)
warnings.filterwarnings("ignore", message="PKCS#7 certificates could not be parsed as DER")

OPENSSL = "openssl"


def message_time(date_header) -> datetime:
    try:
        when = parsedate_to_datetime(date_header)
        return when if when.tzinfo else when.replace(tzinfo=timezone.utc)
    except Exception:
        return datetime.now(timezone.utc)


def choose_signer(certs):
    """The signing certificate is the first non-CA one (digitalSignature / emailProtection)."""
    for cert in certs:
        try:
            if not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
                return cert
        except x509.ExtensionNotFound:
            return cert
    return certs[0]


def verify_chain(signer, certs, when, ca_file, errors: List[str]) -> Optional[bool]:
    """Chain to the PEM certificates in ``ca_file``. ``None`` if no ``ca_file`` was given."""
    if not ca_file:
        return None
    roots = x509.load_pem_x509_certificates(Path(ca_file).read_bytes())
    try:
        # PEC provider certificates lack the e-mail/clientAuth EKU the default client verifier insists on:
        # the end-entity gets a permissive policy (no EKU/KU check) while CA certificates keep the
        # standard checks (basicConstraints, ...).
        verifier = (PolicyBuilder().store(Store(roots)).time(when.astimezone(timezone.utc).replace(tzinfo=None))
                    .extension_policies(ca_policy=ExtensionPolicy.webpki_defaults_ca(),
                                        ee_policy=ExtensionPolicy.permit_all())
                    .build_client_verifier())
        verifier.verify(signer, [c for c in certs if c is not signer])
        return True
    except Exception as exc:
        errors.append(str(exc))
        return False


# --- revocation -------------------------------------------------------------------------------
_crl_cache: Dict[str, object] = {}


def _extension_urls(extension_class, cert, access_method=None) -> List[str]:
    urls: List[str] = []
    try:
        value = cert.extensions.get_extension_for_class(extension_class).value
    except x509.ExtensionNotFound:
        return urls
    if extension_class is x509.AuthorityInformationAccess:
        for description in value:
            if (description.access_method == access_method
                    and isinstance(description.access_location, x509.UniformResourceIdentifier)):
                urls.append(description.access_location.value)
    else:
        for point in value:
            for name in point.full_name or []:
                if isinstance(name, x509.UniformResourceIdentifier):
                    urls.append(name.value)
    return urls


def _find_issuer(cert, candidates):
    """Issuer certificate: among ``candidates`` (certs in the signature, --ca), else via AIA caIssuers."""
    for candidate in candidates:
        if candidate is not cert:
            try:
                cert.verify_directly_issued_by(candidate)
                return candidate
            except Exception:
                pass
    for url in _extension_urls(x509.AuthorityInformationAccess, cert, AuthorityInformationAccessOID.CA_ISSUERS):
        raw = netsafe.http_get(url)
        if not raw:
            continue
        for load in (x509.load_der_x509_certificate, x509.load_pem_x509_certificate):
            try:
                candidate = load(raw)
                cert.verify_directly_issued_by(candidate)
                return candidate
            except Exception:
                pass
    return None


def _pem(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def _ocsp_status(cert, issuer, url, ca_file):
    """Ask the responder with ``openssl ocsp``. Returns ``(status | None, details, response_authenticated)``."""
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "c.pem").write_bytes(_pem(cert))
        Path(tmp, "i.pem").write_bytes(_pem(issuer))
        base = [OPENSSL, "ocsp", "-issuer", "i.pem", "-cert", "c.pem", "-url", url, "-no_nonce", "-timeout", "15"]
        attempts = ([(["-CAfile", os.path.abspath(ca_file)], True)] if ca_file else []) + [(["-noverify"], False)]
        proc = None
        for extra, authenticated in attempts:
            proc = subprocess.run(base + extra, cwd=tmp, capture_output=True, text=True)
            match = re.search(r"^c\.pem: (good|revoked|unknown)", proc.stdout, re.M)
            if match:
                details = [l.strip() for l in proc.stdout.splitlines()[1:] if l.strip()]
                return match.group(1), details, authenticated and "Response verify OK" in proc.stderr
        last = (proc.stderr.strip().splitlines() or ["no response"])[-1] if proc else "no response"
        return None, [last], False


def _check_one(cert, issuer, when, ca_file, add) -> None:
    """Append OCSP/CRL results for one certificate through ``add(method, status, url=None, **extra)``."""
    ocsp_urls = _extension_urls(x509.AuthorityInformationAccess, cert, AuthorityInformationAccessOID.OCSP)
    crl_urls = _extension_urls(x509.CRLDistributionPoints, cert)
    if not ocsp_urls and not crl_urls:
        add("none", "no_reference", detail="the certificate names neither OCSP nor CRL")
        return
    if issuer is None:
        add("none", "issuer_not_found",
            detail="issuer certificate not found (not in the signature, in --ca or via AIA): cannot check")
        return
    now = datetime.now(timezone.utc)
    for url in ocsp_urls[:2]:
        if not netsafe.url_allowed(url):
            add("ocsp", "refused", url, detail="non-public host or scheme")
            continue
        status, details, authenticated = _ocsp_status(cert, issuer, url, ca_file)
        if status is None:
            add("ocsp", "unavailable", url, detail=details[0][:150])
            continue
        add("ocsp", status, url, response_authenticated=authenticated, detail="; ".join(details[:3]))
        break
    for url in crl_urls[:3]:
        if url not in _crl_cache:
            raw = netsafe.http_get(url)
            crl = None
            for load in (x509.load_der_x509_crl, x509.load_pem_x509_crl):
                try:
                    crl = load(raw) if raw else None
                    break
                except Exception:
                    pass
            _crl_cache[url] = crl
        crl = _crl_cache[url]
        if crl is None:
            add("crl", "unavailable", url, detail="not downloadable/readable")
            continue
        try:
            signature_ok = crl.is_signature_valid(issuer.public_key())
        except Exception:
            signature_ok = False
        entry = crl.get_revoked_certificate_by_serial_number(cert.serial_number)
        revoked_on = entry.revocation_date_utc if entry is not None else None
        add("crl", "revoked" if entry is not None else "not_revoked", url,
            signature_verified=signature_ok,
            expired=crl.next_update_utc is not None and crl.next_update_utc < now,
            next_update=crl.next_update_utc.isoformat() if crl.next_update_utc else None,
            revoked_on=revoked_on.isoformat() if revoked_on else None,
            revoked_relative_to_message=(None if revoked_on is None else "after" if revoked_on > when else "before"))
        break


def check_revocation(signer, certs, when, ca_file) -> List[dict]:
    """OCSP + CRL for every certificate from the signer up to (excluding) the self-signed root.

    Returns a flat list of results ``{"level", "subject", "method", "status", "url", ...}`` where ``level`` is
    ``"signer"``, ``"ca_1"``, ``"ca_2"``... or ``"root"``, ``method`` is ``ocsp``/``crl``/``none`` and ``status`` is
    ``good|revoked|unknown|not_revoked|unavailable|refused|no_reference|issuer_not_found|self_signed_root``.
    """
    candidates = list(certs)
    if ca_file:
        try:
            candidates += x509.load_pem_x509_certificates(Path(ca_file).read_bytes())
        except Exception:
            pass
    results: List[dict] = []
    current, level = signer, 0
    while level < 6:
        subject = current.subject.rfc4514_string()
        if current.issuer == current.subject:
            results.append({"level": "root", "subject": subject, "method": "none", "status": "self_signed_root",
                            "url": None})
            return results
        issuer = _find_issuer(current, candidates)
        label = "signer" if level == 0 else f"ca_{level}"

        def add(method, status, url=None, _label=label, _subject=subject, **extra):
            results.append({"level": _label, "subject": _subject, "method": method, "status": status,
                            "url": url, **extra})

        _check_one(current, issuer, when, ca_file, add)
        if issuer is None:
            return results
        current, level = issuer, level + 1
    results.append({"level": "ca_6", "subject": None, "method": "none", "status": "chain_too_long", "url": None})
    return results


def revocation_lines(results: Optional[List[dict]]) -> List[str]:
    if results is None:
        return ["revocation (CRL/OCSP): not checked (--no-revocation)"]
    lines = []
    for r in results:
        label = {"signer": "signer"}.get(r["level"], "CA level " + r["level"][3:] if r["level"].startswith("ca_") else "")
        tag = f"[{label + ': ' if label else ''}{(r['subject'] or '')[:60]}]"
        method, status, url = r["method"], r["status"], r["url"]
        if status == "self_signed_root":
            lines.append(f"{tag} self-signed root: no revocation to check")
        elif status == "chain_too_long":
            lines.append("revocation: chain longer than 6 levels, check stopped")
        elif method == "none":
            lines.append(f"{tag} revocation: {r['detail']}")
        elif method == "ocsp" and status in ("refused", "unavailable"):
            lines.append(f"{tag} revocation OCSP ({url}): "
                         + ("URL refused (non-public host or scheme)" if status == "refused"
                            else f"unavailable - {r['detail']}"))
        elif method == "ocsp":
            lines.append(f"{tag} revocation OCSP ({url}): {status.upper()}"
                         + ("" if r["response_authenticated"] else " (response signature NOT verified)")
                         + (" | " + r["detail"] if r["detail"] else ""))
        elif status == "unavailable":
            lines.append(f"{tag} revocation CRL ({url}): not downloadable/readable")
        else:
            if status == "revoked":
                relation = "AFTER" if r["revoked_relative_to_message"] == "after" else "BEFORE"
                verdict = f"REVOKED on {r['revoked_on'][:16].replace('T', ' ')} ({relation} the message date)"
            else:
                verdict = "not listed in the CRL (not revoked)"
            lines.append(f"{tag} revocation CRL ({url}): {verdict}; CRL signature "
                         f"{'verified' if r['signature_verified'] else 'NOT verified'}"
                         + (f"; CRL EXPIRED (nextUpdate {r['next_update'][:10]})" if r["expired"] else ""))
    return lines


# --- CMS helpers ------------------------------------------------------------------------------
def to_der(data: bytes) -> bytes:
    """``.p7m``/``.p7s`` files are often base64 or PEM instead of DER."""
    if data[:1] == b"\x30":
        return data
    text = data.strip()
    if text.startswith(b"-----BEGIN"):
        text = b"".join(l for l in text.splitlines() if not l.startswith(b"-----"))
    try:
        return base64.b64decode(text, validate=False)
    except Exception:
        return data


def trim_der(data: bytes) -> bytes:
    """Strip the zero padding after a DER structure (typical of the /Contents field of signed PDFs)."""
    if len(data) < 2 or data[1] == 0x80:        # indefinite-length BER: leave as is
        return data
    if data[1] < 0x80:
        total = 2 + data[1]
    else:
        count = data[1] & 0x7F
        total = 2 + count + int.from_bytes(data[2:2 + count], "big")
    return data[:total]


def cms_certificates(der: bytes):
    try:
        return pkcs7.load_der_pkcs7_certificates(der)
    except Exception:                    # BER: cryptography cannot read it, openssl can
        proc = subprocess.run([OPENSSL, "pkcs7", "-inform", "DER", "-print_certs"], input=der, capture_output=True)
        return x509.load_pem_x509_certificates(proc.stdout) if proc.returncode == 0 and proc.stdout else []


def cms_verify(signature_der: bytes, content: Optional[bytes] = None, save_to: Optional[str] = None):
    """Integrity of a CMS signature with openssl (``-noverify``: trust is evaluated separately).
    ``content=None``: enveloping signature (.p7m); otherwise a detached signature over ``content``."""
    with tempfile.TemporaryDirectory() as tmp:
        sig = os.path.join(tmp, "signature.der")
        Path(sig).write_bytes(signature_der)
        command = [OPENSSL, "cms", "-verify", "-inform", "DER", "-in", sig, "-binary", "-noverify",
                   "-out", save_to or os.devnull]
        if content is not None:
            data = os.path.join(tmp, "content.bin")
            Path(data).write_bytes(content)
            command += ["-content", data]
        proc = subprocess.run(command, capture_output=True, text=True)
    return proc.returncode == 0, (proc.stderr.strip() or "ok")


def signer_info(certs, when: datetime, ca_file, revocation: bool) -> dict:
    """Facts about the signing certificate: validity at the message date, trust chain, revocation."""
    signer = choose_signer(certs)
    not_before, not_after = signer.not_valid_before_utc, signer.not_valid_after_utc
    errors: List[str] = []
    chain = verify_chain(signer, certs, when, ca_file, errors)
    return {
        "signer": signer.subject.rfc4514_string(),
        "issuer": signer.issuer.rfc4514_string(),
        "certificate_sha1": signer.fingerprint(hashes.SHA1()).hex(),
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "valid_at_message_date": not_before <= when <= not_after,
        "chain": {"status": "not_checked" if chain is None else "verified" if chain else "not_verified",
                  "error": "; ".join(errors) or None},
        "revocation": check_revocation(signer, certs, when, ca_file) if revocation else None,
    }


def describe_signature(label, signature_der, content, date_header, ca_file, revocation, save_to=None) -> dict:
    ok, detail = cms_verify(signature_der, content, save_to)
    result = {"label": label, "integrity_ok": ok, "detail": detail}
    certs = cms_certificates(signature_der)
    if not certs:
        result["signer"] = None
        return result
    result.update(signer_info(certs, message_time(date_header), ca_file, revocation))
    return result


def _info_lines(info: dict) -> List[str]:
    if info.get("signer") is None:
        return ["no readable certificate in the signature"]
    validity = "VALID at the message date" if info["valid_at_message_date"] else "NOT valid at the message date"
    lines = [f"signer: {info['signer']}", f"issuer: {info['issuer']}",
             f"certificate validity: {info['not_before'][:10]} -> {info['not_after'][:10]} ({validity})"]
    if info["chain"]["error"]:
        lines.append(f"chain: {info['chain']['error']}")
    return lines


def _chain_line(info: dict) -> str:
    status = info["chain"]["status"]
    return "trust chain: " + {"not_checked": "NOT verified (no --ca)", "verified": "VERIFIED",
                              "not_verified": "NOT verified"}[status]


def signature_lines(sig: dict) -> List[str]:
    lines = [f"signature {sig['label']}: {'VALID (integrity)' if sig['integrity_ok'] else 'INVALID'} - {sig['detail']}"]
    if sig.get("signer") is None:
        return lines + ["  no readable certificate in the signature"]
    lines += ["  " + l for l in _info_lines(sig)]
    lines.append("  " + _chain_line(sig))
    lines += ["  " + l for l in revocation_lines(sig["revocation"])]
    if sig.get("extracted_to"):
        lines.append(f"  content extracted: {sig['extracted_to']}")
    if sig.get("covers_whole_file") is False:
        lines.append("  !! the signature does NOT cover the whole file: data was appended after signing "
                     "(incremental update)")
    return lines


# --- attachments ------------------------------------------------------------------------------
def safe_filename(name: str) -> str:
    """Attachment names come from the sender: never let them escape the output directory."""
    name = os.path.basename(name.replace("\\", "/")).strip().lstrip(".")
    name = re.sub(r"[^\w.\- ()\[\]]", "_", name)
    return name[:150] or "attachment"


def check_attachment_signatures(attachments: Dict[str, bytes], prefix, date_header, ca_file, out_dir,
                                revocation: bool) -> List[dict]:
    """``attachments``: ``{name: bytes}`` of the *original* message (not the PEC envelope parts).

    Returns one result per file/signature, each with ``name`` and ``type`` (``cades_enveloping``,
    ``cades_detached``, ``pades``, ``pdf``, ``xmldsig``) plus the fields of :func:`describe_signature`
    or a ``status`` explaining why nothing could be verified."""
    results: List[dict] = []
    for name, data in attachments.items():
        low = name.lower()
        if low.endswith(".p7m"):
            inner = safe_filename(name[:-4] or name + ".content")
            target = os.path.join(out_dir, prefix + "signed_" + inner)
            sig = describe_signature(f"{name} (CAdES, enveloping)", to_der(data), None, date_header, ca_file,
                                     revocation, save_to=target)
            sig.update(name=name, type="cades_enveloping",
                       extracted_to=os.path.basename(target) if sig["integrity_ok"] else None)
            results.append(sig)
        elif low.endswith(".p7s") and low != "smime.p7s":
            document = attachments.get(name[:-4])
            if document is None:
                results.append({"name": name, "type": "cades_detached", "document": name[:-4],
                                "status": "document_missing",
                                "label": f"{name} (CAdES, detached)",
                                "detail": f"detached, but the signed file ({name[:-4]}) is not among the attachments"})
            else:
                sig = describe_signature(f"{name} over {name[:-4]} (CAdES, detached)", to_der(data), document,
                                         date_header, ca_file, revocation)
                sig.update(name=name, type="cades_detached", document=name[:-4])
                results.append(sig)
        elif low.endswith(".pdf"):
            ranges = list(re.finditer(rb"/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]", data))
            if not ranges:
                results.append({"name": name, "type": "pdf", "signed": False, "label": name})
                continue
            for index, match in enumerate(ranges, 1):
                o1, l1, o2, l2 = (int(x) for x in match.groups())
                base = {"name": name, "type": "pades", "index": index, "of": len(ranges)}
                label = f"{name} #{index}/{len(ranges)} (PAdES)"
                if o1 != 0 or o2 + l2 > len(data) or o1 + l1 > o2:
                    results.append({**base, "label": label, "status": "unverifiable",
                                    "detail": "inconsistent /ByteRange"})
                    continue
                hex_blob = re.sub(rb"\s", b"", data[o1 + l1:o2]).strip(b"<>")
                try:
                    der = trim_der(bytes.fromhex(hex_blob.decode("ascii")))
                except ValueError:
                    results.append({**base, "label": label, "status": "unverifiable",
                                    "detail": "/Contents is not hexadecimal"})
                    continue
                sig = describe_signature(label, der, data[o1:o1 + l1] + data[o2:o2 + l2], date_header, ca_file,
                                         revocation)
                sig.update(base, covers_whole_file=(o2 + l2 == len(data)))
                results.append(sig)
        elif low.endswith(".xml") and b"Signature" in data and b"xmldsig" in data:
            results.append({"name": name, "type": "xmldsig", "status": "not_verified", "label": name,
                            "detail": "XMLDSig/XAdES present, verification NOT performed (unsupported)"})
    return results


def attachment_lines(results: List[dict]) -> List[str]:
    lines: List[str] = []
    for r in results:
        if "integrity_ok" in r:
            lines += signature_lines(r)
        elif r["type"] == "pdf":
            lines.append(f"signature {r['name']}: no digital signature in the PDF (it may only carry a graphical stamp)")
        else:
            lines.append(f"signature {r['label']}: {r['detail']}"
                         if r["type"] != "xmldsig" else f"signature {r['name']}: {r['detail']}")
    if not any(r["type"] != "pdf" for r in results):
        lines.append("original attachments: no digital signature found")
    return lines


# --- envelope ---------------------------------------------------------------------------------
def verify_envelope_signature(eml_path, p7s_der, date_header, ca_file=None, index_file=None, revocation=True) -> dict:
    """Check ``smime.p7s`` of a PEC envelope."""
    certs = pkcs7.load_der_pkcs7_certificates(p7s_der)
    info = signer_info(certs, message_time(date_header), ca_file, revocation)
    # DM 2/11/2005 sec. 6: the provider is identified by the SHA-1 of its certificate ("providerCertificateHash"
    # in the LDAP index of the providers, base o=postacert)
    index_match = None
    if index_file:
        index_match = info["certificate_sha1"] in Path(index_file).read_text(encoding="utf-8", errors="ignore").lower()
    proc = subprocess.run([OPENSSL, "smime", "-verify", "-in", eml_path, "-out", os.devnull, "-noverify"],
                          capture_output=True, text=True)
    return {"integrity_ok": proc.returncode == 0, "detail": proc.stderr.strip() or "ok",
            "provider_index_match": index_match, **info}


def envelope_lines(sig: dict) -> List[str]:
    lines = [f"S/MIME signature (integrity): {'VALID' if sig['integrity_ok'] else 'INVALID'} - {sig['detail']}",
             f"  certificate SHA-1 (providerCertificateHash): {sig['certificate_sha1']}"]
    if sig["provider_index_match"] is not None:
        lines.append("  listed in the provider index (--index): " + ("YES" if sig["provider_index_match"] else "NO"))
    lines += ["  " + l for l in _info_lines(sig)]
    lines += ["  " + l for l in revocation_lines(sig["revocation"]) if sig["revocation"] is not None]
    status = sig["chain"]["status"]
    lines.append("  trust chain: " + {"not_checked": "NOT verified (no --ca)", "verified": "VERIFIED against --ca",
                                       "not_verified": "NOT verified against --ca"}[status])
    return lines
