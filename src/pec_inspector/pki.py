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
"""
from __future__ import annotations

import base64
import os
import re
import subprocess
import tempfile
import warnings
from pathlib import Path
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Callable, Dict, List, Optional

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


def verify_chain(signer, certs, when, ca_file, lines) -> Optional[bool]:
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
        lines.append(f"chain: {exc}")
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


def _check_one(cert, issuer, when, ca_file, lines) -> None:
    ocsp_urls = _extension_urls(x509.AuthorityInformationAccess, cert, AuthorityInformationAccessOID.OCSP)
    crl_urls = _extension_urls(x509.CRLDistributionPoints, cert)
    if not ocsp_urls and not crl_urls:
        lines.append("revocation: the certificate names neither OCSP nor CRL")
        return
    if issuer is None:
        lines.append("revocation: issuer certificate not found (not in the signature, in --ca or via AIA): cannot check")
        return
    now = datetime.now(timezone.utc)
    for url in ocsp_urls[:2]:
        if not netsafe.url_allowed(url):
            lines.append(f"revocation OCSP ({url}): URL refused (non-public host or scheme)")
            continue
        status, details, authenticated = _ocsp_status(cert, issuer, url, ca_file)
        if status is None:
            lines.append(f"revocation OCSP ({url}): unavailable - {details[0][:150]}")
            continue
        lines.append(f"revocation OCSP ({url}): {status.upper()}"
                     + ("" if authenticated else " (response signature NOT verified)")
                     + (" | " + "; ".join(details[:3]) if details else ""))
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
            lines.append(f"revocation CRL ({url}): not downloadable/readable")
            continue
        try:
            signature_ok = crl.is_signature_valid(issuer.public_key())
        except Exception:
            signature_ok = False
        expired = crl.next_update_utc is not None and crl.next_update_utc < now
        entry = crl.get_revoked_certificate_by_serial_number(cert.serial_number)
        if entry is None:
            status = "not listed in the CRL (not revoked)"
        else:
            relation = "AFTER" if entry.revocation_date_utc > when else "BEFORE"
            status = f"REVOKED on {entry.revocation_date_utc:%Y-%m-%d %H:%M} ({relation} the message date)"
        lines.append(f"revocation CRL ({url}): {status}; CRL signature "
                     f"{'verified' if signature_ok else 'NOT verified'}"
                     + (f"; CRL EXPIRED (nextUpdate {crl.next_update_utc:%Y-%m-%d})" if expired else ""))
        break


def check_revocation(signer, certs, when, ca_file, lines) -> None:
    """OCSP + CRL for every certificate from the signer up to (excluding) the self-signed root."""
    candidates = list(certs)
    if ca_file:
        try:
            candidates += x509.load_pem_x509_certificates(Path(ca_file).read_bytes())
        except Exception:
            pass
    current, level = signer, 0
    while level < 6:
        if current.issuer == current.subject:
            lines.append(f"[{current.subject.rfc4514_string()[:60]}] self-signed root: no revocation to check")
            return
        issuer = _find_issuer(current, candidates)
        tmp: List[str] = []
        _check_one(current, issuer, when, ca_file, tmp)
        label = "signer" if level == 0 else f"CA level {level}"
        lines.extend(f"[{label}: {current.subject.rfc4514_string()[:60]}] {line}" for line in tmp)
        if issuer is None:
            return
        current, level = issuer, level + 1
    lines.append("revocation: chain longer than 6 levels, check stopped")


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


def describe_signature(label, signature_der, content, date_header, ca_file, revocation,
                       out: Callable[[str], None], save_to=None) -> bool:
    ok, result = cms_verify(signature_der, content, save_to)
    out(f"signature {label}: {'VALID (integrity)' if ok else 'INVALID'} - {result}")
    certs = cms_certificates(signature_der)
    if not certs:
        out("  no readable certificate in the signature")
        return ok
    signer = choose_signer(certs)
    when = message_time(date_header)
    nb, na = signer.not_valid_before_utc, signer.not_valid_after_utc
    lines = [f"signer: {signer.subject.rfc4514_string()}",
             f"issuer: {signer.issuer.rfc4514_string()}",
             f"certificate validity: {nb:%Y-%m-%d} -> {na:%Y-%m-%d} "
             f"({'VALID at the message date' if nb <= when <= na else 'NOT valid at the message date'})"]
    chain = verify_chain(signer, certs, when, ca_file, lines)
    lines.append("trust chain: " + ("NOT verified (no --ca)" if chain is None
                                    else "VERIFIED" if chain else "NOT verified"))
    if revocation:
        check_revocation(signer, certs, when, ca_file, lines)
    else:
        lines.append("revocation (CRL/OCSP): not checked (--no-revocation)")
    for line in lines:
        out("  " + line)
    return ok


def safe_filename(name: str) -> str:
    """Attachment names come from the sender: never let them escape the output directory."""
    name = os.path.basename(name.replace("\\", "/")).strip().lstrip(".")
    name = re.sub(r"[^\w.\- ()\[\]]", "_", name)
    return name[:150] or "attachment"


def check_attachment_signatures(attachments: Dict[str, bytes], prefix, date_header, ca_file, out_dir,
                                revocation, out: Callable[[str], None]) -> None:
    """``attachments``: ``{name: bytes}`` of the *original* message (not the PEC envelope parts)."""
    signed = 0
    for name, data in attachments.items():
        low = name.lower()
        if low.endswith(".p7m"):
            signed += 1
            inner = safe_filename(name[:-4] or name + ".content")
            target = os.path.join(out_dir, prefix + "signed_" + inner)
            ok = describe_signature(f"{name} (CAdES, enveloping)", to_der(data), None, date_header, ca_file,
                                    revocation, out, save_to=target)
            if ok:
                out(f"  content extracted: {os.path.basename(target)}")
        elif low.endswith(".p7s") and low != "smime.p7s":
            signed += 1
            document = attachments.get(name[:-4])
            if document is None:
                out(f"signature {name}: detached, but the signed file ({name[:-4]}) is not among the attachments")
            else:
                describe_signature(f"{name} over {name[:-4]} (CAdES, detached)", to_der(data), document,
                                   date_header, ca_file, revocation, out)
        elif low.endswith(".pdf"):
            ranges = list(re.finditer(rb"/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]", data))
            if not ranges:
                out(f"signature {name}: no digital signature in the PDF (it may only carry a graphical stamp)")
                continue
            for index, match in enumerate(ranges, 1):
                o1, l1, o2, l2 = (int(x) for x in match.groups())
                signed += 1
                if o1 != 0 or o2 + l2 > len(data) or o1 + l1 > o2:
                    out(f"signature {name} #{index}: inconsistent /ByteRange, cannot verify")
                    continue
                hex_blob = re.sub(rb"\s", b"", data[o1 + l1:o2]).strip(b"<>")
                try:
                    der = trim_der(bytes.fromhex(hex_blob.decode("ascii")))
                except ValueError:
                    out(f"signature {name} #{index}: /Contents is not hexadecimal, cannot verify")
                    continue
                describe_signature(f"{name} #{index}/{len(ranges)} (PAdES)", der, data[o1:o1 + l1] + data[o2:o2 + l2],
                                   date_header, ca_file, revocation, out)
                if o2 + l2 != len(data):
                    out("  !! the signature does NOT cover the whole file: data was appended after signing "
                        "(incremental update)")
        elif low.endswith(".xml") and b"Signature" in data and b"xmldsig" in data:
            signed += 1
            out(f"signature {name}: XMLDSig/XAdES present, verification NOT performed (unsupported)")
    if not signed:
        out("original attachments: no digital signature found")


def verify_envelope_signature(eml_path, p7s_der, date_header, ca_file=None, index_file=None, revocation=True):
    """Check ``smime.p7s`` of a PEC envelope.  Returns ``(integrity_ok, message, chain_ok | None, lines)``."""
    lines: List[str] = []
    certs = pkcs7.load_der_pkcs7_certificates(p7s_der)
    signer = choose_signer(certs)
    # DM 2/11/2005 sec. 6: the provider is identified by the SHA-1 of its certificate ("providerCertificateHash"
    # in the LDAP index of the providers, base o=postacert)
    sha1 = signer.fingerprint(hashes.SHA1()).hex()
    lines.append(f"certificate SHA-1 (providerCertificateHash): {sha1}")
    if index_file:
        text = Path(index_file).read_text(encoding="utf-8", errors="ignore").lower()
        lines.append("listed in the provider index (--index): " + ("YES" if sha1 in text else "NO"))
    lines.append(f"signer: {signer.subject.rfc4514_string()}")
    lines.append(f"issuer: {signer.issuer.rfc4514_string()}")
    when = message_time(date_header)
    nb, na = signer.not_valid_before_utc, signer.not_valid_after_utc
    lines.append(f"certificate validity: {nb:%Y-%m-%d} -> {na:%Y-%m-%d} "
                 f"({'VALID at the message date' if nb <= when <= na else 'NOT valid at the message date'})")
    chain = verify_chain(signer, certs, when, ca_file, lines)
    if revocation:
        check_revocation(signer, certs, when, ca_file, lines)
    proc = subprocess.run([OPENSSL, "smime", "-verify", "-in", eml_path, "-out", os.devnull, "-noverify"],
                          capture_output=True, text=True)
    return proc.returncode == 0, (proc.stderr.strip() or "ok"), chain, lines
