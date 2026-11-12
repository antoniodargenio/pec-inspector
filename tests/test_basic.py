import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from pec_inspector import cli, credentials, discovery, export, formats, netsafe, pki, threads   # noqa: E402

HAVE_OPENSSL = shutil.which("openssl") is not None
CRLF = bytes([13, 10])

AUTOCONFIG = b"""<?xml version="1.0"?>
<clientConfig><emailProvider id="example.test">
 <incomingServer type="pop3"><hostname>pop.example.test</hostname><port>995</port><socketType>SSL</socketType></incomingServer>
 <incomingServer type="imap"><hostname>imap-plain.example.test</hostname><port>143</port><socketType>plain</socketType></incomingServer>
 <incomingServer type="imap"><hostname>imap.%EMAILDOMAIN%</hostname><port>143</port><socketType>STARTTLS</socketType>
   <username>%EMAILLOCALPART%</username></incomingServer>
 <incomingServer type="imap"><hostname>imaps.example.test</hostname><port>993</port><socketType>SSL</socketType>
   <username>%EMAILADDRESS%</username></incomingServer>
</emailProvider></clientConfig>"""


class CredentialsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.file = os.path.join(self.tmp.name, "cred.tsv")
        with open(self.file, "w", encoding="utf-8") as fh:
            fh.write("Username\tPassword\n# comment\na@example.test\tpw-a\nb@example.test\tpw-b\timap.b.test\t1993\n")
        if os.name == "posix":
            os.chmod(self.file, 0o600)

    def tearDown(self):
        self.tmp.cleanup()

    def test_file_multiple_accounts_need_address(self):
        with self.assertRaises(credentials.CredentialsError):
            credentials.resolve_credentials(credentials_file=self.file, env={}, prompt=False)

    def test_file_selects_account_and_server(self):
        c = credentials.resolve_credentials("B@example.test", credentials_file=self.file, env={}, prompt=False)
        self.assertEqual((c.password, c.host, c.port), ("pw-b", "imap.b.test", 1993))

    def test_env_overrides_file_and_per_account_wins(self):
        env = {"PEC_PASSWORD": "generic", "PEC_PASSWORD_A_EXAMPLE_TEST": "specific"}
        a = credentials.resolve_credentials("a@example.test", credentials_file=self.file, env=env, prompt=False)
        b = credentials.resolve_credentials("b@example.test", credentials_file=self.file, env=env, prompt=False)
        self.assertEqual((a.password, b.password), ("specific", "generic"))

    def test_env_only_and_missing_password(self):
        c = credentials.resolve_credentials(env={"PEC_ADDRESS": "x@example.test", "PEC_PASSWORD": "p",
                                                 "PEC_IMAP_HOST": "h", "PEC_IMAP_PORT": "143",
                                                 "PEC_IMAP_SECURITY": "starttls"}, prompt=False)
        self.assertEqual((c.address, c.host, c.port, c.security), ("x@example.test", "h", 143, "starttls"))
        with self.assertRaises(credentials.CredentialsError):
            credentials.resolve_credentials(env={"PEC_ADDRESS": "x@example.test"}, prompt=False)

    def test_password_not_in_repr(self):
        c = credentials.Credentials("a@example.test", "a@example.test", "topsecret")
        self.assertNotIn("topsecret", repr(c))

    def test_account_variable(self):
        self.assertEqual(credentials.account_variable("PEC_PASSWORD", "user@example-pec.test"),
                         "PEC_PASSWORD_USER_EXAMPLE_PEC_TEST")


class DiscoveryTest(unittest.TestCase):
    def test_autoconfig_prefers_tls_and_skips_plain_and_pop(self):
        servers = discovery.parse_autoconfig(AUTOCONFIG, "me@example.test", "test")
        self.assertEqual([(s.host, s.port, s.security) for s in servers],
                         [("imaps.example.test", 993, "ssl"), ("imap.example.test", 143, "starttls")])
        self.assertEqual(servers[0].username, "me@example.test")
        self.assertEqual(servers[1].username, "me")

    def test_autoconfig_rejects_entities(self):
        evil = b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "b">]><clientConfig/>'
        self.assertEqual(discovery.parse_autoconfig(evil, "me@example.test", "t"), [])

    def test_parent_domains(self):
        self.assertEqual(discovery.parent_domains("mx1.mail.example.net"), ["mail.example.net", "example.net"])
        self.assertEqual(discovery.parent_domains("example.net"), [])

    def test_split_address(self):
        self.assertEqual(discovery.split_address("A@Example.TEST"), ("A", "example.test"))
        for bad in ("nope", "a@b@c.test", "@example.test", "a@localhost"):
            with self.assertRaises(ValueError):
                discovery.split_address(bad)


class NetsafeTest(unittest.TestCase):
    def test_private_and_bad_scheme_refused(self):
        netsafe.set_allow_private(False)
        for url in ("http://127.0.0.1/x", "http://localhost/x", "http://169.254.169.254/", "ftp://example.test/x",
                    "file:///etc/passwd"):
            self.assertFalse(netsafe.url_allowed(url), url)
            self.assertIsNone(netsafe.http_get(url))


class FormatsTest(unittest.TestCase):
    def test_daticert_checks(self):
        xml = (b'<postacert tipo="posta-certificata" errore="nessuno"><intestazione><mittente>a@x.test</mittente>'
               b'<destinatari tipo="certificato">b@y.test</destinatari><risposte>c@x.test</risposte>'
               b'<oggetto>s</oggetto></intestazione><dati><gestore-emittente>Provider</gestore-emittente>'
               b'<data zona="+0100"><giorno>01/01/2026</giorno><ora>10:00:00</ora></data>'
               b'<identificativo>id@x</identificativo><msgid>&lt;m&gt;</msgid></dati></postacert>')
        d = formats.read_daticert(xml)
        self.assertEqual(d["_issues"], [])
        self.assertEqual(d["recipients"], [("certificato", "b@y.test")])
        bad = formats.read_daticert(b'<postacert tipo="boh" errore="virus"><intestazione/><dati/></postacert>')
        self.assertTrue(any("unexpected type" in i for i in bad["_issues"]))

    def test_dtd_rejected(self):
        import xml.etree.ElementTree as ET
        with self.assertRaises(ET.ParseError):
            formats.read_daticert(b'<!DOCTYPE a [<!ENTITY e "x">]><postacert/>')


class PkiHelpersTest(unittest.TestCase):
    def test_safe_filename(self):
        self.assertEqual(pki.safe_filename("../../etc/passwd"), "passwd")
        self.assertEqual(pki.safe_filename("C:\\dir\\evil.exe"), "evil.exe")
        self.assertEqual(pki.safe_filename("..."), "attachment")

    def test_trim_der(self):
        der = b"\x30\x03\x02\x01\x05"
        self.assertEqual(pki.trim_der(der + b"\x00" * 10), der)


@unittest.skipUnless(HAVE_OPENSSL, "openssl not available")
class SignatureTest(unittest.TestCase):
    """Synthetic signatures made with a throw-away self-signed certificate."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        t = cls.tmp.name

        def sh(*cmd):
            subprocess.run(cmd, cwd=t, check=True, capture_output=True)

        sh("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "k.pem", "-out", "c.pem",
           "-subj", "/CN=Test Signer", "-days", "30")
        Path(t, "doc.txt").write_bytes(b"test content\n")
        sh("openssl", "cms", "-sign", "-in", "doc.txt", "-signer", "c.pem", "-inkey", "k.pem",
           "-outform", "DER", "-out", "doc.txt.p7m", "-nodetach", "-binary")
        sh("openssl", "cms", "-sign", "-in", "doc.txt", "-signer", "c.pem", "-inkey", "k.pem",
           "-outform", "DER", "-out", "doc.txt.p7s", "-binary")
        # synthetic PDF with a /ByteRange signature placeholder
        size = 6000
        head = b"%PDF-1.4\n1 0 obj\n<</Type/Sig/ByteRange [0 0000000000 0000000000 0000000000]/Contents <"
        tail = b">>\nendobj\ntrailer<<>>\n%%EOF\n"
        l1 = len(head)
        o2 = l1 + size
        l2 = len(tail)
        head = head.replace(b"0000000000 0000000000 0000000000", b"%010d %010d %010d" % (l1, o2, l2))
        covered = head + tail
        Path(t, "covered.bin").write_bytes(covered)
        sh("openssl", "cms", "-sign", "-in", "covered.bin", "-signer", "c.pem", "-inkey", "k.pem",
           "-outform", "DER", "-out", "pdf.der", "-binary")
        sig = Path(t, "pdf.der").read_bytes().hex().encode()
        cls.pdf = head + sig + b"0" * (size - len(sig)) + tail
        tampered = bytearray(cls.pdf)
        tampered[-20] ^= 0x01
        cls.pdf_tampered = bytes(tampered)
        cls.p7m = Path(t, "doc.txt.p7m").read_bytes()
        cls.p7s = Path(t, "doc.txt.p7s").read_bytes()

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def run_checks(self, attachments):
        out = tempfile.TemporaryDirectory()
        self.results = pki.check_attachment_signatures(attachments, "1_orig_", "Wed, 11 Nov 2026 16:09:24 +0100",
                                                       None, out.name, False)
        extracted = sorted(os.listdir(out.name))
        out.cleanup()
        return "\n".join(pki.attachment_lines(self.results)), extracted

    def test_enveloping_p7m_and_extraction(self):
        text, extracted = self.run_checks({"doc.txt.p7m": self.p7m})
        self.assertIn("VALID (integrity)", text)
        self.assertEqual(extracted, ["1_orig_signed_doc.txt"])

    def test_detached_p7s(self):
        text, _ = self.run_checks({"doc.txt": b"test content\n", "doc.txt.p7s": self.p7s})
        self.assertIn("VALID (integrity)", text)
        text, _ = self.run_checks({"doc.txt": b"altered content\n", "doc.txt.p7s": self.p7s})
        self.assertIn("INVALID", text)

    def test_pades_valid_and_tampered(self):
        text, _ = self.run_checks({"a.pdf": self.pdf})
        self.assertIn("VALID (integrity)", text)
        self.assertNotIn("INVALID", text)
        text, _ = self.run_checks({"a.pdf": self.pdf_tampered})
        self.assertIn("INVALID", text)

    def test_pdf_without_signature(self):
        text, _ = self.run_checks({"plain.pdf": b"%PDF-1.4\n%%EOF\n"})
        self.assertIn("no digital signature in the PDF", text)


class ExportTest(unittest.TestCase):
    def build(self, with_p7m=None):
        from email.message import EmailMessage
        inner = EmailMessage()
        inner["From"], inner["To"], inner["Subject"] = "a@example.test", "b@example.test", "Hello è world"
        inner.set_content("plain body è")
        inner.add_alternative("<html><body><p>html <b>body</b></p><script>x()</script></body></html>", subtype="html")
        inner.add_attachment(b"%PDF-1.4 data", maintype="application", subtype="pdf", filename="../../evil.pdf")
        inner.add_attachment(b"one", maintype="text", subtype="plain", filename="dup.txt")
        inner.add_attachment(b"two", maintype="text", subtype="plain", filename="dup.txt")
        if with_p7m:
            inner.add_attachment(with_p7m, maintype="application", subtype="pkcs7-mime", filename="doc.txt.p7m")
        outer = EmailMessage()
        outer["From"], outer["Subject"] = "posta-certificata@example.test", "POSTA CERTIFICATA: Hello"
        outer.set_content("PEC wrapper text")
        outer.add_attachment(inner, filename="postacert.eml")
        outer.add_attachment(b"<postacert/>", maintype="application", subtype="xml", filename="daticert.xml")
        outer.add_attachment(b"sig", maintype="application", subtype="pkcs7-signature", filename="smime.p7s")
        return outer

    def test_export_layout(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder, count = export.export_message("7", self.build(), tmp, raw=b"RAW")
            self.assertEqual(folder.parent, Path(tmp))
            self.assertEqual(count, 3)
            names = sorted(p.name for p in (folder / "attachments").iterdir())
            self.assertEqual(names, ["dup.txt", "dup_2.txt", "evil.pdf"])      # duplicates are renamed
            self.assertTrue((folder / "attachments" / "evil.pdf").exists())   # path traversal neutralised
            text = (folder / "message.txt").read_text(encoding="utf-8")
            self.assertIn("From: a@example.test", text)
            self.assertIn("plain body è", text)
            self.assertNotIn("PEC wrapper text", text)
            html = (folder / "message.html").read_text(encoding="utf-8")
            self.assertTrue(html.startswith("<meta http-equiv=\"Content-Security-Policy\""))
            pec = sorted(p.name for p in (folder / "pec").iterdir())
            self.assertEqual(pec, ["daticert.xml", "envelope.eml", "envelope.txt", "smime.p7s"])
            self.assertEqual(list(Path(tmp).glob("**/evil.pdf")), [folder / "attachments" / "evil.pdf"])

    def test_html_only_body_and_receipt(self):
        from email.message import EmailMessage
        receipt = EmailMessage()
        receipt["Subject"] = "ACCETTAZIONE: x"
        receipt.set_content("Receipt text")
        with tempfile.TemporaryDirectory() as tmp:
            folder, count = export.export_message("1", receipt, tmp)
            self.assertEqual(count, 0)
            self.assertIn("Receipt text", (folder / "message.txt").read_text(encoding="utf-8"))
        self.assertEqual(export.html_to_text("<p>a</p><script>x</script><div>b &amp; c</div>").split(), ["a", "b", "&", "c"])

    @unittest.skipUnless(HAVE_OPENSSL, "openssl not available")
    def test_p7m_content_extracted(self):
        with tempfile.TemporaryDirectory() as tmp:
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "k.pem", "-out", "c.pem",
                            "-subj", "/CN=T", "-days", "2"], cwd=tmp, check=True, capture_output=True)
            Path(tmp, "doc.txt").write_bytes(b"signed content\n")
            subprocess.run(["openssl", "cms", "-sign", "-in", "doc.txt", "-signer", "c.pem", "-inkey", "k.pem", "-outform",
                            "DER", "-out", "doc.txt.p7m", "-nodetach", "-binary"], cwd=tmp, check=True, capture_output=True)
            out = Path(tmp, "out")
            folder, _ = export.export_message("1", self.build(Path(tmp, "doc.txt.p7m").read_bytes()), out)
            self.assertEqual((folder / "attachments" / "doc.txt").read_bytes(), b"signed content\n")
            self.assertTrue((folder / "attachments" / "doc.txt.p7m").exists())


class OutputDirectoryTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.eml = os.path.join(self.tmp.name, "m.eml")
        Path(self.eml).write_bytes(b"\r\n".join([b"From: a@example.test", b"Subject: ANOMALIA MESSAGGIO: t",
                                                 b"X-Trasporto: errore", b"", b"body", b""]))
        self.old_tempdir, self.old_env = tempfile.tempdir, os.environ.pop("PEC_OUT_DIR", None)
        tempfile.tempdir = os.path.join(self.tmp.name, "systemtemp")
        os.mkdir(tempfile.tempdir)

    def tearDown(self):
        tempfile.tempdir = self.old_tempdir
        if self.old_env is not None:
            os.environ["PEC_OUT_DIR"] = self.old_env
        self.tmp.cleanup()

    def run_cli(self, *argv):
        import contextlib
        import io
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer), contextlib.redirect_stderr(io.StringIO()):
            code = cli.main(list(argv))
        return code, buffer.getvalue()

    def test_explicit_directory_is_used(self):
        target = os.path.join(self.tmp.name, "chosen", "sub")
        code, out = self.run_cli(target, "--eml", self.eml, "--no-revocation")
        self.assertEqual(code, 0)
        self.assertTrue(os.path.exists(os.path.join(target, "msg_file.eml")))
        self.assertIn("Download folder: " + str(Path(target).resolve()), out)
        self.assertEqual(os.listdir(tempfile.tempdir), [])

    def test_system_temp_is_used_when_omitted(self):
        code, out = self.run_cli("--eml", self.eml, "--no-revocation", "--export")
        self.assertEqual(code, 0)
        created = os.listdir(tempfile.tempdir)
        self.assertEqual(len(created), 1)
        self.assertTrue(created[0].startswith("pec-inspector-"))
        folder = os.path.join(tempfile.tempdir, created[0])
        self.assertTrue(os.path.exists(os.path.join(folder, "msg_file.eml")))
        self.assertTrue(os.path.isdir(os.path.join(folder, "export")))
        self.assertIn("Link: file://", out)

    def test_environment_variable_sets_the_root(self):
        target = os.path.join(self.tmp.name, "fromenv")
        os.environ["PEC_OUT_DIR"] = target
        try:
            self.run_cli("--eml", self.eml, "--no-revocation")
        finally:
            del os.environ["PEC_OUT_DIR"]
        self.assertTrue(os.path.exists(os.path.join(target, "msg_file.eml")))


def _report(num, date, role_kind, original_id, subject, sender, to="b@pec.test", receipt=None, refs=()):
    return {"id": num, "date": date, "subject": subject, "from": sender, "to": to, "kind": role_kind,
            "headers": {"x_ricevuta": receipt, "x_trasporto": None}, "rem": None, "daticert": None, "evidence": [],
            "original_message": None,
            "threading": threads.threading_info("<own%s@p>" % num, original_id, "", "", refs)}


class ThreadsTest(unittest.TestCase):
    def test_sent_receipts_and_reply_are_grouped(self):
        reports = [
            _report("1", "Mon, 02 Nov 2026 10:00:00 +0100", "not_certified", "<a@x>", "Richiesta", "me@pec.test"),
            _report("2", "Mon, 02 Nov 2026 10:00:05 +0100", "pec", "<a@x>", "ACCETTAZIONE: Richiesta",
                    "posta-certificata@p", receipt="accettazione"),
            _report("3", "Mon, 02 Nov 2026 10:01:00 +0100", "pec", "<a@x>", "CONSEGNA: Richiesta",
                    "posta-certificata@p", receipt="avvenuta-consegna"),
            _report("4", "Tue, 03 Nov 2026 09:00:00 +0100", "pec", "<b@x>", "Re: Richiesta", "Other <b@pec.test>",
                    to="me@pec.test", refs=["a@x"]),
            _report("5", "Tue, 03 Nov 2026 11:00:00 +0100", "pec", "<z@x>", "Altro", "c@pec.test", to="me@pec.test"),
        ]
        result = threads.build_threads(reports, "ME@pec.test")
        self.assertEqual([t["id"] for t in result], ["t1", "t2"])
        first, second = result
        self.assertEqual([m["id"] for m in first["messages"]], ["1", "2", "3", "4"])
        self.assertEqual([m["role"] for m in first["messages"]], ["sent", "receipt", "receipt", "received"])
        self.assertEqual(first["counts"], {"sent": 1, "received": 1, "receipts": 2, "other": 0})
        self.assertEqual(first["receipts"], ["accettazione", "avvenuta-consegna"])
        self.assertEqual(first["subject"], "Richiesta")
        self.assertEqual([m["id"] for m in second["messages"]], ["5"])
        self.assertIn("[t1] Richiesta", "\n".join(threads.thread_lines(result)))

    def test_without_address_role_is_unknown(self):
        result = threads.build_threads([_report("1", "Mon, 02 Nov 2026 10:00:00 +0100", "pec", "<a@x>", "S", "a@p")])
        self.assertEqual(result[0]["messages"][0]["role"], "message")


class JsonOutputTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.eml = os.path.join(self.tmp.name, "m.eml")
        Path(self.eml).write_bytes(CRLF.join([b"From: a@example.test", b"Subject: ANOMALIA MESSAGGIO: t",
                                              b"X-Trasporto: errore", b"", b"body", b""]))

    def tearDown(self):
        self.tmp.cleanup()

    def run_json(self, *argv):
        import contextlib
        import io
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def test_stdout_is_a_single_json_document(self):
        import json
        code, out, err = self.run_json(os.path.join(self.tmp.name, "o"), "--eml", self.eml, "--no-revocation",
                                       "--export", "--json")
        self.assertEqual(code, 0)
        doc = json.loads(out)                               # stdout holds nothing but the document
        self.assertEqual((doc["schema_version"], doc["tool"]), (1, "pec-inspector"))
        self.assertEqual(doc["mailbox"]["source"], "eml")
        self.assertEqual(doc["options"], {"ca_file": False, "revocation_checked": False})
        message, = doc["messages"]
        self.assertEqual(message["kind"], "anomaly")
        self.assertIsNone(message["envelope_signature"])
        self.assertTrue(any("ANOMALY ENVELOPE" in w for w in message["warnings"]))
        self.assertTrue(any("smime.p7s missing" in w for w in message["warnings"]))
        self.assertEqual(doc["summary"], {"messages": 1, "messages_with_warnings": 1, "invalid_signatures": 0})
        self.assertTrue(os.path.isdir(message["export"]["folder"]))
        self.assertIn("download folder", err)               # diagnostics stay on stderr

    def test_thread_option_adds_threads(self):
        import json
        code, out, _ = self.run_json(os.path.join(self.tmp.name, "o"), "--eml", self.eml, "--no-revocation",
                                     "--thread", "--json")
        self.assertEqual(code, 0)
        doc = json.loads(out)
        thread, = doc["threads"]
        self.assertEqual([m["id"] for m in thread["messages"]], ["file"])
        self.assertIn("threading", doc["messages"][0])

    @unittest.skipUnless(__import__("importlib.util").util.find_spec("reportlab"), "reportlab not installed")
    def test_thread_pdf_is_a4(self):
        import json
        code, out, _ = self.run_json(os.path.join(self.tmp.name, "o"), "--eml", self.eml, "--no-revocation",
                                     "--thread-pdf", "--json")
        self.assertEqual(code, 0)
        pdf = Path(json.loads(out)["threads"][0]["pdf"]).read_bytes()
        self.assertTrue(pdf.startswith(b"%PDF"))
        self.assertIn(b"595.27", pdf)                       # MediaBox of A4: 595.28 x 841.89 pt
        self.assertIn(b"841.88", pdf)

    def test_error_is_reported_as_json(self):
        import json
        old = {k: os.environ.pop(k, None) for k in ("PEC_ADDRESS", "PEC_PASSWORD", "PEC_CREDENTIALS_FILE")}
        try:
            code, out, err = self.run_json(os.path.join(self.tmp.name, "o"), "--json")
        finally:
            os.environ.update({k: v for k, v in old.items() if v is not None})
        self.assertEqual(code, 2)
        doc = json.loads(out)
        self.assertEqual(doc["error"]["code"], "credentials")
        self.assertIn("error:", err)

    def test_attachment_signatures_are_json_serialisable(self):
        import json
        if not HAVE_OPENSSL:
            self.skipTest("openssl not available")
        data = SignatureTest
        data.setUpClass()
        try:
            results = pki.check_attachment_signatures({"a.pdf": data.pdf, "doc.txt.p7m": data.p7m}, "1_", "Wed, 11 Nov 2026 16:09:24 +0100",
                                                      None, self.tmp.name, True)
        finally:
            data.tearDownClass()
        text = json.dumps(results)
        types = {r["type"] for r in json.loads(text)}
        self.assertEqual(types, {"pades", "cades_enveloping"})
        pades = next(r for r in results if r["type"] == "pades")
        self.assertTrue(pades["integrity_ok"] and pades["covers_whole_file"])
        self.assertEqual(pades["chain"]["status"], "not_checked")
        self.assertIsInstance(pades["revocation"], list)       # revocation requested: a list (self-signed: no OCSP/CRL)


if __name__ == "__main__":
    unittest.main()
