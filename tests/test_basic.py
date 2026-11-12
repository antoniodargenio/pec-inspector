import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from pec_inspector import credentials, discovery, formats, netsafe, pki   # noqa: E402

HAVE_OPENSSL = shutil.which("openssl") is not None

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
        lines, out = [], tempfile.TemporaryDirectory()
        pki.check_attachment_signatures(attachments, "1_orig_", "Wed, 11 Nov 2026 16:09:24 +0100", None, out.name,
                                        False, lines.append)
        extracted = sorted(os.listdir(out.name))
        out.cleanup()
        return "\n".join(lines), extracted

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


if __name__ == "__main__":
    unittest.main()
