import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import next_version as nv   # noqa: E402


class ClassifyTest(unittest.TestCase):
    def test_types(self):
        self.assertEqual(nv.classify("feat: add thing"), "minor")
        self.assertEqual(nv.classify("feat(cli): add thing"), "minor")
        self.assertEqual(nv.classify("fix: repair"), "patch")
        self.assertEqual(nv.classify("perf: faster"), "patch")
        self.assertEqual(nv.classify("Add a --json flag"), "patch")          # not conventional: patch
        for t in ("docs", "chore", "ci", "test", "style", "build"):
            self.assertEqual(nv.classify(f"{t}: something"), "none", t)

    def test_breaking(self):
        self.assertEqual(nv.classify("feat!: drop option"), "major")
        self.assertEqual(nv.classify("refactor(api)!: rename"), "major")
        self.assertEqual(nv.classify("fix: x\n\nBREAKING CHANGE: output changed"), "major")
        self.assertEqual(nv.classify("chore: x\n\nBREAKING-CHANGE: y"), "major")


class BumpTest(unittest.TestCase):
    def test_first_release(self):
        self.assertEqual(nv.bump(None, ["anything"]), "0.1.0")
        self.assertIsNone(nv.bump(None, []))

    def test_levels(self):
        self.assertEqual(nv.bump((1, 2, 3), ["fix: a"]), "1.2.4")
        self.assertEqual(nv.bump((1, 2, 3), ["fix: a", "feat: b"]), "1.3.0")
        self.assertEqual(nv.bump((1, 2, 3), ["fix: a", "feat!: b"]), "2.0.0")

    def test_major_zero_breaking_bumps_minor(self):
        self.assertEqual(nv.bump((0, 4, 2), ["feat!: b"]), "0.5.0")

    def test_nothing_to_release(self):
        self.assertIsNone(nv.bump((1, 0, 0), []))
        self.assertIsNone(nv.bump((1, 0, 0), ["docs: readme", "ci: workflow", "chore: deps"]))
        self.assertEqual(nv.bump((1, 0, 0), ["docs: readme", "fix: bug"]), "1.0.1")


if __name__ == "__main__":
    unittest.main()
