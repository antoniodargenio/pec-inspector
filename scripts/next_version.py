#!/usr/bin/env python3
"""Compute the next release version from the commit messages since the last ``vX.Y.Z`` tag.

Conventional Commits drive the bump:

* ``type!: ...`` or a ``BREAKING CHANGE:`` footer  -> major (minor while the major version is still 0)
* ``feat: ...``                                    -> minor
* ``fix:``, ``perf:``, ``refactor:`` or any other message that is not listed below -> patch
* only ``docs:``, ``chore:``, ``ci:``, ``test:``, ``style:``, ``build:`` commits -> no release

With no previous tag the first release is ``0.1.0``.  Prints the new version (without the ``v``) on stdout,
or nothing when there is nothing to release.  Uses only the standard library and ``git``.

    python scripts/next_version.py            # print the next version, if any
    python scripts/next_version.py --explain  # also say why, on stderr
"""
from __future__ import annotations

import re
import subprocess
import sys
from typing import List, Optional, Tuple

NO_RELEASE_TYPES = {"docs", "chore", "ci", "test", "tests", "style", "build"}
TAG_RE = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")
SUBJECT_RE = re.compile(r"^(?P<type>[A-Za-z]+)(\((?P<scope>[^)]*)\))?(?P<bang>!)?:\s")


def classify(message: str) -> str:
    """``major`` | ``minor`` | ``patch`` | ``none`` for one commit message (subject + body)."""
    subject = message.strip().splitlines()[0] if message.strip() else ""
    match = SUBJECT_RE.match(subject)
    ctype = match.group("type").lower() if match else ""
    if (match and match.group("bang")) or re.search(r"^BREAKING[ -]CHANGE:", message, re.M):
        return "major"
    if ctype == "feat":
        return "minor"
    if ctype in NO_RELEASE_TYPES:
        return "none"
    return "patch"


def bump(last: Optional[Tuple[int, int, int]], messages: List[str]) -> Optional[str]:
    """Next version string for ``messages`` since ``last`` (``None`` = no tag yet); ``None`` = no release."""
    if last is None:
        return "0.1.0" if messages else None
    levels = {classify(m) for m in messages}
    major, minor, patch = last
    if "major" in levels:
        return f"{major}.{minor + 1}.0" if major == 0 else f"{major + 1}.0.0"
    if "minor" in levels:
        return f"{major}.{minor + 1}.0"
    if "patch" in levels:
        return f"{major}.{minor}.{patch + 1}"
    return None


def _git(*args: str) -> str:
    return subprocess.run(["git", *args], capture_output=True, text=True, check=True).stdout


def last_tag() -> Optional[Tuple[str, Tuple[int, int, int]]]:
    tags = [t for t in _git("tag", "--merged", "HEAD").split() if TAG_RE.match(t)]
    if not tags:
        return None
    best = max(tags, key=lambda t: tuple(int(x) for x in TAG_RE.match(t).groups()))
    return best, tuple(int(x) for x in TAG_RE.match(best).groups())


def commits_since(tag: Optional[str]) -> List[str]:
    rev = f"{tag}..HEAD" if tag else "HEAD"
    raw = _git("log", rev, "--format=%B%x00")
    return [m.strip() for m in raw.split("\x00") if m.strip()]


def main(argv: List[str]) -> int:
    found = last_tag()
    tag, numbers = (found if found else (None, None))
    messages = commits_since(tag)
    version = bump(numbers, messages)
    if "--explain" in argv:
        print(f"last tag: {tag or '(none)'}; {len(messages)} commit(s) since; "
              f"next version: {version or '(no release)'}", file=sys.stderr)
    if version:
        print(version)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
