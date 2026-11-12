"""pec-inspector: read-only download and verification of Italian PEC / REM messages."""
try:
    from importlib.metadata import PackageNotFoundError, version as _version
    __version__ = _version("pec-inspector")      # set from the git tag at build time (setuptools-scm)
except Exception:                                # running from a source tree without installing
    __version__ = "0+unknown"
