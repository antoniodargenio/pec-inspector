#!/usr/bin/env bash
# Install pec-inspector and every Python dependency it needs (Linux / macOS / Git Bash / WSL).
#
#   scripts/install.sh                      # venv in ./.venv, extras: all (cryptography, dnspython, lxml, reportlab)
#   scripts/install.sh --extras core        # only the required dependency (cryptography)
#   scripts/install.sh --venv ~/pec-venv    # another virtual environment directory
#   scripts/install.sh --no-venv            # install into the current Python environment
#   scripts/install.sh --editable           # development install (pip install -e)
#   scripts/install.sh --python python3.12  # choose the interpreter
#
# Idempotent: an existing virtual environment is reused and packages that are already installed are left alone.
# The script never uses sudo and never installs system packages; it only tells you what is missing (openssl).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXTRAS="all"
VENV="$ROOT/.venv"
USE_VENV=1
EDITABLE=0
PYTHON_BIN=""

usage() { sed -n '2,12p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }
die() { echo "error: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --extras)   EXTRAS="${2:-}"; shift 2 ;;
    --venv)     VENV="${2:-}"; shift 2 ;;
    --no-venv)  USE_VENV=0; shift ;;
    --editable) EDITABLE=1; shift ;;
    --python)   PYTHON_BIN="${2:-}"; shift 2 ;;
    -h|--help)  usage; exit 0 ;;
    *) die "unknown option: $1 (try --help)" ;;
  esac
done
case "$EXTRAS" in core|dns|xsd|pdf|all) ;; *) die "--extras must be one of: core, dns, xsd, pdf, all" ;; esac

# 1. a Python >= 3.9
find_python() {
  local candidate
  for candidate in ${PYTHON_BIN:+"$PYTHON_BIN"} python3 python; do
    if command -v "$candidate" >/dev/null 2>&1 \
       && "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' 2>/dev/null; then
      command -v "$candidate"; return 0
    fi
  done
  return 1
}
BASE_PY="$(find_python)" || die "Python 3.9 or newer not found (install it from your package manager or python.org, or pass --python)"
echo "Python: $BASE_PY ($("$BASE_PY" -c 'import sys; print(sys.version.split()[0])'))"

# 2. virtual environment (unless --no-venv)
if [ "$USE_VENV" -eq 1 ]; then
  if [ ! -x "$VENV/bin/python" ] && [ ! -x "$VENV/Scripts/python.exe" ]; then
    echo "Creating virtual environment: $VENV"
    "$BASE_PY" -m venv "$VENV" || die "cannot create the virtual environment (on Debian/Ubuntu: apt install python3-venv)"
  else
    echo "Reusing virtual environment: $VENV"
  fi
  if [ -x "$VENV/bin/python" ]; then PY="$VENV/bin/python"; else PY="$VENV/Scripts/python.exe"; fi
else
  PY="$BASE_PY"
fi

# 3. packages
"$PY" -m pip install --quiet --upgrade pip
# Git Bash/MSYS passes POSIX-style paths (/c/...) that a native Windows Python cannot read: convert them
ROOT_FOR_PIP="$(cygpath -m "$ROOT" 2>/dev/null || echo "$ROOT")"
TARGET="$ROOT_FOR_PIP"
[ "$EXTRAS" = "core" ] || TARGET="$ROOT_FOR_PIP[$EXTRAS]"
if [ "$EDITABLE" -eq 1 ]; then
  echo "Installing (editable): $TARGET"
  "$PY" -m pip install --quiet -e "$TARGET"
else
  echo "Installing: $TARGET"
  "$PY" -m pip install --quiet "$TARGET"
fi

# 4. verify the Python side
"$PY" - <<'EOF'
import importlib.util
for module, role in (("cryptography", "required"), ("dns", "optional: SRV/MX IMAP discovery"),
                     ("lxml", "optional: XSD validation of REM evidence"),
                     ("reportlab", "optional: --thread-pdf")):
    state = "ok" if importlib.util.find_spec(module) else "not installed"
    print(f"  {module:<13} {state:<14} ({role})")
EOF

# 5. the openssl command line tool is not a Python package: check it and explain how to get it
if command -v openssl >/dev/null 2>&1; then
  echo "  openssl       ok             ($(openssl version))"
else
  echo "  openssl       NOT FOUND      (required for CMS/S-MIME/OCSP checks)" >&2
  case "$(uname -s 2>/dev/null)" in
    Darwin) echo "    install it with: brew install openssl" >&2 ;;
    Linux)  echo "    install it with: sudo apt install openssl   (or dnf/pacman/apk equivalents)" >&2 ;;
    *)      echo "    install OpenSSL and make sure 'openssl' is on PATH (Windows: winget install ShiningLight.OpenSSL.Light)" >&2 ;;
  esac
fi

echo
"$PY" -m pec_inspector --version
if [ "$USE_VENV" -eq 1 ]; then
  if [ -x "$VENV/bin/activate" ] || [ -f "$VENV/bin/activate" ]; then ACT=". \"$VENV/bin/activate\""; else ACT="\"$VENV/Scripts/activate\""; fi
  echo "Done. Activate the environment with:  $ACT   then run: pec-inspector --help"
else
  echo "Done. Run: pec-inspector --help"
fi
