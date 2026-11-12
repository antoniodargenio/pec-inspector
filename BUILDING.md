# Building pec-inspector

pec-inspector is pure Python, so "building" means one of two things:

1. a **Python package** (wheel + source archive), installable with `pip` on any system;
2. optionally, a **standalone executable** (no Python needed on the target machine) made with PyInstaller.
   PyInstaller does not cross-compile: build the Linux executable on Linux and the Windows one on Windows.

For a plain installation you do not need to build anything: see [Install in the README](README.md#install)
(`scripts/install.sh` / `scripts/install.ps1`).

## Requirements

| | Linux | Windows |
|---|---|---|
| Python 3.9+ | `python3` (Debian/Ubuntu: `sudo apt install python3 python3-venv python3-pip`) | `winget install Python.Python.3.13` (the `py` launcher is installed with it) |
| `git` | `sudo apt install git` | `winget install Git.Git` |
| `openssl` CLI (needed at run time, and by the tests) | `sudo apt install openssl` | `winget install ShiningLight.OpenSSL.Light`, or the copy bundled with Git for Windows (`C:\Program Files\Git\usr\bin`) |

`git` matters for building: the package version is taken from the git tag (`vX.Y.Z`, see
[Versions and releases](README.md#versions-and-releases)) by `setuptools-scm`. In a clone, fetch the tags first,
otherwise the version comes out as `0.1.1.dev…` instead of the real one:

```sh
git clone https://github.com/antoniodargenio/pec-inspector.git
cd pec-inspector
git fetch --tags
```

A source archive without git metadata builds as version `0+unknown`.

## 1. Python package (wheel and sdist)

### Linux / macOS

```sh
python3 -m venv .venv && . .venv/bin/activate
python -m pip install --upgrade pip build
python -m build                       # creates dist/*.whl and dist/*.tar.gz
pip install dist/*.whl                # optional: install what you built
pec-inspector --version
```

### Windows (PowerShell)

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1          # if scripts are blocked: Set-ExecutionPolicy -Scope Process Bypass
python -m pip install --upgrade pip build
python -m build                       # creates dist\*.whl and dist\*.tar.gz
pip install (Get-ChildItem dist\*.whl).FullName
pec-inspector --version
```

The result is `dist/pec_inspector-<version>-py3-none-any.whl` plus the `.tar.gz`: one wheel works on every
platform. The extras (`dns`, `xsd`, `all`) are chosen at install time:
`pip install "pec_inspector-<version>-py3-none-any.whl[all]"`.

## 2. Standalone executable (PyInstaller)

Install the package with all extras and PyInstaller in a clean virtual environment, then build a single file.
`--copy-metadata` is needed so that `--version` reports the real version instead of `0+unknown`.

### Linux

```sh
python3 -m venv .venv && . .venv/bin/activate
pip install ".[all]" pyinstaller
printf 'import sys\nfrom pec_inspector.cli import main\nsys.exit(main())\n' > entry.py
pyinstaller --onefile --name pec-inspector \
    --collect-submodules pec_inspector --copy-metadata pec-inspector entry.py
./dist/pec-inspector --version        # the executable is dist/pec-inspector
```

### Windows (PowerShell)

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install ".[all]" pyinstaller
Set-Content entry.py "import sys`nfrom pec_inspector.cli import main`nsys.exit(main())"
pyinstaller --onefile --name pec-inspector `
    --collect-submodules pec_inspector --copy-metadata pec-inspector entry.py
.\dist\pec-inspector.exe --version    # the executable is dist\pec-inspector.exe
```

Notes:

* The executable still needs the **`openssl` command line tool** in `PATH` on the machine where it runs: it is
  an external program, not part of the bundle.
* Build on the oldest Linux distribution you want to support (the executable links against the build machine's
  glibc). The size is about 15-20 MB because the Python runtime and `cryptography` are bundled.
* Windows executables made with PyInstaller are sometimes flagged by antivirus software; sign the file or
  distribute the wheel instead if that is a problem.
* The commands above were checked on Windows 11 with Python 3.14 and PyInstaller; on Linux they are the same
  commands and are not run in this repository's CI.

The leftovers (`entry.py`, `build/`, `dist/`, `*.spec`) are git-ignored; delete them when you are done.

## 3. Run the tests

```sh
pip install -e ".[all]"
python -W error::ResourceWarning -m unittest discover -s tests -v      # Linux and Windows alike
```

CI runs the same command on Ubuntu, macOS and Windows (see [`.github/workflows/ci.yml`](.github/workflows/ci.yml)).
Releases (tag, wheel and sdist attached to a GitHub release) are produced automatically on every push to `main`
that contains releasable commits; you do not need to build or upload anything by hand.
