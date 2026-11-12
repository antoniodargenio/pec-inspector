<#
.SYNOPSIS
  Install pec-inspector and every Python dependency it needs (Windows PowerShell 5.1+ / PowerShell 7+).

.DESCRIPTION
  Creates (or reuses) a virtual environment, installs the package with the chosen extras and checks the
  tools it relies on. Idempotent: an existing virtual environment is reused and packages that are already
  installed are left alone. It never installs system software; it only tells you what is missing (openssl).

.PARAMETER Extras
  core = only cryptography (required); dns = + dnspython (SRV/MX IMAP discovery); xsd = + lxml
  (XSD validation of REM evidence); all = everything (default).

.PARAMETER VenvDir
  Virtual environment directory (default: .venv in the repository).

.PARAMETER NoVenv
  Install into the current Python environment instead of a virtual environment.

.PARAMETER Editable
  Development install (pip install -e).

.PARAMETER Python
  Interpreter to use (default: py -3, python3 or python, the first one that is 3.9+).

.EXAMPLE
  .\scripts\install.ps1
  .\scripts\install.ps1 -Extras core
  .\scripts\install.ps1 -VenvDir C:\tools\pec-venv -Editable
#>
[CmdletBinding()]
param(
    [ValidateSet('core', 'dns', 'xsd', 'all')][string]$Extras = 'all',
    [string]$VenvDir,
    [switch]$NoVenv,
    [switch]$Editable,
    [string]$Python
)
$ErrorActionPreference = 'Stop'

$Root = Split-Path -Parent $PSScriptRoot
if (-not $VenvDir) { $VenvDir = Join-Path $Root '.venv' }

function Test-Python([string[]]$Command) {
    try {
        $rest = @($Command[1..($Command.Length)] | Where-Object { $_ })
        & $Command[0] @rest -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' 2>$null
        return ($LASTEXITCODE -eq 0)
    } catch { return $false }
}

# 1. a Python >= 3.9
$candidates = @()
if ($Python) { $candidates += , @($Python) }
$candidates += , @('py', '-3')
$candidates += , @('python3')
$candidates += , @('python')
$base = $null
foreach ($candidate in $candidates) {
    if ((Get-Command $candidate[0] -ErrorAction SilentlyContinue) -and (Test-Python $candidate)) { $base = $candidate; break }
}
if (-not $base) { throw 'Python 3.9 or newer not found: install it from python.org or "winget install Python.Python.3.13", or pass -Python.' }
$baseArgs = @($base[1..($base.Length)] | Where-Object { $_ })
$baseVersion = (& $base[0] @baseArgs -c 'import sys; print(sys.version.split()[0])')
Write-Host "Python: $($base -join ' ') ($baseVersion)"

# 2. virtual environment (unless -NoVenv)
if ($NoVenv) {
    $py = $base[0]; $pyArgs = $baseArgs
} else {
    $venvPython = Join-Path $VenvDir 'Scripts\python.exe'
    if (-not (Test-Path $venvPython)) {
        Write-Host "Creating virtual environment: $VenvDir"
        & $base[0] @baseArgs -m venv $VenvDir
        if ($LASTEXITCODE -ne 0) { throw 'cannot create the virtual environment' }
    } else {
        Write-Host "Reusing virtual environment: $VenvDir"
    }
    $py = $venvPython; $pyArgs = @()
}

# 3. packages
& $py @pyArgs -m pip install --quiet --upgrade pip
$target = if ($Extras -eq 'core') { $Root } else { "$Root[$Extras]" }
if ($Editable) {
    Write-Host "Installing (editable): $target"
    & $py @pyArgs -m pip install --quiet -e $target
} else {
    Write-Host "Installing: $target"
    & $py @pyArgs -m pip install --quiet $target
}
if ($LASTEXITCODE -ne 0) { throw 'pip install failed' }

# 4. verify the Python side
$check = @'
import importlib.util
for module, role in (("cryptography", "required"), ("dns", "optional: SRV/MX IMAP discovery"),
                     ("lxml", "optional: XSD validation of REM evidence")):
    state = "ok" if importlib.util.find_spec(module) else "not installed"
    print(f"  {module:<13} {state:<14} ({role})")
'@
& $py @pyArgs -c $check

# 5. the openssl command line tool is not a Python package: check it and explain how to get it
$openssl = Get-Command openssl -ErrorAction SilentlyContinue
if (-not $openssl) {   # the usual Windows locations, which are often not on PATH
    foreach ($dir in 'C:\Program Files\OpenSSL-Win64\bin', 'C:\Program Files\OpenSSL\bin', 'C:\Program Files\Git\usr\bin', 'C:\Program Files\Git\mingw64\bin') {
        $exe = Join-Path $dir 'openssl.exe'
        if (Test-Path $exe) { $openssl = Get-Item $exe; $foundOffPath = $dir; break }
    }
}
if ($openssl) {
    $where = if ($openssl.Source) { $openssl.Source } else { $openssl.FullName }
    Write-Host "  openssl       ok             ($(& $where version))"
    if ($foundOffPath) { Write-Warning "openssl is not on PATH: add '$foundOffPath' to PATH, or pec-inspector will not find it." }
} else {
    Write-Warning 'openssl NOT FOUND (required for CMS/S-MIME/OCSP checks). Install it with: winget install ShiningLight.OpenSSL.Light  (then reopen the terminal so PATH is refreshed)'
}

Write-Host ''
& $py @pyArgs -m pec_inspector --version
if ($NoVenv) { Write-Host 'Done. Run: pec-inspector --help' }
else { Write-Host "Done. Activate the environment with:  & '$(Join-Path $VenvDir 'Scripts\Activate.ps1')'   then run: pec-inspector --help" }
