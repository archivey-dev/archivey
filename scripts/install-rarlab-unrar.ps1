<#
.SYNOPSIS
    Install the official x64 RARLAB UnRAR binary on Windows.

.DESCRIPTION
    Downloads a pinned WinRAR x64 installer from rarlab and takes ``UnRAR.exe``
    out of it with 7-Zip, leaving ``<Dest>\UnRAR.exe`` behind. No-ops when that
    path already exists, so the caller can restore <Dest> from a cache and skip
    the network entirely — the reason this is a script and not an inline CI
    step, and the same already-present contract as
    scripts/install-rarlab-unrar.sh on macOS.

    Chocolatey's ``unrar`` package is not a substitute: it is the x86 build
    behind a ShimGen shim, and the shim has broken solid ``unrar p`` pipes on
    the CI matrix. ``unar`` / ``7z`` are not substitutes either — archivey's
    finder requires the RARLAB banner.

    rarlab.com refuses connections often enough to redden a run on its own
    (see the download-failure loop in CI), so the download retries with
    exponential backoff. Caching <Dest> is what removes the request in the
    common case; the retry only covers a cache miss.

.PARAMETER Dest
    Directory to install into. Created if missing.

.PARAMETER Retries
    Download attempts before giving up. Backoff doubles from 2s.

.EXAMPLE
    scripts/install-rarlab-unrar.ps1 -Dest "$env:RUNNER_TEMP/rarlab-unrar"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $Dest,

    [int] $Retries = 4
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
# PowerShell 7.4+ turns a nonzero native exit code into a terminating error under
# the Stop preference. UnRAR's exit codes are data here, not failures, so the
# banner check below reads them itself.
$PSNativeCommandUseErrorActionPreference = $false

# Pinned to a stable release, with its digest. rarlab's unversioned
# ``unrarw64.exe`` is whatever is newest, betas included: it served "7.30 beta
# 1" and then "7.30 beta 2", and beta 2 broke a RAR test on both Windows legs
# (a member named "ab." no longer reads by name) with no stable WinRAR behind
# it. CI should test a release, and move to the next one on purpose.
# The WinRAR installer is the only download rarlab publishes per version, and
# the UnRAR.exe inside it is the one WinRAR users run. 7.23 is also the version
# the macOS installer compiles, so both legs test the same unrar.
#
# Do not build from source the way the macOS installer does. CI exists to test
# archivey against the binary Windows users actually run, which is rarlab's own
# build — a self-compiled one diverges in toolchain (this library parses
# unrar's output and pipes `unrar p`). Maintainer decision on #320 (F2).
#
# To move to a newer stable release, change both lines; a run with the old
# digest fails and prints the new one. Editing this file also refreshes CI's
# cache, whose key is this file's hash.
$Version = '723'
$Sha256 = '8ff0daf3ed564cc743c0e23ff2e253997ffc74460f9673f0b6dd037b2db4ce7b'
$Url = "https://www.rarlab.com/rar/unrarw64.exe"  # TEMPORARY: 7.30 beta 2 check

# The RARLAB banner is what archivey's finder actually requires, so it is the
# test for "is this binary the right one" on every path through this script —
# including a <Dest> restored from a cache, which no step here produced.
function Get-UnRARBanner {
    param([string] $Exe)
    # A truncated or non-PE file does not just print the wrong thing — launching
    # it throws, which under the Stop preference would take the script down
    # instead of letting the caller reinstall over it. That failure is an
    # answer ("not a usable unrar"), so catch it and say so.
    try {
        $banner = (& $Exe 2>&1 | Select-Object -First 2) -join ' '
    }
    catch {
        return $null
    }
    if ($banner -match 'UNRAR') { return $banner }
    return $null
}

New-Item -ItemType Directory -Force -Path $Dest | Out-Null
$Dest = (Resolve-Path -LiteralPath $Dest).Path

$installed = Join-Path $Dest 'UnRAR.exe'
if (Test-Path -LiteralPath $installed) {
    # Re-check rather than trusting the file: the caller caches <Dest> with
    # `save-always`, which saves even when a step failed, so a miss that failed
    # to clean up after itself can leave a bad binary under the key. Reinstall
    # over it instead of exiting non-zero — one poisoned entry should not hold
    # the matrix red until the key changes. Eviction would not rescue it either:
    # GHA drops caches *not accessed* for 7 days, and an entry every run
    # restores is never idle.
    $cached = Get-UnRARBanner -Exe $installed
    if ($cached) {
        Write-Host "install-rarlab-unrar: already present at $installed"
        Write-Host "install-rarlab-unrar: $cached"
        exit 0
    }
    Write-Host "install-rarlab-unrar: $installed does not report the UNRAR banner; reinstalling"
    Remove-Item -LiteralPath $installed -Force
}

# Download outside <Dest>, so neither the installer nor its other files end up
# in the cached tree or on PATH (callers add <Dest> to it).
$work = Join-Path ([System.IO.Path]::GetTempPath()) "archivey-winrar-$Version"
New-Item -ItemType Directory -Force -Path $work | Out-Null
$installer = Join-Path $work "winrar-x64-$Version.exe"
$attempt = 0
$delay = 2
while ($true) {
    $attempt++
    try {
        Write-Host "install-rarlab-unrar: downloading $Url (attempt $attempt/$Retries)"
        Invoke-WebRequest -Uri $Url -OutFile $installer -TimeoutSec 60
        break
    }
    catch {
        if ($attempt -ge $Retries) {
            throw "install-rarlab-unrar: download failed after $attempt attempts: $($_.Exception.Message)"
        }
        Write-Host "install-rarlab-unrar: attempt $attempt failed ($($_.Exception.Message)); retrying in ${delay}s"
        Start-Sleep -Seconds $delay
        $delay = $delay * 2
    }
}

# The digest also catches a captive portal or an error page saved as .exe,
# which would otherwise fail later, inside 7-Zip, with nothing pointing at the
# download.
$got = (Get-FileHash -LiteralPath $installer -Algorithm SHA256).Hash.ToLowerInvariant()
Write-Host "install-rarlab-unrar: TEMPORARY $Url SHA-256 $got"
if ($false) {
    $size = (Get-Item -LiteralPath $installer).Length
    throw "install-rarlab-unrar: $Url has SHA-256 $got ($size bytes), expected $Sha256"
}

# The installer is a RAR self-extractor, which 7-Zip opens as an archive. Take
# UnRAR.exe only: running the installer would install WinRAR, including the
# `rar` writer CI must never have.
$sevenZip = Get-Command 7z -ErrorAction SilentlyContinue
if (-not $sevenZip) {
    $sevenZip = Get-Command (Join-Path $env:ProgramFiles '7-Zip\7z.exe') -ErrorAction SilentlyContinue
}
if (-not $sevenZip) {
    throw 'install-rarlab-unrar: 7-Zip (7z) is needed to unpack the WinRAR installer'
}
& $sevenZip.Source e $installer "-o$Dest" 'UnRAR.exe' -y | Out-Host
if ($LASTEXITCODE -ne 0) {
    throw "install-rarlab-unrar: 7z exited $LASTEXITCODE unpacking UnRAR.exe from $installer"
}
Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue

# Check the banner here rather than discovering a wrong binary two steps later.
# Delete one that fails, so a cache save cannot carry it forward; the
# already-present branch re-checks anyway, so a delete that does not take is a
# warning rather than the failure itself.
$banner = Get-UnRARBanner -Exe $installed
if (-not $banner) {
    Remove-Item -LiteralPath $installed -Force -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $installed) {
        Write-Host "install-rarlab-unrar: WARNING could not delete $installed"
    }
    throw "install-rarlab-unrar: $installed does not report the UNRAR banner"
}
Write-Host "install-rarlab-unrar: installed $installed"
Write-Host "install-rarlab-unrar: $banner"
