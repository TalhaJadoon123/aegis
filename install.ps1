#requires -Version 5.1
<#
.SYNOPSIS
  Install Aegis on Windows.

.DESCRIPTION
  Downloads the verified release tarball from GitHub and installs it globally
  with npm. No npm account is required and the package has zero dependencies.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\install.ps1
#>
param(
  [string]$Version = '0.1.2'
)

$ErrorActionPreference = 'Stop'

function Fail($message) {
  Write-Host ''
  Write-Host "  ERROR: $message" -ForegroundColor Red
  Write-Host ''
  exit 1
}

Write-Host ''
Write-Host '  Aegis installer' -ForegroundColor Cyan
Write-Host '  ---------------'
Write-Host ''

$node = Get-Command node -ErrorAction SilentlyContinue
if (-not $node) {
  Fail 'Node.js is not installed. Install Node.js 22 or newer from https://nodejs.org and run this script again.'
}

$nodeVersion = (& node --version).TrimStart('v')
$major = [int]($nodeVersion.Split('.')[0])
if ($major -lt 22) {
  Fail "Node.js $nodeVersion found, but Aegis needs 22 or newer. Install the current LTS from https://nodejs.org."
}
Write-Host "  Node.js $nodeVersion  OK"

$npm = Get-Command npm -ErrorAction SilentlyContinue
if (-not $npm) { Fail 'npm was not found next to Node.js. Reinstall Node.js with the npm component included.' }

$asset = "talhajadoon123-aegis-$Version.tgz"
$url = "https://github.com/TalhaJadoon123/aegis/releases/download/v$Version/$asset"
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) $asset

Write-Host "  Downloading Aegis $Version ..."
try {
  Invoke-WebRequest -Uri $url -OutFile $tmp -UseBasicParsing
} catch {
  Fail "Could not download $url`n         Check your internet connection, or install with: npm install -g $url"
}
Write-Host ('  Downloaded ' + [math]::Round((Get-Item $tmp).Length / 1KB) + ' KB')

Write-Host '  Installing ...'
& npm install -g $tmp --no-audit --no-fund
if ($LASTEXITCODE -ne 0) { Fail 'npm install failed. See the output above.' }

$installed = & aegis --version 2>&1
if ($LASTEXITCODE -ne 0) {
  Fail "Aegis was installed but does not run. Try: npm install -g $tmp"
}

Write-Host ''
Write-Host "  Installed: $installed" -ForegroundColor Green
Write-Host ''
Write-Host '  Try it:'
Write-Host '    aegis scan .                 scan the current project'
Write-Host '    aegis desktop                open the dashboard'
Write-Host '    aegis report --compliance    compliance attestation'
Write-Host ''
Write-Host "  Documentation: https://github.com/TalhaJadoon123/aegis#readme"
Write-Host ''