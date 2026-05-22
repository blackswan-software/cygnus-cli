# Cygnus CLI installer for Windows
# Usage: irm https://install.blackswan-software.ai/win | iex
#
# Downloads standalone binary, verifies checksum, installs to %LOCALAPPDATA%\cygnus\

$ErrorActionPreference = "Stop"

$CDN = "https://cygnus-registry.sfo3.cdn.digitaloceanspaces.com/cli"
$Version = if ($env:CYGNUS_VERSION) { $env:CYGNUS_VERSION } else { "0.1.0" }
$InstallDir = if ($env:CYGNUS_INSTALL_DIR) { $env:CYGNUS_INSTALL_DIR } else { "$env:LOCALAPPDATA\cygnus" }

$Arch = if ([System.Environment]::Is64BitOperatingSystem) { "x86_64" } else { "x86" }
$BinaryName = "cygnus-windows-$Arch.exe"

Write-Host "cygnus Installing Cygnus CLI v$Version for windows-$Arch" -ForegroundColor Cyan

# Create install directory
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

$BinaryUrl = "$CDN/$Version/$BinaryName"
$ChecksumUrl = "$CDN/$Version/$BinaryName.sha256"
$TempBinary = "$env:TEMP\cygnus.exe"
$TempChecksum = "$env:TEMP\cygnus.sha256"

# Download binary
Write-Host "  Downloading from CDN..." -ForegroundColor Cyan
try {
    Invoke-WebRequest -Uri $BinaryUrl -OutFile $TempBinary -UseBasicParsing
} catch {
    Write-Host "  Download failed. Check https://blackswan-software.ai for install options." -ForegroundColor Red
    exit 1
}

# Verify checksum
try {
    Invoke-WebRequest -Uri $ChecksumUrl -OutFile $TempChecksum -UseBasicParsing
    $Expected = (Get-Content $TempChecksum).Split(" ")[0]
    $Actual = (Get-FileHash $TempBinary -Algorithm SHA256).Hash.ToLower()
    if ($Expected -ne $Actual) {
        Write-Host "  Checksum mismatch — download may be corrupted" -ForegroundColor Red
        Remove-Item $TempBinary -Force
        exit 1
    }
    Write-Host "  Checksum verified" -ForegroundColor Green
} catch {
    Write-Host "  Checksum not available — skipping verification" -ForegroundColor Yellow
}

# Install
Move-Item -Force $TempBinary "$InstallDir\cygnus.exe"
Write-Host "  Installed to $InstallDir\cygnus.exe" -ForegroundColor Green

# Add to PATH if not already there
$CurrentPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($CurrentPath -notlike "*$InstallDir*") {
    [Environment]::SetEnvironmentVariable("Path", "$CurrentPath;$InstallDir", "User")
    Write-Host "  Added to PATH (restart terminal to use)" -ForegroundColor Cyan
}

# Done
Write-Host ""
Write-Host "  Cygnus CLI installed!" -ForegroundColor Green
Write-Host ""
Write-Host "  Get started:" -ForegroundColor Cyan
Write-Host "    cygnus verify flask          # check a library"
Write-Host "    cygnus auth signup           # create free account"
Write-Host "    cygnus check                 # scan for CVEs"
Write-Host ""
Write-Host "  Free: grade + CVE for the daily quota. No payment required." -ForegroundColor DarkGray

# Cleanup
Remove-Item $TempChecksum -Force -ErrorAction SilentlyContinue
