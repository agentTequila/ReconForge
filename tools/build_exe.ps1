# Build ReconForge portable Windows executables + SHA256SUMS into dist/.
# Usage: powershell -ExecutionPolicy Bypass -File tools/build_exe.ps1
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$m = Select-String -Path (Join-Path $root "reconforge\__init__.py") -Pattern '__version__\s*=\s*"([^"]+)"'
if (-not $m) { throw "could not read __version__" }
$version = $m.Matches[0].Groups[1].Value
Write-Host "[build] ReconForge $version"

$py = Join-Path $root ".venv\Scripts\python.exe"
if (-not (Test-Path $py)) { throw "venv python not found: $py" }

Write-Host "[build] installing pyinstaller"
& $py -m pip install --quiet pyinstaller

foreach ($spec in "packaging\reconforge-gui.spec", "packaging\reconforge-cli.spec") {
    Write-Host "[build] $spec"
    & $py -m PyInstaller --noconfirm --clean $spec
    if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed for $spec" }
}

$gui = Join-Path $root "dist\ReconForge.exe"
$cli = Join-Path $root "dist\reconforge-cli.exe"
if (-not (Test-Path $gui)) { throw "GUI exe missing after build" }
if (-not (Test-Path $cli)) { throw "CLI exe missing after build" }

$guiRel = "ReconForge-v$version-win64.exe"
$cliRel = "reconforge-cli-v$version-win64.exe"
Move-Item -Force $gui (Join-Path $root "dist\$guiRel")
Move-Item -Force $cli (Join-Path $root "dist\$cliRel")

$lines = foreach ($name in @($guiRel, $cliRel)) {
    $hash = (Get-FileHash (Join-Path $root "dist\$name") -Algorithm SHA256).Hash.ToLower()
    "$hash  $name"
}
Set-Content -Path (Join-Path $root "dist\SHA256SUMS.txt") -Value ($lines -join "`n") -NoNewline -Encoding ascii

Write-Host "[build] artifacts:"
Get-ChildItem (Join-Path $root "dist") | Format-Table Name, @{n = "MB"; e = { [math]::Round($_.Length / 1MB, 1) } } -AutoSize
