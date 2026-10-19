# Builds VPNer. Downloads a pinned Go toolchain into .tools if needed.
#   powershell -ExecutionPolicy Bypass -File build.ps1 [-Arch amd64|arm64|all] [-Version 0.1.0]
param(
    [ValidateSet('amd64', 'arm64', 'all')][string]$Arch = 'amd64',
    [string]$Version = '0.1.0'
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Set-Location $PSScriptRoot

$GoVersion = '1.27.2'
$GoSha256 = '1314008898bd40df77af4b014f777f08873dbdfbcd3d92308728ee03304fe04f'
$go = Join-Path $PSScriptRoot '.tools\go\bin\go.exe'

if (-not (Test-Path $go)) {
    Write-Host "Installing Go $GoVersion into .tools ..."
    New-Item -ItemType Directory -Force .tools | Out-Null
    $zip = Join-Path $PSScriptRoot '.tools\go.zip'
    Invoke-WebRequest "https://go.dev/dl/go$GoVersion.windows-amd64.zip" -OutFile $zip
    $sum = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower()
    if ($sum -ne $GoSha256) { Remove-Item $zip; throw "Go archive checksum mismatch: $sum" }
    Expand-Archive $zip -DestinationPath .tools -Force
    Remove-Item $zip
}

function GzipFile($src, $dst) {
    $in = [IO.File]::OpenRead($src)
    $out = [IO.File]::Create($dst)
    $gz = New-Object IO.Compression.GZipStream($out, [IO.Compression.CompressionLevel]::Optimal)
    $in.CopyTo($gz); $gz.Close(); $out.Close(); $in.Close()
}

# Sanity check of the embedded UI script (optional, needs Node.js)
if (Get-Command node -ErrorAction SilentlyContinue) {
    $check = @'
const fs = require('fs');
const s = fs.readFileSync('internal/web/index.html', 'utf8');
const re = /<script>([\s\S]*?)<\/script>/g;
let m;
try { while ((m = re.exec(s))) new Function(m[1]); }
catch (e) { console.error('UI script error: ' + e.message); process.exit(1); }
'@
    node -e $check
    if ($LASTEXITCODE) { throw 'UI script has a syntax error' }
}

$env:CGO_ENABLED = '0'
$ldflags = "-s -w -X main.version=$Version"
New-Item -ItemType Directory -Force build, dist | Out-Null

# 1. Linux agent for both WSL architectures, embedded into vpner.exe
foreach ($a in 'amd64', 'arm64') {
    Write-Host "Building vpner-agent linux/$a ..."
    $env:GOOS = 'linux'; $env:GOARCH = $a
    & $go build -trimpath -ldflags $ldflags -o "build\vpner-agent-linux-$a" .\cmd\vpner-agent
    if ($LASTEXITCODE) { throw 'agent build failed' }
    GzipFile "build\vpner-agent-linux-$a" "internal\assets\agent\vpner-agent-linux-$a.gz"
}

# 2. Windows app
$targets = if ($Arch -eq 'all') { 'amd64', 'arm64' } else { @($Arch) }
foreach ($a in $targets) {
    Write-Host "Building vpner.exe windows/$a ..."
    $env:GOOS = 'windows'; $env:GOARCH = $a
    $out = if ($targets.Count -gt 1) { "dist\vpner-$a.exe" } else { 'dist\vpner.exe' }
    & $go build -trimpath -ldflags "$ldflags -H windowsgui" -o $out .\cmd\vpner
    if ($LASTEXITCODE) { throw 'app build failed' }
    Write-Host ("  -> {0} ({1:N1} MB)" -f $out, ((Get-Item $out).Length / 1MB))

    # 3. Installer with the program inside
    GzipFile (Resolve-Path $out) "$PWD\cmd\vpner-setup\payload\vpner.exe.gz"
    $setup = if ($targets.Count -gt 1) { "dist\vpner-setup-$a.exe" } else { 'dist\vpner-setup.exe' }
    Write-Host "Building $setup ..."
    & $go build -trimpath -ldflags "$ldflags -H windowsgui" -o $setup .\cmd\vpner-setup
    if ($LASTEXITCODE) { throw 'setup build failed' }
    Remove-Item cmd\vpner-setup\payload\vpner.exe.gz
    Write-Host ("  -> {0} ({1:N1} MB)" -f $setup, ((Get-Item $setup).Length / 1MB))
}
Remove-Item Env:GOOS, Env:GOARCH
Write-Host 'Done.'
