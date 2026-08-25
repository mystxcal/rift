param(
    [string]$Archive,
    [string]$Repo,
    [string]$BundleDir,
    [string]$Tag = "latest",
    [string]$InstallDir = "$env:LOCALAPPDATA\Programs\RIFT",
    [string]$Relay,
    [string]$CaCert,
    [switch]$NoPath
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if (-not $Archive -and -not $Repo -and -not $BundleDir) {
    if ((Test-Path (Join-Path $PSScriptRoot "manifest.json")) -and
        (Test-Path (Join-Path $PSScriptRoot "rift.exe"))) {
        $BundleDir = $PSScriptRoot
    }
}
$Sources = @(@($Archive, $Repo, $BundleDir) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
if ($Sources.Count -ne 1) {
    throw "provide exactly one of -Archive, -Repo, or -BundleDir"
}
if ($CaCert -and -not $Relay) {
    throw "-CaCert requires -Relay"
}
$Work = Join-Path ([System.IO.Path]::GetTempPath()) ("rift-install-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $Work | Out-Null
try {
    if ($Repo) {
        if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
            throw "gh is required for a private GitHub release"
        }
        if ($Tag -eq "latest") {
            gh release download --repo $Repo --pattern "*x86_64-pc-windows-msvc.zip" --dir $Work
            gh release download --repo $Repo --pattern "*x86_64-pc-windows-msvc.zip.sha256" --dir $Work
        } else {
            gh release download $Tag --repo $Repo --pattern "*x86_64-pc-windows-msvc.zip" --dir $Work
            gh release download $Tag --repo $Repo --pattern "*x86_64-pc-windows-msvc.zip.sha256" --dir $Work
        }
        $Archives = @(Get-ChildItem -File $Work -Filter "*.zip")
        if ($Archives.Count -ne 1) { throw "release must contain exactly one Windows archive" }
        $Archive = $Archives[0].FullName
    }
    if ($Archive) {
        if (-not (Test-Path -LiteralPath $Archive -PathType Leaf)) { throw "archive not found: $Archive" }
        $Sidecar = "$Archive.sha256"
        if (-not (Test-Path -LiteralPath $Sidecar -PathType Leaf)) {
            throw "archive checksum not found: $Sidecar"
        }
        $SidecarLine = (Get-Content -LiteralPath $Sidecar -Raw).Trim()
        if ($SidecarLine -notmatch '^([0-9a-fA-F]{64})  (.+)$') { throw "invalid archive checksum" }
        if ($Matches[2] -ne [System.IO.Path]::GetFileName($Archive)) {
            throw "archive checksum names the wrong file"
        }
        $ArchiveHash = (Get-FileHash -LiteralPath $Archive -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($ArchiveHash -ne $Matches[1].ToLowerInvariant()) { throw "release archive checksum mismatch" }

        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $Zip = [System.IO.Compression.ZipFile]::OpenRead($Archive)
        try {
            $Entries = @($Zip.Entries | ForEach-Object FullName)
            if ($Entries.Count -eq 0) { throw "empty RIFT release archive" }
            $Root = $Entries[0].Split('/')[0]
            if (-not $Root.StartsWith("rift-")) { throw "invalid release root" }
            foreach ($Entry in $Entries) {
                if (-not $Entry.StartsWith("$Root/", [StringComparison]::Ordinal)) {
                    throw "release contains entries outside its root"
                }
                if ($Entry.StartsWith('/') -or $Entry.Contains('\') -or $Entry.Split('/') -contains '..') {
                    throw "release contains an unsafe path"
                }
            }
        } finally {
            $Zip.Dispose()
        }
        $Expanded = Join-Path $Work "expanded"
        Expand-Archive -LiteralPath $Archive -DestinationPath $Expanded
        $BundleDir = Join-Path $Expanded $Root
    }
    if (-not (Test-Path -LiteralPath $BundleDir -PathType Container)) {
        throw "bundle not found: $BundleDir"
    }
    $Actual = @(Get-ChildItem -LiteralPath $BundleDir | ForEach-Object Name | Sort-Object)
    $Expected = @("LICENSE", "README.md", "SHA256SUMS", "install.cmd", "install.ps1", "manifest.json", "rift.exe") | Sort-Object
    if (($Actual -join "`n") -ne ($Expected -join "`n")) {
        throw "release contains an unexpected file set"
    }
    $Bundle = $BundleDir
    $Binary = Get-Item -LiteralPath (Join-Path $Bundle "rift.exe")
    $Sums = Get-Item -LiteralPath (Join-Path $Bundle "SHA256SUMS")
    $ChecksumNames = @()
    $AllowedChecksumNames = @("LICENSE", "README.md", "install.cmd", "install.ps1", "manifest.json", "rift.exe")
    foreach ($Line in (Get-Content $Sums.FullName)) {
        if ($Line -notmatch '^([0-9a-f]{64})  (LICENSE|README\.md|install\.cmd|install\.ps1|manifest\.json|rift\.exe)$') {
            throw "checksum manifest contains an unsafe or unexpected entry"
        }
        $Name = $Matches[2]
        $ChecksumNames += $Name
        $File = Join-Path $Sums.DirectoryName $Name
        $Actual = (Get-FileHash -LiteralPath $File -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($Actual -ne $Matches[1]) { throw "checksum mismatch: $Name" }
    }
    if ((($ChecksumNames | Sort-Object) -join "`n") -ne (($AllowedChecksumNames | Sort-Object) -join "`n")) {
        throw "checksum manifest must name every payload file exactly once"
    }
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    & $Binary.FullName --json doctor | Out-Null
    $Installing = Join-Path $InstallDir ".rift.install.$PID"
    Copy-Item -LiteralPath $Binary.FullName -Destination $Installing -Force
    Move-Item -LiteralPath $Installing -Destination (Join-Path $InstallDir "rift.exe") -Force
    if (-not $NoPath) {
        $UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
        $Segments = @($UserPath -split ';' | Where-Object { $_ })
        if ($Segments -notcontains $InstallDir) {
            $NewPath = (@($Segments) + $InstallDir) -join ';'
            [Environment]::SetEnvironmentVariable("Path", $NewPath, "User")
        }
        if (($env:Path -split ';') -notcontains $InstallDir) { $env:Path += ";$InstallDir" }
    }
    if ($Relay) {
        $InstalledCa = $null
        if ($CaCert) {
            if (-not (Test-Path -LiteralPath $CaCert -PathType Leaf)) {
                throw "CA certificate not found: $CaCert"
            }
            $InstalledCa = Join-Path $InstallDir "rift-relay-ca.pem"
            Copy-Item -LiteralPath $CaCert -Destination $InstalledCa -Force
        }
        $Config = @("config", "set-relay", $Relay)
        if ($InstalledCa) { $Config += @("--ca-cert", $InstalledCa) }
        & (Join-Path $InstallDir "rift.exe") @Config | Out-Null
    }
    Write-Output "Installed $(Join-Path $InstallDir 'rift.exe')"
} finally {
    Remove-Item -LiteralPath $Work -Recurse -Force -ErrorAction SilentlyContinue
}
