param(
    [string]$OutDir = "target/dist"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $Root
if ((git status --porcelain --untracked-files=no)) {
    throw "tracked worktree must be clean so the artifact has one exact source identity"
}

$Revision = (git rev-parse HEAD).Trim()
$Metadata = cargo metadata --no-deps --format-version 1 | ConvertFrom-Json
$Version = ($Metadata.packages | Where-Object name -eq "rift-cli").version
$Target = "x86_64-pc-windows-msvc"
$Name = "rift-$Version-$Target"
$Out = Join-Path $Root $OutDir
$Stage = Join-Path $Out $Name
$Archive = Join-Path $Out "$Name.zip"
if ((Test-Path $Stage) -or (Test-Path $Archive)) {
    throw "artifact already exists under $Out"
}

$env:CARGO_INCREMENTAL = "0"
cargo build --release --locked -p rift-cli
New-Item -ItemType Directory -Path $Stage -Force | Out-Null
Copy-Item "target/release/rift.exe" (Join-Path $Stage "rift.exe")
Copy-Item "scripts/install.ps1" (Join-Path $Stage "install.ps1")
Copy-Item "scripts/install.cmd" (Join-Path $Stage "install.cmd")
Copy-Item "README.md" (Join-Path $Stage "README.md")
Copy-Item "LICENSE" (Join-Path $Stage "LICENSE")
$BinaryHash = (Get-FileHash (Join-Path $Stage "rift.exe") -Algorithm SHA256).Hash.ToLowerInvariant()
[ordered]@{
    schema = "rift.release.v1"
    version = $Version
    target = $Target
    source_revision = $Revision
    binary_sha256 = $BinaryHash
} | ConvertTo-Json | Set-Content -Encoding utf8NoBOM (Join-Path $Stage "manifest.json")

$ChecksumFiles = @("LICENSE", "README.md", "install.cmd", "install.ps1", "manifest.json", "rift.exe")
$ChecksumLines = foreach ($File in $ChecksumFiles) {
    $Hash = (Get-FileHash (Join-Path $Stage $File) -Algorithm SHA256).Hash.ToLowerInvariant()
    "$Hash  $File"
}
[System.IO.File]::WriteAllText(
    (Join-Path $Stage "SHA256SUMS"),
    (($ChecksumLines -join "`n") + "`n"),
    [System.Text.UTF8Encoding]::new($false)
)

Add-Type -AssemblyName System.IO.Compression
$Stream = [System.IO.File]::Open($Archive, [System.IO.FileMode]::CreateNew)
try {
    $Zip = [System.IO.Compression.ZipArchive]::new(
        $Stream,
        [System.IO.Compression.ZipArchiveMode]::Create,
        $false
    )
    try {
        $Epoch = [DateTimeOffset]::new(1980, 1, 1, 0, 0, 0, [TimeSpan]::Zero)
        foreach ($File in (Get-ChildItem -File $Stage | Sort-Object Name)) {
            $Entry = $Zip.CreateEntry("$Name/$($File.Name)", [System.IO.Compression.CompressionLevel]::Optimal)
            $Entry.LastWriteTime = $Epoch
            $Input = [System.IO.File]::OpenRead($File.FullName)
            $Output = $Entry.Open()
            try { $Input.CopyTo($Output) } finally { $Output.Dispose(); $Input.Dispose() }
        }
    } finally {
        $Zip.Dispose()
    }
} finally {
    $Stream.Dispose()
}

$ArchiveHash = (Get-FileHash $Archive -Algorithm SHA256).Hash.ToLowerInvariant()
[System.IO.File]::WriteAllText(
    "$Archive.sha256",
    "$ArchiveHash  $([System.IO.Path]::GetFileName($Archive))`n",
    [System.Text.UTF8Encoding]::new($false)
)
Write-Output $Archive
