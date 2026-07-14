param(
    [Parameter(Mandatory = $true)][string]$TrustStore,
    [string]$Prefix = "$env:ProgramFiles\Certael",
    [string]$Version = "0.1.0"
)
$ErrorActionPreference = 'Stop'
if ($Version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$') {
    throw 'The install version is invalid.'
}
$trustItem = Get-Item -LiteralPath $TrustStore -Force
if (-not $trustItem.PSIsContainer -and -not ($trustItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    $source = Split-Path -Parent $PSScriptRoot
    $agent = Join-Path $source 'certael-agent.exe'
    $launcher = Join-Path $source 'certael-agent-launcher.exe'
    if (-not (Test-Path -LiteralPath $agent -PathType Leaf)) {
        throw 'certael-agent.exe is missing from the extracted release directory.'
    }
    if (-not (Test-Path -LiteralPath $launcher -PathType Leaf)) {
        throw 'certael-agent-launcher.exe is missing from the extracted release directory.'
    }
    & $agent validate-trust-store --trust-store $TrustStore | Out-Null
    $versions = Join-Path $Prefix 'versions'
    $destination = Join-Path $versions $Version
    if (Test-Path -LiteralPath $destination) { throw "Certael Agent $Version is already installed." }
    New-Item -ItemType Directory -Force -Path $versions | Out-Null
    $temporary = Join-Path $versions ('.install.' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $temporary | Out-Null
    try {
        Copy-Item -LiteralPath $agent -Destination $temporary
        foreach ($name in @('certael_agent_probe.dll', 'certael_agent_probe.h',
                'compatibility-v1.json', 'LICENSE', 'README.md')) {
            $candidate = Join-Path $source $name
            if (Test-Path -LiteralPath $candidate -PathType Leaf) {
                Copy-Item -LiteralPath $candidate -Destination $temporary
            }
        }
        & (Join-Path $temporary 'certael-agent.exe') --help | Out-Null
        Move-Item -LiteralPath $temporary -Destination $destination
    }
    finally { if (Test-Path -LiteralPath $temporary) { Remove-Item -Recurse -Force $temporary } }

    & (Join-Path $destination 'certael-agent.exe') register-installed-version `
        --install-root $Prefix --version $Version --installed-name certael-agent.exe --activate

    $configuration = Join-Path $Prefix 'config'
    New-Item -ItemType Directory -Force -Path $configuration | Out-Null
    $newTrust = Join-Path $configuration 'trust-store.json.new'
    Copy-Item -LiteralPath $TrustStore -Destination $newTrust -Force
    Move-Item -LiteralPath $newTrust -Destination (Join-Path $configuration 'trust-store.json') -Force
    Copy-Item -LiteralPath $launcher `
        -Destination (Join-Path $Prefix 'certael-agent.exe.new') -Force
    Move-Item -LiteralPath (Join-Path $Prefix 'certael-agent.exe.new') `
        -Destination (Join-Path $Prefix 'certael-agent.exe') -Force

    & icacls.exe $configuration /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' | Out-Null
    Write-Host "Installed Certael Agent $Version at $Prefix"
} else { throw 'A regular, non-reparse-point public trust-store file is required.' }
