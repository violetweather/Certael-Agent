param(
    [string]$Prefix = "$env:ProgramFiles\Certael",
    [string]$Version = "0.2.0",
    [string]$Registration,
    [string]$PublisherTrustStore,
    [string]$UpdateRoot,
    [string]$GameRoot
)
$ErrorActionPreference = 'Stop'
if ($Version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$') {
    throw 'The install version is invalid.'
}
$registrationValues = @($Registration, $PublisherTrustStore, $UpdateRoot, $GameRoot)
$provided = @($registrationValues | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count
if ($provided -ne 0 -and $provided -ne 4) {
    throw 'Registration, PublisherTrustStore, UpdateRoot, and GameRoot must be supplied together.'
}
foreach ($path in @($Registration, $PublisherTrustStore, $UpdateRoot) | Where-Object { $_ }) {
    $item = Get-Item -LiteralPath $path -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "$path must be a regular, non-reparse-point file."
    }
}
if ($provided -eq 4 -and -not (Test-Path -LiteralPath $GameRoot -PathType Container)) {
    throw 'GameRoot must be an existing directory.'
}
$source = Split-Path -Parent $PSScriptRoot
    $agent = Join-Path $source 'certael-agent.exe'
    $launcher = Join-Path $source 'certael-agent-launcher.exe'
    if (-not (Test-Path -LiteralPath $agent -PathType Leaf)) {
        throw 'certael-agent.exe is missing from the extracted release directory.'
    }
    if (-not (Test-Path -LiteralPath $launcher -PathType Leaf)) {
        throw 'certael-agent-launcher.exe is missing from the extracted release directory.'
    }
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

    Copy-Item -LiteralPath $launcher `
        -Destination (Join-Path $Prefix 'certael-agent.exe.new') -Force
    Move-Item -LiteralPath (Join-Path $Prefix 'certael-agent.exe.new') `
        -Destination (Join-Path $Prefix 'certael-agent.exe') -Force

    if ($provided -eq 4) {
        & (Join-Path $Prefix 'certael-agent.exe') register-game `
            --registration $Registration --publisher-trust-store $PublisherTrustStore `
            --update-root $UpdateRoot --game-root $GameRoot
    }
Write-Host "Installed Certael Agent $Version at $Prefix"
