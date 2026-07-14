param([string]$Prefix = "$env:ProgramFiles\Certael", [switch]$Purge)
$ErrorActionPreference = 'Stop'
Remove-Item -LiteralPath (Join-Path $Prefix 'certael-agent.exe') -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path $Prefix 'activation.json') -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path $Prefix 'versions') -Recurse -Force -ErrorAction SilentlyContinue
if ($Purge) { Remove-Item -LiteralPath (Join-Path $Prefix 'config') -Recurse -Force -ErrorAction SilentlyContinue }
Write-Host 'Removed Certael Agent binaries. Use -Purge to remove public trust configuration.'
