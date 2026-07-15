param(
    [Parameter(Mandatory = $true)][string]$CertificateBase64,
    [Parameter(Mandatory = $true)][string]$CertificatePassword,
    [Parameter(Mandatory = $true)][string[]]$Files
)
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($CertificateBase64) -or
    [string]::IsNullOrWhiteSpace($CertificatePassword)) {
    throw 'Stable Windows releases require an Authenticode certificate and password.'
}
$pfx = Join-Path $env:RUNNER_TEMP 'certael-authenticode.pfx'
[IO.File]::WriteAllBytes($pfx, [Convert]::FromBase64String($CertificateBase64))
try {
    $secure = ConvertTo-SecureString $CertificatePassword -AsPlainText -Force
    $certificate = Import-PfxCertificate -FilePath $pfx `
        -CertStoreLocation Cert:\CurrentUser\My -Password $secure
    if ($null -eq $certificate) { throw 'Authenticode certificate import failed.' }
    foreach ($file in $Files) {
        & signtool.exe sign /sha1 $certificate.Thumbprint /fd SHA256 `
            /tr http://timestamp.digicert.com /td SHA256 $file
        if ($LASTEXITCODE -ne 0) { throw "Authenticode signing failed for $file" }
        & signtool.exe verify /pa /all $file
        if ($LASTEXITCODE -ne 0) { throw "Authenticode verification failed for $file" }
    }
}
finally {
    Remove-Item -LiteralPath $pfx -Force -ErrorAction SilentlyContinue
    if ($null -ne $certificate) {
        Remove-Item -LiteralPath "Cert:\CurrentUser\My\$($certificate.Thumbprint)" -Force
    }
}
