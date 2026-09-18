# scripts/sign.ps1 - Authenticode Code Signing Utility for Bluebirds Secure Browser
# Usage:
#   .\scripts\sign.ps1 -CertPath "path\to\cert.pfx" -CertPassword "secret"
#   .\scripts\sign.ps1 -CreateDevCert  (Creates and uses a local development code-signing certificate)

param (
    [string]$CertPath = "",
    [string]$CertPassword = "",
    [string]$TargetFile = "release\BluebirdsSecureBrowser-Setup.exe",
    [switch]$CreateDevCert = $false,
    [string]$TimestampServer = "http://timestamp.digicert.com"
)

$ErrorActionPreference = "Stop"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " Bluebirds Secure Browser — Authenticode Signing Utility    " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# 1. Handle Self-Signed Dev Certificate Creation
if ($CreateDevCert) {
    $certSubject = "CN=Bluebirds Solutions Development Code Signing"
    Write-Host "[Sign] Creating self-signed code-signing certificate: $certSubject..." -ForegroundColor Yellow
    
    $cert = New-SelfSignedCertificate `
        -Type CodeSigningCert `
        -Subject $certSubject `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -HashAlgorithm "SHA256" `
        -NotAfter (Get-Date).AddYears(3)
        
    Write-Host "[Sign] Certificate created with Thumbprint: $($cert.Thumbprint)" -ForegroundColor Green
    
    $devPfxPath = Join-Path $PSScriptRoot "dev-codesign.pfx"
    $devPwd = ConvertTo-SecureString -String "BluebirdsDev123!" -Force -AsPlainText
    
    Export-PfxCertificate -Cert $cert -FilePath $devPfxPath -Password $devPwd | Out-Null
    Write-Host "[Sign] Exported dev certificate to: $devPfxPath" -ForegroundColor Green
    
    $CertPath = $devPfxPath
    $CertPassword = "BluebirdsDev123!"
}

# 2. Validate Target File
if (-not (Test-Path $TargetFile)) {
    Write-Error "[Sign] Target executable not found: $TargetFile. Please run 'npm run dist' first."
}

# 3. Obtain Certificate
$codeSignCert = $null
if ($CertPath -and (Test-Path $CertPath)) {
    Write-Host "[Sign] Loading certificate from: $CertPath..." -ForegroundColor Cyan
    if ($CertPassword) {
        $securePwd = ConvertTo-SecureString -String $CertPassword -Force -AsPlainText
        $codeSignCert = Get-PfxCertificate -FilePath $CertPath
    } else {
        $codeSignCert = Get-PfxCertificate -FilePath $CertPath
    }
} else {
    Write-Host "[Sign] Looking for Code Signing certificate in Windows Certificate Store (CurrentUser\My)..." -ForegroundColor Cyan
    $certs = Get-ChildItem -Path Cert:\CurrentUser\My -CodeSigningCert
    if ($certs.Count -gt 0) {
        $codeSignCert = $certs[0]
        Write-Host "[Sign] Found installed certificate: $($codeSignCert.Subject) (Thumbprint: $($codeSignCert.Thumbprint))" -ForegroundColor Green
    }
}

if (-not $codeSignCert) {
    Write-Warning "[Sign] No code signing certificate found or specified."
    Write-Host "To sign with an existing PFX: .\scripts\sign.ps1 -CertPath 'path\to\cert.pfx' -CertPassword 'pwd'" -ForegroundColor Yellow
    Write-Host "To generate a local testing cert: .\scripts\sign.ps1 -CreateDevCert" -ForegroundColor Yellow
    exit 1
}

# 4. Sign the Executable
Write-Host "[Sign] Signing '$TargetFile' with timestamp server '$TimestampServer'..." -ForegroundColor Cyan

try {
    $sigResult = Set-AuthenticodeSignature `
        -FilePath $TargetFile `
        -Certificate $codeSignCert `
        -HashAlgorithm "SHA256" `
        -TimestampServer $TimestampServer

    if ($sigResult.Status -eq "Valid") {
        Write-Host "[Sign] SUCCESS: Successfully signed $TargetFile!" -ForegroundColor Green
        Write-Host "Status: $($sigResult.Status)" -ForegroundColor Green
        Write-Host "Signer: $($sigResult.SignerCertificate.Subject)" -ForegroundColor Green
    } else {
        Write-Warning "[Sign] Signature applied but status is: $($sigResult.Status) ($($sigResult.StatusMessage))"
    }
} catch {
    Write-Error "[Sign] Failed to sign $TargetFile : $_"
}

# 5. Verify Signature
Write-Host "[Sign] Verifying signature..." -ForegroundColor Cyan
$verification = Get-AuthenticodeSignature -FilePath $TargetFile
$verification | Format-List
