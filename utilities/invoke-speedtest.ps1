<#
.SYNOPSIS
  Tests approximate download and upload speeds using only native PowerShell commands,
  forcing TLS 1.2 or ignoring certificate validation if needed.

  Oneliner to call and run the speed test. 
  irm "https://raw.githubusercontent.com/david-pitre-csiq/PowerShell-Scripts/refs/heads/main/utilities/invoke-speedtest.ps1" | iex

#>

# ------------------------------
# 1) Force TLS 1.2 for the session
# ------------------------------
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# ------------------------------
# 2) (Optional) Completely ignore SSL certificate errors
#    Uncomment if forcing TLS 1.2 alone does not help
# ------------------------------
<# 
Add-Type -TypeDefinition @"
using System;
using System.Net;
using System.Security.Cryptography.X509Certificates;

public static class SSLTrust {
    public static bool OverrideCertificateValidation() {
        ServicePointManager.ServerCertificateValidationCallback = 
            new RemoteCertificateValidationCallback(
                delegate { return true; }
            );
        return true;
    }
}
"@

[void][SSLTrust]::OverrideCertificateValidation()
#>

# ------------------------------
# 3) Configuration
# ------------------------------
$downloadUrl   = "https://nbg1-speed.hetzner.com/100MB.bin"
$uploadSizeMB  = 10

Write-Host "`n=== Starting Speed Test (Pure PowerShell) ===`n"

# DOWNLOAD TEST
Write-Host "-> Download Test from $downloadUrl"
$downloadStart = Get-Date

try {
    $response = Invoke-WebRequest -Uri $downloadUrl -UseBasicParsing
} catch {
    Write-Host "Download failed: $($_.Exception.Message)"
    return
}

$downloadEnd     = Get-Date
$downloadElapsed = ($downloadEnd - $downloadStart).TotalSeconds
$downloadBytes   = $response.Content.Length
$downloadSpeedMbps = ($downloadBytes * 8 / 1MB) / $downloadElapsed

Write-Host "Downloaded:      $($downloadBytes / 1MB) MB"
Write-Host "Download Time:   $downloadElapsed seconds"
Write-Host ("Approx. DL Speed: {0:N2} Mbps`n" -f $downloadSpeedMbps)

# UPLOAD TEST
Write-Host "-> Upload Test to https://httpbin.org/post"
$uploadBytesCount = $uploadSizeMB * 1MB
$randomData = New-Object Byte[] $uploadBytesCount
$rand = New-Object Random
for ($i = 0; $i -lt $randomData.Length; $i++) {
    $randomData[$i] = [byte]$rand.Next(256)
}

$uploadStart = Get-Date
try {
    $responseUpload = Invoke-WebRequest -Uri "https://httpbin.org/post" -Method POST -Body $randomData -UseBasicParsing
} catch {
    Write-Host "Upload failed: $($_.Exception.Message)"
    return
}
$uploadEnd = Get-Date
$uploadElapsed = ($uploadEnd - $uploadStart).TotalSeconds
$uploadSpeedMbps = ($uploadBytesCount * 8 / 1MB) / $uploadElapsed

Write-Host "Uploaded:        $($uploadBytesCount / 1MB) MB"
Write-Host "Upload Time:     $uploadElapsed seconds"
Write-Host ("Approx. UL Speed: {0:N2} Mbps`n" -f $uploadSpeedMbps)
Write-Host "=== Test Complete ==="
