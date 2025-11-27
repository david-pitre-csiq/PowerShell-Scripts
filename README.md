# Windows Configuration Scripts

This repository contains PowerShell scripts for configuring various settings on Windows 10 and Windows 11. Each script requires administrative privileges to run and provides functionality to modify system settings such as Autoplay, local account names, SMB Signing, and application management.

These scripts are used to address common Windows vulnerabilities identified by an authenticated vulnerability scanner such as Qualys or Nessus, as well as manage security-related applications. 

## Scripts

### 1. Set-Autoplay.ps1

**Description:**  
This script disables, enables, or checks the status of Autoplay and Autorun on Windows 10 and Windows 11 by modifying the registry settings.

**Parameters:**
- `-Disable`: Disables Autoplay and Autorun.
- `-Enable`: Enables Autoplay and Autorun.
- `-Check`: Retrieves the current Autoplay and Autorun status.

**Example Usage:**

```powershell
.\Set-Autoplay.ps1 -Disable
```


### 2. Disable-LegacyBlockCiphers.ps1

**Description:**  
This script manages legacy block ciphers (such as DES, 3DES, IDEA, and RC2) by modifying registry settings. It can disable or enable legacy block ciphers to address security vulnerabilities.

**Parameters:**
- `-DisableLegacyBlockCiphers`: Disables legacy block ciphers (3DES).
- `-EnableLegacyBlockCiphers`: Enables legacy block ciphers (3DES).
- `-Check`: Checks the current status of legacy block ciphers without making any changes.

**Example Usage:**

```powershell
.\Disable-LegacyBlockCiphers.ps1 -DisableLegacyBlockCiphers
```


### 3. Set-LmCompatibilityLevel.ps1

**Description:**  
This script enforces, checks, or reverts LmCompatibilityLevel to block NTLMv1 (CVE-2025-21311 workaround). It sets the registry value to level 5, which sends NTLMv2 only and refuses LM & NTLM. A restart is NOT required; the setting is effective immediately.

**Parameters:**
- `-Enable`: Sets LmCompatibilityLevel = 5 (NTLMv2 only; refuse LM & NTLM).
- `-Disable`: Removes LmCompatibilityLevel (Not Defined).
- `-Check`: Checks the current status of LmCompatibilityLevel.

**Example Usage:**

```powershell
.\Set-LmCompatibilityLevel.ps1 -Enable
```


### 4. Set-LocalAccountNames.ps1

**Description:**  
This script renames and optionally disables or enables the local Administrator and Guest accounts.

**Parameters:**
- `-NewAdminName <string>`: The new name for the Administrator account.
- `-NewGuestName <string>`: The new name for the Guest account.
- `-DisableAccounts`: Disables the Administrator and Guest accounts after renaming.
- `-EnableAccounts`: Enables the Administrator and Guest accounts after renaming.

**Example Usage:**

```powershell
.\Set-LocalAccountNames.ps1 -NewAdminName "Admin123" -NewGuestName "Visitor" -DisableAccounts
```


### 5. Set-NullSessions.ps1

**Description:**  
This script restricts null sessions by modifying registry settings to prevent unauthorized access. It can restrict anonymous access and null session access.

**Parameters:**
- `-RestrictAnonymous`: Enables restriction of anonymous access.
- `-RestrictNullSessionAccess`: Enables restriction of null session access.
- `-EnableNullSessionAccess`: Enables null session access.
- `-EnableAnonymous`: Enables anonymous access.
- `-Check`: Checks the current null session restriction status without making any changes.

**Example Usage:**

```powershell
.\Set-NullSessions.ps1 -RestrictAnonymous -RestrictNullSessionAccess
```


### 6. Set-SMBSigning.ps1

**Description:**  
This script enables or disables SMB Signing on both the client and server sides on Windows 10 and 11.

**Parameters:**
- `-EnableClientSigning`: Enables SMB Signing on the client side.
- `-EnableServerSigning`: Enables SMB Signing on the server side.
- `-RequireServerSigning`: Requires SMB Signing on the server side.
- `-DisableClientSigning`: Disables SMB Signing on the client side.
- `-DisableServerSigning`: Disables SMB Signing on the server side.
- `-DisableRequireServerSigning`: Disables the requirement for SMB Signing on the server side.
- `-EnableAllRequiredSigning`: Enables all required SMB Signing on both client and server sides.
- `-Check`: Checks the current SMB Signing status without making any changes.

**Example Usage:**

```powershell
.\Set-SMBSigning.ps1 -EnableClientSigning -EnableServerSigning -RequireServerSigning
```


### 7. Set-SMBv1.ps1

**Description:**  
This script enables or disables SMBv1 on both the client and server sides on Windows 10 and 11. SMBv1 is a legacy protocol that should typically be disabled for security reasons.

**Parameters:**
- `-Enable`: Enables SMBv1 on both the client and server sides.
- `-Disable`: Disables SMBv1 on both the client and server sides.
- `-Check`: Checks the current SMBv1 status without making any changes.

**Example Usage:**

```powershell
.\Set-SMBv1.ps1 -Disable
```


### 8. Set-WinVerifyTrust.ps1

**Description:**  
This script enables, checks, or disables the EnableCertPaddingCheck mitigation for CVE-2013-3900. It configures the WinTrust registry value in both 64-bit and 32-bit registry views. A system restart is required after enabling or disabling for the change to take effect.

**Parameters:**
- `-Enable`: Enables the mitigation by setting REG_DWORD = 1.
- `-Disable`: Disables the mitigation by removing the value.
- `-Check`: Checks the current status of EnableCertPaddingCheck.

**Example Usage:**

```powershell
.\Set-WinVerifyTrust.ps1 -Enable
```


### 9. Set-Paint3d.ps1

**Description:**  
This script manages Microsoft Paint 3D (Microsoft.MSPaint) installations on Windows 10/11 systems. It provides functionality to check installation status (including vulnerability detection for outdated versions), update existing installations, and completely uninstall Paint 3D. Note: Microsoft discontinued Paint 3D on November 4, 2024, so new installations are no longer possible.

**Parameters:**
- `-Check`: Checks Paint and Paint 3D installation status, including vulnerability detection against a safe version baseline.
- `-Update`: Checks for updates to existing Paint 3D installations (limited functionality due to discontinuation).
- `-Uninstall`: Uninstalls Paint 3D using winget and Appx package removal. Requires admin rights.
- `-AllUsers`: Applies operations to all users (requires admin rights for Paint 3D detection).
- `-SafePaint3DVersion`: Baseline version for vulnerability checking (default: 6.2305.16087.0).

**Example Usage:**

```powershell
.\Set-Paint3d.ps1 -Check
```

```powershell
.\Set-Paint3d.ps1 -Uninstall -AllUsers
```

## Prerequisites

- PowerShell 5.1 or later
- Administrative privileges

## Usage Manual Execution

1. Open PowerShell with administrative privileges.
2. Navigate to the directory containing the script.
3. Execute the script with the desired parameters.

**Note:** If you receive an error that an execution policy has prevented the script from running, run the following command:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

## Automatic deployment through RMM tools

1. Get the SHA256 Hash of the script.

```Powershell
$scriptUrl = "<RAW GitHubLink>"

# Define the local path to save the downloaded script in the Windows Temp directory
$tempDirectory = [System.IO.Path]::GetTempPath()
$localScriptPath = Join-Path -Path $tempDirectory -ChildPath "Set-NullSessions.Tests.ps1"

# Download the script
Write-Host "Downloading script from $scriptUrl..."
Invoke-WebRequest -Uri $scriptUrl -OutFile $localScriptPath -UseBasicParsing

# Check if the script was downloaded successfully
if (Test-Path -Path $localScriptPath) {
    Write-Host "Script downloaded successfully to $localScriptPath"
    
    # Calculate the SHA256 checksum of the downloaded file
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $fileStream = [System.IO.File]::OpenRead($localScriptPath)
    try {
        $checksumBytes = $sha256.ComputeHash($fileStream)
        $checksum = -join ($checksumBytes | ForEach-Object { $_.ToString("x2") })
        Write-Host "SHA256 Hash of the downloaded file: $checksum"
    } finally {
        $fileStream.Close()
    }
} else {
    Write-Host "Failed to download the script. Please check the URL or your network connection."
}
```

2. Run the below powershell to download, execute and remove itself once the action is complete. refer to he output from your RMM tool to confirm it is completed.

```PowerShell
# Define the URL of the script to download
$scriptUrl = "<RAW GitHubLink>"

# Define the expected SHA256 checksum of the script (get this value from the source)
$expectedChecksum = "<SHA256 CHECKSUM>"

# Define the local path to save the downloaded script in the Windows Temp directory
$tempDirectory = [System.IO.Path]::GetTempPath()
$localScriptPath = Join-Path -Path $tempDirectory -ChildPath "Set-SMBv1.ps1"

# Function to calculate the SHA256 checksum of a file
function Get-FileChecksum($filePath) {
    if (-not (Test-Path -Path $filePath)) {
        return $null
    }
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $fileStream = [System.IO.File]::OpenRead($filePath)
    try {
        $checksumBytes = $sha256.ComputeHash($fileStream)
        return -join ($checksumBytes | ForEach-Object { $_.ToString("x2") })
    } finally {
        $fileStream.Close()
    }
}

# Check if the script already exists and verify its checksum
if (Test-Path -Path $localScriptPath) {
    Write-Host "Script already exists at $localScriptPath. Verifying its checksum..."
    $currentChecksum = Get-FileChecksum -filePath $localScriptPath
    if ($currentChecksum -eq $expectedChecksum) {
        Write-Host "Checksum verified. The existing file is valid. Proceeding with execution."
    } else {
        Write-Host "Checksum mismatch. Replacing the file with the new version..."
        Remove-Item -Path $localScriptPath -Force -ErrorAction SilentlyContinue
    }
}

# Download the script
Write-Host "Downloading script from $scriptUrl..."
Invoke-WebRequest -Uri $scriptUrl -OutFile $localScriptPath -UseBasicParsing

# Verify the checksum of the downloaded file
Write-Host "Verifying checksum of the downloaded script..."
$downloadedChecksum = Get-FileChecksum -filePath $localScriptPath
if ($downloadedChecksum -eq $expectedChecksum) {
    Write-Host "Checksum verification passed. Proceeding with execution..."
    
    # Import the script
    Write-Host "Executing the script..."
    . $localScriptPath <PARAMETER>

    # Cleanup: Remove the downloaded script
    Write-Host "Cleaning up..."
    Remove-Item -Path $localScriptPath -Force -ErrorAction SilentlyContinue

    if (-not (Test-Path -Path $localScriptPath)) {
        Write-Host "Cleanup complete. Script removed successfully."
    } else {
        Write-Host "Cleanup failed. Script file still exists: $localScriptPath"
    }
} else {
    Write-Host "Checksum verification failed. The file may be corrupted or tampered with. Exiting..."
    Remove-Item -Path $localScriptPath -Force -ErrorAction SilentlyContinue
    exit 1
}

```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request with your changes.

## Disclaimer

These scripts modify system settings and require administrative privileges. Use them at your own risk. Always ensure you have backups and understand the changes being made to your system.
