# Windows Configuration Scripts

This repository contains PowerShell scripts for configuring various settings on Windows 10 and Windows 11. Each script requires administrative privileges to run and provides functionality to modify system settings such as Autoplay, local account names, and SMB Signing etc.

These scripts are used to address commmon Windows vulnerabilities identified by an authenticated vulnerability scanner such as Qualys or Nessus. 

## Scripts

### 1. Set-Autoplay.ps1

**Description:**  
This script disables, enables, or checks the status of Autoplay and Autorun on Windows 10 and Windows 11 by modifying the registry settings.

**Parameters:**
- `-Disable`: Disables Autoplay and Autorun.
- `-Enable`: Enables Autoplay and Autorun.
- `-Check`: Retrieves the current Autoplay and Autorun status.

**Example Usage:**

.\Set-Autoplay.ps1 -Disable


### 2. Set-LocalAccountNames.ps1

**Description:**  
This script renames and optionally disables or enables the local Administrator and Guest accounts.

**Parameters:**
- `-NewAdminName <string>`: The new name for the Administrator account.
- `-NewGuestName <string>`: The new name for the Guest account.
- `-DisableAccounts`: Disables the Administrator and Guest accounts after renaming.
- `-EnableAccounts`: Enables the Administrator and Guest accounts after renaming.

**Example Usage:**

.\Set-LocalAccountNames.ps1 -NewAdminName "Admin123" -NewGuestName "Visitor" -DisableAccounts


### 3. Set-SMBSigning.ps1

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

.\Enable-SMBSigning.ps1 -EnableClientSigning -EnableServerSigning -RequireServerSigning

## Prerequisites

- PowerShell 5.1 or later
- Administrative privileges

## Usage Manual Execution

1. Open PowerShell with administrative privileges.
2. Navigate to the directory containing the script.
3. Execute the script with the desired parameters.

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
    . $localScriptPath

    # Execute the desired command
    Write-Host "Running the command: Set-NullSessions.ps1 -RestrictAnonymous -RestrictNullSessionAccess"
    .\<SCRIPT> <PARAMETER>

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

---

**Author:** David Pitre
**Contact:** https://www.csiq.co.uk
