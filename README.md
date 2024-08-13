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

## Usage

1. Open PowerShell with administrative privileges.
2. Navigate to the directory containing the script.
3. Execute the script with the desired parameters.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request with your changes.

## Disclaimer

These scripts modify system settings and require administrative privileges. Use them at your own risk. Always ensure you have backups and understand the changes being made to your system.

---

**Author:** David Pitre
**Contact:** https://www.csiq.co.uk
