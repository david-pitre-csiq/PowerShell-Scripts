# Set-LocalAccountNames

## Description

`Set-LocalAccountNames.ps1` is a PowerShell script designed to enhance the security of Windows systems by managing local user accounts. It provides functionality to rename the built-in Administrator and Guest accounts, as well as optionally disable or enable these accounts.

## Key Features

- **Rename Accounts**: Allows renaming of the local Administrator and Guest accounts to custom names.
- **Enable/Disable Accounts**: Option to enable or disable the Administrator and Guest accounts after renaming.
- **Logging**: Comprehensive logging of all operations for auditing and troubleshooting.
- **Error Handling**: Robust error handling and informative error messages.
- **Command Pattern**: Utilises the Command design pattern for flexible and extensible account management operations.

## Usage

The script supports the following parameters:

- `-NewAdminName`: Specify a new name for the Administrator account.
- `-NewGuestName`: Specify a new name for the Guest account.
- `-DisableAccounts`: Switch to disable the accounts after renaming.
- `-EnableAccounts`: Switch to enable the accounts after renaming.

## Example
```
.\Set-LocalAccountNames.ps1 -NewAdminName "Admin123" -NewGuestName "Visitor" -DisableAccounts
```
## Requirements

- Windows PowerShell 5.1 or later
- Administrative privileges

## Security Note

This script is designed to enhance system security by obscuring default account names and managing their state. Always use caution when modifying system accounts and ensure you have proper authorisation before running this script in a production environment.

## CIS Control

This script helps address CIS Control 5: Account Management. Specifically, it aids in implementing the following sub-controls:

- 5.2: Maintain Inventory of Accounts
- 5.3: Disable Dormant Accounts
- 5.4: Restrict Administrator Privileges to Dedicated Administrator Accounts

By renaming and optionally disabling the built-in Administrator and Guest accounts, this script contributes to reducing the attack surface and improving the overall security posture of Windows systems in alignment with CIS best practices.



# Enable-SMBSigning

## Description

`Enable-SMBSigning.ps1` is a PowerShell script designed to manage SMB (Server Message Block) Signing settings on Windows 10 and 11 systems. It provides functionality to enable or disable SMB Signing on both the client and server sides, as well as to check the current SMB Signing status.

## Key Features

- **Enable/Disable SMB Signing**: Allows enabling or disabling SMB Signing on both client and server sides.
- **Require/Disable Required SMB Signing**: Option to require or disable the requirement for SMB Signing on the server side.
- **Check Status**: Check the current SMB Signing status without making any changes.
- **Logging**: Comprehensive logging of all operations for auditing and troubleshooting.
- **Error Handling**: Robust error handling and informative error messages.
- **Command Pattern**: Utilizes the Command design pattern for flexible and extensible SMB Signing management operations.

## Usage

The script supports the following parameters:

- `-EnableClientSigning`: Enables SMB Signing on the client side.
- `-EnableServerSigning`: Enables SMB Signing on the server side.
- `-RequireServerSigning`: Requires SMB Signing on the server side.
- `-DisableClientSigning`: Disables SMB Signing on the client side.
- `-DisableServerSigning`: Disables SMB Signing on the server side.
- `-DisableRequireServerSigning`: Disables the requirement for SMB Signing on the server side.
- `-EnableAllRequiredSigning`: Enables all required SMB Signing on both client and server sides.
- `-Check`: Checks the current SMB Signing status without making any changes.

## Example
```
.\Enable-SMBSigning.ps1 -EnableClientSigning -EnableServerSigning -RequireServerSigning

.\Enable-SMBSigning.ps1 -EnableAllRequiredSigning
```

## Requirements

- Windows PowerShell 5.1 or later
- Administrative privileges

## Security Note

This script is designed to enhance system security by managing SMB Signing settings. Always use caution when modifying system settings and ensure you have proper authorization before running this script in a production environment.

## CIS Control

This script helps address CIS Control 9: Limitation and Control of Network Ports, Protocols, and Services. Specifically, it aids in implementing the following sub-controls:

- 9.2: Ensure Only Necessary Ports, Protocols, and Services Are Running
- 9.4: Apply Host-Based Firewalls or Port Filtering

By managing SMB Signing settings, this script contributes to reducing the attack surface and improving the overall security posture of Windows systems in alignment with CIS best practices.
