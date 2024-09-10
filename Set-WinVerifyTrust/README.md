# Set-WinVerifyTrust

## Description

`Set-WinVerifyTrust.ps1` is a PowerShell script designed to manage the `EnableCertPaddingCheck` registry key to mitigate CVE-2013-3900. It provides functionality to enable, disable, or check the status of the `EnableCertPaddingCheck` setting in both the 32-bit and 64-bit registry paths.

## Key Features

- **Enable/Disable Cert Padding Check**: Allows enabling or disabling the `EnableCertPaddingCheck` registry key.
- **Check Status**: Check the current status of the `EnableCertPaddingCheck` registry key without making any changes.
- **Logging**: Comprehensive logging of all operations for auditing and troubleshooting.
- **Error Handling**: Robust error handling and informative error messages.
- **Command Pattern**: Utilises the Command design pattern for flexible and extensible registry management operations.

## Usage

The script supports the following parameters:

- `-Check`: Checks the current status of `EnableCertPaddingCheck`.
- `-Enable`: Enables the `EnableCertPaddingCheck` registry key.
- `-Disable`: Disables the `EnableCertPaddingCheck` registry key.

## Example
.\Set-WinVerifyTrust.ps1 -Enable


## Requirements

- Windows PowerShell 5.1 or later
- Administrative privileges

## Security Note

This script is designed to enhance system security by managing the `EnableCertPaddingCheck` registry key. Always use caution when modifying system settings and ensure you have proper authorisation before running this script in a production environment.

## CIS Control

This script helps address CIS Control 9: Limitation and Control of Network Ports, Protocols, and Services. Specifically, it aids in implementing the following sub-controls:

- 9.2: Ensure Only Necessary Ports, Protocols, and Services Are Running
- 9.4: Apply Host-Based Firewalls or Port Filtering

By managing the `EnableCertPaddingCheck` registry key, this script contributes to reducing the attack surface and improving the overall security posture of Windows systems in alignment with CIS best practices.
