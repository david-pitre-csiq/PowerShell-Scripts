# Set-SMBv1

## Description

`Set-SMBv1.ps1` is a PowerShell script designed to manage SMBv1 (Server Message Block version 1) settings on Windows 10 and 11 systems. It provides functionality to enable or disable SMBv1 on both the client and server sides, as well as to check the current SMBv1 status.

## Key Features

- **Enable/Disable SMBv1**: Allows enabling or disabling SMBv1 on both client and server sides.
- **Check Status**: Check the current SMBv1 status without making any changes.
- **Logging**: Comprehensive logging of all operations for auditing and troubleshooting.
- **Error Handling**: Robust error handling and informative error messages.
- **Command Pattern**: Utilizes the Command design pattern for flexible and extensible SMBv1 management operations.

## Usage

The script supports the following parameters:

- `-Enable`: Enables SMBv1 on both the client and server sides.
- `-Disable`: Disables SMBv1 on both the client and server sides.
- `-Check`: Checks the current SMBv1 status without making any changes.

## Example

.\Set-SMBv1.ps1 -Disable

## Requirements

- Windows PowerShell 5.1 or later
- Administrative privileges

## Security Note

This script is designed to enhance system security by managing SMBv1 settings. Always use caution when modifying system settings and ensure you have proper authorization before running this script in a production environment.

## CIS Control

This script helps address CIS Control 9: Limitation and Control of Network Ports, Protocols, and Services. Specifically, it aids in implementing the following sub-controls:

- 9.2: Ensure Only Necessary Ports, Protocols, and Services Are Running
- 9.4: Apply Host-Based Firewalls or Port Filtering

By managing SMBv1 settings, this script contributes to reducing the attack surface and improving the overall security posture of Windows systems in alignment with CIS best practices.
