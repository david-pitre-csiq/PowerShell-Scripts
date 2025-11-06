# Set-LmCompatibilityLevel

## Description

`Set-LmCompatibilityLevel.ps1` is a PowerShell script that configures the **LmCompatibilityLevel** registry value to mitigate [CVE-2025-21311](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-21311) by blocking NTLMv1 authentication.  
This setting enforces NTLMv2-only authentication, preventing attackers from exploiting weaker NTLMv1 protocols.

The script provides options to **enable**, **disable**, or **check** the current mitigation state for both 64-bit and 32-bit registry locations.

---

## Key Features

- **Enable / Disable Mitigation**  
  Easily enable or disable the `LmCompatibilityLevel` registry key in both 32-bit and 64-bit registry paths.

- **Check Status**  
  View the current status of the mitigation without making changes, including decoded meaning of each level.

- **Accurate Registry Handling**  
  Uses .NET registry APIs to ensure consistent behavior regardless of PowerShell host bitness.

- **Logging & Error Handling**  
  Detailed logging and clear error messages for auditability and troubleshooting.

- **Command Pattern Architecture**  
  Implements a clean, extensible structure for registry operations.

- **No Reboot Required**  
  Changes take effect immediately without requiring a system restart.

---

## Usage

| Parameter | Description |
|-----------|-------------|
| `-Check`   | Checks the current status of `LmCompatibilityLevel`. |
| `-Enable`  | Enables the mitigation by setting `LmCompatibilityLevel` to `5` (REG_DWORD). |
| `-Disable` | Disables the mitigation by removing the registry value. |

### Examples

```powershell
# Enable the mitigation
.\Set-LmCompatibilityLevel.ps1 -Enable

# Check current status
.\Set-LmCompatibilityLevel.ps1 -Check

# Disable the mitigation
.\Set-LmCompatibilityLevel.ps1 -Disable
```

---

## LmCompatibilityLevel Values

The script supports the following compatibility levels:

| Value | Description |
|-------|-------------|
| 0 | Send LM & NTLM responses |
| 1 | Send LM & NTLM – use NTLMv2 session security if negotiated |
| 2 | Send NTLM response only |
| 3 | Send NTLMv2 response only |
| 4 | Send NTLMv2 response only. Refuse LM |
| 5 | Send NTLMv2 response only. Refuse LM & NTLM (Recommended) |

When enabled, the script sets the value to **5**, which is the most secure setting and blocks both LM and NTLMv1 authentication.

---

## Output Example

```
[2025-01-15 10:41:27] [Info] Starting. Checking for administrative rights...
[2025-01-15 10:41:27] [Info] Queued: Enable mitigation (set REG_DWORD=5).
[2025-01-15 10:41:27] [Info] Executing requested operations...
[2025-01-15 10:41:27] [Info] Set LmCompatibilityLevel at HKLM:\SYSTEM\CurrentControlSet\Control\Lsa (64-bit view): REG_DWORD = 5.
[2025-01-15 10:41:27] [Info] Set LmCompatibilityLevel at HKLM:\SYSTEM\CurrentControlSet\Control\Lsa (32-bit view): REG_DWORD = 5.
[2025-01-15 10:41:27] [Info] Changes applied. A restart is NOT required; the setting is effective immediately.
[2025-01-15 10:41:27] [Info] Finished.
```

---

## Requirements

* **Windows PowerShell 5.1 or later**
* **Administrative privileges**
* **No system restart required** - changes take effect immediately

## Troubleshooting

If you receive an error that an execution policy has prevented the script from running, run the following command:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

---

## Security Note

This script directly manages Windows NTLM authentication behavior by setting `LmCompatibilityLevel`.  
Enabling this key to level 5 strengthens authentication security by blocking NTLMv1, but may cause compatibility issues with:

* Legacy applications that only support NTLMv1
* Older network devices that cannot negotiate NTLMv2
* Systems in mixed environments with older Windows versions

Before widespread deployment:

* Test in a controlled environment.
* Verify that all applications and network resources support NTLMv2.
* Monitor authentication logs for any failures.

Microsoft reference:
[CVE-2025-21311 | NTLM Authentication Vulnerability](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-21311)

---

## Related Security Frameworks

This script supports security configuration practices aligned with:

* **CIS Control 4: Secure Configuration of Enterprise Assets and Software**
  * 4.1: Establish and maintain a secure configuration process
  * 4.2: Establish and maintain secure configuration settings for endpoints

* **CIS Control 8: Audit Log Management**
  * 8.1: Establish and maintain an audit log management process

By enforcing NTLMv2-only authentication, this script helps **reduce the risk of credential theft and relay attacks**, improving system security and compliance posture.

---

## License

This script is provided **as-is** without warranty.  
Use at your own risk and verify in a non-production environment before deployment.

