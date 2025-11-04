<#
.SYNOPSIS
    Enables, checks, or disables the EnableCertPaddingCheck mitigation for CVE-2013-3900.

.DESCRIPTION
    Configures the WinTrust registry value 'EnableCertPaddingCheck' in the correct
    64-bit and/or 32-bit registry views (as applicable) using .NET Registry APIs,
    so it works regardless of the bitness of the PowerShell host.

    -Enable  : Creates/sets the value as REG_DWORD = 1 (recommended).
    -Disable : Deletes the value (per Microsoft guidance).
    -Check   : Reports the current status in each registry view.

    NOTE: A system restart is required after enabling or disabling for the change to take effect.

.PARAMETER Check
    Checks the current status of EnableCertPaddingCheck.

.PARAMETER Enable
    Enables the mitigation by setting REG_DWORD 1.

.PARAMETER Disable
    Disables the mitigation by removing the value.

.EXAMPLE
    .\Set-WinVerifyTrust.ps1 -Check

.EXAMPLE
    .\Set-WinVerifyTrust.ps1 -Enable

.EXAMPLE
    .\Set-WinVerifyTrust.ps1 -Disable

.EXAMPLE
    .\Set-WinVerifyTrust.ps1 -Enable -WhatIf
    # Shows what would change without making changes.

.NOTES
    Requires administrative privileges.
    Tested on Windows 10/11 with PowerShell 5.1+.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$Check,
    [switch]$Enable,
    [switch]$Disable
)

#region Setup & Utilities
$ErrorActionPreference = 'Stop'
$script:WintrustSubkeyPath = 'Software\Microsoft\Cryptography\Wintrust\Config'
$script:RegValueName = 'EnableCertPaddingCheck'

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message,
        [ValidateSet('Info','Warning','Error')]
        [string]$Level = 'Info'
    )
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = "[$ts] [$Level] $Message"
    switch ($Level) {
        'Info'    { Write-Host    $line }
        'Warning' { Write-Warning $line }
        'Error'   { Write-Error   $line }
    }
}

function Test-AdminRights {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-RegistryViews {
    if ([Environment]::Is64BitOperatingSystem) {
        [Microsoft.Win32.RegistryView]::Registry64, [Microsoft.Win32.RegistryView]::Registry32
    } else {
        [Microsoft.Win32.RegistryView]::Registry32
    }
}

function Get-DisplayPath {
    param([Microsoft.Win32.RegistryView]$View)
    if ([Environment]::Is64BitOperatingSystem) {
        if ($View -eq [Microsoft.Win32.RegistryView]::Registry64) {
            'HKLM:\Software\Microsoft\Cryptography\Wintrust\Config'
        } else {
            'HKLM:\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config'
        }
    } else {
        'HKLM:\Software\Microsoft\Cryptography\Wintrust\Config'
    }
}

function Open-OrCreate-ConfigKey {
    param([Microsoft.Win32.RegistryView]$View)
    $hive   = [Microsoft.Win32.RegistryHive]::LocalMachine
    $base   = [Microsoft.Win32.RegistryKey]::OpenBaseKey($hive, $View)
    $key    = $base.OpenSubKey($script:WintrustSubkeyPath, $true)
    if (-not $key) { $key = $base.CreateSubKey($script:WintrustSubkeyPath) }
    return $key
}
#endregion

#region Actions
function Get-EnableCertPaddingCheck {
    [CmdletBinding()]
    param()

    $results = @()
    foreach ($view in (Get-RegistryViews)) {
        $display = Get-DisplayPath -View $view
        $exists  = $false
        $value   = $null
        $kind    = $null
        $enabled = $false
        $status  = 'Missing'

        try {
            $hive = [Microsoft.Win32.RegistryHive]::LocalMachine
            $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($hive, $view)
            $key  = $base.OpenSubKey($script:WintrustSubkeyPath, $false)
            if ($key) {
                $exists = $true
                $value  = $key.GetValue($script:RegValueName, $null,
                                        [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                try { $kind = $key.GetValueKind($script:RegValueName) } catch { $kind = $null }
                if ($null -ne $value) {
                    $num = 0
                    $isNum = [int]::TryParse([string]$value, [ref]$num)
                    if ($isNum -and $num -ne 0) { $enabled = $true }
                    elseif (($value -is [int] -or $value -is [long]) -and [int64]$value -ne 0) { $enabled = $true }
                    $status = if ($enabled) { 'Enabled' } else { 'Disabled' }
                } else {
                    $status = 'Missing'
                }
                $key.Close()
            }
        } catch {
            $status = "Error: $($_.Exception.Message)"
        }

        $results += [pscustomobject]@{
            View        = if ($view -eq [Microsoft.Win32.RegistryView]::Registry64) {'Registry64'} else {'Registry32'}
            Path        = $display
            Exists      = $exists
            Value       = $value
            ValueKind   = if ($kind) { $kind.ToString() } else { $null }
            Status      = $status
        }
    }

    foreach ($r in $results) {
        Write-Log -Message ("{0} --> {1}: {2}{3}" -f $r.View, $r.Path, $r.Status,
            ($(if ($r.Value -ne $null) { " (Value=$($r.Value); Type=$($r.ValueKind))" } else { "" }))) -Level 'Info'
    }

    return $results
}

function Set-EnableCertPaddingCheck {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param()

    $changed = $false
    foreach ($view in (Get-RegistryViews)) {
        $display = Get-DisplayPath -View $view
        try {
            $key = Open-OrCreate-ConfigKey -View $view
            $cur = $key.GetValue($script:RegValueName, $null)
            $kind = $null
            try { $kind = $key.GetValueKind($script:RegValueName) } catch { $kind = $null }

            $needsUpdate = $true
            if ($null -ne $cur -and $kind -eq [Microsoft.Win32.RegistryValueKind]::DWord) {
                $needsUpdate = ([int64]$cur -eq 0)
            }

            if ($PSCmdlet.ShouldProcess($display, "Set ${script:RegValueName}=DWORD:1")) {
                if ($needsUpdate -or $kind -ne [Microsoft.Win32.RegistryValueKind]::DWord) {
                    $key.SetValue($script:RegValueName, 1, [Microsoft.Win32.RegistryValueKind]::DWord)
                    Write-Log -Message "Enabled ${script:RegValueName} at $($display): REG_DWORD = 1." -Level 'Info'
                    $changed = $true
                } else {
                    Write-Log -Message "${script:RegValueName} already enabled at $($display): REG_DWORD = $cur." -Level 'Info'
                }
            }
            $key.Close()
        } catch {
            Write-Log -Message "Failed to set ${script:RegValueName} at $($display): $($_.Exception.Message)" -Level 'Error'
            throw
        }
    }
    return $changed
}

function Remove-EnableCertPaddingCheck {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param()

    $changed = $false
    foreach ($view in (Get-RegistryViews)) {
        $display = Get-DisplayPath -View $view
        try {
            $hive = [Microsoft.Win32.RegistryHive]::LocalMachine
            $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($hive, $view)
            $key  = $base.OpenSubKey($script:WintrustSubkeyPath, $true)
            if (-not $key) {
                Write-Log -Message "No config key present at $($display); nothing to remove." -Level 'Info'
                continue
            }

            $cur = $key.GetValue($script:RegValueName, $null)
            if ($null -ne $cur) {
                if ($PSCmdlet.ShouldProcess($display, "Remove ${script:RegValueName}")) {
                    $key.DeleteValue($script:RegValueName, $false)
                    Write-Log -Message "Removed ${script:RegValueName} at $($display)." -Level 'Info'
                    $changed = $true
                }
            } else {
                Write-Log -Message "No ${script:RegValueName} value at $($display); nothing to remove." -Level 'Info'
            }
            $key.Close()
        } catch {
            Write-Log -Message "Failed to remove ${script:RegValueName} at $($display): $($_.Exception.Message)" -Level 'Error'
            throw
        }
    }
    return $changed
}
#endregion

#region Command classes
class Command { [void] Execute() { } }

class EnableCertPaddingCheckCommand : Command {
    [bool] $Changed = $false
    [void] Execute() { $this.Changed = Set-EnableCertPaddingCheck }
}

class DisableCertPaddingCheckCommand : Command {
    [bool] $Changed = $false
    [void] Execute() { $this.Changed = Remove-EnableCertPaddingCheck }
}

class CheckCertPaddingCheckCommand : Command { [void] Execute() { [void](Get-EnableCertPaddingCheck) } }

class CertPaddingCheckManager {
    [System.Collections.Generic.List[Command]] $Commands = [System.Collections.Generic.List[Command]]::new()
    [void] AddCommand([Command]$c) { $this.Commands.Add($c) }
    [bool] ExecuteCommands() {
        $anyChanged = $false
        foreach ($c in $this.Commands) {
            $c.Execute()
            if ($c -is [EnableCertPaddingCheckCommand] -and $c.Changed) { $anyChanged = $true }
            if ($c -is [DisableCertPaddingCheckCommand] -and $c.Changed) { $anyChanged = $true }
        }
        return $anyChanged
    }
}
#endregion

#region Main
function Main {
    begin {
        Write-Log -Message "Starting. Checking for administrative rights..." -Level 'Info'
        if (-not (Test-AdminRights)) {
            throw "Administrator rights are required. Please run this script in an elevated PowerShell session."
        }

        if (-not ($Check -or $Enable -or $Disable)) {
            Write-Log -Message "No action specified. Use -Check, -Enable, or -Disable." -Level 'Warning'
            return
        }

        if ($Enable -and $Disable) {
            throw "Conflicting parameters: -Enable and -Disable cannot be used together."
        }
    }
    process {
        $mgr = [CertPaddingCheckManager]::new()

        if ($Check)   { $mgr.AddCommand([CheckCertPaddingCheckCommand]::new());   Write-Log -Message "Queued: Check current status." -Level 'Info' }
        if ($Enable)  { $mgr.AddCommand([EnableCertPaddingCheckCommand]::new());  Write-Log -Message "Queued: Enable mitigation (set REG_DWORD=1)." -Level 'Info' }
        if ($Disable) { $mgr.AddCommand([DisableCertPaddingCheckCommand]::new()); Write-Log -Message "Queued: Disable mitigation (remove value)." -Level 'Info' }

        Write-Log -Message "Executing requested operations..." -Level 'Info'
        $changed = $mgr.ExecuteCommands()
        if ($changed) {
            Write-Log -Message "A system restart is required for changes to take effect." -Level 'Warning'
        } elseif (-not $Check) {
            Write-Log -Message "No changes were necessary." -Level 'Info'
        }
    }
    end { Write-Log -Message "Finished." -Level 'Info' }
}

Main @PSBoundParameters
#endregion
