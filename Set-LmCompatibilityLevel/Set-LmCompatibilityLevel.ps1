<#
.SYNOPSIS
    Enforces, checks, or reverts LmCompatibilityLevel to block NTLMv1 (CVE-2025-21311 workaround).

.DESCRIPTION
    Sets HKLM\SYSTEM\CurrentControlSet\Control\Lsa\LmCompatibilityLevel:

      -Enable  -> REG_DWORD = 5  (Send NTLMv2 only; refuse LM & NTLM)
      -Disable -> Remove value   (Not Defined)
      -Check   -> Show current value + decoded meaning for each registry view

    NOTE: A restart is NOT required; the setting is effective immediately.

.PARAMETER Check
    Checks the current status of LmCompatibilityLevel.

.PARAMETER Enable
    Sets LmCompatibilityLevel = 5 (NTLMv2 only; refuse LM & NTLM).

.PARAMETER Disable
    Removes LmCompatibilityLevel (Not Defined).

.EXAMPLE
    .\Set-LmCompatibilityLevel.ps1 -Check

.EXAMPLE
    .\Set-LmCompatibilityLevel.ps1 -Enable

.EXAMPLE
    .\Set-LmCompatibilityLevel.ps1 -Disable

.EXAMPLE
    .\Set-LmCompatibilityLevel.ps1 -Enable -WhatIf
    # Shows what would change without making changes.

.NOTES
    Requires administrative privileges.
    Tested on Windows 10/11 with PowerShell 5.1+.
    Avoids PowerShell classes to prevent "PowerShell Class Assembly" cast errors when re-running in the same session.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$Check,
    [switch]$Enable,
    [switch]$Disable
)

#region Setup & Utilities
$ErrorActionPreference = 'Stop'
$script:LsaSubkeyPath = 'System\CurrentControlSet\Control\Lsa'
$script:RegValueName = 'LmCompatibilityLevel'

$script:LmLevelMap = @{
    0 = 'Send LM & NTLM responses'
    1 = 'Send LM & NTLM – use NTLMv2 session security if negotiated'
    2 = 'Send NTLM response only'
    3 = 'Send NTLMv2 response only'
    4 = 'Send NTLMv2 response only. Refuse LM'
    5 = 'Send NTLMv2 response only. Refuse LM & NTLM'
}

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
    $suffix = if ([Environment]::Is64BitOperatingSystem) {
        if ($View -eq [Microsoft.Win32.RegistryView]::Registry64) { ' (64-bit view)' } else { ' (32-bit view)' }
    } else { '' }
    'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' + $suffix
}

function Open-OrCreateLsaKey {
    param([Microsoft.Win32.RegistryView]$View)
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $View)
    $key  = $base.OpenSubKey($script:LsaSubkeyPath, $true)
    if (-not $key) { $key = $base.CreateSubKey($script:LsaSubkeyPath) }
    return $key
}

function Get-LevelText {
    param([Nullable[int]]$Value)
    if ($null -eq $Value) { return 'Not Defined' }
    elseif ($script:LmLevelMap.ContainsKey($Value)) { return $script:LmLevelMap[$Value] }
    else { return "Unknown ($Value)" }
}
#endregion

#region Actions
function Get-LmCompatibilityLevel {
    [CmdletBinding()]
    param()

    $results = @()
    foreach ($view in (Get-RegistryViews)) {
        $display = Get-DisplayPath -View $view
        $exists  = $false
        $value   = $null
        $kind    = $null
        $status  = 'Missing'

        try {
            $hive = [Microsoft.Win32.RegistryHive]::LocalMachine
            $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($hive, $view)
            $key  = $base.OpenSubKey($script:LsaSubkeyPath, $false)
            if ($key) {
                $exists = $true
                $value  = $key.GetValue($script:RegValueName, $null,
                                        [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                try { $kind = $key.GetValueKind($script:RegValueName) } catch { $kind = $null }
                if ($null -ne $value) {
                    $status = Get-LevelText -Value $value
                } else {
                    $status = 'Not Defined'
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
        $detail = if ($null -ne $r.Value) { " (Value=$($r.Value); Type=$($r.ValueKind))" } else { "" }
        Write-Log -Message ("{0} --> {1}: {2}{3}" -f $r.View, $r.Path, $r.Status, $detail) -Level 'Info'
    }

    return $results
}

function Set-LmCompatibilityLevel {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param()

    $changed = $false
    $wouldChange = $false
    foreach ($view in (Get-RegistryViews)) {
        $display = Get-DisplayPath -View $view
        try {
            $key = Open-OrCreateLsaKey -View $view
            $cur = $key.GetValue($script:RegValueName, $null)
            $kind = $null
            try { $kind = $key.GetValueKind($script:RegValueName) } catch { $kind = $null }

            $needsUpdate = -not ($null -ne $cur -and $kind -eq [Microsoft.Win32.RegistryValueKind]::DWord -and [int]$cur -eq 5)

            if ($needsUpdate) {
                $wouldChange = $true
                if ($PSCmdlet.ShouldProcess($display, "Set ${script:RegValueName}=DWORD:5 (NTLMv2 only; refuse LM & NTLM)")) {
                    $key.SetValue($script:RegValueName, 5, [Microsoft.Win32.RegistryValueKind]::DWord)
                    Write-Log -Message "Set ${script:RegValueName} at $($display): REG_DWORD = 5." -Level 'Info'
                    $changed = $true
                }
            } else {
                Write-Log -Message "${script:RegValueName} already set to 5 at $($display)." -Level 'Info'
            }
            $key.Close()
        } catch {
            Write-Log -Message "Failed to set ${script:RegValueName} at $($display): $($_.Exception.Message)" -Level 'Error'
            throw
        }
    }
    return @{ Changed = $changed; WouldChange = $wouldChange }
}

function Remove-LmCompatibilityLevel {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param()

    $changed = $false
    $wouldChange = $false
    foreach ($view in (Get-RegistryViews)) {
        $display = Get-DisplayPath -View $view
        try {
            $hive = [Microsoft.Win32.RegistryHive]::LocalMachine
            $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($hive, $view)
            $key  = $base.OpenSubKey($script:LsaSubkeyPath, $true)
            if (-not $key) {
                Write-Log -Message "No LSA key at $($display); nothing to remove." -Level 'Info'
                continue
            }

            $cur = $key.GetValue($script:RegValueName, $null)
            if ($null -ne $cur) {
                $wouldChange = $true
                if ($PSCmdlet.ShouldProcess($display, "Remove ${script:RegValueName} (Not Defined)")) {
                    $key.DeleteValue($script:RegValueName, $false)
                    Write-Log -Message "Removed ${script:RegValueName} at $($display)." -Level 'Info'
                    $changed = $true
                }
            } else {
                Write-Log -Message "No ${script:RegValueName} at $($display); nothing to remove." -Level 'Info'
            }
            $key.Close()
        } catch {
            Write-Log -Message "Failed to remove ${script:RegValueName} at $($display): $($_.Exception.Message)" -Level 'Error'
            throw
        }
    }
    return @{ Changed = $changed; WouldChange = $wouldChange }
}
#endregion

#region Command classes
class Command { [void] Execute() { } }

class EnableLmCompatibilityLevelCommand : Command {
    [bool] $Changed = $false
    [bool] $WouldChange = $false
    [void] Execute() {
        $result = Set-LmCompatibilityLevel
        $this.Changed = $result.Changed
        $this.WouldChange = $result.WouldChange
    }
}

class DisableLmCompatibilityLevelCommand : Command {
    [bool] $Changed = $false
    [bool] $WouldChange = $false
    [void] Execute() {
        $result = Remove-LmCompatibilityLevel
        $this.Changed = $result.Changed
        $this.WouldChange = $result.WouldChange
    }
}

class CheckLmCompatibilityLevelCommand : Command { [void] Execute() { [void](Get-LmCompatibilityLevel) } }

class LmCompatibilityLevelManager {
    [System.Collections.Generic.List[Command]] $Commands = [System.Collections.Generic.List[Command]]::new()
    [void] AddCommand([Command]$c) { $this.Commands.Add($c) }
    [hashtable] ExecuteCommands() {
        $anyChanged = $false
        $anyWouldChange = $false
        foreach ($c in $this.Commands) {
            $c.Execute()
            if ($c -is [EnableLmCompatibilityLevelCommand]) {
                if ($c.Changed) { $anyChanged = $true }
                if ($c.WouldChange) { $anyWouldChange = $true }
            }
            if ($c -is [DisableLmCompatibilityLevelCommand]) {
                if ($c.Changed) { $anyChanged = $true }
                if ($c.WouldChange) { $anyWouldChange = $true }
            }
        }
        return @{ Changed = $anyChanged; WouldChange = $anyWouldChange }
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

        # Warn about common misspelling some tools use
        try {
            $miss = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LmCompatabilityLvl' -ErrorAction SilentlyContinue
            if ($miss) {
                Write-Log -Message "Detected nonstandard value 'LmCompatabilityLvl'. Windows ignores this; use 'LmCompatibilityLevel'." -Level 'Warning'
            }
        } catch {}
    }
    process {
        $mgr = [LmCompatibilityLevelManager]::new()

        if ($Check)   { $mgr.AddCommand([CheckLmCompatibilityLevelCommand]::new());   Write-Log -Message "Queued: Check current status." -Level 'Info' }
        if ($Enable)  { $mgr.AddCommand([EnableLmCompatibilityLevelCommand]::new());  Write-Log -Message "Queued: Enable mitigation (set REG_DWORD=5)." -Level 'Info' }
        if ($Disable) { $mgr.AddCommand([DisableLmCompatibilityLevelCommand]::new()); Write-Log -Message "Queued: Disable mitigation (remove value)." -Level 'Info' }

        Write-Log -Message "Executing requested operations..." -Level 'Info'
        $result = $mgr.ExecuteCommands()
        if ($result.Changed) {
            Write-Log -Message "Changes applied. A restart is NOT required; the setting is effective immediately." -Level 'Info'
        } elseif ($result.WouldChange) {
            Write-Log -Message "Changes would be made, but -WhatIf was specified. No changes were applied." -Level 'Info'
        } elseif (-not $Check) {
            Write-Log -Message "No changes were necessary." -Level 'Info'
        }
    }
    end { Write-Log -Message "Finished." -Level 'Info' }
}

Main @PSBoundParameters
#endregion

