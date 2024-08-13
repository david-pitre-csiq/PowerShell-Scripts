<#
.SYNOPSIS
    Ensures EnableCertPaddingCheck is set in the registry to mitigate CVE-2013-3900.
.DESCRIPTION
    This script sets, checks, or disables the EnableCertPaddingCheck registry key in both the 32-bit and 64-bit registry paths.
    It requires administrative privileges to run.
.PARAMETER Check
    If specified, checks the current status of EnableCertPaddingCheck.
.PARAMETER Enable
    If specified, enables EnableCertPaddingCheck.
.PARAMETER Disable
    If specified, disables EnableCertPaddingCheck.
.EXAMPLE
    .\Set-WinVerifyTrust.ps1 -Check
.EXAMPLE
    .\Set-WinVerifyTrust.ps1 -Enable
.EXAMPLE
    .\Set-WinVerifyTrust.ps1 -Disable
#>
#region Script Parameters
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $false)]
    [switch]$Check,

    [Parameter(Mandatory = $false)]
    [switch]$Enable,

    [Parameter(Mandatory = $false)]
    [switch]$Disable
)
#endregion

#region Script Setup
$ErrorActionPreference = 'Stop'
#endregion

#region Functions
function Write-Log {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("Info", "Warning", "Error")]
        [string]$Level
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] $Message"
    
    if ($Level) {
        $logMessage = "[$timestamp] [$Level] $Message"
        switch ($Level) {
            "Info" { Write-Verbose $logMessage }
            "Warning" { Write-Warning $logMessage }
            "Error" { Write-Error $logMessage }
        }
    }
    else {
        Write-Host $logMessage
    }
}

function Test-AdminRights {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-RegistryValue {
    param (
        [string]$Path,
        [string]$Name
    )

    if (Test-Path $Path) {
        $value = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        if ($null -ne $value) {
            return $value.$Name
        }
    }
    return $null
}
#endregion

#region Classes
#region Command Interface
class Command {
    [void] Execute() { }
}
#endregion

#region Concrete Commands
class EnableCertPaddingCheckCommand : Command {
    [void] Execute() {
        $regPaths = @(
            "HKLM:\Software\Microsoft\Cryptography\Wintrust\Config",
            "HKLM:\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config"
        )
        $regName = "EnableCertPaddingCheck"
        $regValue = 1

        foreach ($path in $regPaths) {
            if (-not (Test-Path $path)) {
                New-Item -Path $path -Force | Out-Null
            }
            Set-ItemProperty -Path $path -Name $regName -Value $regValue
            Write-Log -Message "Set $regName to $regValue at $path"
        }
    }
}

class DisableCertPaddingCheckCommand : Command {
    [void] Execute() {
        $regPaths = @(
            "HKLM:\Software\Microsoft\Cryptography\Wintrust\Config",
            "HKLM:\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config"
        )
        $regName = "EnableCertPaddingCheck"
        $regValue = 0

        foreach ($path in $regPaths) {
            if (-not (Test-Path $path)) {
                New-Item -Path $path -Force | Out-Null
            }
            Set-ItemProperty -Path $path -Name $regName -Value $regValue
            Write-Log -Message "Set $regName to $regValue at $path"
        }
    }
}

class CheckCertPaddingCheckCommand : Command {
    [void] Execute() {
        $regPaths = @(
            "HKLM:\Software\Microsoft\Cryptography\Wintrust\Config",
            "HKLM:\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config"
        )
        $regName = "EnableCertPaddingCheck"

        foreach ($path in $regPaths) {
            $value = Get-RegistryValue -Path $path -Name $regName
            switch ($value) {
                $null { Write-Log -Message "Current value of $regName at ${path}: Missing" }
                1 { Write-Log -Message "Current value of $regName at ${path}: Enabled" }
                0 { Write-Log -Message "Current value of $regName at ${path}: Disabled" }
                default { Write-Log -Message "Current value of $regName at ${path}: ${value}" }
            }
        }
    }
}
#endregion

#region Command Invoker
class CertPaddingCheckManager {
    [System.Collections.Generic.List[Command]]$commands = @()

    [void] AddCommand([Command]$command) {
        $this.commands.Add($command)
    }

    [void] ExecuteCommands() {
        foreach ($command in $this.commands) {
            $command.Execute()
        }
    }
}
#endregion
#endregion

#region Main Function
function Main {
    begin {
        Write-Log -Message "Script started. Checking for administrative rights..." -Level "Info"

        if (-not (Test-AdminRights)) {
            throw "This script requires administrator rights. Please run as administrator."
        }

        if (-not ($Check -or $Enable -or $Disable)) {
            Get-Help -Name ".\Enable-SMBSigning.ps1"
            return
        }
        # Check for conflicting parameters
        if (($Enable -and $Disable) -or (-not ($Check -or $Enable -or $Disable))) {
            throw "Conflicting or missing parameters detected. Use -Check, -Enable, or -Disable."
        }

    }

    process {
        try {
            $certPaddingCheckManager = [CertPaddingCheckManager]::new()

            if ($Check) {
                $checkCommand = [CheckCertPaddingCheckCommand]::new()
                $certPaddingCheckManager.AddCommand($checkCommand)
                Write-Log -Message "Queued operation to check EnableCertPaddingCheck status." -Level "Info"
            }

            if ($Enable) {
                $enableCommand = [EnableCertPaddingCheckCommand]::new()
                $certPaddingCheckManager.AddCommand($enableCommand)
                Write-Log -Message "Queued operation to enable EnableCertPaddingCheck." -Level "Info"
            }

            if ($Disable) {
                $disableCommand = [DisableCertPaddingCheckCommand]::new()
                $certPaddingCheckManager.AddCommand($disableCommand)
                Write-Log -Message "Queued operation to disable EnableCertPaddingCheck." -Level "Info"
            }

            if ($certPaddingCheckManager.commands.Count -gt 0) {
                Write-Log -Message "Executing EnableCertPaddingCheck operations..." -Level "Info"
                $certPaddingCheckManager.ExecuteCommands()
            }
            else {
                Write-Log -Message "No EnableCertPaddingCheck operations needed." -Level "Info"
            }
        }
        catch {
            Write-Log -Message "An error occurred during script execution: $_" -Level "Error"
        }
    }

    end {
        Write-Log -Message "Script execution finished." -Level "Info"
    }
}
#endregion

# Call the main function
Main @PSBoundParameters
