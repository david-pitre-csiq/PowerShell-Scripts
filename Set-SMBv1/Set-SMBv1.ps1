<#
.SYNOPSIS
    Enables or disables SMBv1 on Windows 10 and 11.
.DESCRIPTION
    This script enables or disables SMBv1 on both the client and server sides.
    It requires administrative privileges to run.
.PARAMETER Enable
    If specified, enables SMBv1 on both the client and server sides.
.PARAMETER Disable
    If specified, disables SMBv1 on both the client and server sides.
.PARAMETER Check
    If specified, checks the current SMBv1 status without making any changes.
.EXAMPLE
    .\Set-SMBv1.ps1 -Disable
    .\Set-SMBv1.ps1 -Enable
    .\Set-SMBv1.ps1 -Check
#>
#region Script Parameters
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $false)]
    [switch]$Enable,

    [Parameter(Mandatory = $false)]
    [switch]$Disable,

    [Parameter(Mandatory = $false)]
    [switch]$Check
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

function Get-SMBv1Status {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$FeatureName
    )

    $feature = Get-WindowsOptionalFeature -Online -FeatureName $FeatureName
    return $feature.State
}
#endregion

#region Classes
#region Command Interface
class Command {
    [void] Execute() { }
}
#endregion

#region Concrete Commands
class EnableSMBv1ClientCommand : Command {
    [void] Execute() {
        Enable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart
        Write-Log -Message "SMBv1 has been enabled on the client side."
    }
}

class EnableSMBv1ServerCommand : Command {
    [void] Execute() {
        if (Get-WindowsOptionalFeature -Online -FeatureName "FS-SMB1") {
            Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force
            Write-Log -Message "SMBv1 has been enabled on the server side."
        } else {
            Write-Log -Message "SMBv1 server feature is not available on this machine." -Level "Warning"
        }
    }
}

class DisableSMBv1ClientCommand : Command {
    [void] Execute() {
        Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart
        Write-Log -Message "SMBv1 has been disabled on the client side."
    }
}

class DisableSMBv1ServerCommand : Command {
    [void] Execute() {
        if (Get-WindowsOptionalFeature -Online -FeatureName "FS-SMB1") {
            Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
            Write-Log -Message "SMBv1 has been disabled on the server side."
        } else {
            Write-Log -Message "SMBv1 server feature is not available on this machine." -Level "Warning"
        }
    }
}
#endregion

#region Command Invoker
class SMBv1Manager {
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
        # Check if no parameters were provided
        if (-not ($Enable -or $Disable -or $Check)) {
            Get-Help -Name ".\Set-SMBv1.ps1"
            return
        }

        $ErrorActionPreference = 'Stop'
        Write-Log -Message "Script started. Checking parameters..." -Level "Info"

        if (-not (Test-AdminRights)) {
            throw "This script requires administrator rights. Please run as administrator."
        }

        # Check for conflicting parameters
        if (($Enable -and $Disable) -or ($Check -and ($Enable -or $Disable))) {
            throw "Conflicting parameters detected. Enable, Disable, and Check commands cannot be run at the same time."
        }
    }

    process {
        try {
            if ($Check) {
                # Check current SMBv1 status
                $clientStatus = if (Get-SMBv1Status -FeatureName "SMB1Protocol") { "Enabled" } else { "Disabled" }
                $serverStatus = if ((Get-SmbServerConfiguration).EnableSMB1Protocol) { "Enabled" } else { "Disabled" }

                Write-Log -Message "Current SMBv1 status on client: $clientStatus"
                Write-Log -Message "Current SMBv1 status on server: $serverStatus"
                return
            }

            $smbv1Manager = [SMBv1Manager]::new()

            if ($Enable) {
                $clientCommand = [EnableSMBv1ClientCommand]::new()
                $smbv1Manager.AddCommand($clientCommand)
                Write-Log -Message "Queued operation to enable SMBv1 on the client side." -Level "Info"

                $serverCommand = [EnableSMBv1ServerCommand]::new()
                $smbv1Manager.AddCommand($serverCommand)
                Write-Log -Message "Queued operation to enable SMBv1 on the server side." -Level "Info"

                Write-Log -Message "Restarting LanmanWorkstation and LanmanServer services to apply changes..."
                Restart-Service -Name "LanmanWorkstation" -Force
                Restart-Service -Name "LanmanServer" -Force
                Write-Log -Message "LanmanWorkstation and LanmanServer services have been restarted."
            }

            if ($Disable) {
                $clientCommand = [DisableSMBv1ClientCommand]::new()
                $smbv1Manager.AddCommand($clientCommand)
                Write-Log -Message "Queued operation to disable SMBv1 on the client side." -Level "Info"

                $serverCommand = [DisableSMBv1ServerCommand]::new()
                $smbv1Manager.AddCommand($serverCommand)
                Write-Log -Message "Queued operation to disable SMBv1 on the server side." -Level "Info"

                Write-Log -Message "Restarting LanmanWorkstation and LanmanServer services to apply changes..."
                Restart-Service -Name "LanmanWorkstation" -Force
                Restart-Service -Name "LanmanServer" -Force
                Write-Log -Message "LanmanWorkstation and LanmanServer services have been restarted."
            }

            if ($smbv1Manager.commands.Count -gt 0) {
                Write-Log -Message "Executing SMBv1 operations..." -Level "Info"
                $smbv1Manager.ExecuteCommands()
            }
            else {
                Write-Log -Message "No SMBv1 operations specified."
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
