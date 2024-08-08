<#
.SYNOPSIS
    Disables Autoplay and Autorun on Windows 10 and Windows 11.
.DESCRIPTION
    This script modifies the registry settings to disable Autoplay and Autorun for all drives.
    It requires administrative privileges to run.
.PARAMETER Disable
    If specified, disables Autoplay and Autorun.
.PARAMETER Enable
    If specified, enables Autoplay and Autorun.
.EXAMPLE
    .\Set-Autoplay.ps1 -Disable
#>
#region Script Parameters
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $false)]
    [switch]$Disable,

    [Parameter(Mandatory = $false)]
    [switch]$Enable
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
#endregion

#region Classes
#region Command Interface
class Command {
    [void] Execute() { }
}
#endregion

#region Concrete Commands
class SetRegistryValueCommand : Command {
    [string]$Path
    [string]$Name
    [object]$Value
    [string]$PropertyType = 'DWORD'

    SetRegistryValueCommand([string]$path, [string]$name, [object]$value, [string]$propertyType = 'DWORD') {
        $this.Path = $path
        $this.Name = $name
        $this.Value = $value
        $this.PropertyType = $propertyType
    }

    [void] Execute() {
        if ($PSCmdlet.ShouldProcess("$($this.Path)\$($this.Name)", "Set to $($this.Value)")) {
            try {
                # Check if the registry key exists, create if not
                if (-not (Test-Path $this.Path)) {
                    New-Item -Path $this.Path -Force | Out-Null
                }

                # Set the registry value
                Set-ItemProperty -Path $this.Path -Name $this.Name -Value $this.Value
                Write-Log -Message "Set $($this.Name) to $($this.Value) at $($this.Path)." -Level "Info"
            }
            catch {
                Write-Log -Message "Failed to set $($this.Name) at $($this.Path): $_" -Level "Error"
            }
        }
    }
}
#endregion

#region Command Invoker
class RegistryManager {
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
        if (-not ($Disable -or $Enable)) {
            Get-Help -Name ".\Set-Autoplay.ps1"
            return
        }

        $ErrorActionPreference = 'Stop'
        Write-Log -Message "Script started. Checking administrative privileges..." -Level "Info"

        if (-not (Test-AdminRights)) {
            throw "This script requires administrator rights. Please run as administrator."
        }

        if ($Disable -and $Enable) {
            throw "Both Disable and Enable cannot be set simultaneously. Please choose one option."
        }
    }

    process {
        try {
            $registryManager = [RegistryManager]::new()

            if ($Disable) {
                Write-Log -Message "Disable switch is set. Preparing to disable Autoplay and Autorun..." -Level "Info"

                # Disable Autoplay and Autorun for all drives
                $autoRunPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
                $disableAutoRun = [SetRegistryValueCommand]::new($autoRunPath, "NoDriveTypeAutoRun", 255, 'DWORD')
                $registryManager.AddCommand($disableAutoRun)

                # Disable Autoplay for CD-ROM and removable media drives
                $autoPlayPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
                $disableAutoPlay = [SetRegistryValueCommand]::new($autoPlayPath, "NoDriveTypeAutoRun", 255, 'DWORD')
                $registryManager.AddCommand($disableAutoPlay)
            }
            elseif ($Enable) {
                Write-Log -Message "Enable switch is set. Preparing to enable Autoplay and Autorun..." -Level "Info"

                # Enable Autoplay and Autorun for all drives
                $autoRunPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
                $enableAutoRun = [SetRegistryValueCommand]::new($autoRunPath, "NoDriveTypeAutoRun", 0, 'DWORD')
                $registryManager.AddCommand($enableAutoRun)

                # Enable Autoplay for CD-ROM and removable media drives
                $autoPlayPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
                $enableAutoPlay = [SetRegistryValueCommand]::new($autoPlayPath, "NoDriveTypeAutoRun", 0, 'DWORD')
                $registryManager.AddCommand($enableAutoPlay)
            }

            if ($registryManager.commands.Count -gt 0) {
                Write-Log -Message "Executing registry changes..." -Level "Info"
                $registryManager.ExecuteCommands()
                Write-Log -Message "Autoplay and Autorun settings have been updated."

                # Refresh the policy
                gpupdate /force | Out-Null
                Write-Log -Message "Group Policy updated." -Level "Info"
            }
            else {
                Write-Log -Message "No changes needed. Autoplay and Autorun settings are already correct."
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
