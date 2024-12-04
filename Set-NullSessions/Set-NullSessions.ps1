<#
.SYNOPSIS
    Restricts null sessions by modifying registry settings.
.DESCRIPTION
    This script modifies registry settings to restrict null sessions and prevent unauthorised access.
    It requires administrative privileges to run.
.PARAMETER RestrictAnonymous
    If specified, enables restriction of anonymous access.
.PARAMETER RestrictNullSessionAccess
    If specified, enables restriction of null session access.
.PARAMETER EnableNullSessionAccess
    If specified, enables null session access.
.PARAMETER EnableAnonymous
    If specified, enables anonymous access.
.PARAMETER Check
    If specified, checks the current null session restriction status without making any changes.
.EXAMPLE
    .\Set-NullSessions.ps1 -RestrictAnonymous -RestrictNullSessionAccess
#>

#region Script Parameters
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $false)]
    [switch]$RestrictAnonymous,

    [Parameter(Mandatory = $false)]
    [switch]$RestrictNullSessionAccess,

    [Parameter(Mandatory = $false)]
    [switch]$EnableNullSessionAccess,

    [Parameter(Mandatory = $false)]
    [switch]$EnableAnonymous,

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

function Get-RegistryValue {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$RegPath,
        
        [Parameter(Mandatory = $true)]
        [string]$ValueName
    )

    if (Test-Path $RegPath) {
        $value = Get-ItemProperty -Path $RegPath -Name $ValueName -ErrorAction SilentlyContinue
        if ($null -ne $value) {
            return $value.$ValueName
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
class RestrictAnonymousCommand : Command {
    [void] Execute() {
        $lsaRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\LSA"
        $valueName = "RestrictAnonymous"
        $value = 1

        if (-not (Test-Path $lsaRegPath)) {
            New-Item -Path $lsaRegPath -Force | Out-Null
        }

        Set-ItemProperty -Path $lsaRegPath -Name $valueName -Value $value
        Write-Log -Message "Anonymous access restriction has been enabled."
    }
}

class RestrictNullSessionAccessCommand : Command {
    [void] Execute() {
        $lanmanServerRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
        $valueName = "RestrictNullSessAccess"
        $value = 1

        if (-not (Test-Path $lanmanServerRegPath)) {
            New-Item -Path $lanmanServerRegPath -Force | Out-Null
        }

        Set-ItemProperty -Path $lanmanServerRegPath -Name $valueName -Value $value
        Write-Log -Message "Null session access restriction has been enabled."
    }
}

class EnableNullSessionAccessCommand : Command {
    [void] Execute() {
        $lanmanServerRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
        $valueName = "RestrictNullSessAccess"
        $value = 0

        if (-not (Test-Path $lanmanServerRegPath)) {
            New-Item -Path $lanmanServerRegPath -Force | Out-Null
        }

        Set-ItemProperty -Path $lanmanServerRegPath -Name $valueName -Value $value
        Write-Log -Message "Null session access has been enabled."
    }
}

class EnableAnonymousCommand : Command {
    [void] Execute() {
        $lsaRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\LSA"
        $valueName = "RestrictAnonymous"
        $value = 0

        if (-not (Test-Path $lsaRegPath)) {
            New-Item -Path $lsaRegPath -Force | Out-Null
        }

        Set-ItemProperty -Path $lsaRegPath -Name $valueName -Value $value
        Write-Log -Message "Anonymous access has been enabled."
    }
}
#endregion

#region Command Invoker
class NullSessionManager {
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
        if (-not ($RestrictAnonymous -or $RestrictNullSessionAccess -or $EnableNullSessionAccess -or $EnableAnonymous -or $Check)) {
            Get-Help -Name ".\Set-NullSessions.ps1"
            return
        }

        $ErrorActionPreference = 'Stop'
        Write-Log -Message "Script started. Checking parameters..." -Level "Info"

        if (-not (Test-AdminRights)) {
            throw "This script requires administrator rights. Please run as administrator."
        }
    }

    process {
        try {
            if ($Check) {
                # Check current null session restriction status
                $lsaRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\LSA"
                $lanmanServerRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
                $restrictAnonymousStatus = Get-RegistryValue -RegPath $lsaRegPath -ValueName "RestrictAnonymous"
                $restrictNullSessAccessStatus = Get-RegistryValue -RegPath $lanmanServerRegPath -ValueName "RestrictNullSessAccess"

                Write-Log -Message "Current RestrictAnonymous status: $restrictAnonymousStatus"
                Write-Log -Message "Current RestrictNullSessAccess status: $restrictNullSessAccessStatus"
                return
            }

            $nullSessionManager = [NullSessionManager]::new()

            if ($RestrictAnonymous) {
                $anonymousCommand = [RestrictAnonymousCommand]::new()
                $nullSessionManager.AddCommand($anonymousCommand)
                Write-Log -Message "Queued operation to enable anonymous access restriction." -Level "Info"
            }

            if ($RestrictNullSessionAccess) {
                $nullSessAccessCommand = [RestrictNullSessionAccessCommand]::new()
                $nullSessionManager.AddCommand($nullSessAccessCommand)
                Write-Log -Message "Queued operation to enable null session access restriction." -Level "Info"
            }

            if ($EnableNullSessionAccess) {
                $nullSessionsCommand = [EnableNullSessionAccessCommand]::new()
                $nullSessionManager.AddCommand($nullSessionsCommand)
                Write-Log -Message "Queued operation to enable null session access." -Level "Info"
            }

            if ($EnableAnonymous) {
                $anonymousCommand = [EnableAnonymousCommand]::new()
                $nullSessionManager.AddCommand($anonymousCommand)
                Write-Log -Message "Queued operation to enable anonymous access." -Level "Info"
            }

            if ($nullSessionManager.commands.Count -gt 0) {
                Write-Log -Message "Executing null session restriction operations..." -Level "Info"
                $nullSessionManager.ExecuteCommands()
            }
            else {
                Write-Log -Message "No null session restriction operations needed."
            }
        }
        catch {
            # Enhanced error logging with string conversion
            $errorMessage = "An error occurred during script execution: $_"
            Write-Log -Message $errorMessage -Level "Error"
        }
    }

    end {
        Write-Log -Message "Script execution finished." -Level "Info"
    }
}
#endregion

# Call the main function
Main @PSBoundParameters