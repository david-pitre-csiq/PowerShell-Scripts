<#
.SYNOPSIS
    Enables or disables SMB Signing on Windows 10 and 11.
.DESCRIPTION
    This script enables or disables SMB Signing on both the client and server sides.
    It requires administrative privileges to run.
.PARAMETER EnableClientSigning
    If specified, enables SMB Signing on the client side.
.PARAMETER EnableServerSigning
    If specified, enables SMB Signing on the server side.
.PARAMETER RequireServerSigning
    If specified, requires SMB Signing on the server side.
.PARAMETER DisableClientSigning
    If specified, disables SMB Signing on the client side.
.PARAMETER DisableServerSigning
    If specified, disables SMB Signing on the server side.
.PARAMETER DisableRequireServerSigning
    If specified, disables the requirement for SMB Signing on the server side.
.PARAMETER EnableAllRequiredSigning
    If specified, enables all required SMB Signing on both client and server sides.
.PARAMETER Check
    If specified, checks the current SMB Signing status without making any changes.
.EXAMPLE
    .\Enable-SMBSigning.ps1 -EnableClientSigning -EnableServerSigning -RequireServerSigning
#>
#region Script Parameters
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $false)]
    [switch]$EnableClientSigning,

    [Parameter(Mandatory = $false)]
    [switch]$EnableServerSigning,

    [Parameter(Mandatory = $false)]
    [switch]$RequireServerSigning,

    [Parameter(Mandatory = $false)]
    [switch]$DisableClientSigning,

    [Parameter(Mandatory = $false)]
    [switch]$DisableServerSigning,

    [Parameter(Mandatory = $false)]
    [switch]$DisableRequireServerSigning,

    [Parameter(Mandatory = $false)]
    [switch]$EnableAllRequiredSigning,

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

function Get-SMBSigningStatus {
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
class EnableClientSMBSigningCommand : Command {
    [void] Execute() {
        $clientRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
        $clientValueName = "EnableSecuritySignature"
        $clientValue = 1

        if (-not (Test-Path $clientRegPath)) {
            New-Item -Path $clientRegPath -Force | Out-Null
        }

        Set-ItemProperty -Path $clientRegPath -Name $clientValueName -Value $clientValue
        Write-Log -Message "SMB Signing has been enabled on the client side."
    }
}

class EnableServerSMBSigningCommand : Command {
    [void] Execute() {
        $serverRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
        $serverValueName = "EnableSecuritySignature"
        $serverValue = 1

        if (-not (Test-Path $serverRegPath)) {
            New-Item -Path $serverRegPath -Force | Out-Null
        }

        Set-ItemProperty -Path $serverRegPath -Name $serverValueName -Value $serverValue
        Write-Log -Message "SMB Signing has been enabled on the server side."
    }
}

class RequireServerSMBSigningCommand : Command {
    [void] Execute() {
        $serverRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
        $requireServerValueName = "RequireSecuritySignature"
        $requireServerValue = 1

        if (-not (Test-Path $serverRegPath)) {
            New-Item -Path $serverRegPath -Force | Out-Null
        }

        Set-ItemProperty -Path $serverRegPath -Name $requireServerValueName -Value $requireServerValue
        Write-Log -Message "SMB Signing is now required on the server side."
    }
}

class DisableClientSMBSigningCommand : Command {
    [void] Execute() {
        $clientRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
        $clientValueName = "EnableSecuritySignature"
        $clientValue = 0

        if (-not (Test-Path $clientRegPath)) {
            New-Item -Path $clientRegPath -Force | Out-Null
        }

        Set-ItemProperty -Path $clientRegPath -Name $clientValueName -Value $clientValue
        Write-Log -Message "SMB Signing has been disabled on the client side."
    }
}

class DisableServerSMBSigningCommand : Command {
    [void] Execute() {
        $serverRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
        $serverValueName = "EnableSecuritySignature"
        $serverValue = 0

        if (-not (Test-Path $serverRegPath)) {
            New-Item -Path $serverRegPath -Force | Out-Null
        }

        Set-ItemProperty -Path $serverRegPath -Name $serverValueName -Value $serverValue
        Write-Log -Message "SMB Signing has been disabled on the server side."
    }
}

class DisableRequireServerSMBSigningCommand : Command {
    [void] Execute() {
        $serverRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
        $requireServerValueName = "RequireSecuritySignature"
        $requireServerValue = 0

        if (-not (Test-Path $serverRegPath)) {
            New-Item -Path $serverRegPath -Force | Out-Null
        }

        Set-ItemProperty -Path $serverRegPath -Name $requireServerValueName -Value $requireServerValue
        Write-Log -Message "Requirement for SMB Signing has been disabled on the server side."
    }
}

class EnableAllRequiredSMBSigningCommand : Command {
    [void] Execute() {
        $clientRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
        $serverRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
        $clientValueName = "EnableSecuritySignature"
        $serverValueName = "EnableSecuritySignature"
        $requireServerValueName = "RequireSecuritySignature"
        $value = 1

        if (-not (Test-Path $clientRegPath)) {
            New-Item -Path $clientRegPath -Force | Out-Null
        }
        if (-not (Test-Path $serverRegPath)) {
            New-Item -Path $serverRegPath -Force | Out-Null
        }

        Set-ItemProperty -Path $clientRegPath -Name $clientValueName -Value $value
        Set-ItemProperty -Path $serverRegPath -Name $serverValueName -Value $value
        Set-ItemProperty -Path $serverRegPath -Name $requireServerValueName -Value $value

        Write-Log -Message "All required SMB Signing has been enabled on both client and server sides."
    }
}
#endregion

#region Command Invoker
class SMBSigningManager {
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
        if (-not ($EnableClientSigning -or $EnableServerSigning -or $RequireServerSigning -or $DisableClientSigning -or $DisableServerSigning -or $DisableRequireServerSigning -or $EnableAllRequiredSigning -or $Check)) {
            Get-Help -Name ".\Enable-SMBSigning.ps1"
            return
        }

        $ErrorActionPreference = 'Stop'
        Write-Log -Message "Script started. Checking parameters..." -Level "Info"

        if (-not (Test-AdminRights)) {
            throw "This script requires administrator rights. Please run as administrator."
        }

        # Check for conflicting parameters
        if (($EnableClientSigning -and $DisableClientSigning) -or
            ($EnableServerSigning -and $DisableServerSigning) -or
            ($RequireServerSigning -and $DisableRequireServerSigning) -or
            ($EnableAllRequiredSigning -and ($DisableClientSigning -or $DisableServerSigning -or $DisableRequireServerSigning))) {
            throw "Conflicting parameters detected. Enable and Disable commands cannot be run at the same time."
        }
    }

    process {
        try {
            if ($Check) {
                # Check current SMB Signing status
                $clientRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
                $serverRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
                $clientSigningStatus = Get-SMBSigningStatus -RegPath $clientRegPath -ValueName "EnableSecuritySignature"
                $serverSigningStatus = Get-SMBSigningStatus -RegPath $serverRegPath -ValueName "EnableSecuritySignature"
                $requireServerSigningStatus = Get-SMBSigningStatus -RegPath $serverRegPath -ValueName "RequireSecuritySignature"

                Write-Log -Message "Current SMB Signing status on client: $clientSigningStatus"
                Write-Log -Message "Current SMB Signing status on server: $serverSigningStatus"
                Write-Log -Message "Current SMB Signing requirement on server: $requireServerSigningStatus"
                return
            }

            $smbSigningManager = [SMBSigningManager]::new()

            if ($EnableClientSigning) {
                $clientCommand = [EnableClientSMBSigningCommand]::new()
                $smbSigningManager.AddCommand($clientCommand)
                Write-Log -Message "Queued operation to enable SMB Signing on the client side." -Level "Info"
            }

            if ($DisableClientSigning) {
                $clientCommand = [DisableClientSMBSigningCommand]::new()
                $smbSigningManager.AddCommand($clientCommand)
                Write-Log -Message "Queued operation to disable SMB Signing on the client side." -Level "Info"
            }

            if ($EnableServerSigning) {
                $serverCommand = [EnableServerSMBSigningCommand]::new()
                $smbSigningManager.AddCommand($serverCommand)
                Write-Log -Message "Queued operation to enable SMB Signing on the server side." -Level "Info"
            }

            if ($DisableServerSigning) {
                $serverCommand = [DisableServerSMBSigningCommand]::new()
                $smbSigningManager.AddCommand($serverCommand)
                Write-Log -Message "Queued operation to disable SMB Signing on the server side." -Level "Info"
            }

            if ($RequireServerSigning) {
                $requireServerCommand = [RequireServerSMBSigningCommand]::new()
                $smbSigningManager.AddCommand($requireServerCommand)
                Write-Log -Message "Queued operation to require SMB Signing on the server side." -Level "Info"
            }

            if ($DisableRequireServerSigning) {
                $requireServerCommand = [DisableRequireServerSMBSigningCommand]::new()
                $smbSigningManager.AddCommand($requireServerCommand)
                Write-Log -Message "Queued operation to disable the requirement for SMB Signing on the server side." -Level "Info"
            }

            if ($EnableAllRequiredSigning) {
                $allRequiredCommand = [EnableAllRequiredSMBSigningCommand]::new()
                $smbSigningManager.AddCommand($allRequiredCommand)
                Write-Log -Message "Queued operation to enable all required SMB Signing on both client and server sides." -Level "Info"
            }

            if ($smbSigningManager.commands.Count -gt 0) {
                Write-Log -Message "Executing SMB Signing operations..." -Level "Info"
                $smbSigningManager.ExecuteCommands()
            }
            else {
                Write-Log -Message "No SMB Signing operations needed."
            }

            Write-Log -Message "Restarting LanmanWorkstation and LanmanServer services to apply changes..."
            Restart-Service -Name "LanmanWorkstation" -Force
            Restart-Service -Name "LanmanServer" -Force
            Write-Log -Message "LanmanWorkstation and LanmanServer services have been restarted."
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
