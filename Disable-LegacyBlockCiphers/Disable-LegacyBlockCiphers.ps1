<#
.SYNOPSIS
    Manages legacy block ciphers by modifying registry settings.
.DESCRIPTION
    This script modifies registry settings to enable or disable legacy block ciphers such as DES, 3DES, IDEA, and RC2.
    It requires administrative privileges to run.
.PARAMETER Check
    If specified, checks the current status of legacy block ciphers without making any changes.
.PARAMETER DisableLegacyBlockCiphers
    If specified, disables legacy block ciphers.
.PARAMETER EnableLegacyBlockCiphers
    If specified, enables legacy block ciphers.
.EXAMPLE
    .\Disable-LegacyBlockCiphers.ps1 -DisableLegacyBlockCiphers
#>

#region Script Parameters
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $false)]
    [switch]$Check,

    [Parameter(Mandatory = $false)]
    [switch]$DisableLegacyBlockCiphers,

    [Parameter(Mandatory = $false)]
    [switch]$EnableLegacyBlockCiphers
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
class Disable3DESCipherCommand : Command {
    [void] Execute() {
        $cipherRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168"
        $valueName = "Enabled"
        $value = 0

        if (-not (Test-Path $cipherRegPath)) {
            New-Item -Path $cipherRegPath -Force | Out-Null
        }

        Set-ItemProperty -Path $cipherRegPath -Name $valueName -Value $value
        Write-Log -Message "3DES cipher has been disabled."
    }
}

class Enable3DESCipherCommand : Command {
    [void] Execute() {
        $cipherRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168"
        $valueName = "Enabled"
        $value = 1

        if (-not (Test-Path $cipherRegPath)) {
            New-Item -Path $cipherRegPath -Force | Out-Null
        }

        Set-ItemProperty -Path $cipherRegPath -Name $valueName -Value $value
        Write-Log -Message "3DES cipher has been enabled."
    }
}

class Remove3DESCipherFromPolicyCommand : Command {
    [void] Execute() {
        $policyRegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"
        $valueName = "Functions"
        $functions = Get-RegistryValue -RegPath $policyRegPath -ValueName $valueName

        if ($functions -and $functions -match "TLS_RSA_WITH_3DES_EDE_CBC_SHA") {
            $newFunctions = $functions -replace "TLS_RSA_WITH_3DES_EDE_CBC_SHA", ""
            Set-ItemProperty -Path $policyRegPath -Name $valueName -Value $newFunctions
            Write-Log -Message "3DES cipher removed from policy configuration."
        }
    }
}

class Add3DESCipherToPolicyCommand : Command {
    [void] Execute() {
        $policyRegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"
        $valueName = "Functions"
        $functions = Get-RegistryValue -RegPath $policyRegPath -ValueName $valueName

        if ($functions -notmatch "TLS_RSA_WITH_3DES_EDE_CBC_SHA") {
            $newFunctions = $functions + ",TLS_RSA_WITH_3DES_EDE_CBC_SHA"
            Set-ItemProperty -Path $policyRegPath -Name $valueName -Value $newFunctions
            Write-Log -Message "3DES cipher added to policy configuration."
        }
    }
}
#endregion

#region Command Invoker
class CipherManager {
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
        if (-not ($Check -or $DisableLegacyBlockCiphers -or $EnableLegacyBlockCiphers)) {
            Get-Help -Name ".\Disable-LegacyBlockCiphers.ps1"
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
                # Check current cipher status
                $cipherRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168"
                $policyRegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"
                $cipherStatus = Get-RegistryValue -RegPath $cipherRegPath -ValueName "Enabled"
                $policyFunctions = Get-RegistryValue -RegPath $policyRegPath -ValueName "Functions"

                Write-Log -Message "Current 3DES cipher status: $cipherStatus"
                Write-Log -Message "Current policy functions: $policyFunctions"
                return
            }

            $cipherManager = [CipherManager]::new()

            if ($DisableLegacyBlockCiphers) {
                $disable3DESCommand = [Disable3DESCipherCommand]::new()
                $cipherManager.AddCommand($disable3DESCommand)
                Write-Log -Message "Queued operation to disable 3DES cipher." -Level "Info"

                $remove3DESPolicyCommand = [Remove3DESCipherFromPolicyCommand]::new()
                $cipherManager.AddCommand($remove3DESPolicyCommand)
                Write-Log -Message "Queued operation to remove 3DES cipher from policy." -Level "Info"
            }

            if ($EnableLegacyBlockCiphers) {
                $enable3DESCommand = [Enable3DESCipherCommand]::new()
                $cipherManager.AddCommand($enable3DESCommand)
                Write-Log -Message "Queued operation to enable 3DES cipher." -Level "Info"

                $add3DESPolicyCommand = [Add3DESCipherToPolicyCommand]::new()
                $cipherManager.AddCommand($add3DESPolicyCommand)
                Write-Log -Message "Queued operation to add 3DES cipher to policy." -Level "Info"
            }

            if ($cipherManager.commands.Count -gt 0) {
                Write-Log -Message "Executing cipher operations..." -Level "Info"
                $cipherManager.ExecuteCommands()
            }
            else {
                Write-Log -Message "No cipher operations needed."
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