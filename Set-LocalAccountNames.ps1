<#
.SYNOPSIS
    Renames and optionally disables local Administrator and Guest accounts.
.DESCRIPTION
    This script renames the local Administrator and Guest accounts and optionally disables them.
    It requires administrative privileges to run.
.PARAMETER NewAdminName
    The new name for the Administrator account.
.PARAMETER NewGuestName
    The new name for the Guest account.
.PARAMETER DisableAccounts
    If specified, disables the Administrator and Guest accounts after renaming.
.PARAMETER EnableAccounts
    If specified, enables the Administrator and Guest accounts after renaming.
.EXAMPLE
    .\Set-LocalAccountNames.ps1 -NewAdminName "Admin123" -NewGuestName "Visitor" -DisableAccounts
#>
#region Script Parameters
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [ValidatePattern('^[a-zA-Z0-9\.\-_]+$')]
    [string]$NewAdminName,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [ValidatePattern('^[a-zA-Z0-9\.\-_]+$')]
    [string]$NewGuestName,

    [Parameter(Mandatory = $false)]
    [switch]$DisableAccounts,

    [Parameter(Mandatory = $false)]
    [switch]$EnableAccounts
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
class RenameUserCommand : Command {
    [string]$OldName
    [string]$NewName

    RenameUserCommand([string]$oldName, [string]$newName) {
        $this.OldName = $oldName
        $this.NewName = $newName
    }

    [void] Execute() {
        if ($this.OldName -eq $this.NewName) {
            Write-Log -Message "$($this.OldName) account is already named correctly. Skipping rename operation."
            return
        }

        if ($PSCmdlet.ShouldProcess("$($this.OldName)", "Rename to $($this.NewName)")) {
            try {
                Rename-LocalUser -Name $this.OldName -NewName $this.NewName
                Write-Log -Message "$($this.OldName) account renamed to $($this.NewName)."
            }
            catch {
                Write-Log -Message "Failed to rename $($this.OldName) account: $_" -Level "Error"
            }
        }
    }
}

class DisableUserCommand : Command {
    [string]$UserName

    DisableUserCommand([string]$userName) {
        $this.UserName = $userName
    }

    [void] Execute() {
        if ($PSCmdlet.ShouldProcess("$($this.UserName)", "Disable account")) {
            try {
                $user = Get-LocalUser -Name $this.UserName
                if ($user.Enabled) {
                    Disable-LocalUser -Name $this.UserName
                    Write-Log -Message "$($this.UserName) account disabled."
                }
                else {
                    Write-Log -Message "$($this.UserName) account is already disabled."
                }
            }
            catch {
                Write-Log -Message "Failed to disable $($this.UserName) account: $_" -Level "Error"
            }
        }
    }
}

class EnableUserCommand : Command {
    [string]$UserName

    EnableUserCommand([string]$userName) {
        $this.UserName = $userName
    }

    [void] Execute() {
        if ($PSCmdlet.ShouldProcess("$($this.UserName)", "Enable account")) {
            try {
                $user = Get-LocalUser -Name $this.UserName
                if (-not $user.Enabled) {
                    Enable-LocalUser -Name $this.UserName
                    Write-Log -Message "$($this.UserName) account enabled."
                }
                else {
                    Write-Log -Message "$($this.UserName) account is already enabled."
                }
            }
            catch {
                Write-Log -Message "Failed to enable $($this.UserName) account: $_" -Level "Error"
            }
        }
    }
}
#endregion

#region Command Invoker
class UserManager {
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
        if (-not ($NewAdminName -or $NewGuestName -or $DisableAccounts -or $EnableAccounts)) {
            Get-Help -Name ".\Set-LocalAccountNames.ps1"
            return
        }

        $ErrorActionPreference = 'Stop'
        Write-Log -Message "Script started. Checking current account names..." -Level "Info"

        if (-not (Test-AdminRights)) {
            throw "This script requires administrator rights. Please run as administrator."
        }

        if ($DisableAccounts -and $EnableAccounts) {
            throw "Both DisableAccounts and EnableAccounts cannot be set simultaneously. Please choose one option."
        }
    }

    process {
        try {
            $userManager = [UserManager]::new()

            # Rename Operations
            if ($NewAdminName) {
                $currentAdminName = (Get-LocalUser | Where-Object { $_.SID.Value -like '*-500' }).Name
                if ($currentAdminName -ne $NewAdminName) {
                    Write-Log -Message "Current Administrator account name: $currentAdminName" -Level "Info"
                    $adminRename = [RenameUserCommand]::new($currentAdminName, $NewAdminName)
                    $userManager.AddCommand($adminRename)
                    Write-Log -Message "Queued rename operation for Administrator account: $currentAdminName -> $NewAdminName" -Level "Info"
                }
            }

            if ($NewGuestName) {
                $currentGuestName = (Get-LocalUser | Where-Object { $_.SID.Value -like '*-501' }).Name
                if ($currentGuestName -ne $NewGuestName) {
                    Write-Log -Message "Current Guest account name: $currentGuestName" -Level "Info"
                    $guestRename = [RenameUserCommand]::new($currentGuestName, $NewGuestName)
                    $userManager.AddCommand($guestRename)
                    Write-Log -Message "Queued rename operation for Guest account: $currentGuestName -> $NewGuestName" -Level "Info"
                }
            }

            if ($userManager.commands.Count -gt 0) {
                Write-Log -Message "Executing rename operations..." -Level "Info"
                $userManager.ExecuteCommands()
            }
            else {
                Write-Log -Message "No rename operations needed. Account names are already correct."
            }

            # Account State Operations
            if ($DisableAccounts -or $EnableAccounts) {
                $userManager = [UserManager]::new()
                $operation = if ($DisableAccounts) { "disable" } else { "enable" }
                Write-Log -Message "${operation}Accounts switch is set. Preparing to $operation accounts..." -Level "Info"
                
                if ($NewAdminName) {
                    $adminUser = Get-LocalUser -Name $NewAdminName
                    $adminCurrentState = if ($adminUser.Enabled) { "enabled" } else { "disabled" }
                    if (($DisableAccounts -and $adminUser.Enabled) -or ($EnableAccounts -and -not $adminUser.Enabled)) {
                        $adminCommand = if ($DisableAccounts) { 
                            [DisableUserCommand]::new($NewAdminName) 
                        }
                        else { 
                            [EnableUserCommand]::new($NewAdminName) 
                        }
                        $userManager.AddCommand($adminCommand)
                        Write-Log -Message "Queued $operation operation for Administrator account: $NewAdminName (currently $adminCurrentState)" -Level "Info"
                    }
                    else {
                        Write-Log -Message "Administrator account $NewAdminName is already $adminCurrentState. Skipping $operation operation."
                    }
                }
                
                if ($NewGuestName) {
                    $guestUser = Get-LocalUser -Name $NewGuestName
                    $guestCurrentState = if ($guestUser.Enabled) { "enabled" } else { "disabled" }
                    if (($DisableAccounts -and $guestUser.Enabled) -or ($EnableAccounts -and -not $guestUser.Enabled)) {
                        $guestCommand = if ($DisableAccounts) { 
                            [DisableUserCommand]::new($NewGuestName) 
                        }
                        else { 
                            [EnableUserCommand]::new($NewGuestName) 
                        }
                        $userManager.AddCommand($guestCommand)
                        Write-Log -Message "Queued $operation operation for Guest account: $NewGuestName (currently $guestCurrentState)" -Level "Info"
                    }
                    else {
                        Write-Log -Message "Guest account $NewGuestName is already $guestCurrentState. Skipping $operation operation."
                    }
                }
                
                if ($userManager.commands.Count -gt 0) {
                    Write-Log -Message "Executing $operation operations..." -Level "Info"
                    $userManager.ExecuteCommands()
                }
                else {
                    Write-Log -Message "No account state changes needed. Accounts are already in the desired state."
                }
            }
            else {
                Write-Log -Message "Neither DisableAccounts nor EnableAccounts switch is set. Skipping account enable/disable operations." -Level "Info"
            }

            # Final Status
            if ($NewAdminName) {
                $finalAdminName = (Get-LocalUser | Where-Object { $_.SID.Value -like '*-500' }).Name
                Write-Log -Message "Final Administrator account name: $finalAdminName" -Level "Info"
            }

            if ($NewGuestName) {
                $finalGuestName = (Get-LocalUser | Where-Object { $_.SID.Value -like '*-501' }).Name
                Write-Log -Message "Final Guest account name: $finalGuestName" -Level "Info"
            }

            Write-Log -Message "Script execution completed." -Level "Info"
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
