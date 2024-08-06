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
[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [ValidatePattern('^[a-zA-Z0-9\.\-_]+$')]
    [string]$NewAdminName,

    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [ValidatePattern('^[a-zA-Z0-9\.\-_]+$')]
    [string]$NewGuestName,

    [Parameter(Mandatory=$false)]
    [switch]$DisableAccounts,

    [Parameter(Mandatory=$false)]
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
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("Info", "Warning", "Error")]
        [string]$Level = "Info"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    switch ($Level) {
        "Info"    { Write-Verbose $logMessage }
        "Warning" { Write-Warning $logMessage }
        "Error"   { Write-Error $logMessage }
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
                    Write-Log -Message "$($this.UserName) account disabled." -Level "Info"
                }
                else {
                    Write-Log -Message "$($this.UserName) account is already disabled." -Level "Info"
                }
            }
            catch [Microsoft.PowerShell.Commands.UserNotFoundException] {
                Write-Log -Message "$($this.UserName) account not found. Unable to disable." -Level "Warning"
            }
            catch [System.UnauthorizedAccessException] {
                Write-Log -Message "Access denied while trying to disable $($this.UserName). Make sure you have the necessary permissions." -Level "Error"
            }
            catch [System.InvalidOperationException] {
                Write-Log -Message "Unable to disable $($this.UserName). The account might be in use or protected." -Level "Error"
            }
            catch {
                Write-Log -Message "An unexpected error occurred while disabling $($this.UserName): $_" -Level "Error"
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
                    Write-Log -Message "$($this.UserName) account enabled." -Level "Info"
                }
                else {
                    Write-Log -Message "$($this.UserName) account is already enabled." -Level "Info"
                }
            }
            catch [Microsoft.PowerShell.Commands.UserNotFoundException] {
                Write-Log -Message "$($this.UserName) account not found. Unable to enable." -Level "Warning"
            }
            catch [System.UnauthorizedAccessException] {
                Write-Log -Message "Access denied while trying to enable $($this.UserName). Make sure you have the necessary permissions." -Level "Error"
            }
            catch {
                Write-Log -Message "An unexpected error occurred while enabling $($this.UserName): $_" -Level "Error"
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

#region Main Script Logic
try {
    # Initialisation
    if (-not (Test-AdminRights)) {
        throw "This script requires administrator rights. Please run as administrator."
    }

    if ($DisableAccounts -and $EnableAccounts) {
        throw "Both DisableAccounts and EnableAccounts cannot be set simultaneously. Please choose one option."
    }

    Write-Log -Message "Script started. Checking current account names..." -Level "Info"

    $currentAdminName = (Get-LocalUser | Where-Object { $_.SID.Value -like '*-500' }).Name
    $currentGuestName = (Get-LocalUser | Where-Object { $_.SID.Value -like '*-501' }).Name

    Write-Log -Message "Current Administrator account name: $currentAdminName" -Level "Info"
    Write-Log -Message "Current Guest account name: $currentGuestName" -Level "Info"

    $userManager = [UserManager]::new()

    $adminNameToUse = $currentAdminName
    $guestNameToUse = $currentGuestName

    # Main Process
    #region Rename Operations
    if ($currentAdminName -and $NewAdminName) {
        $adminRename = [RenameUserCommand]::new($currentAdminName, $NewAdminName)
        $userManager.AddCommand($adminRename)
        $adminNameToUse = $NewAdminName
        Write-Log -Message "Queued rename operation for Administrator account: $currentAdminName -> $NewAdminName" -Level "Info"
    }

    if ($currentGuestName -and $NewGuestName) {
        $guestRename = [RenameUserCommand]::new($currentGuestName, $NewGuestName)
        $userManager.AddCommand($guestRename)
        $guestNameToUse = $NewGuestName
        Write-Log -Message "Queued rename operation for Guest account: $currentGuestName -> $NewGuestName" -Level "Info"
    }

    Write-Log -Message "Executing rename operations..." -Level "Info"
    $userManager.ExecuteCommands()
    #endregion

    #region Account State Operations
    if ($DisableAccounts) {
        Write-Log -Message "DisableAccounts switch is set. Preparing to disable accounts..." -Level "Info"
        $userManager = [UserManager]::new()
        
        if ($adminNameToUse) {
            $adminDisable = [DisableUserCommand]::new($adminNameToUse)
            $userManager.AddCommand($adminDisable)
            Write-Log -Message "Queued disable operation for Administrator account: $adminNameToUse" -Level "Info"
        }
        
        if ($guestNameToUse) {
            $guestDisable = [DisableUserCommand]::new($guestNameToUse)
            $userManager.AddCommand($guestDisable)
            Write-Log -Message "Queued disable operation for Guest account: $guestNameToUse" -Level "Info"
        }
        
        Write-Log -Message "Executing disable operations..." -Level "Info"
        $userManager.ExecuteCommands()
    }
    elseif ($EnableAccounts) {
        Write-Log -Message "EnableAccounts switch is set. Preparing to enable accounts..." -Level "Info"
        $userManager = [UserManager]::new()
        
        if ($adminNameToUse) {
            $adminEnable = [EnableUserCommand]::new($adminNameToUse)
            $userManager.AddCommand($adminEnable)
            Write-Log -Message "Queued enable operation for Administrator account: $adminNameToUse" -Level "Info"
        }
        
        if ($guestNameToUse) {
            $guestEnable = [EnableUserCommand]::new($guestNameToUse)
            $userManager.AddCommand($guestEnable)
            Write-Log -Message "Queued enable operation for Guest account: $guestNameToUse" -Level "Info"
        }
        
        Write-Log -Message "Executing enable operations..." -Level "Info"
        $userManager.ExecuteCommands()
    }
    else {
        Write-Log -Message "Neither DisableAccounts nor EnableAccounts switch is set. Skipping account enable/disable operations." -Level "Info"
    }
    #endregion

    # Final Status
    $finalAdminName = (Get-LocalUser | Where-Object { $_.SID.Value -like '*-500' }).Name
    $finalGuestName = (Get-LocalUser | Where-Object { $_.SID.Value -like '*-501' }).Name

    Write-Log -Message "Final Administrator account name: $finalAdminName" -Level "Info"
    Write-Log -Message "Final Guest account name: $finalGuestName" -Level "Info"

    Write-Log -Message "Script execution completed." -Level "Info"
}
catch {
    Write-Log -Message "An error occurred during script execution: $_" -Level "Error"
}
finally {
    # Perform any necessary cleanup here
    Write-Log -Message "Script execution finished." -Level "Info"
}
#endregion
