<#
.SYNOPSIS
    Manages Microsoft Paint 3D installation (check or uninstall existing installations).

.DESCRIPTION
    This script manages Microsoft Paint 3D (Microsoft.MSPaint) through various actions:
    
      -Check      -> Display current installation status, including:
                     * Classic Paint (mspaint.exe) detection and version
                     * Paint 3D (Microsoft.MSPaint) detection and version
                     * Vulnerability status (compares against safe baseline version)
      -Update     -> Check for updates (NOTE: Paint 3D discontinued Nov 4, 2024)
      -Uninstall  -> Remove via winget, then Appx package as fallback
    
    IMPORTANT: Microsoft discontinued Paint 3D on November 4, 2024, and removed it
    from the Microsoft Store. New installations are no longer possible. This script
    can still manage existing installations (check status and uninstall).
    
    The -Check operation now includes vulnerability detection by comparing installed
    Paint 3D versions against a safe baseline (default: 6.2305.16087.0).
    
    Uses the -AllUsers switch to manage installation for all users where applicable.

.PARAMETER Check
    Checks the current installation status of Paint applications:
    - Classic Paint (mspaint.exe) - path and version
    - Paint 3D (Microsoft.MSPaint) - version and vulnerability status
    Compares Paint 3D version against SafePaint3DVersion to flag vulnerabilities.

.PARAMETER Update
    Checks for updates to an existing Paint 3D installation.
    NOTE: Paint 3D was discontinued by Microsoft on November 4, 2024. New installations
    are not possible. If Paint 3D is already installed, this will attempt to check for
    updates, though none are expected since the app has been discontinued.

.PARAMETER Uninstall
    Uninstalls Paint 3D using winget and removes Appx packages.

.PARAMETER AllUsers
    When set, operations apply to all users where possible (primarily for uninstall).

.PARAMETER SafePaint3DVersion
    Minimum "safe" version of Paint 3D for vulnerability checking during -Check operations.
    Default: 6.2305.16087.0

.EXAMPLE
    .\Set-Paint3d.ps1 -Check
    Checks Paint and Paint 3D installation status, including vulnerability detection.

.EXAMPLE
    .\Set-Paint3d.ps1 -Check -SafePaint3DVersion "6.2305.16087.0"
    Checks installation status with a custom safe version baseline for vulnerability detection.

.EXAMPLE
    .\Set-Paint3d.ps1 -Check -AllUsers
    Checks installation status across all users.

.EXAMPLE
    .\Set-Paint3d.ps1 -Update
    Attempts to update existing Paint 3D installation.

.EXAMPLE
    .\Set-Paint3d.ps1 -Uninstall
    Uninstalls Paint 3D for the current user.

.EXAMPLE
    .\Set-Paint3d.ps1 -Uninstall -AllUsers -WhatIf
    Shows what would be removed without making changes.

.NOTES
    IMPORTANT: Paint 3D was discontinued by Microsoft on November 4, 2024.
    New installations are no longer possible via Microsoft Store or winget.
    This script can still check and uninstall existing installations.
    
    Requires administrative privileges for update/uninstall operations.
    Tested on Windows 10/11 with PowerShell 5.1+.
    Uses command pattern for extensibility and maintainability.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$Check,
    [switch]$Update,
    [switch]$Uninstall,
    [switch]$AllUsers,
    
    # Minimum "safe" version of Paint 3D for vulnerability checking
    [version]$SafePaint3DVersion = [version]"6.2305.16087.0"
)

#region Setup & Utilities
$ErrorActionPreference = 'Stop'
$script:AppxName = 'Microsoft.MSPaint'
$script:StoreId = '9NBLGGH5FV99'  # Paint 3D

function Write-Log {
    [CmdletBinding()]
    param(
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

function Get-Paint3DPackage {
    [CmdletBinding()]
    param([switch]$AllUsers)
    
    if ($AllUsers) {
        return Get-AppxPackage -Name $script:AppxName -AllUsers -ErrorAction SilentlyContinue
    } else {
        return Get-AppxPackage -Name $script:AppxName -ErrorAction SilentlyContinue
    }
}

function Get-WingetCommand {
    return Get-Command winget -ErrorAction SilentlyContinue
}
#endregion

#region Actions
function Get-Paint3DStatus {
    [CmdletBinding()]
    param(
        [switch]$AllUsers,
        [version]$SafeVersion = [version]"6.2305.16087.0"
    )
    
    Write-Log -Message "=== Detecting Paint Applications ===" -Level 'Info'
    Write-Log -Message "Safe Paint 3D baseline version: $SafeVersion" -Level 'Info'
    Write-Log -Message "" -Level 'Info'
    
    # ----- Classic Paint (mspaint.exe) -----
    # Modern Paint is now a Store app (Microsoft.Paint), check multiple sources
    $classicInstalled = $false
    $classicVersion = $null
    $classicPaintPath = $null
    $paintPackageInfo = $null
    
    # Check for Microsoft.Paint Store app (Windows 11+)
    $paintAppx = Get-AppxPackage -Name "Microsoft.Paint" -ErrorAction SilentlyContinue
    if ($paintAppx) {
        $classicInstalled = $true
        $classicVersion = $paintAppx.Version
        $paintPackageInfo = "Store App: $($paintAppx.PackageFullName)"
        $classicPaintPath = "Microsoft Store App"
    }
    # Fallback: Check System32 (legacy Windows 10)
    elseif (Test-Path (Join-Path $env:WINDIR "System32\mspaint.exe")) {
        $classicInstalled = $true
        $classicPaintPath = Join-Path $env:WINDIR "System32\mspaint.exe"
        $classicFile = Get-Item $classicPaintPath
        $classicVersion = $classicFile.VersionInfo.ProductVersion
    }
    # Final fallback: Check if mspaint.exe is in PATH
    else {
        $paintCmd = Get-Command mspaint.exe -ErrorAction SilentlyContinue
        if ($paintCmd) {
            $classicInstalled = $true
            $classicPaintPath = $paintCmd.Source
            if (Test-Path $classicPaintPath) {
                $classicFile = Get-Item $classicPaintPath
                $classicVersion = $classicFile.VersionInfo.ProductVersion
            }
        }
    }
    
    if ($classicInstalled) {
        Write-Log -Message "Classic Paint / Paint:" -Level 'Info'
        Write-Log -Message "  Installed : Yes" -Level 'Info'
        if ($paintPackageInfo) {
            Write-Log -Message "  Type      : $paintPackageInfo" -Level 'Info'
        } else {
            Write-Log -Message "  Path      : $classicPaintPath" -Level 'Info'
        }
        Write-Log -Message "  Version   : $classicVersion" -Level 'Info'
    } else {
        Write-Log -Message "Classic Paint / Paint:" -Level 'Info'
        Write-Log -Message "  Installed : No" -Level 'Info'
    }
    
    Write-Log -Message "" -Level 'Info'
    
    # ----- Paint 3D (Microsoft.MSPaint) -----
    $packages = $null
    try {
        $packages = Get-Paint3DPackage -AllUsers:$AllUsers
    }
    catch [System.UnauthorizedAccessException] {
        # Access denied when -AllUsers is used without admin rights
        # Try without -AllUsers as fallback
        if ($AllUsers) {
            $packages = Get-Paint3DPackage
        }
    }
    catch {
        # Other errors, silently continue
        $packages = $null
    }
    
    $paint3dInstalled = $false
    $paint3dVersion = $null
    $isVulnerable = $false
    $highestPackage = $null
    
    if ($packages) {
        # Take highest version found across users
        $highestPackage = $packages | Sort-Object Version -Descending | Select-Object -First 1
        $paint3dInstalled = $true
        $paint3dVersion = [version]$highestPackage.Version
        $isVulnerable = $paint3dVersion -lt $SafeVersion
        
        Write-Log -Message "Paint 3D:" -Level 'Info'
        Write-Log -Message "  Installed          : Yes" -Level 'Info'
        Write-Log -Message "  Highest Appx Ver.  : $paint3dVersion" -Level 'Info'
        Write-Log -Message "  PackageFullName    : $($highestPackage.PackageFullName)" -Level 'Info'
        
        if ($isVulnerable) {
            Write-Log -Message "  Vulnerable         : YES (below safe version $SafeVersion)" -Level 'Warning'
        } else {
            Write-Log -Message "  Vulnerable         : No" -Level 'Info'
        }
        
        # Show all packages if multiple found
        if ($packages.Count -gt 1) {
            Write-Log -Message "  Additional installations:" -Level 'Info'
            foreach ($pkg in ($packages | Where-Object { $_.PackageFullName -ne $highestPackage.PackageFullName })) {
                Write-Log -Message "    - $($pkg.PackageFullName) (v$($pkg.Version))" -Level 'Info'
            }
        }
    } else {
        Write-Log -Message "Paint 3D:" -Level 'Info'
        Write-Log -Message "  Installed : No" -Level 'Info'
    }
    
    Write-Log -Message "" -Level 'Info'
    Write-Log -Message "=== Summary ===" -Level 'Info'
    Write-Log -Message "ClassicPaintInstalled : $classicInstalled" -Level 'Info'
    Write-Log -Message "ClassicPaintVersion   : $(if ($classicVersion) { $classicVersion } else { 'N/A' })" -Level 'Info'
    Write-Log -Message "Paint3DInstalled      : $paint3dInstalled" -Level 'Info'
    Write-Log -Message "Paint3DVersion        : $(if ($paint3dVersion) { $paint3dVersion } else { 'N/A' })" -Level 'Info'
    Write-Log -Message "Paint3DVulnerable     : $isVulnerable" -Level 'Info'
    
    # Return structured object
    return [pscustomobject]@{
        ComputerName          = $env:COMPUTERNAME
        ClassicPaintInstalled = $classicInstalled
        ClassicPaintVersion   = $classicVersion
        Paint3DInstalled      = $paint3dInstalled
        Paint3DVersion        = $paint3dVersion
        Paint3DVulnerable     = $isVulnerable
        Packages              = $packages
    }
}

function Show-Paint3DDiscontinuedMessage {
    [CmdletBinding()]
    param()
    
    Write-Log -Message "" -Level 'Warning'
    Write-Log -Message "═══════════════════════════════════════════════════════" -Level 'Warning'
    Write-Log -Message "  IMPORTANT: Paint 3D Has Been Discontinued" -Level 'Warning'
    Write-Log -Message "═══════════════════════════════════════════════════════" -Level 'Warning'
    Write-Log -Message "" -Level 'Warning'
    Write-Log -Message "Microsoft discontinued Paint 3D on November 4, 2024." -Level 'Warning'
    Write-Log -Message "It is no longer available in the Microsoft Store." -Level 'Warning'
    Write-Log -Message "" -Level 'Warning'
    Write-Log -Message "Alternatives:" -Level 'Info'
    Write-Log -Message "  • Microsoft Paint (updated with new features)" -Level 'Info'
    Write-Log -Message "  • Other 3D modeling software (Blender, SketchUp, etc.)" -Level 'Info'
    Write-Log -Message "" -Level 'Warning'
    Write-Log -Message "If you already have Paint 3D installed:" -Level 'Info'
    Write-Log -Message "  • It will continue to work on your system" -Level 'Info'
    Write-Log -Message "  • You can use -Check to verify installation" -Level 'Info'
    Write-Log -Message "  • You can use -Uninstall to remove it" -Level 'Info'
    Write-Log -Message "" -Level 'Warning'
    Write-Log -Message "═══════════════════════════════════════════════════════" -Level 'Warning'
    Write-Log -Message "" -Level 'Warning'
}

function Update-Paint3D {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param()
    
    # Check if Paint 3D is currently installed
    $currentPackages = Get-Paint3DPackage
    $isInstalled = ($null -ne $currentPackages)
    
    if (-not $isInstalled) {
        # Paint 3D is not installed and cannot be installed (discontinued)
        Write-Log -Message "Paint 3D is not currently installed." -Level 'Warning'
        Show-Paint3DDiscontinuedMessage
        return @{ Success = $false; Changed = $false; Discontinued = $true }
    }
    
    # Paint 3D is already installed, attempt to update it
    Write-Log -Message "Paint 3D is currently installed. Checking for updates..." -Level 'Info'
    
    $winget = Get-WingetCommand
    if (-not $winget) {
        Write-Log -Message "winget is not available. Cannot check for updates." -Level 'Warning'
        Write-Log -Message "Note: Microsoft discontinued Paint 3D on November 4, 2024." -Level 'Warning'
        Write-Log -Message "Your existing installation will continue to work, but no updates are available." -Level 'Info'
        return @{ Success = $false; Changed = $false; Discontinued = $true }
    }
    
    if ($PSCmdlet.ShouldProcess("Paint 3D (Store ID $script:StoreId)", "Check for updates via winget")) {
        Write-Log -Message "Attempting to upgrade Paint 3D with winget..." -Level 'Info'
        
        $upgradeResult = & winget upgrade --id $script:StoreId -e --accept-package-agreements --accept-source-agreements 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            Write-Log -Message "Paint 3D upgraded successfully." -Level 'Info'
            return @{ Success = $true; Changed = $true }
        } else {
            Write-Log -Message "No updates available or upgrade failed." -Level 'Info'
            Write-Log -Message "Note: Microsoft discontinued Paint 3D on November 4, 2024." -Level 'Warning'
            Write-Log -Message "Your existing installation will continue to work." -Level 'Info'
            return @{ Success = $false; Changed = $false; Discontinued = $true }
        }
    }
    
    return @{ Success = $false; Changed = $false; WhatIf = $true }
}

function Uninstall-Paint3D {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param([switch]$AllUsers)
    
    $changed = $false
    $winget = Get-WingetCommand
    
    # Try winget first
    if ($winget) {
        if ($PSCmdlet.ShouldProcess("Paint 3D (Store ID $script:StoreId)", "Uninstall via winget")) {
            Write-Log -Message "Attempting to uninstall Paint 3D via winget..." -Level 'Info'
            $uninstallResult = & winget uninstall --id $script:StoreId -e --accept-source-agreements 2>&1
            
            if ($LASTEXITCODE -eq 0) {
                Write-Log -Message "Paint 3D uninstalled via winget." -Level 'Info'
                $changed = $true
            } else {
                Write-Log -Message "winget uninstall failed or package not found. Trying Appx removal..." -Level 'Warning'
            }
        }
    } else {
        Write-Log -Message "winget not available. Using Appx package removal..." -Level 'Info'
    }
    
    # Fallback: remove Appx packages
    $packages = Get-Paint3DPackage -AllUsers:$AllUsers
    if ($packages) {
        Write-Log -Message "Removing Appx package(s) Microsoft.MSPaint..." -Level 'Info'
        foreach ($pkg in $packages) {
            if ($PSCmdlet.ShouldProcess("Appx package $($pkg.PackageFullName)", "Remove-AppxPackage")) {
                try {
                    if ($AllUsers) {
                        # Remove for all users if supported
                        Remove-AppxPackage -Package $pkg.PackageFullName -AllUsers -ErrorAction Stop
                        Write-Log -Message "Removed package for all users: $($pkg.PackageFullName)" -Level 'Info'
                    } else {
                        Remove-AppxPackage -Package $pkg.PackageFullName -ErrorAction Stop
                        Write-Log -Message "Removed package: $($pkg.PackageFullName)" -Level 'Info'
                    }
                    $changed = $true
                }
                catch {
                    Write-Log -Message "Failed to remove $($pkg.PackageFullName): $($_.Exception.Message)" -Level 'Warning'
                }
            }
        }
    } else {
        Write-Log -Message "No Microsoft.MSPaint Appx packages found to remove." -Level 'Info'
    }
    
    return @{ Changed = $changed }
}
#endregion

#region Command classes
class Command { [void] Execute() { } }

class CheckPaint3DCommand : Command {
    [bool] $AllUsers
    [version] $SafeVersion
    [pscustomobject] $Result
    
    CheckPaint3DCommand([bool]$allUsers, [version]$safeVersion) {
        $this.AllUsers = $allUsers
        $this.SafeVersion = $safeVersion
    }
    
    [void] Execute() {
        $this.Result = Get-Paint3DStatus -AllUsers:$this.AllUsers -SafeVersion:$this.SafeVersion
    }
}

class UpdatePaint3DCommand : Command {
    [bool] $Changed = $false
    [bool] $Success = $false
    
    [void] Execute() {
        $result = Update-Paint3D
        $this.Success = $result.Success
        $this.Changed = $result.Changed
    }
}

class UninstallPaint3DCommand : Command {
    [bool] $AllUsers
    [bool] $Changed = $false
    
    UninstallPaint3DCommand([bool]$allUsers) {
        $this.AllUsers = $allUsers
    }
    
    [void] Execute() {
        $result = Uninstall-Paint3D -AllUsers:$this.AllUsers
        $this.Changed = $result.Changed
    }
}

class Paint3DManager {
    [System.Collections.Generic.List[Command]] $Commands = [System.Collections.Generic.List[Command]]::new()
    
    [void] AddCommand([Command]$c) {
        $this.Commands.Add($c)
    }
    
    [hashtable] ExecuteCommands() {
        $anyChanged = $false
        foreach ($c in $this.Commands) {
            $c.Execute()
            if ($c -is [UpdatePaint3DCommand]) {
                if ($c.Changed) { $anyChanged = $true }
            }
            if ($c -is [UninstallPaint3DCommand]) {
                if ($c.Changed) { $anyChanged = $true }
            }
        }
        return @{ Changed = $anyChanged }
    }
}
#endregion

#region Main
function Main {
    begin {
        Write-Log -Message "=== Paint 3D Management Script ===" -Level 'Info'
        Write-Log -Message "Scope: $(if ($AllUsers) { 'All users' } else { 'Current user' })" -Level 'Info'
        Write-Log -Message "" -Level 'Info'
        
        if (-not ($Check -or $Update -or $Uninstall)) {
            Write-Log -Message "No action specified. Use -Check, -Update, or -Uninstall." -Level 'Warning'
            return
        }
        
        if (($Update -and $Uninstall)) {
            throw "Conflicting parameters: -Update and -Uninstall cannot be used together."
        }
        
        # Check admin rights for Update/Uninstall operations
        if (($Update -or $Uninstall) -and -not (Test-AdminRights)) {
            throw "Administrator rights are required for Update/Uninstall operations. Please run this script in an elevated PowerShell session."
        }
        
        # Warn about admin rights for Check -AllUsers
        if ($Check -and $AllUsers -and -not (Test-AdminRights)) {
            Write-Log -Message "WARNING: -AllUsers with -Check requires administrator rights for complete Paint 3D detection." -Level 'Warning'
            Write-Log -Message "Paint detection will work, but Paint 3D detection may be limited to current user." -Level 'Warning'
            Write-Log -Message "" -Level 'Warning'
        }
    }
    
    process {
        $mgr = [Paint3DManager]::new()
        
        if ($Check) {
            $mgr.AddCommand([CheckPaint3DCommand]::new($AllUsers, $SafePaint3DVersion))
            Write-Log -Message "Queued: Check current status (Safe version baseline: $SafePaint3DVersion)." -Level 'Info'
        }
        
        if ($Update) {
            $mgr.AddCommand([UpdatePaint3DCommand]::new())
            Write-Log -Message "Queued: Update Paint 3D." -Level 'Info'
        }
        
        if ($Uninstall) {
            $mgr.AddCommand([UninstallPaint3DCommand]::new($AllUsers))
            Write-Log -Message "Queued: Uninstall Paint 3D." -Level 'Info'
        }
        
        Write-Log -Message "Executing requested operations..." -Level 'Info'
        Write-Log -Message "" -Level 'Info'
        
        $result = $mgr.ExecuteCommands()
        
        Write-Log -Message "" -Level 'Info'
        if ($result.Changed) {
            Write-Log -Message "Changes applied successfully." -Level 'Info'
        } elseif (-not $Check) {
            Write-Log -Message "No changes were necessary or possible." -Level 'Info'
        }
        
        # Show post-action state
        if (-not $Check) {
            Write-Log -Message "" -Level 'Info'
            Write-Log -Message "=== Post-action state ===" -Level 'Info'
            $status = Get-Paint3DStatus -AllUsers:$AllUsers
        }
    }
    
    end {
        Write-Log -Message "" -Level 'Info'
        Write-Log -Message "Finished." -Level 'Info'
    }
}

Main @PSBoundParameters
#endregion

