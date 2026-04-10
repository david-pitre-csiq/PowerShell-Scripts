<#
.SYNOPSIS
    Checks and removes Microsoft Paint-family Store apps by exact version.

.DESCRIPTION
    Supports these Microsoft Store apps:
      - Microsoft Paint  (Microsoft.Paint)
      - Paint 3D         (Microsoft.MSPaint)
      - 3D Viewer        (Microsoft.Microsoft3DViewer)

    -Check:
      * Shows scanner-aligned Win32_InstalledStoreProgram inventory
      * Shows installed Appx packages
      * Shows provisioned packages in the online image

    -Uninstall:
      * Prompts for the target app unless -TargetApp is supplied
      * Prompts for the exact version to remove unless -TargetVersion is supplied
      * Current-user mode removes only installed MAIN packages for the current user
      * All-users mode removes BUNDLE packages first (when present), then MAIN as fallback
      * Optionally removes provisioned packages from the online image

    Note:
      * This script targets Microsoft Store / Appx packages.
      * It does not remove classic mspaint.exe as a Windows component.

.EXAMPLE
    .\Manage-PaintApps.ps1 -Check

.EXAMPLE
    .\Manage-PaintApps.ps1 -Uninstall

.EXAMPLE
    .\Manage-PaintApps.ps1 -Uninstall -AllUsers

.EXAMPLE
    .\Manage-PaintApps.ps1 -Uninstall -AllUsers -TargetApp Paint -TargetVersion ALL -WhatIf
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$Check,
    [switch]$Uninstall,
    [switch]$AllUsers,

    [ValidateSet('Paint','Paint3D','3DViewer')]
    [string]$TargetApp,

    [string]$TargetVersion,

    [switch]$SkipProvisionedRemoval
)

$ErrorActionPreference = 'Stop'

$script:Targets = [ordered]@{
    Paint = [pscustomobject]@{
        Key                    = 'Paint'
        DisplayName            = 'Microsoft Paint'
        AppxNames              = @('Microsoft.Paint')
        StoreProgramIdPrefixes = @('Microsoft.Paint')
    }
    Paint3D = [pscustomobject]@{
        Key                    = 'Paint3D'
        DisplayName            = 'Paint 3D'
        AppxNames              = @('Microsoft.MSPaint')
        StoreProgramIdPrefixes = @('Microsoft.MSPaint')
    }
    '3DViewer' = [pscustomobject]@{
        Key                    = '3DViewer'
        DisplayName            = '3D Viewer'
        AppxNames              = @('Microsoft.Microsoft3DViewer')
        StoreProgramIdPrefixes = @('Microsoft.Microsoft3DViewer')
    }
}

function Write-Log {
    [CmdletBinding()]
    param(
        [string]$Message,
        [ValidateSet('Info','Warning','Error')]
        [string]$Level = 'Info'
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = "[{0}] [{1}] {2}" -f $timestamp, $Level, $Message

    switch ($Level) {
        'Info'    { Write-Host $line }
        'Warning' { Write-Warning $line }
        'Error'   { Write-Error $line }
    }
}

function Test-AdminRights {
    [CmdletBinding()]
    param()

    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-UniqueSortedVersions {
    [CmdletBinding()]
    param([string[]]$Strings)

    $clean = @(
        $Strings |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            ForEach-Object { $_.Trim() } |
            Select-Object -Unique
    )

    if (-not $clean) {
        return @()
    }

    return @(
        $clean |
            Sort-Object {
                try { [version]$_ }
                catch { [version]'0.0.0.0' }
            } -Descending
    )
}

function Get-StorePrograms {
    [CmdletBinding()]
    param()

    try {
        return @(Get-CimInstance -ClassName Win32_InstalledStoreProgram -ErrorAction Stop)
    }
    catch {
        Write-Log -Message "Win32_InstalledStoreProgram inventory is unavailable: $($_.Exception.Message)" -Level 'Warning'
        return @()
    }
}

function Get-AllProvisionedPackages {
    [CmdletBinding()]
    param()

    try {
        return @(Get-AppxProvisionedPackage -Online -ErrorAction Stop)
    }
    catch {
        Write-Log -Message "Unable to query provisioned Appx packages: $($_.Exception.Message)" -Level 'Warning'
        return @()
    }
}

function Test-StoreProgramMatch {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$StoreProgram,

        [Parameter(Mandatory)]
        [pscustomobject]$Target
    )

    $programId = [string]$StoreProgram.ProgramId

    foreach ($prefix in $Target.StoreProgramIdPrefixes) {
        if ($programId -like "$prefix*") {
            return $true
        }
    }

    return $false
}

function Test-PackageInstalledForAnyUser {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Package
    )

    $infos = @($Package.PackageUserInformation)
    if ($infos.Count -eq 0) {
        return $true
    }

    foreach ($info in $infos) {
        if ([string]$info.InstallState -eq 'Installed') {
            return $true
        }
    }

    return $false
}

function Get-InstalledPackages {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Target,

        [switch]$AllUsers,

        [ValidateSet('Main','Bundle')]
        [string]$PackageType = 'Main'
    )

    $packages = @()

    foreach ($name in $Target.AppxNames) {
        $params = @{
            Name              = $name
            PackageTypeFilter = @($PackageType)
            ErrorAction       = 'Stop'
        }

        if ($AllUsers) {
            $params['AllUsers'] = $true
        }

        try {
            $found = @(Get-AppxPackage @params)
        }
        catch {
            $message = $_.Exception.Message

            if ($AllUsers -and $message -match 'denied|administrator|elevat') {
                Write-Log -Message "Unable to query $PackageType packages for all users on $($Target.DisplayName): $message" -Level 'Warning'
            }
            else {
                Write-Log -Message "Package query failed for $($Target.DisplayName): $message" -Level 'Warning'
            }

            $found = @()
        }

        if ($AllUsers) {
            $found = @($found | Where-Object { Test-PackageInstalledForAnyUser -Package $_ })
        }

        $packages += $found
    }

    return @($packages | Sort-Object PackageFullName -Unique)
}

function Get-TargetInventory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Target,

        [switch]$AllUsers,

        [object[]]$StorePrograms,

        [object[]]$AllProvisionedPackages
    )

    if (-not $PSBoundParameters.ContainsKey('StorePrograms')) {
        $StorePrograms = Get-StorePrograms
    }

    if (-not $PSBoundParameters.ContainsKey('AllProvisionedPackages')) {
        $AllProvisionedPackages = Get-AllProvisionedPackages
    }

    $scannerMatches = @(
        $StorePrograms |
            Where-Object { Test-StoreProgramMatch -StoreProgram $_ -Target $Target }
    )

    $mainPackages = @(Get-InstalledPackages -Target $Target -AllUsers:$AllUsers -PackageType Main)
    $bundlePackages = @()
    if ($AllUsers) {
        $bundlePackages = @(Get-InstalledPackages -Target $Target -AllUsers:$AllUsers -PackageType Bundle)
    }

    $provisionedPackages = @(
        $AllProvisionedPackages |
            Where-Object { $Target.AppxNames -contains $_.DisplayName }
    )

    $scannerVersions = @(Get-UniqueSortedVersions -Strings @($scannerMatches | ForEach-Object { [string]$_.Version }))
    $mainVersions = @(Get-UniqueSortedVersions -Strings @($mainPackages | ForEach-Object { [string]$_.Version }))
    $bundleVersions = @(Get-UniqueSortedVersions -Strings @($bundlePackages | ForEach-Object { [string]$_.Version }))
    $provisionedVersions = @(Get-UniqueSortedVersions -Strings @($provisionedPackages | ForEach-Object { [string]$_.Version }))

    $removableVersions = if ($AllUsers) {
        @(Get-UniqueSortedVersions -Strings (@($bundleVersions) + @($mainVersions) + @($provisionedVersions)))
    }
    else {
        @(Get-UniqueSortedVersions -Strings @($mainVersions))
    }

    $displayVersions = @(Get-UniqueSortedVersions -Strings (@($scannerVersions) + @($bundleVersions) + @($mainVersions) + @($provisionedVersions)))

    return [pscustomobject]@{
        Target              = $Target
        StorePrograms       = $scannerMatches
        MainPackages        = $mainPackages
        BundlePackages      = $bundlePackages
        ProvisionedPackages = $provisionedPackages
        ScannerVersions     = $scannerVersions
        MainVersions        = $mainVersions
        BundleVersions      = $bundleVersions
        ProvisionedVersions = $provisionedVersions
        RemovableVersions   = $removableVersions
        Versions            = $displayVersions
    }
}

function Show-Inventory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject[]]$Inventories
    )

    foreach ($inventory in $Inventories) {
        Write-Host ''
        Write-Log -Message ("=== {0} ===" -f $inventory.Target.DisplayName)

        if ($inventory.Versions.Count -gt 0) {
            Write-Log -Message ("Detected versions: {0}" -f ($inventory.Versions -join ', '))
        }
        else {
            Write-Log -Message 'Detected versions: none'
        }

        Write-Log -Message 'Scanner view (Win32_InstalledStoreProgram):'
        if ($inventory.StorePrograms.Count -gt 0) {
            foreach ($item in ($inventory.StorePrograms | Sort-Object {
                try { [version]$_.Version }
                catch { [version]'0.0.0.0' }
            } -Descending)) {
                Write-Log -Message ("  - Name='{0}'; ProgramId='{1}'; Version='{2}'" -f $item.Name, $item.ProgramId, $item.Version)
            }
        }
        else {
            Write-Log -Message '  - Not detected'
        }

        Write-Log -Message 'Installed MAIN packages:'
        if ($inventory.MainPackages.Count -gt 0) {
            foreach ($pkg in ($inventory.MainPackages | Sort-Object {
                try { [version]$_.Version }
                catch { [version]'0.0.0.0' }
            } -Descending)) {
                Write-Log -Message ("  - {0}" -f $pkg.PackageFullName)
            }
        }
        else {
            Write-Log -Message '  - None'
        }

        Write-Log -Message 'Installed BUNDLE packages:'
        if ($inventory.BundlePackages.Count -gt 0) {
            foreach ($pkg in ($inventory.BundlePackages | Sort-Object {
                try { [version]$_.Version }
                catch { [version]'0.0.0.0' }
            } -Descending)) {
                Write-Log -Message ("  - {0}" -f $pkg.PackageFullName)
            }
        }
        else {
            Write-Log -Message '  - None'
        }

        Write-Log -Message 'Provisioned packages:'
        if ($inventory.ProvisionedPackages.Count -gt 0) {
            foreach ($pkg in ($inventory.ProvisionedPackages | Sort-Object {
                try { [version]$_.Version }
                catch { [version]'0.0.0.0' }
            } -Descending)) {
                Write-Log -Message ("  - {0}" -f $pkg.PackageName)
            }
        }
        else {
            Write-Log -Message '  - None'
        }

        if ($inventory.RemovableVersions.Count -gt 0) {
            Write-Log -Message ("Removable versions in this mode: {0}" -f ($inventory.RemovableVersions -join ', '))
        }
        else {
            Write-Log -Message 'Removable versions in this mode: none'
        }
    }
}

function Get-AllInventories {
    [CmdletBinding()]
    param([switch]$AllUsers)

    $storePrograms = Get-StorePrograms
    $allProvisionedPackages = Get-AllProvisionedPackages

    $inventories = foreach ($target in $script:Targets.Values) {
        Get-TargetInventory `
            -Target $target `
            -AllUsers:$AllUsers `
            -StorePrograms $storePrograms `
            -AllProvisionedPackages $allProvisionedPackages
    }

    return @($inventories)
}

function Resolve-InventoryForUninstall {
    [CmdletBinding()]
    param(
        [switch]$AllUsers,
        [string]$TargetApp
    )

    if ($TargetApp) {
        $inventory = Get-TargetInventory -Target $script:Targets[$TargetApp] -AllUsers:$AllUsers

        if ($inventory.RemovableVersions.Count -eq 0) {
            if (-not $AllUsers -and $inventory.ProvisionedPackages.Count -gt 0) {
                Write-Log -Message "Only provisioned packages remain for $($inventory.Target.DisplayName). Re-run with -AllUsers to remove them." -Level 'Warning'
            }
            else {
                Write-Log -Message "No removable packages were found for $($inventory.Target.DisplayName)." -Level 'Warning'
            }
            return $null
        }

        return $inventory
    }

    $inventories = Get-AllInventories -AllUsers:$AllUsers
    $removable = @(
        $inventories |
            Where-Object { $_.RemovableVersions.Count -gt 0 }
    )

    if (-not $removable) {
        Write-Log -Message 'No removable Paint-family Appx packages were found.' -Level 'Warning'
        return $null
    }

    if ($removable.Count -eq 1) {
        return $removable[0]
    }

    Write-Host ''
    Write-Host 'Select the Paint-family app to remove:'
    for ($i = 0; $i -lt $removable.Count; $i++) {
        $versionsText = $removable[$i].RemovableVersions -join ', '
        Write-Host ("[{0}] {1}  (versions: {2})" -f ($i + 1), $removable[$i].Target.DisplayName, $versionsText)
    }

    while ($true) {
        $answer = Read-Host "Enter a number from 1 to $($removable.Count)"
        $selectedIndex = 0

        if ([int]::TryParse($answer, [ref]$selectedIndex) -and
            $selectedIndex -ge 1 -and
            $selectedIndex -le $removable.Count) {
            return $removable[$selectedIndex - 1]
        }

        Write-Host 'Invalid selection. Try again.'
    }
}

function Resolve-VersionForUninstall {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Inventory,

        [string]$TargetVersion
    )

    $availableVersions = @($Inventory.RemovableVersions)

    if (-not $availableVersions) {
        Write-Log -Message "No removable versions were found for $($Inventory.Target.DisplayName)." -Level 'Warning'
        return $null
    }

    if ($TargetVersion) {
        $trimmed = $TargetVersion.Trim()

        if ($trimmed -ieq 'ALL') {
            return 'ALL'
        }

        if ($availableVersions -contains $trimmed) {
            return $trimmed
        }

        throw "TargetVersion '$TargetVersion' is not removable for $($Inventory.Target.DisplayName). Removable versions: $($availableVersions -join ', ')"
    }

    Write-Host ''
    Write-Host ("Removable versions for {0}:" -f $Inventory.Target.DisplayName)
    for ($i = 0; $i -lt $availableVersions.Count; $i++) {
        Write-Host ("[{0}] {1}" -f ($i + 1), $availableVersions[$i])
    }
    Write-Host '[A] ALL versions'

    $promptText = if ($Inventory.Target.Key -eq 'Paint') {
        'Enter the version of Microsoft Paint you want to remove'
    }
    else {
        "Enter the version of $($Inventory.Target.DisplayName) you want to remove"
    }

    while ($true) {
        $answer = (Read-Host "$promptText (number, exact version, or A)").Trim()

        if ($answer -match '^(?i)A(LL)?$') {
            return 'ALL'
        }

        $selectedIndex = 0
        if ([int]::TryParse($answer, [ref]$selectedIndex) -and
            $selectedIndex -ge 1 -and
            $selectedIndex -le $availableVersions.Count) {
            return $availableVersions[$selectedIndex - 1]
        }

        if ($availableVersions -contains $answer) {
            return $answer
        }

        Write-Host 'Invalid selection. Try again.'
    }
}

function Remove-SelectedTargetVersion {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Inventory,

        [Parameter(Mandatory)]
        [string]$Version,

        [switch]$AllUsers,

        [switch]$SkipProvisionedRemoval
    )

    $removedAnything = $false

    if ($AllUsers) {
        $bundleMatches = if ($Version -eq 'ALL') {
            @($Inventory.BundlePackages)
        }
        else {
            @($Inventory.BundlePackages | Where-Object { [string]$_.Version -eq $Version })
        }

        if ($bundleMatches.Count -gt 0) {
            foreach ($pkg in ($bundleMatches | Sort-Object PackageFullName -Descending)) {
                $targetText = "{0} BUNDLE package {1}" -f $Inventory.Target.DisplayName, $pkg.PackageFullName

                if ($PSCmdlet.ShouldProcess($targetText, 'Remove-AppxPackage -AllUsers')) {
                    try {
                        Remove-AppxPackage -Package $pkg.PackageFullName -AllUsers -ErrorAction Stop
                        Write-Log -Message "Removed installed BUNDLE package for all users: $($pkg.PackageFullName)"
                        $removedAnything = $true
                    }
                    catch {
                        Write-Log -Message "Failed to remove installed BUNDLE package $($pkg.PackageFullName): $($_.Exception.Message)" -Level 'Warning'
                    }
                }
            }
        }
        else {
            $mainMatches = if ($Version -eq 'ALL') {
                @($Inventory.MainPackages)
            }
            else {
                @($Inventory.MainPackages | Where-Object { [string]$_.Version -eq $Version })
            }

            foreach ($pkg in ($mainMatches | Sort-Object PackageFullName -Descending)) {
                $targetText = "{0} MAIN package {1}" -f $Inventory.Target.DisplayName, $pkg.PackageFullName

                if ($PSCmdlet.ShouldProcess($targetText, 'Remove-AppxPackage -AllUsers')) {
                    try {
                        Remove-AppxPackage -Package $pkg.PackageFullName -AllUsers -ErrorAction Stop
                        Write-Log -Message "Removed installed MAIN package for all users: $($pkg.PackageFullName)"
                        $removedAnything = $true
                    }
                    catch {
                        Write-Log -Message "Failed to remove installed MAIN package $($pkg.PackageFullName): $($_.Exception.Message)" -Level 'Warning'
                    }
                }
            }
        }
    }
    else {
        $mainMatches = if ($Version -eq 'ALL') {
            @($Inventory.MainPackages)
        }
        else {
            @($Inventory.MainPackages | Where-Object { [string]$_.Version -eq $Version })
        }

        if ($mainMatches.Count -eq 0) {
            Write-Log -Message "No installed MAIN packages matched version '$Version' for $($Inventory.Target.DisplayName)." -Level 'Warning'
        }
        else {
            foreach ($pkg in ($mainMatches | Sort-Object PackageFullName -Descending)) {
                $targetText = "{0} MAIN package {1}" -f $Inventory.Target.DisplayName, $pkg.PackageFullName

                if ($PSCmdlet.ShouldProcess($targetText, 'Remove-AppxPackage')) {
                    try {
                        Remove-AppxPackage -Package $pkg.PackageFullName -ErrorAction Stop
                        Write-Log -Message "Removed installed MAIN package: $($pkg.PackageFullName)"
                        $removedAnything = $true
                    }
                    catch {
                        Write-Log -Message "Failed to remove installed MAIN package $($pkg.PackageFullName): $($_.Exception.Message)" -Level 'Warning'
                    }
                }
            }
        }
    }

    if ($AllUsers -and -not $SkipProvisionedRemoval) {
        $provisionedMatches = if ($Version -eq 'ALL') {
            @($Inventory.ProvisionedPackages)
        }
        else {
            @($Inventory.ProvisionedPackages | Where-Object { [string]$_.Version -eq $Version })
        }

        foreach ($pkg in ($provisionedMatches | Sort-Object PackageName -Descending)) {
            $targetText = "{0} provisioned package {1}" -f $Inventory.Target.DisplayName, $pkg.PackageName

            if ($PSCmdlet.ShouldProcess($targetText, 'Remove-AppxProvisionedPackage')) {
                try {
                    Remove-AppxProvisionedPackage -Online -PackageName $pkg.PackageName -ErrorAction Stop | Out-Null
                    Write-Log -Message "Removed provisioned package: $($pkg.PackageName)"
                    $removedAnything = $true
                }
                catch {
                    Write-Log -Message "Failed to remove provisioned package $($pkg.PackageName): $($_.Exception.Message)" -Level 'Warning'
                }
            }
        }
    }
    elseif (-not $AllUsers -and $Inventory.ProvisionedPackages.Count -gt 0) {
        Write-Log -Message 'Provisioned package removal was skipped because -AllUsers was not specified.'
    }

    return $removedAnything
}

function Main {
    [CmdletBinding()]
    param()

    Write-Log -Message '=== Microsoft Paint-family App Manager ==='
    Write-Log -Message ("Scope: {0}" -f $(if ($AllUsers) { 'All users' } else { 'Current user' }))

    if ($Check -and $Uninstall) {
        throw 'Use either -Check or -Uninstall, not both.'
    }

    if (-not ($Check -or $Uninstall)) {
        throw 'No action specified. Use -Check or -Uninstall.'
    }

    if ($Uninstall -and -not (Test-AdminRights)) {
        throw 'Administrator rights are required for -Uninstall. Run the script in an elevated PowerShell session.'
    }

    if ($Check) {
        $inventories = Get-AllInventories -AllUsers:$AllUsers
        Show-Inventory -Inventories $inventories
        Write-Host ''
        Write-Log -Message 'Finished.'
        return
    }

    $inventory = Resolve-InventoryForUninstall -AllUsers:$AllUsers -TargetApp $TargetApp
    if (-not $inventory) {
        Write-Host ''
        Write-Log -Message 'Finished.'
        return
    }

    $versionToRemove = Resolve-VersionForUninstall -Inventory $inventory -TargetVersion $TargetVersion
    if (-not $versionToRemove) {
        Write-Host ''
        Write-Log -Message 'Finished.'
        return
    }

    Write-Host ''
    Write-Log -Message ("Selected app                 : {0}" -f $inventory.Target.DisplayName)
    Write-Log -Message ("Selected version             : {0}" -f $versionToRemove)
    Write-Log -Message ("Remove provisioned packages  : {0}" -f $(if ($AllUsers -and -not $SkipProvisionedRemoval) { 'Yes' } else { 'No' }))

    $changed = Remove-SelectedTargetVersion `
        -Inventory $inventory `
        -Version $versionToRemove `
        -AllUsers:$AllUsers `
        -SkipProvisionedRemoval:$SkipProvisionedRemoval

    Write-Host ''
    Write-Log -Message '=== Post-removal state ==='

    $postInventory = Get-TargetInventory -Target $inventory.Target -AllUsers:$AllUsers
    Show-Inventory -Inventories @($postInventory)

    if (-not $AllUsers -and $postInventory.StorePrograms.Count -gt 0 -and $postInventory.MainPackages.Count -eq 0) {
        Write-Host ''
        Write-Log -Message "The scanner-aligned WMI view still shows $($postInventory.Target.DisplayName), but no current-user MAIN package remains." -Level 'Warning'
        Write-Log -Message "That usually means another user profile still has the app installed, or WMI inventory has not refreshed yet." -Level 'Warning'
        Write-Log -Message "Run again with -Uninstall -AllUsers, or inspect PackageUserInformation with Get-AppxPackage -AllUsers." -Level 'Warning'
    }

    Write-Host ''
    if ($changed) {
        Write-Log -Message 'Removal attempt completed.'
    }
    else {
        Write-Log -Message 'No packages were removed.' -Level 'Warning'
    }

    Write-Log -Message 'Finished.'
}

Main
