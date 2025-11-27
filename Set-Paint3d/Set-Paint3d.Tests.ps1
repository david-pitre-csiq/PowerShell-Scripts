# Load the script to be tested
. "$PSScriptRoot\Set-Paint3d.ps1"

Describe "Set-Paint3d.ps1" {
    BeforeAll {
        # Mock the functions that interact with the system
        Mock -CommandName Test-AdminRights -MockWith { return $true }
        Mock -CommandName Write-Log
        Mock -CommandName Get-AppxPackage -MockWith { return $null }
        Mock -CommandName Get-Command -MockWith { return $null }
    }

    Context "When checking Paint 3D status" {
        It "Should call Get-Paint3DStatus when -Check is specified" {
            Mock -CommandName Get-Paint3DPackage -MockWith { return $null }
            
            $Check = $true
            $Update = $false
            $Uninstall = $false
            $AllUsers = $false
            
            { Main } | Should -Not -Throw
            Assert-MockCalled -CommandName Write-Log -Times -AtLeast 1
        }
        
        It "Should detect installed Paint 3D package" {
            $mockPackage = [PSCustomObject]@{
                PackageFullName = 'Microsoft.MSPaint_6.1905.29027.0_x64__8wekyb3d8bbwe'
                Version = '6.1905.29027.0'
            }
            
            Mock -CommandName Get-AppxPackage -MockWith { return $mockPackage }
            
            $status = Get-Paint3DStatus
            $status.IsInstalled | Should -Be $true
        }
        
        It "Should detect when Paint 3D is not installed" {
            Mock -CommandName Get-AppxPackage -MockWith { return $null }
            
            $status = Get-Paint3DStatus
            $status.IsInstalled | Should -Be $false
        }
    }

    Context "When updating Paint 3D" {
        It "Should attempt to use winget when available" {
            Mock -CommandName Get-Command -MockWith { 
                return [PSCustomObject]@{ Name = 'winget' } 
            }
            Mock -CommandName Start-Process
            
            $Check = $false
            $Update = $true
            $Uninstall = $false
            
            { Main } | Should -Not -Throw
            Assert-MockCalled -CommandName Write-Log -Times -AtLeast 1
        }
        
        It "Should warn when winget is not available" {
            Mock -CommandName Get-Command -MockWith { return $null }
            
            $result = Update-Paint3D
            $result.Success | Should -Be $false
        }
    }

    Context "When uninstalling Paint 3D" {
        It "Should remove Appx packages when found" {
            $mockPackage = [PSCustomObject]@{
                PackageFullName = 'Microsoft.MSPaint_6.1905.29027.0_x64__8wekyb3d8bbwe'
            }
            
            Mock -CommandName Get-AppxPackage -MockWith { return $mockPackage }
            Mock -CommandName Remove-AppxPackage
            
            $Check = $false
            $Update = $false
            $Uninstall = $true
            
            { Main } | Should -Not -Throw
        }
        
        It "Should handle AllUsers parameter correctly" {
            Mock -CommandName Get-AppxPackage -MockWith { return $null }
            
            $Check = $false
            $Update = $false
            $Uninstall = $true
            $AllUsers = $true
            
            { Main } | Should -Not -Throw
            Assert-MockCalled -CommandName Write-Log -Times -AtLeast 1
        }
    }

    Context "When running without parameters" {
        It "Should log a warning for missing parameters" {
            $Check = $false
            $Update = $false
            $Uninstall = $false
            
            Main
            Assert-MockCalled -CommandName Write-Log -ParameterFilter { 
                $Level -eq 'Warning' -and $Message -like '*No action specified*' 
            } -Times 1
        }
    }

    Context "When running with conflicting parameters" {
        It "Should throw an error for conflicting parameters" {
            $Check = $false
            $Update = $true
            $Uninstall = $true
            
            { Main } | Should -Throw "*Conflicting parameters*"
        }
    }

    Context "When running without admin rights" {
        It "Should throw an error when not running as administrator for Update" {
            Mock -CommandName Test-AdminRights -MockWith { return $false }
            
            $Check = $false
            $Update = $true
            $Uninstall = $false
            
            { Main } | Should -Throw "*Administrator rights are required*"
        }
        
        It "Should throw an error when not running as administrator for Uninstall" {
            Mock -CommandName Test-AdminRights -MockWith { return $false }
            
            $Check = $false
            $Update = $false
            $Uninstall = $true
            
            { Main } | Should -Throw "*Administrator rights are required*"
        }
        
        It "Should allow Check without admin rights" {
            Mock -CommandName Test-AdminRights -MockWith { return $false }
            Mock -CommandName Get-AppxPackage -MockWith { return $null }
            
            $Check = $true
            $Update = $false
            $Uninstall = $false
            
            { Main } | Should -Not -Throw
        }
    }

    Context "Get-Paint3DPackage function" {
        It "Should call Get-AppxPackage with correct parameters" {
            Mock -CommandName Get-AppxPackage -MockWith { return $null }
            
            Get-Paint3DPackage -AllUsers
            
            Assert-MockCalled -CommandName Get-AppxPackage -ParameterFilter {
                $Name -eq 'Microsoft.MSPaint' -and $AllUsers -eq $true
            } -Times 1
        }
        
        It "Should call Get-AppxPackage for current user when AllUsers not specified" {
            Mock -CommandName Get-AppxPackage -MockWith { return $null }
            
            Get-Paint3DPackage
            
            Assert-MockCalled -CommandName Get-AppxPackage -ParameterFilter {
                $Name -eq 'Microsoft.MSPaint'
            } -Times 1
        }
    }

    Context "Command Pattern Implementation" {
        It "Should create CheckPaint3DCommand successfully" {
            $cmd = [CheckPaint3DCommand]::new($false)
            $cmd | Should -Not -BeNullOrEmpty
            $cmd.AllUsers | Should -Be $false
        }
        
        It "Should create UpdatePaint3DCommand successfully" {
            $cmd = [UpdatePaint3DCommand]::new()
            $cmd | Should -Not -BeNullOrEmpty
            $cmd.Changed | Should -Be $false
            $cmd.Success | Should -Be $false
        }
        
        It "Should create UninstallPaint3DCommand successfully" {
            $cmd = [UninstallPaint3DCommand]::new($true)
            $cmd | Should -Not -BeNullOrEmpty
            $cmd.AllUsers | Should -Be $true
        }
        
        It "Should add commands to Paint3DManager" {
            $mgr = [Paint3DManager]::new()
            $cmd = [CheckPaint3DCommand]::new($false)
            $mgr.AddCommand($cmd)
            $mgr.Commands.Count | Should -Be 1
        }
    }
}

