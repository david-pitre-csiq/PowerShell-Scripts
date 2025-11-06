# Load the script to be tested
. "$PSScriptRoot\Set-LmCompatibilityLevel.ps1"

Describe "Set-LmCompatibilityLevel.ps1" {
    BeforeAll {
        # Mock the functions that interact with the system
        Mock -CommandName Test-AdminRights -MockWith { return $true }
        Mock -CommandName Write-Log
        Mock -CommandName Get-ItemProperty -MockWith { return $null }
    }

    Context "When checking LmCompatibilityLevel status" {
        It "Should call Get-LmCompatibilityLevel when -Check is specified" {
            $Check = $true
            $Enable = $false
            $Disable = $false
            { Main } | Should -Not -Throw
            Assert-MockCalled -CommandName Write-Log -Times -AtLeast 1
        }
    }

    Context "When enabling LmCompatibilityLevel" {
        It "Should set LmCompatibilityLevel to 5 when -Enable is specified" {
            $Check = $false
            $Enable = $true
            $Disable = $false
            { Main } | Should -Not -Throw
            Assert-MockCalled -CommandName Write-Log -Times -AtLeast 1
        }
    }

    Context "When disabling LmCompatibilityLevel" {
        It "Should remove LmCompatibilityLevel when -Disable is specified" {
            $Check = $false
            $Enable = $false
            $Disable = $true
            { Main } | Should -Not -Throw
            Assert-MockCalled -CommandName Write-Log -Times -AtLeast 1
        }
    }

    Context "When running without parameters" {
        It "Should log a warning for missing parameters" {
            $Check = $false
            $Enable = $false
            $Disable = $false
            Main
            Assert-MockCalled -CommandName Write-Log -ParameterFilter { $Level -eq 'Warning' -and $Message -like '*No action specified*' } -Times 1
        }
    }

    Context "When running with conflicting parameters" {
        It "Should throw an error for conflicting parameters" {
            $Check = $false
            $Enable = $true
            $Disable = $true
            { Main } | Should -Throw "*Conflicting parameters*"
        }
    }

    Context "When running without admin rights" {
        It "Should throw an error when not running as administrator" {
            Mock -CommandName Test-AdminRights -MockWith { return $false }
            $Check = $true
            $Enable = $false
            $Disable = $false
            { Main } | Should -Throw "*Administrator rights are required*"
        }
    }

    Context "Get-LevelText function" {
        It "Should return 'Not Defined' for null value" {
            Get-LevelText -Value $null | Should -Be 'Not Defined'
        }

        It "Should return correct description for level 5" {
            Get-LevelText -Value 5 | Should -Be 'Send NTLMv2 response only. Refuse LM & NTLM'
        }

        It "Should return 'Unknown' for invalid level" {
            Get-LevelText -Value 99 | Should -BeLike 'Unknown*'
        }
    }

    Context "Get-RegistryViews function" {
        It "Should return appropriate registry views based on OS" {
            $views = Get-RegistryViews
            $views | Should -Not -BeNullOrEmpty
            if ([Environment]::Is64BitOperatingSystem) {
                $views.Count | Should -Be 2
            } else {
                $views.Count | Should -Be 1
            }
        }
    }
}

