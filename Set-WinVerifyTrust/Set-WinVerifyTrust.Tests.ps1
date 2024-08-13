# Load the script to be tested
. "$PSScriptRoot\Set-WinVerifyTrust.ps1"

Describe "Set-WinVerifyTrust.ps1" {
    BeforeAll {
        # Mock the functions that interact with the system
        Mock -CommandName Test-AdminRights -MockWith { return $true }
        Mock -CommandName Get-RegistryValue -MockWith { return 1 }
        Mock -CommandName Set-ItemProperty
        Mock -CommandName New-Item
        Mock -CommandName Write-Log
    }

    Context "When checking EnableCertPaddingCheck status" {
        It "Should call Get-RegistryValue for each registry path" {
            . "$PSScriptRoot\Set-WinVerifyTrust.ps1" -Check
            Assert-MockCalled -CommandName Get-RegistryValue -Times 2
        }
    }

    Context "When enabling EnableCertPaddingCheck" {
        It "Should set EnableCertPaddingCheck to 1 for each registry path" {
            . "$PSScriptRoot\Set-WinVerifyTrust.ps1" -Enable
            Assert-MockCalled -CommandName Set-ItemProperty -Times 2 -Exactly -Scope It
            Assert-MockCalled -CommandName Set-ItemProperty -ParameterFilter { $Name -eq "EnableCertPaddingCheck" -and $Value -eq 1 }
        }
    }

    Context "When disabling EnableCertPaddingCheck" {
        It "Should set EnableCertPaddingCheck to 0 for each registry path" {
            . "$PSScriptRoot\Set-WinVerifyTrust.ps1" -Disable
            Assert-MockCalled -CommandName Set-ItemProperty -Times 2 -Exactly -Scope It
            Assert-MockCalled -CommandName Set-ItemProperty -ParameterFilter { $Name -eq "EnableCertPaddingCheck" -and $Value -eq 0 }
        }
    }

    Context "When running without parameters" {
        It "Should throw an error for missing parameters" {
            { . "$PSScriptRoot\Set-WinVerifyTrust.ps1" } | Should -Throw "Conflicting or missing parameters detected. Use -Check, -Enable, or -Disable."
        }
    }

    Context "When running with conflicting parameters" {
        It "Should throw an error for conflicting parameters" {
            { . "$PSScriptRoot\Set-WinVerifyTrust.ps1" -Enable -Disable } | Should -Throw "Conflicting or missing parameters detected. Use -Check, -Enable, or -Disable."
        }
    }
}
