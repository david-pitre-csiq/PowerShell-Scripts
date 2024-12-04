# Set-NullSessions.Tests.ps1

# Import the script to be tested
. "$PSScriptRoot\Set-NullSessions.ps1"

Describe "Set-NullSessions Script Tests" {
    BeforeAll {
        # Mock the functions that interact with the system
        Mock -CommandName Test-AdminRights -MockWith { return $true }
        Mock -CommandName Write-Log
        Mock -CommandName Set-ItemProperty
        Mock -CommandName Get-RegistryValue -MockWith { return 1 }
    }

    Context "When checking null session restriction status" {
        It "Should return the current null session restriction status" {
            $resultAnonymous = Get-RegistryValue -RegPath "HKLM:\SYSTEM\CurrentControlSet\Control\LSA" -ValueName "RestrictAnonymous"
            $resultNullSessAccess = Get-RegistryValue -RegPath "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -ValueName "RestrictNullSessAccess"
            $resultAnonymous | Should -Be 1
            $resultNullSessAccess | Should -Be 1
        }
    }

    Context "When enabling anonymous access restriction" {
        It "Should set the registry value to enable anonymous access restriction" {
            $command = [RestrictAnonymousCommand]::new()
            $command.Execute()
            Assert-MockCalled -CommandName Set-ItemProperty -Exactly 1 -Scope It
        }
    }

    Context "When enabling null session access restriction" {
        It "Should set the registry value to enable null session access restriction" {
            $command = [RestrictNullSessionAccessCommand]::new()
            $command.Execute()
            Assert-MockCalled -CommandName Set-ItemProperty -Exactly 1 -Scope It
        }
    }

    Context "When enabling null session access" {
        It "Should set the registry value to enable null session access" {
            $command = [EnableNullSessionAccessCommand]::new()
            $command.Execute()
            Assert-MockCalled -CommandName Set-ItemProperty -Exactly 1 -Scope It
        }
    }

    Context "When enabling anonymous access" {
        It "Should set the registry value to enable anonymous access" {
            $command = [EnableAnonymousCommand]::new()
            $command.Execute()
            Assert-MockCalled -CommandName Set-ItemProperty -Exactly 1 -Scope It
        }
    }

    Context "When no parameters are provided" {
        It "Should display help information" {
            Mock -CommandName Get-Help
            Main -Check:$false -RestrictAnonymous:$false -RestrictNullSessionAccess:$false -EnableNullSessionAccess:$false -EnableAnonymous:$false
            Assert-MockCalled -CommandName Get-Help -Exactly 1 -Scope It
        }
    }
}
