# Enable-SMBSigning.Tests.ps1

# Import the script to be tested
. "$PSScriptRoot\Enable-SMBSigning.ps1"

Describe "Enable-SMBSigning Script Tests" {
    BeforeAll {
        # Mock the functions that interact with the system
        Mock -CommandName Test-AdminRights -MockWith { return $true }
        Mock -CommandName Write-Log
        Mock -CommandName Set-ItemProperty
        Mock -CommandName Get-ItemProperty -MockWith { return @{ EnableSecuritySignature = 1 } }
        Mock -CommandName Restart-Service
    }

    Context "When checking SMB Signing status" {
        It "Should return the current SMB Signing status" {
            $result = Get-SMBSigningStatus -RegPath "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -ValueName "EnableSecuritySignature"
            $result | Should -Be 1
        }
    }

    Context "When enabling SMB Signing on the client side" {
        It "Should set the registry value to enable SMB Signing" {
            $command = [EnableClientSMBSigningCommand]::new()
            $command.Execute()
            Assert-MockCalled -CommandName Set-ItemProperty -Exactly 1 -Scope It
        }
    }

    Context "When disabling SMB Signing on the client side" {
        It "Should set the registry value to disable SMB Signing" {
            $command = [DisableClientSMBSigningCommand]::new()
            $command.Execute()
            Assert-MockCalled -CommandName Set-ItemProperty -Exactly 1 -Scope It
        }
    }

    Context "When enabling SMB Signing on the server side" {
        It "Should set the registry value to enable SMB Signing" {
            $command = [EnableServerSMBSigningCommand]::new()
            $command.Execute()
            Assert-MockCalled -CommandName Set-ItemProperty -Exactly 1 -Scope It
        }
    }

    Context "When disabling SMB Signing on the server side" {
        It "Should set the registry value to disable SMB Signing" {
            $command = [DisableServerSMBSigningCommand]::new()
            $command.Execute()
            Assert-MockCalled -CommandName Set-ItemProperty -Exactly 1 -Scope It
        }
    }

    Context "When requiring SMB Signing on the server side" {
        It "Should set the registry value to require SMB Signing" {
            $command = [RequireServerSMBSigningCommand]::new()
            $command.Execute()
            Assert-MockCalled -CommandName Set-ItemProperty -Exactly 1 -Scope It
        }
    }

    Context "When disabling the requirement for SMB Signing on the server side" {
        It "Should set the registry value to disable the requirement for SMB Signing" {
            $command = [DisableRequireServerSMBSigningCommand]::new()
            $command.Execute()
            Assert-MockCalled -CommandName Set-ItemProperty -Exactly 1 -Scope It
        }
    }

    Context "When enabling all required SMB Signing" {
        It "Should set the registry values to enable all required SMB Signing" {
            $command = [EnableAllRequiredSMBSigningCommand]::new()
            $command.Execute()
            Assert-MockCalled -CommandName Set-ItemProperty -Exactly 3 -Scope It
        }
    }
}
