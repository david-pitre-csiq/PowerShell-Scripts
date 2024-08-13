# Import the script to be tested
. "$PSScriptRoot\..\Computer\Set-SMBv1.ps1"

Describe "Set-SMBv1 Script Tests" {
    BeforeAll {
        # Mock functions that interact with the system
        Mock -CommandName Get-WindowsOptionalFeature -MockWith {
            return @{
                State = "Enabled"
            }
        }
        Mock -CommandName Set-SmbServerConfiguration
        Mock -CommandName Enable-WindowsOptionalFeature
        Mock -CommandName Disable-WindowsOptionalFeature
        Mock -CommandName Restart-Service
        Mock -CommandName Write-Log
        Mock -CommandName Get-SmbServerConfiguration -MockWith {
            return @{
                EnableSMB1Protocol = $true
            }
        }
    }

    Context "When checking SMBv1 status" {
        It "Should log the current SMBv1 status" {
            $params = @{
                Check = $true
            }
            Main @params

            Assert-MockCalled -CommandName Get-WindowsOptionalFeature -Times 1
            Assert-MockCalled -CommandName Get-SmbServerConfiguration -Times 1
            Assert-MockCalled -CommandName Write-Log -Times 2
        }
    }

    Context "When enabling SMBv1" {
        It "Should enable SMBv1 on both client and server" {
            $params = @{
                Enable = $true
            }
            Main @params

            Assert-MockCalled -CommandName Enable-WindowsOptionalFeature -Times 1
            Assert-MockCalled -CommandName Set-SmbServerConfiguration -Times 1
            Assert-MockCalled -CommandName Restart-Service -Times 2
            Assert-MockCalled -CommandName Write-Log -Times 5
        }
    }

    Context "When disabling SMBv1" {
        It "Should disable SMBv1 on both client and server" {
            $params = @{
                Disable = $true
            }
            Main @params

            Assert-MockCalled -CommandName Disable-WindowsOptionalFeature -Times 1
            Assert-MockCalled -CommandName Set-SmbServerConfiguration -Times 1
            Assert-MockCalled -CommandName Restart-Service -Times 2
            Assert-MockCalled -CommandName Write-Log -Times 5
        }
    }

    Context "When no parameters are provided" {
        It "Should display help" {
            Mock -CommandName Get-Help
            $params = @{}
            Main @params

            Assert-MockCalled -CommandName Get-Help -Times 1
        }
    }

    Context "When conflicting parameters are provided" {
        It "Should throw an error" {
            $params = @{
                Enable = $true
                Disable = $true
            }
            { Main @params } | Should -Throw "Conflicting parameters detected. Enable, Disable, and Check commands cannot be run at the same time."
        }
    }

    Context "When not running as administrator" {
        It "Should throw an error" {
            Mock -CommandName Test-AdminRights -MockWith { return $false }
            $params = @{
                Enable = $true
            }
            { Main @params } | Should -Throw "This script requires administrator rights. Please run as administrator."
        }
    }
}
