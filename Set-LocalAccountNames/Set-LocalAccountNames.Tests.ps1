# Import the module or script to be tested
. "$PSScriptRoot\Set-LocalAccountNames.ps1"

Describe "Set-LocalAccountNames" {
    BeforeAll {
        # Mocking functions and cmdlets
        Mock -CommandName Get-LocalUser -MockWith {
            param ($Name)
            if ($Name -eq "Administrator") {
                return [PSCustomObject]@{ Name = "Administrator"; Enabled = $true; SID = "S-1-5-21-500" }
            }
            elseif ($Name -eq "Guest") {
                return [PSCustomObject]@{ Name = "Guest"; Enabled = $false; SID = "S-1-5-21-501" }
            }
        }

        Mock -CommandName Rename-LocalUser
        Mock -CommandName Disable-LocalUser
        Mock -CommandName Enable-LocalUser
        Mock -CommandName Write-Log
        Mock -CommandName Test-AdminRights -MockWith { return $true }
    }

    Context "Renaming Accounts" {
        It "Renames Administrator account" {
            $params = @{
                NewAdminName = "Admin123"
            }
            Main @params

            Assert-MockCalled -CommandName Rename-LocalUser -Exactly 1 -Scope It
            Assert-MockCalled -CommandName Write-Log -Exactly 1 -Scope It -ParameterFilter { $Message -like "*account renamed to Admin123*" }
        }

        It "Renames Guest account" {
            $params = @{
                NewGuestName = "Visitor"
            }
            Main @params

            Assert-MockCalled -CommandName Rename-LocalUser -Exactly 1 -Scope It
            Assert-MockCalled -CommandName Write-Log -Exactly 1 -Scope It -ParameterFilter { $Message -like "*account renamed to Visitor*" }
        }
    }

    Context "Disabling Accounts" {
        It "Disables Administrator account" {
            $params = @{
                NewAdminName = "Administrator"
                DisableAccounts = $true
            }
            Main @params

            Assert-MockCalled -CommandName Disable-LocalUser -Exactly 1 -Scope It
            Assert-MockCalled -CommandName Write-Log -Exactly 1 -Scope It -ParameterFilter { $Message -like "*account disabled*" }
        }

        It "Disables Guest account" {
            $params = @{
                NewGuestName = "Guest"
                DisableAccounts = $true
            }
            Main @params

            Assert-MockCalled -CommandName Disable-LocalUser -Exactly 1 -Scope It
            Assert-MockCalled -CommandName Write-Log -Exactly 1 -Scope It -ParameterFilter { $Message -like "*account disabled*" }
        }
    }

    Context "Enabling Accounts" {
        It "Enables Administrator account" {
            Mock -CommandName Get-LocalUser -MockWith {
                param ($Name)
                if ($Name -eq "Administrator") {
                    return [PSCustomObject]@{ Name = "Administrator"; Enabled = $false; SID = "S-1-5-21-500" }
                }
            }

            $params = @{
                NewAdminName = "Administrator"
                EnableAccounts = $true
            }
            Main @params

            Assert-MockCalled -CommandName Enable-LocalUser -Exactly 1 -Scope It
            Assert-MockCalled -CommandName Write-Log -Exactly 1 -Scope It -ParameterFilter { $Message -like "*account enabled*" }
        }

        It "Enables Guest account" {
            Mock -CommandName Get-LocalUser -MockWith {
                param ($Name)
                if ($Name -eq "Guest") {
                    return [PSCustomObject]@{ Name = "Guest"; Enabled = $false; SID = "S-1-5-21-501" }
                }
            }

            $params = @{
                NewGuestName = "Guest"
                EnableAccounts = $true
            }
            Main @params

            Assert-MockCalled -CommandName Enable-LocalUser -Exactly 1 -Scope It
            Assert-MockCalled -CommandName Write-Log -Exactly 1 -Scope It -ParameterFilter { $Message -like "*account enabled*" }
        }
    }
}
