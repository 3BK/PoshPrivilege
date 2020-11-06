#handle PS2
if(-not $PSScriptRoot)
{
    $PSScriptRoot = Split-Path $MyInvocation.MyCommand.Path -Parent
}
 
#Verbose output if this isn't master, or we are testing locally
$Verbose = @{}
if($env:APPVEYOR_REPO_BRANCH -and $env:APPVEYOR_REPO_BRANCH -notlike "master" -or -not $env:APPVEYOR_REPO_BRANCH)
{
    $Verbose.add("Verbose",$False)
}
 
Import-Module $PSScriptRoot\..\PoshPrivilege\PoshPrivilege -Verbose -Force -ErrorAction SilentlyContinue
 
Describe "PoshPrivilege PS$PSVersion" {
    Context 'Strict mode' {
        Set-StrictMode -Version latest
        It 'should load all functions' {
            $Commands = @( Get-Command -CommandType Function -Module PoshPrivilege | Select -ExpandProperty Name)
            $Commands.count | Should be 1
            $Commands -contains "Get-Privilege"   | Should be $True

        }
        It 'should load all aliases' {
            $Commands = @( Get-Command -CommandType Alias -Module PoshPrivilege | Select -ExpandProperty Name)
            $Commands.count | Should be 1
            $Commands -contains "gppv"   | Should be $True
        }
    }
}
