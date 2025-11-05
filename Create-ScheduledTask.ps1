<#
#   Intent: Creates a scheduled task that will run a script.
#   Author: Matthew Wurtz
#   Date: 28-Feb-25
#>

#===========================================
# FUNCTION TO ENCODE SCRIPTS TO BASE64
#===========================================
function ConvertTo-Base64EncodedScript {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ScriptPath
    )
    
    if (-not (Test-Path $ScriptPath)) {
        throw "Script file not found: $ScriptPath"
    }
    
    $scriptContent = Get-Content $ScriptPath -Raw -Encoding UTF8
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($scriptContent)
    $encodedScript = [Convert]::ToBase64String($bytes)
    
    return $encodedScript
}

# Path to the script file containing the surveillance shortcuts logic
$surveillanceScriptPath = Join-Path $PSScriptRoot "Build-SURV-Shortcuts.ps1"

# Validate script path exists before encoding
if (-not (Test-Path $surveillanceScriptPath)) {
    throw "Required surveillance script file not found: $surveillanceScriptPath"
}

# Create encoded version of surveillance script for scheduled task execution
$encodedCheck = ConvertTo-Base64EncodedScript -ScriptPath $surveillanceScriptPath

#====================================
# Global Varaibles for Scheduled Task
#====================================
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Friday -At 4am
$settings = New-ScheduledTaskSettingsSet -WakeToRun
$principal = New-ScheduledTaskPrincipal -UserId "$env:USERNAME" -LogonType Interactive

#=============================
# Create Create-SurvShortcuts Task
#=============================
$action = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -EncodedCommand $encodedCheck"

$desc = "Scheduled task to create shortcuts to surveillance machines."


serviceui.exe Register-ScheduledTask -TaskName "Create-SurvShortcuts" `
                       -Action $action `
                       -Trigger $trigger `
                       -RunLevel Highest `
                       -settings $settings `
                       -Principal $principal `
                       -Description $desc