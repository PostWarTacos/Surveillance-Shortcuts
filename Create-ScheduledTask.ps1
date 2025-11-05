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
# Global Variables for Scheduled Task
#====================================
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Friday -At 4am
$settings = New-ScheduledTaskSettingsSet -WakeToRun

# Create task with placeholder user - service account credentials will be configured manually
# in Task Scheduler after task creation
$principal = New-ScheduledTaskPrincipal -UserId "DOMAIN\svc-surveillance" -LogonType Password -RunLevel Highest

#=============================
# Create Create-SurvShortcuts Task
#=============================
$action = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -EncodedCommand $encodedCheck"

$desc = "Scheduled task to create shortcuts to surveillance machines."


Register-ScheduledTask -TaskName "Create-SurvShortcuts" `
                       -Action $action `
                       -Trigger $trigger `
                       -Settings $settings `
                       -Principal $principal `
                       -Description $desc

Write-Host "Scheduled task 'Create-SurvShortcuts' created successfully."
Write-Host "IMPORTANT: You must manually configure the service account password in Task Scheduler:"
Write-Host "1. Open Task Scheduler (taskschd.msc)"
Write-Host "2. Navigate to the 'Create-SurvShortcuts' task"
Write-Host "3. Right-click -> Properties"
Write-Host "4. Go to 'General' tab -> 'Change User or Group'"
Write-Host "5. Enter the service account password when prompted"
Write-Host ""
Write-Host "Alternatively, you can run Build-SURV-Shortcuts.ps1 manually as an admin without using the scheduled task."