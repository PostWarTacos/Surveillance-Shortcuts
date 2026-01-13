#######################################################################################
#
#   Set Surveillance Share Permissions
#   Intent: Apply correct permissions to surveillance shares
#       - BUILTIN\Administrators: Full Control (Share and NTFS)
#       - DDS\FW-Milestone: Read (Share and NTFS)
#   Author: PostWarTacos
#   Date: 1/13/2026
#
#######################################################################################

[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName='SpecificComputers')]
param(
    [Parameter(Mandatory=$true, ParameterSetName='SpecificComputers', Position=0)]
    [string[]]$ComputerName,
    
    [Parameter(Mandatory=$true, ParameterSetName='AllComputers')]
    [switch]$AllComputers,
    
    [Parameter(Mandatory=$false)]
    [switch]$SharePermissionsOnly,
    
    [Parameter(Mandatory=$false)]
    [switch]$NTFSPermissionsOnly
)

# --------------- Script Configuration --------------- #
$Config = @{
    # File and Directory Paths
    LogFilePath         = "$env:USERPROFILE\Desktop\SURV-SetPermissions_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    
    # ADSI Configuration
    ADSIFilter          = "(&(objectClass=computer)(sAMAccountName=*))"
    ADSIPageSize        = 1000
    OrganizationalUnits = @(
        "LDAP://OU=SURV,OU=Shared_Use,OU=Endpoints,DC=dds,DC=dillards,DC=net",
        "LDAP://OU=SURV,OU=Shared_Use,OU=Win11,OU=Endpoints,DC=dds,DC=dillards,DC=net",
        "LDAP://OU=SURV,OU=Shared_Use,OU=WildWest,OU=Endpoints,DC=dds,DC=dillards,DC=net"
    )
    
    # Permission Configuration
    NTFSAdminGroup      = "BUILTIN\Administrators"
    ShareAdminGroup     = "DDS\Desktop-Admin"
    MilestoneGroup      = "DDS\FW-Milestone"
}

# --------------- Script Variables --------------- #
$script:results = @{
    Success = @()
    Failed = @()
    Skipped = @()
    TotalProcessed = 0
}

# --------------- Helper Functions --------------- #

Function Get-ComputersFromOUs {
    [CmdletBinding()]
    param()
    
    Write-LogMessage "=== Starting Computer Discovery from OUs ===" -Level Info -LogFile $Config.LogFilePath
    $allComputers = @()
    
    foreach ($ou in $Config.OrganizationalUnits) {
        Write-LogMessage "Querying OU: $ou" -Level Info -LogFile $Config.LogFilePath
        
        try {
            $searcher = New-Object System.DirectoryServices.DirectorySearcher
            $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry($ou)
            $searcher.Filter = $Config.ADSIFilter
            $searcher.PageSize = $Config.ADSIPageSize
            $searcher.PropertiesToLoad.AddRange(@("name", "cn", "distinguishedName"))
            
            $results = $searcher.FindAll()
            
            foreach ($result in $results) {
                $computerName = $result.Properties["name"][0]
                if ($computerName) {
                    $allComputers += $computerName
                }
            }
            
            Write-LogMessage "  Found $($results.Count) computers in this OU"  -Level Success -LogFile $Config.LogFilePath
            $results.Dispose()
        }
        catch {
            Write-LogMessage "ERROR querying OU $ou : $_"  -Level Error -LogFile $Config.LogFilePath
        }
    }
    
    Write-LogMessage "=== Total computers discovered: $($allComputers.Count) ==="  -Level Success -LogFile $Config.LogFilePath
    write-host
    
    return $allComputers
}

Function Set-SharePermissions {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName,
        
        [Parameter(Mandatory)]
        [string]$ShareName
    )
    
    if (-not $PSCmdlet.ShouldProcess("\\$ComputerName\$ShareName", "Set share permissions")) {
        return $false
    }
    
    try {
        Write-LogMessage "    Setting share permissions..." -Level Info -LogFile $Config.LogFilePath
        
        # Get the share security
        $share = Get-WmiObject -Class Win32_LogicalShareSecuritySetting -Filter "Name='$ShareName'" -ComputerName $ComputerName -ErrorAction Stop
        
        if (-not $share) {
            Write-LogMessage "    ERROR: Share not found via WMI" -Level Error -LogFile $Config.LogFilePath
            return $false
        }
        
        # Get current security descriptor
        $sd = $share.GetSecurityDescriptor().Descriptor
        $newDACL = @()
        
        # Create trustees for our required groups
        $desktopAdminTrustee = ([WMIClass] "\\$ComputerName\root\cimv2:Win32_Trustee").CreateInstance()
        $desktopAdminTrustee.Domain = "DDS"
        $desktopAdminTrustee.Name = "Desktop-Admin"
        
        $milestoneTrustee = ([WMIClass] "\\$ComputerName\root\cimv2:Win32_Trustee").CreateInstance()
        $milestoneTrustee.Domain = "DDS"
        $milestoneTrustee.Name = "FW-Milestone"
        
        # Create Desktop-Admin ACE (Full Control = 2032127)
        $desktopAdminACE = ([WMIClass] "\\$ComputerName\root\cimv2:Win32_ACE").CreateInstance()
        $desktopAdminACE.AccessMask = 2032127
        $desktopAdminACE.AceFlags = 0
        $desktopAdminACE.AceType = 0  # Allow
        $desktopAdminACE.Trustee = $desktopAdminTrustee
        $newDACL += $desktopAdminACE
        
        # Create Milestone ACE (Read = 1179817)
        $milestoneACE = ([WMIClass] "\\$ComputerName\root\cimv2:Win32_ACE").CreateInstance()
        $milestoneACE.AccessMask = 1179817
        $milestoneACE.AceFlags = 0
        $milestoneACE.AceType = 0  # Allow
        $milestoneACE.Trustee = $milestoneTrustee
        $newDACL += $milestoneACE
        
        # Apply new DACL
        $sd.DACL = $newDACL
        $result = $share.SetSecurityDescriptor($sd)
        
        if ($result.ReturnValue -eq 0) {
            Write-LogMessage "    Successfully set share permissions" -Level Success -LogFile $Config.LogFilePath
            return $true
        } else {
            Write-LogMessage "    ERROR: Failed to set share permissions (Return Code: $($result.ReturnValue))" -Level Error -LogFile $Config.LogFilePath
            return $false
        }
    }
    catch {
        Write-LogMessage "    ERROR setting share permissions: $($_.Exception.Message)" -Level Error -LogFile $Config.LogFilePath
        return $false
    }
}

Function Set-NTFSPermissions {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName,
        
        [Parameter(Mandatory)]
        [string]$ShareName
    )
    
    $sharePath = "\\$ComputerName\$ShareName"
    
    if (-not $PSCmdlet.ShouldProcess($sharePath, "Set NTFS permissions")) {
        return $false
    }
    
    try {
        Write-LogMessage "    Setting NTFS permissions..." -Level Info -LogFile $Config.LogFilePath
        
        # Get current ACL
        $acl = Get-Acl -Path $sharePath -ErrorAction Stop
        
        # Remove existing explicit permissions for our target groups
        $acl.Access | Where-Object { 
            (-not $_.IsInherited) -and 
            (($_.IdentityReference -like "*Administrators*") -or ($_.IdentityReference -like "*Milestone*"))
        } | ForEach-Object {
            $acl.RemoveAccessRule($_) | Out-Null
        }
        
        # Add BUILTIN\Administrators Full Control
        $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $Config.NTFSAdminGroup,
            "FullControl",
            "ContainerInherit, ObjectInherit",
            "None",
            "Allow"
        )
        $acl.AddAccessRule($adminRule)
        
        # Add Milestone Read
        $milestoneRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $Config.MilestoneGroup,
            "Read",
            "ContainerInherit, ObjectInherit",
            "None",
            "Allow"
        )
        $acl.AddAccessRule($milestoneRule)
        
        # Apply the ACL
        Set-Acl -Path $sharePath -AclObject $acl -ErrorAction Stop
        
        Write-LogMessage "    Successfully set NTFS permissions" -Level Success -LogFile $Config.LogFilePath
        return $true
    }
    catch {
        Write-LogMessage "    ERROR setting NTFS permissions: $($_.Exception.Message)" -Level Error -LogFile $Config.LogFilePath
        return $false
    }
}

Function Set-ComputerSharePermissions {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName
    )
    
    Write-LogMessage "Processing $ComputerName..." -Level Info -LogFile $Config.LogFilePath
    $script:results.TotalProcessed++
    
    # Test connection
    try {
        $pingResult = Test-Connection -ComputerName $ComputerName -Count 2 -Quiet -ErrorAction Stop
        if (-not $pingResult) {
            Write-LogMessage "  [SKIPPED] $ComputerName is not reachable" -Level Warning -LogFile $Config.LogFilePath
            $script:results.Skipped += $ComputerName
            return
        }
    }
    catch {
        Write-LogMessage "  [SKIPPED] $ComputerName is not reachable" -Level Warning -LogFile $Config.LogFilePath
        $script:results.Skipped += $ComputerName
        return
    }
    
    Write-LogMessage "  [ONLINE] $ComputerName is reachable" -Level Success -LogFile $Config.LogFilePath
    
    # Calculate share name
    $shareName = $ComputerName.Substring(1,4) + "_corp"
    $sharePath = "\\$ComputerName\$shareName"
    
    # Test if share exists
    try {
        $shareExists = Test-Path -Path $sharePath -ErrorAction Stop
        if (-not $shareExists) {
            Write-LogMessage "  [SKIPPED] Share $sharePath does not exist" -Level Warning -LogFile $Config.LogFilePath
            $script:results.Skipped += $ComputerName
            return
        }
    }
    catch {
        Write-LogMessage "  [SKIPPED] Cannot access share $sharePath" -Level Warning -LogFile $Config.LogFilePath
        $script:results.Skipped += $ComputerName
        return
    }
    
    Write-LogMessage "  [SHARE EXISTS] $sharePath" -Level Success -LogFile $Config.LogFilePath
    
    $shareSuccess = $true
    $ntfsSuccess = $true
    
    # Set Share Permissions
    if (-not $NTFSPermissionsOnly) {
        $shareSuccess = Set-SharePermissions -ComputerName $ComputerName -ShareName $shareName
    }
    
    # Set NTFS Permissions
    if (-not $SharePermissionsOnly) {
        $ntfsSuccess = Set-NTFSPermissions -ComputerName $ComputerName -ShareName $shareName
    }
    
    # Track results
    if ($shareSuccess -and $ntfsSuccess) {
        Write-LogMessage "  [SUCCESS] Permissions applied successfully" -Level Success -LogFile $Config.LogFilePath
        $script:results.Success += $ComputerName
    } else {
        Write-LogMessage "  [FAILED] Some permissions could not be applied" -Level Error -LogFile $Config.LogFilePath
        $script:results.Failed += $ComputerName
    }
    
    write-host
}

Function Write-SummaryReport {
    [CmdletBinding()]
    param()
    
    Write-LogMessage "=========================================" -Level Success -LogFile $Config.LogFilePath
    Write-LogMessage "=== PERMISSION APPLICATION SUMMARY ===" -Level Success -LogFile $Config.LogFilePath
    Write-LogMessage "=========================================" -Level Success -LogFile $Config.LogFilePath
    write-host
    Write-LogMessage "Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -Level Info -LogFile $Config.LogFilePath
    Write-LogMessage "Total Computers Processed: $($script:results.TotalProcessed)" -Level Info -LogFile $Config.LogFilePath
    write-host
    Write-LogMessage "--- Results ---" -Level Success -LogFile $Config.LogFilePath
    Write-LogMessage "Success: $($script:results.Success.Count)" -Level Info -LogFile $Config.LogFilePath
    Write-LogMessage "Failed:  $($script:results.Failed.Count)" -Level Info -LogFile $Config.LogFilePath
    Write-LogMessage "Skipped: $($script:results.Skipped.Count)" -Level Info -LogFile $Config.LogFilePath
    write-host
    
    if ($script:results.Success.Count -gt 0) {
        Write-LogMessage "=========================================" -Level Success -LogFile $Config.LogFilePath
        Write-LogMessage "=== SUCCESSFUL COMPUTERS ===" -Level Success -LogFile $Config.LogFilePath
        Write-LogMessage "=========================================" -Level Success -LogFile $Config.LogFilePath
        foreach ($computer in $script:results.Success) {
            $shareName = $computer.Substring(1,4) + "_corp"
            Write-LogMessage "  - $computer (\\$computer\$shareName)" -Level Info -LogFile $Config.LogFilePath
        }
        write-host
    }
    
    if ($script:results.Failed.Count -gt 0) {
        Write-LogMessage "=========================================" -Level Error -LogFile $Config.LogFilePath
        Write-LogMessage "=== FAILED COMPUTERS ===" -Level Error -LogFile $Config.LogFilePath
        Write-LogMessage "=========================================" -Level Error -LogFile $Config.LogFilePath
        foreach ($computer in $script:results.Failed) {
            $shareName = $computer.Substring(1,4) + "_corp"
            Write-LogMessage "  - $computer (\\$computer\$shareName)" -Level Info -LogFile $Config.LogFilePath
        }
        write-host
    }
    
    if ($script:results.Skipped.Count -gt 0) {
        Write-LogMessage "=========================================" -Level Warning -LogFile $Config.LogFilePath
        Write-LogMessage "=== SKIPPED COMPUTERS ===" -Level Warning -LogFile $Config.LogFilePath
        Write-LogMessage "=========================================" -Level Warning -LogFile $Config.LogFilePath
        foreach ($computer in $script:results.Skipped) {
            $shareName = $computer.Substring(1,4) + "_corp"
            Write-LogMessage "  - $computer (\\$computer\$shareName)" -Level Info -LogFile $Config.LogFilePath
        }
        write-host
    }
    
    Write-LogMessage "=========================================" -Level Success -LogFile $Config.LogFilePath
    Write-LogMessage "=== OPERATION COMPLETE ===" -Level Success -LogFile $Config.LogFilePath
    Write-LogMessage "=========================================" -Level Success -LogFile $Config.LogFilePath
    Write-LogMessage "Log file saved to: $($Config.LogFilePath)" -Level Info -LogFile $Config.LogFilePath
}

# --------------- Main Script Execution --------------- #

try {
    # Initialize log file
    Write-LogMessage "=========================================" -Level Info -LogFile $Config.LogFilePath
    Write-LogMessage "=== SET SURVEILLANCE SHARE PERMISSIONS ===" -Level Info -LogFile $Config.LogFilePath
    Write-LogMessage "=========================================" -Level Info -LogFile $Config.LogFilePath
    write-host
    
    # Determine target computers
    $targetComputers = @()
    
    if ($AllComputers) {
        Write-LogMessage "Mode: All computers from OUs" -Level Info -LogFile $Config.LogFilePath
        $targetComputers = Get-ComputersFromOUs
    }
    else {
        Write-LogMessage "Mode: Specific computer(s)" -Level Info -LogFile $Config.LogFilePath
        $targetComputers = $ComputerName
        Write-LogMessage "Target: $($targetComputers -join ', ')" -Level Info -LogFile $Config.LogFilePath
        write-host
    }
    
    if ($targetComputers.Count -eq 0) {
        Write-LogMessage "ERROR: No computers to process" -Level Error -LogFile $Config.LogFilePath
        exit 1
    }
    
    # Show what will be applied
    if (-not $SharePermissionsOnly -and -not $NTFSPermissionsOnly) {
        Write-LogMessage "Will apply: Share AND NTFS permissions" -Level Info -LogFile $Config.LogFilePath
    }
    elseif ($SharePermissionsOnly) {
        Write-LogMessage "Will apply: Share permissions ONLY" -Level Info -LogFile $Config.LogFilePath
    }
    else {
        Write-LogMessage "Will apply: NTFS permissions ONLY" -Level Info -LogFile $Config.LogFilePath
    }
    write-host
    
    Write-LogMessage "=== Starting Permission Application ===" -Level Info -LogFile $Config.LogFilePath
    
    # Process each computer
    $counter = 0
    foreach ($computer in $targetComputers) {
        $counter++
        $percentComplete = [math]::Round(($counter / $targetComputers.Count) * 100, 2)
        Write-Progress -Activity "Setting Permissions" -Status "Processing $computer ($counter of $($targetComputers.Count))" -PercentComplete $percentComplete
        
        Set-ComputerSharePermissions -ComputerName $computer
    }
    
    Write-Progress -Activity "Setting Permissions" -Completed
    
    # Generate summary report
    Write-SummaryReport
    
    # Open log file
    Write-Host "`nOpening log file..." -ForegroundColor Green
    Start-Process notepad.exe -ArgumentList $Config.LogFilePath
}
catch {
    Write-LogMessage "FATAL ERROR: $_" -Level Error -LogFile $Config.LogFilePath
    Write-LogMessage $_.ScriptStackTrace -LogFile $Config.LogFilePath
    exit 1
}
