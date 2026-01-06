#######################################################################################
#
#   Test Surveillance Shares
#   Intent: Query computers from SURV OUs, test connectivity, verify share existence,
#       and log all results to the desktop for troubleshooting and validation.
#   Author: PostWarTacos
#   Date: 1/5/2026
#
#######################################################################################

# --------------- Script Configuration --------------- #
$Config = @{
    # File and Directory Paths
    LogFilePath         = "$env:USERPROFILE\Desktop\SURV-ShareTest_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    
    # ADSI Configuration
    ADSIFilter          = "(&(objectClass=computer)(sAMAccountName=*))"
    ADSIPageSize        = 1000
    OrganizationalUnits = @(
        "LDAP://OU=SURV,OU=Shared_Use,OU=Endpoints,DC=dds,DC=dillards,DC=net",
        "LDAP://OU=SURV,OU=Shared_Use,OU=Win11,OU=Endpoints,DC=dds,DC=dillards,DC=net",
        "LDAP://OU=SURV,OU=Shared_Use,OU=WildWest,OU=Endpoints,DC=dds,DC=dillards,DC=net"
    )
    
    # Network Configuration
    ConnectionTestCount = 2
}

# --------------- Script Variables --------------- #
$script:results = @{
    Online = @()
    Offline = @()
    ShareExists = @()
    ShareMissing = @()
    TotalComputers = 0
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
    
    $script:results.TotalComputers = $allComputers.Count
    Write-LogMessage "=== Total computers discovered: $($allComputers.Count) ==="  -Level Success -LogFile $Config.LogFilePath
    write-host
    
    return $allComputers
}

Function Test-ComputerConnection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName
    )
    
    try {
        $pingResult = Test-Connection -ComputerName $ComputerName -Count $Config.ConnectionTestCount -Quiet -ErrorAction Stop
        return $pingResult
    }
    catch {
        return $false
    }
}

Function Test-ShareExists {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName
    )
    
    # Calculate share name: first 4 characters after the first character + "_corp"
    $shareName = $ComputerName.Substring(1,4) + "_corp"
    $sharePath = "\\$ComputerName\$shareName"
    
    try {
        $pathExists = Test-Path -Path $sharePath -ErrorAction Stop
        return @{
            ShareName = $shareName
            SharePath = $sharePath
            Exists = $pathExists
        }
    }
    catch {
        return @{
            ShareName = $shareName
            SharePath = $sharePath
            Exists = $false
        }
    }
}

Function Test-AllComputers {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$ComputerList
    )
    
    Write-LogMessage "=== Starting Connection and Share Tests ===" -Level Info -LogFile $Config.LogFilePath
    $counter = 0
    
    foreach ($computer in $ComputerList) {
        $counter++
        $percentComplete = [math]::Round(($counter / $ComputerList.Count) * 100, 2)
        
        Write-Progress -Activity "Testing Computers" -Status "Processing $computer ($counter of $($ComputerList.Count))" -PercentComplete $percentComplete
        
        # Test connection
        Write-LogMessage "Testing $computer..." -LogFile $Config.LogFilePath
        $isOnline = Test-ComputerConnection -ComputerName $computer
        
        if ($isOnline) {
            Write-LogMessage "  [ONLINE] $computer is reachable" -Level Success -LogFile $Config.LogFilePath
            $script:results.Online += $computer
            
            # Test share
            $shareTest = Test-ShareExists -ComputerName $computer
            
            if ($shareTest.Exists) {
                Write-LogMessage "  [SHARE EXISTS] $($shareTest.SharePath) is accessible" -Level Success -LogFile $Config.LogFilePath
                $script:results.ShareExists += $computer
            }
            else {
                Write-LogMessage "  [SHARE MISSING] $($shareTest.SharePath) is NOT accessible" -Level Error -LogFile $Config.LogFilePath
                $script:results.ShareMissing += $computer
            }
        }
        else {
            Write-LogMessage "  [OFFLINE] $computer is NOT reachable" -Level Error -LogFile $Config.LogFilePath
            $script:results.Offline += $computer
        }
        
        write-host
    }
    
    Write-Progress -Activity "Testing Computers" -Completed
}

Function Write-SummaryReport {
    [CmdletBinding()]
    param()
    
    Write-LogMessage "=========================================" -Level Success -LogFile $Config.LogFilePath
    Write-LogMessage "=== SURVEILLANCE SHARE TEST SUMMARY ===" -Level Success -LogFile $Config.LogFilePath
    Write-LogMessage "=========================================" -Level Success -LogFile $Config.LogFilePath
    write-host
    Write-LogMessage "Test Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -Level Info -LogFile $Config.LogFilePath
    Write-LogMessage "Total Computers Discovered: $($script:results.TotalComputers)" -Level Info -LogFile $Config.LogFilePath
    write-host
    Write-LogMessage "--- Connection Results ---" -Level Success -LogFile $Config.LogFilePath
    Write-LogMessage "Online:  $($script:results.Online.Count)" -Level Info -LogFile $Config.LogFilePath
    Write-LogMessage "Offline: $($script:results.Offline.Count)" -Level Info -LogFile $Config.LogFilePath
    write-host
    Write-LogMessage "--- Share Test Results (Online Computers Only) ---" -Level Success -LogFile $Config.LogFilePath
    Write-LogMessage "Share Exists:  $($script:results.ShareExists.Count)" -Level Info -LogFile $Config.LogFilePath
    Write-LogMessage "Share Missing: $($script:results.ShareMissing.Count)" -Level Info -LogFile $Config.LogFilePath
    write-host
    
    if ($script:results.Offline.Count -gt 0) {
        Write-LogMessage "=========================================" -Level Error -LogFile $Config.LogFilePath
        Write-LogMessage "=== OFFLINE COMPUTERS ===" -Level Error -LogFile $Config.LogFilePath
        Write-LogMessage "=========================================" -Level Error -LogFile $Config.LogFilePath
        foreach ($computer in $script:results.Offline) {
            Write-LogMessage "  - $computer" -Level Info -LogFile $Config.LogFilePath
        }
        write-host
    }
    
    if ($script:results.ShareMissing.Count -gt 0) {
        Write-LogMessage "=========================================" -Level Error -LogFile $Config.LogFilePath
        Write-LogMessage "=== COMPUTERS MISSING/MISCONFIGURED SHARES ===" -Level Error -LogFile $Config.LogFilePath
        Write-LogMessage "=========================================" -Level Error -LogFile $Config.LogFilePath
        foreach ($computer in $script:results.ShareMissing) {
            $shareName = $computer.Substring(1,4) + "_corp"
            Write-LogMessage "  - $computer (\\$computer\$shareName)" -Level Info -LogFile $Config.LogFilePath
        }
        write-host
    }
    
    if ($script:results.ShareExists.Count -gt 0) {
        Write-LogMessage "=========================================" -Level Success -LogFile $Config.LogFilePath
        Write-LogMessage "=== COMPUTERS WITH VALID SHARES ===" -Level Success -LogFile $Config.LogFilePath
        Write-LogMessage "=========================================" -Level Success -LogFile $Config.LogFilePath
        foreach ($computer in $script:results.ShareExists) {
            $shareName = $computer.Substring(1,4) + "_corp"
            Write-LogMessage "  - $computer (\\$computer\$shareName)" -Level Info -LogFile $Config.LogFilePath
        }
        write-host
    }
    
    Write-LogMessage "=========================================" -Level Success -LogFile $Config.LogFilePath
    Write-LogMessage "=== TEST COMPLETE ===" -Level Success -LogFile $Config.LogFilePath
    Write-LogMessage "=========================================" -Level Success -LogFile $Config.LogFilePath
    Write-LogMessage "Log file saved to: $($Config.LogFilePath)" -Level Info -LogFile $Config.LogFilePath
}

# --------------- Main Script Execution --------------- #

try {
    # Initialize log file
    Write-LogMessage "=========================================" -Level Info -LogFile $Config.LogFilePath
    Write-LogMessage "=== SURVEILLANCE SHARE TEST SCRIPT ===" -Level Info -LogFile $Config.LogFilePath
    Write-LogMessage "=========================================" -Level Info -LogFile $Config.LogFilePath
    write-host
    
    # Step 1: Get computers from OUs
    $computers = Get-ComputersFromOUs
    
    if ($computers.Count -eq 0) {
        Write-LogMessage "ERROR: No computers found in specified OUs" -Level Error -LogFile $Config.LogFilePath
        exit 1
    }
    
    # Step 2: Test connections and shares
    Test-AllComputers -ComputerList $computers
    
    # Step 3: Generate summary report
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
