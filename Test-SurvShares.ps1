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
    ShareConfiguredCorrectly = @()
    ShareMisconfigured = @()
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

Function Get-ShareAndNTFSPermissions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName,
        
        [Parameter(Mandatory)]
        [string]$ShareName
    )
    
    $permissionsInfo = @{
        SharePermissions = @()
        NTFSPermissions = @()
        Errors = @()
    }
    
    # Get Share Permissions
    try {
        Write-LogMessage "    Retrieving share permissions..." -Level Info -LogFile $Config.LogFilePath
        $sharePermissions = Get-WmiObject -Class Win32_LogicalShareSecuritySetting -Filter "Name='$ShareName'" -ComputerName $ComputerName -ErrorAction Stop
        
        if ($sharePermissions) {
            $securityDescriptor = $sharePermissions.GetSecurityDescriptor()
            if ($securityDescriptor.ReturnValue -eq 0) {
                foreach ($ace in $securityDescriptor.Descriptor.DACL) {
                    $trustee = $ace.Trustee
                    $domain = if ($trustee.Domain) { "$($trustee.Domain)\" } else { "" }
                    $identity = "$domain$($trustee.Name)"
                    
                    $accessMask = $ace.AccessMask
                    $rights = switch ($accessMask) {
                        2032127 { "Full Control" }
                        1245631 { "Change" }
                        1179817 { "Read" }
                        default { "Custom ($accessMask)" }
                    }
                    
                    $permissionsInfo.SharePermissions += [PSCustomObject]@{
                        Identity = $identity
                        Rights = $rights
                        Type = if ($ace.AceType -eq 0) { "Allow" } else { "Deny" }
                    }
                }
                Write-LogMessage "    Found $($permissionsInfo.SharePermissions.Count) share permission entries" -Level Success -LogFile $Config.LogFilePath
            } else {
                $permissionsInfo.Errors += "Failed to retrieve share security descriptor (Return Code: $($securityDescriptor.ReturnValue))"
                Write-LogMessage "    Failed to retrieve share security descriptor" -Level Warning -LogFile $Config.LogFilePath
            }
        } else {
            $permissionsInfo.Errors += "Share not found via WMI"
            Write-LogMessage "    Share not found via WMI" -Level Warning -LogFile $Config.LogFilePath
        }
    }
    catch {
        $permissionsInfo.Errors += "Share permissions error: $($_.Exception.Message)"
        Write-LogMessage "    Error getting share permissions: $($_.Exception.Message)" -Level Warning -LogFile $Config.LogFilePath
    }
    
    # Get NTFS Permissions
    try {
        Write-LogMessage "    Retrieving NTFS permissions..." -Level Info -LogFile $Config.LogFilePath
        $sharePath = "\\$ComputerName\$ShareName"
        $acl = Get-Acl -Path $sharePath -ErrorAction Stop
        
        foreach ($access in $acl.Access) {
            $permissionsInfo.NTFSPermissions += [PSCustomObject]@{
                Identity = $access.IdentityReference
                Rights = $access.FileSystemRights
                Type = $access.AccessControlType
                Inherited = $access.IsInherited
            }
        }
        Write-LogMessage "    Found $($permissionsInfo.NTFSPermissions.Count) NTFS permission entries" -Level Success -LogFile $Config.LogFilePath
    }
    catch {
        $permissionsInfo.Errors += "NTFS permissions error: $($_.Exception.Message)"
        Write-LogMessage "    Error getting NTFS permissions: $($_.Exception.Message)" -Level Warning -LogFile $Config.LogFilePath
    }
    
    return $permissionsInfo
}

Function Test-SharePermissionsConfigured {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Permissions
    )
    
    $isConfiguredCorrectly = $true
    $issues = @()
    
    # Required permissions criteria
    $requiredSharePerms = @{
        "*admin*" = "Full Control"
        "*milestone*" = "Read"
    }
    
    $requiredNTFSPerms = @{
        "*admin*" = @("FullControl")
        "*milestone*" = @("Read", "ReadAndExecute")
    }
    
    # Check Share Permissions
    foreach ($required in $requiredSharePerms.GetEnumerator()) {
        $accountPattern = $required.Key
        $requiredRights = $required.Value
        
        $found = $Permissions.SharePermissions | Where-Object { 
            $_.Identity -like $accountPattern -and 
            $_.Rights -eq $requiredRights -and 
            $_.Type -eq "Allow"
        }
        
        if (-not $found) {
            # Check if pattern matches but rights are wrong
            $partialMatch = $Permissions.SharePermissions | Where-Object { $_.Identity -like $accountPattern }
            if ($partialMatch) {
                Write-LogMessage "      DEBUG: Found matching identity '$($partialMatch.Identity)' with rights '$($partialMatch.Rights)' (need '$requiredRights')" -Level Info -LogFile $Config.LogFilePath
            }
            $isConfiguredCorrectly = $false
            $issues += "Share: Missing or incorrect permissions for '$accountPattern' (Expected: $requiredRights)"
        }
    }
    
    # Check NTFS Permissions
    foreach ($required in $requiredNTFSPerms.GetEnumerator()) {
        $accountPattern = $required.Key
        $acceptableRights = $required.Value
        
        $found = $Permissions.NTFSPermissions | Where-Object { 
            $rights = $_.Rights.ToString()
            $_.Identity.ToString() -like $accountPattern -and 
            $_.Type -eq "Allow" -and
            ($acceptableRights | Where-Object { $rights -like "*$_*" }).Count -gt 0
        }
        
        if (-not $found) {
            # Check if pattern matches but rights are wrong
            $partialMatch = $Permissions.NTFSPermissions | Where-Object { $_.Identity.ToString() -like $accountPattern }
            if ($partialMatch) {
                Write-LogMessage "      DEBUG: Found matching identity '$($partialMatch.Identity)' with rights '$($partialMatch.Rights)' (need '$($acceptableRights -join ' or ')')" -Level Info -LogFile $Config.LogFilePath
            }
            $isConfiguredCorrectly = $false
            $issues += "NTFS: Missing or incorrect permissions for '$accountPattern' (Expected: $($acceptableRights -join ' or '))"
        }
    }
    
    return @{
        IsConfigured = $isConfiguredCorrectly
        Issues = $issues
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
                
                # Get permissions for this share
                $permissions = Get-ShareAndNTFSPermissions -ComputerName $computer -ShareName $shareTest.ShareName
                
                # Log share permissions
                if ($permissions.SharePermissions.Count -gt 0) {
                    Write-LogMessage "    --- Share Permissions ---" -Level Info -LogFile $Config.LogFilePath
                    foreach ($perm in $permissions.SharePermissions) {
                        Write-LogMessage "      $($perm.Identity): $($perm.Rights) ($($perm.Type))" -Level Info -LogFile $Config.LogFilePath
                    }
                }
                
                # Log NTFS permissions
                if ($permissions.NTFSPermissions.Count -gt 0) {
                    Write-LogMessage "    --- NTFS Permissions ---" -Level Info -LogFile $Config.LogFilePath
                    foreach ($perm in $permissions.NTFSPermissions) {
                        $inheritedText = if ($perm.Inherited) { "Inherited" } else { "Explicit" }
                        Write-LogMessage "      $($perm.Identity): $($perm.Rights) ($($perm.Type), $inheritedText)" -Level Info -LogFile $Config.LogFilePath
                    }
                }
                
                # Log any errors
                if ($permissions.Errors.Count -gt 0) {
                    Write-LogMessage "    --- Permission Retrieval Errors ---" -Level Warning -LogFile $Config.LogFilePath
                    foreach ($err in $permissions.Errors) {
                        Write-LogMessage "      $err" -Level Warning -LogFile $Config.LogFilePath
                    }
                }
                
                # Validate permissions configuration
                $validation = Test-SharePermissionsConfigured -Permissions $permissions
                
                if ($validation.IsConfigured) {
                    Write-LogMessage "    [CONFIGURED CORRECTLY] Share permissions match required criteria" -Level Success -LogFile $Config.LogFilePath
                    $script:results.ShareConfiguredCorrectly += $computer
                } else {
                    Write-LogMessage "    [MISCONFIGURED] Share permissions do not match required criteria" -Level Warning -LogFile $Config.LogFilePath
                    foreach ($issue in $validation.Issues) {
                        Write-LogMessage "      - $issue" -Level Warning -LogFile $Config.LogFilePath
                    }
                    $script:results.ShareMisconfigured += $computer
                }
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
    Write-LogMessage "--- Share Configuration Results (Shares That Exist) ---" -Level Success -LogFile $Config.LogFilePath
    Write-LogMessage "Configured Correctly: $($script:results.ShareConfiguredCorrectly.Count)" -Level Info -LogFile $Config.LogFilePath
    Write-LogMessage "Misconfigured:        $($script:results.ShareMisconfigured.Count)" -Level Info -LogFile $Config.LogFilePath
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
    
    if ($script:results.ShareConfiguredCorrectly.Count -gt 0) {
        Write-LogMessage "=========================================" -Level Success -LogFile $Config.LogFilePath
        Write-LogMessage "=== COMPUTERS WITH CORRECTLY CONFIGURED SHARES ===" -Level Success -LogFile $Config.LogFilePath
        Write-LogMessage "=========================================" -Level Success -LogFile $Config.LogFilePath
        foreach ($computer in $script:results.ShareConfiguredCorrectly) {
            $shareName = $computer.Substring(1,4) + "_corp"
            Write-LogMessage "  - $computer (\\$computer\$shareName)" -Level Info -LogFile $Config.LogFilePath
        }
        write-host
    }
    
    if ($script:results.ShareMisconfigured.Count -gt 0) {
        Write-LogMessage "=========================================" -Level Warning -LogFile $Config.LogFilePath
        Write-LogMessage "=== COMPUTERS WITH MISCONFIGURED SHARES ===" -Level Warning -LogFile $Config.LogFilePath
        Write-LogMessage "=========================================" -Level Warning -LogFile $Config.LogFilePath
        foreach ($computer in $script:results.ShareMisconfigured) {
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
