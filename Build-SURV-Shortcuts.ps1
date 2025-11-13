#######################################################################################
#
#   Build Surveillance Shortcuts
#   Intent: Connect to ADSI and pull list of surveillance computers, then create a
#       shortcuts to network shares hosted on each of those computers to view
#       the files on those computers. Shares are test before shortcut links are made.
#   Author: Matthew Wurtz
#   Date: 1/23/2025
#
#######################################################################################

# --------------- Script Configuration --------------- #
$Config = @{
    # File and Directory Paths
    ShortcutLocation    =   "D:\SurvShortcuts"
    IconPath            =   "C:\Windows\System32\imageres.dll,5"
    LogFilePath         =   "C:\Drivers\SURV\SurvShortcuts.log"
    ScriptLocation      =   "C:\Drivers\SURV"
    
    # API Configuration
    ApiUri      = "https://ssdcorpappsrvt1.dpos.loc/esper/Device/AllStores"
    ApiHeaders  = @{"accept" = "text/plain"}
    
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
    
    # Share Configuration
    SharePermissionAccount  = "DDS\FW-Milestone"
    ShareAccessRight        = "Read"
}

# --------------- Script Variables --------------- #
$script:pathValid = @()
$script:storeNumsTable = @()
$script:shortcutsCreated = @()
$script:shortcutsFailed = @()
$script:NoADSIData = @()
$script:pathFailed = @()
$script:deadComputers = @()
$script:alives = @()

# --------------- Helper Functions --------------- #

Function Write-LogMessage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet("Info", "Warning", "Error", "Success")]
        [string]$Level,
        
        [Parameter(Mandatory)]
        [string]$Message,
        
        [string]$LogFile = $Config.LogFilePath 
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    # Add level-specific prefixes
    $prefix = switch ($Level) {
        "Info"    { "[*]" }
        "Warning" { "[!]" }
        "Error"   { "[!!!]" }
        "Success" { "[+]" }
    }
    
    # Build the log entry
    if (-not $prefix) {
        $logEntry = "[$timestamp] $Message"
    }
    else {
        $logEntry = "[$timestamp] $prefix $Message"
    }

    # Console output with colors
    switch ($Level) {
        "Info"    { Write-Host $logEntry -ForegroundColor Cyan }
        "Warning" { Write-Host $logEntry -ForegroundColor Yellow }
        "Error"   { Write-Host $logEntry -ForegroundColor Red }
        "Success" { Write-Host $logEntry -ForegroundColor Green }
    }
    
    # File output
    if ($LogFile) {
        try {
            $logEntry | Out-File -FilePath $LogFile -Append -Encoding UTF8 -ErrorAction Stop
        } catch {
            Write-Warning "Failed to write to log file: $($_.Exception.Message)"
        }
    }
}

Function Remove-SessionSafely {
    [CmdletBinding()]
    param(
        [System.Management.Automation.Runspaces.PSSession]$Session
    )
    
    if ($Session -and $Session.State -eq 'Opened') {
        try {
            Remove-PSSession $Session -ErrorAction Stop
            Write-LogMessage -Level "Info" -Message "Cleaned up PSSession to $($Session.ComputerName)"
        } catch {
            Write-LogMessage -Level "Warning" -Message "Failed to clean up PSSession: $($_.Exception.Message)"
        }
    }
}

Function Get-ComputersFromAllOUs {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$OUs
    )
    
    $allComputers = @()
    
    foreach ($OU in $Config.OrganizationalUnits) {
        try {
            Write-LogMessage -Level "Info" -Message "Querying OU: $OU"
            
            $searcher = [ADSISearcher]::new()
            $searcher.SearchRoot = [ADSI]$OU
            $searcher.Filter = $Config.ADSIFilter
            
            # Load ALL needed properties in ONE query to avoid subsequent individual queries
            $searcher.PropertiesToLoad.AddRange(@("name", "extensionAttribute6", "sAMAccountName"))
            $searcher.PageSize = $Config.ADSIPageSize  # Process in batches for better memory management
            
            $searchResults = $searcher.FindAll()
            
            foreach ($result in $searchResults) {
                $computerName = $result.Properties["name"][0]
                $storeNumber = $result.Properties["extensionAttribute6"][0]
                
                if ($computerName) {  # Only add if we have a valid computer name
                    $allComputers += [PSCustomObject]@{
                        Name = $computerName
                        StoreNumber = if ($storeNumber) { $storeNumber } else { $null }
                        SAMAccountName = $result.Properties["sAMAccountName"][0]
                    }
                }
            }
            
            # Properly dispose of search results to prevent memory leaks
            $searchResults.Dispose()
            Write-LogMessage -Level "Success" -Message "Successfully queried OU $OU - found $($searchResults.Count) computers"
            
        } catch {
            Write-LogMessage -Level "Error" -Message "Failed to query OU $OU : $($_.Exception.Message)"
            continue
        }
    }
    
    Write-LogMessage -Level "Success" -Message "Total computers found across all OUs: $($allComputers.Count)"
    return $allComputers
}

Function Get-SiteInfoFromDDSAPI() {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Hostname
    )

    try {
        $web = Invoke-WebRequest -Uri $Config.ApiUri -Headers $Config.ApiHeaders -ErrorAction Stop
        $db = $web.content | ConvertFrom-Json -ErrorAction Stop

        $localCode = $($Hostname).substring(1,4)
        $result = $db | Where-Object SiteCode -eq $localCode

        $result | Select-Object StoreNumber
        return $result
    } catch {
        Write-LogMessage -Level "Error" -Message "Failed to get site info from DDS API for hostname $Hostname : $($_.Exception.Message)"
        return $null
    }
}

# --------------- Initialize Environment --------------- #
clear

# Clean up by removing and recreating the entire shortcut directory
Write-LogMessage -Level "Info" -Message "Removing and recreating shortcut directory for clean slate"
try {
    # Create shortcut directory if it doesn't exist
    If ( -not ( Test-Path $Config.ShortcutLocation )){
        New-Item -ItemType Directory -Path $Config.ShortcutLocation -ErrorAction Stop
        Write-LogMessage -Level "Success" -Message "Created directory: $($Config.ShortcutLocation)"
    }
    else {
        Remove-Item "$($Config.ShortcutLocation)\*"
    }
    
    Write-LogMessage -Level "Info" -Message "Starting Surveillance Shortcuts creation process"
} catch {
    Write-Error "Failed to initialize environment: $($_.Exception.Message)"
    exit 1
}

# ---------------- Pull List of Computers & Test ---------------- #

Write-LogMessage -Level "Info" -Message "Searching SURV OUs for SURV machines"
# Get all computer information in a single optimized query per OU
$computerInfo = Get-ComputersFromAllOUs -OUs $config.OrganizationalUnits
$computers = $computerInfo | Sort-Object Name | Select-Object -ExpandProperty Name

# Test Connection to all SURV machines
Write-LogMessage -Level "Info" -Message "Testing connectivity to $($computers.Count) computers"
foreach ( $computer in $computers ){
    try {
        if ( Test-Connection -Quiet -Count $Config.ConnectionTestCount -ComputerName $computer -ErrorAction Stop){
            Write-LogMessage -Level "Success" -Message "Computer $computer is reachable"
            $alives += $computer
        } else {
            Write-LogMessage -Level "Warning" -Message "Computer $computer is not reachable"
            $deadComputers += $computer
        }
    } catch {
        Write-LogMessage -Level "Warning" -Message "Computer $computer is not reachable: $($_.Exception.Message)"
        $deadComputers += $computer
    }
}

# --------------- Get Machine Info & Build Store Numbers --------------- #
# Build store numbers table using the computer info we already retrieved
Write-LogMessage -Level "Info" -Message "Building store numbers table for $($alives.Count) alive computers"

foreach ( $computer in $alives ){
    try {
        # Find the computer info from our earlier ADSI query
        $computerData = $computerInfo | Where-Object Name -eq $computer
        
        if ($null -eq $computerData) {
            Write-LogMessage -Level "Warning" -Message "No ADSI data found for computer: $computer"
            $script:NoADSIData += "$($computer) - trying API"
        }

        # Use the store number we already retrieved, or fall back to API
        [string]$storeNum = $computerData.StoreNumber
        If( $null -eq $storeNum -or $storeNum -eq '' ){
            try {
                [string]$storeNum = Get-SiteInfoFromDDSAPI $computer | Select-Object -ExpandProperty StoreNumber -First 1 -ErrorAction SilentlyContinue
                if ( $storeNum -and $storeNum.StartsWith('0')) { 
                    $storeNum = $storeNum.Substring(1) 
                }
            } catch {
                throw
            }
        }

        if ($null -eq $storeNum -or $storenum -eq ''){
            throw
        }

        $script:storeNumsTable += [PSCustomObject]@{
            ComputerName = $computer
            StoreNumber  = $storeNum
            URI          = $computer.Substring(1,4)  + "_corp"
            LocalPath    = "D:\" + $computer.Substring(1,4)  + "_corp"
            Share        = "\\" + $computer + "\" + $computer.Substring(1,4)  + "_corp"
        }
        Write-LogMessage -Level "Success" -Message "Processed computer $computer with store number: $storeNum"
    } catch {
        Write-LogMessage -Level "Error" -Message "Failed to process computer $computer : $($_.Exception.Message)"
        $script:NoADSIData += "$computer Failed to pull any info from ADSI or API"
    }
}

# Resort list
$script:storeNumsTable = $script:storeNumsTable | Sort-Object ComputerName

# --------------- Test Share Paths & Create Shares if needed --------------- #
# Test-Path on all share locations
Write-LogMessage -Level "Info" -Message "Testing share paths for $($script:storeNumsTable.count) stores"
foreach ( $store in $script:storeNumsTable ){
    Write-Host "Testing connection to share $($store.share)"
    $session = $null
    try {
        if ( Test-Path $store.Share -ErrorAction Stop ){ 
            $script:pathValid += $store
            Write-LogMessage -Level "Success" -Message "Share exists: $($store.Share)"
            Continue
        }
        else{ # Failed to connect to share, attempt to create it
            Write-LogMessage -Level "Warning" -Message "Share not found: $($store.Share). Attempting to create share and apply permissions"
            $session = New-PSSession $store.ComputerName -ErrorAction Stop
            try {
                # Create SMB share
                New-SmbShare -Name $store.URI -Path $store.LocalPath -CimSession $session -ErrorAction Stop
                if ( Test-Path $store.share -ErrorAction Stop ){ # Test path again to see if New-SMBshare resolved the issue.
                    Write-LogMessage -Level "Success" -Message "Successfully created share: $($store.Share)"
                    $script:pathValid += $store
                }
                else{
                    Write-LogMessage -Level "Error" -Message "Failed to create share at $($store.Share). Share creation succeeded but path test failed"
                    throw "Share creation succeeded but path test failed"
                }
            } catch {
                Write-LogMessage -Level "Error" -Message "Failed to create share at $($store.Share): $($_.Exception.Message)"
                if ($session) {
                    Remove-SessionSafely -Session $session
                    $session = $null
                }
                throw "Failed to create share at $($store.Share)"
            }
        }
        
        # Grant share permissions
        try {
            # Check current SMB permissions first
            $currentAccess = Get-SmbShareAccess -Name $store.URI -CimSession $session -ErrorAction Stop
            $hasCorrectAccess = $currentAccess | Where-Object { 
                $_.AccountName -eq $Config.SharePermissionAccount -and 
                $_.AccessRight -eq $Config.ShareAccessRight 
            }

            if (-not $hasCorrectAccess) {
                # Only apply if needed
                Grant-SmbShareAccess -Name $store.URI -AccountName $Config.SharePermissionAccount -AccessRight $Config.ShareAccessRight -Force -CimSession $session -ErrorAction Stop
                Write-LogMessage -Level "Success" -Message "Applied SMB permissions for $($store.Share)"
            } else {
                Write-LogMessage -Level "Info" -Message "SMB permissions already correct for $($store.Share)"
            }
            
            # Remove Everyone access if it exists
            $everyoneAccess = $currentAccess | Where-Object { $_.AccountName -eq "Everyone" }
            if ($everyoneAccess) {
                Revoke-SmbShareAccess -Name $store.URI -AccountName "Everyone" -Force -CimSession $session -ErrorAction SilentlyContinue
                Write-LogMessage -Level "Success" -Message "Removed Everyone access from $($store.Share)"
            }
            
        } catch {
            Write-LogMessage -Level "Warning" -Message "Failed to update share permissions for $($store.Share): $($_.Exception.Message)"
            if ($session) {
                Remove-SessionSafely -Session $session
                $session = $null
            }
            throw "Failed to update share permissions for $($store.Share)"
        }

        # Grant NTFS permissions
        try {
            $Access = ((Get-Item $store.share).GetAccessControl('Access').Access) | Select-Object IdentityReference | Where-Object {$_.IdentityReference -match "FW-Milestone"}

            If( -not ( $Access )){
                # Get the current ACL from the folder
                $ACL = Get-Acl $store.share
                # Create rule for modify rights for user
                $Rule = New-Object System.Security.AccessControl.FileSystemAccessRule( $Config.SharePermissionAccount, $Config.ShareAccessRight, "ContainerInherit, ObjectInherit", "None", "Allow" )
                # Add rule to folder
                $ACL.AddAccessRule( $Rule )
                Set-ACL -Path $store.share -AclObject $ACL
                Write-LogMessage -Level "Success" -Message "Updated NTFS permissions for $($store.Share)"
            }
        } catch {
            Write-LogMessage -Level "Warning" -Message "Failed to update NTFS permissions for $($store.Share): $($_.Exception.Message)"
            if ($session) {
                Remove-SessionSafely -Session $session
                $session = $null
            }
            throw "Failed to update NTFS permissions for $($store.Share)"
        }
    } catch {
        Write-LogMessage -Level "Error" -Message "Failed to process store $($store.StoreNumber) - $($Store.ComputerName.substring(1,4)): $($_.Exception.Message)"
        $script:pathFailed += "$($store.StoreNumber) - $($Store.ComputerName)"
        if ($session) {
            Remove-SessionSafely -Session $session
            $session = $null
        }
    }
}

# Reassign array to remove computernames where share couldn't be accessed
$script:storeNumsTable = $script:pathValid | Sort-Object ComputerName

# --------------- Handle Duplicate Store Numbers --------------- #
# Check for duplicate store numbers and rename them with _01, _02, etc.
Write-LogMessage -Level "Info" -Message "Checking for duplicate store numbers and separating"
try {
    $dupeGroups = $script:storeNumsTable | group storenumber | Where-Object count -gt 1

    foreach ( $group in $dupeGroups ){
        $counter = 1
        Write-LogMessage -Level "Warning" -Message "Found duplicate store number: $($group.Name) - creating unique identifiers"
        foreach  ( $store in $group.group ){
            # Construct new name
            $newName = "{0}_{1:D2}" -f $store.StoreNumber, $counter      
            # Rename store number
            $store.StoreNumber = $newName
            $counter++
        }
    }
    
    if ($dupeGroups.Count -gt 0) {
        Write-LogMessage -Level "Success" -Message "Resolved $($dupeGroups.Count) duplicate store number groups"
    }
} catch {
    Write-LogMessage -Level "Error" -Message "Failed to process duplicate store numbers: $($_.Exception.Message)"
}

# --------------- Build Shortcuts --------------- #
Write-LogMessage -Level "Info" -Message "Creating shortcuts for $($script:storeNumsTable.Count) stores"


foreach ($store in $script:storeNumsTable) {
    try {
        $shortcutName = $store.StoreNumber + "-" + $store.ComputerName.Substring(1,4) + ".lnk"
        $shortcutPath = Join-Path -Path $Config.ShortcutLocation -ChildPath $shortcutName
        
        $WScriptShell = New-Object -ComObject WScript.Shell
        $Shortcut = $WScriptShell.CreateShortcut($shortcutPath)
        $Shortcut.TargetPath = $store.share
        $Shortcut.IconLocation = $Config.IconPath
        $Shortcut.Save()

        # Release COM object
        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($WScriptShell) | Out-Null

        Write-LogMessage -Level "Success" -Message "Created shortcut: $shortcutPath"
        $script:shortcutsCreated += "$($store.StoreNumber) - $($Store.ComputerName.substring(1,4))"
    } catch {
        Write-LogMessage -Level "Error" -Message "Failed to create shortcut for $($store.ComputerName): $($_.Exception.Message)"
        $script:shortcutsFailed += "$($store.StoreNumber) - $($Store.ComputerName)"
    }
}

$computers | Out-File "$($Config.ScriptLocation)\PulledFromOU.txt"
$script:deadComputers | Out-File "$($Config.ScriptLocation)\DeadComputers.txt"
$script:pathFailed | Out-File "$($Config.ScriptLocation)\PathFailed.txt"
$script:NoADSIData | Out-File "$($Config.ScriptLocation)\NoADSIData.txt"
$script:shortcutsFailed | Out-File "$($Config.ScriptLocation)\ShortcutsFailed.txt"

Write-LogMessage -Level "Success" -Message "Completed creating $script:shortcutsCreated.count shortcuts. $script:shortcutsFailed.count failed"
Write-LogMessage -Level "Info" -Message "Surveillance Shortcuts creation process completed. Check log file: $($config.LogFilePath)"