#######################################################################################
#
#   Build Surveillance Shares
#   Intent: Connect to ADSI, pull list of surveillance computers from specified OUs,
#       test connectivity, and ensure each computer has the required SMB share configured
#       with proper permissions pointing to the local surveillance storage path.
#   Author: PostWarTacos
#   Date: 12/8/2025
#
#######################################################################################

# --------------- Script Configuration --------------- #
$Config = @{
    # File and Directory Paths
    LogFilePath         = "C:\Drivers\SURV\TS_SURV.txt"
    OutputLocation      = "C:\Drivers\SURV"
    
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
    SharePermissions = @(
        @{ Account = "DDS\FW-Milestone"; AccessRight = "Read" }
        @{ Account = "DDS\Desktop-Admins"; AccessRight = "Full" }
    )
}

# --------------- Script Variables --------------- #
$script:successfulShares = @()
$script:failedShares = @()
$script:deadComputers = @()
$script:aliveComputers = @()

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
    
    # File output only
    if ($LogFile) {
        try {
            $logEntry | Out-File -FilePath $LogFile -Append -Encoding UTF8 -ErrorAction Stop
        } catch {
            # Silent fail if logging doesn't work
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
    
    foreach ($OU in $OUs) {
        try {
            Write-LogMessage -Level "Info" -Message "Querying OU: $OU"
            
            $searcher = [ADSISearcher]::new()
            $searcher.SearchRoot = [ADSI]$OU
            $searcher.Filter = $Config.ADSIFilter
            
            # Load needed properties
            $searcher.PropertiesToLoad.AddRange(@("name", "sAMAccountName"))
            $searcher.PageSize = $Config.ADSIPageSize
            
            $searchResults = $searcher.FindAll()
            
            foreach ($result in $searchResults) {
                $computerName = $result.Properties["name"][0]
                
                if ($computerName) {
                    $allComputers += [PSCustomObject]@{
                        Name = $computerName
                        SAMAccountName = $result.Properties["sAMAccountName"][0]
                    }
                }
            }
            
            # Properly dispose of search results
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

Function Set-SharePermissions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.Runspaces.PSSession]$Session,
        
        [Parameter(Mandatory)]
        [string]$ShareName,
        
        [Parameter(Mandatory)]
        [string]$LocalPath,
        
        [Parameter(Mandatory)]
        [array]$SharePermissions,
        
        [Parameter(Mandatory)]
        [string]$ComputerName
    )
    
    # Configure SMB share permissions
    try {
        Invoke-Command -Session $Session -ScriptBlock {
            param($ShareName, $SharePermissions)
            
            # Remove Everyone access from share if present
            $currentAccess = Get-SmbShareAccess -Name $ShareName -ErrorAction SilentlyContinue
            $everyoneAccess = $currentAccess | Where-Object { $_.AccountName -eq "Everyone" }
            if ($everyoneAccess) {
                Revoke-SmbShareAccess -Name $ShareName -AccountName "Everyone" -Force -ErrorAction SilentlyContinue
            }
            
            # Grant configured access levels
            foreach ($permission in $SharePermissions) {
                Grant-SmbShareAccess -Name $ShareName -AccountName $permission.Account -AccessRight $permission.AccessRight -Force -ErrorAction Stop
            }
        } -ArgumentList $ShareName, $SharePermissions -ErrorAction Stop
        
        Write-LogMessage -Level "Success" -Message "Applied SMB permissions for $ComputerName"
        
    } catch {
        Write-LogMessage -Level "Warning" -Message "Failed to update SMB share permissions for $ComputerName : $($_.Exception.Message)"
    }

    # Configure NTFS permissions
    try {
        Invoke-Command -Session $Session -ScriptBlock {
            param($LocalPath, $SharePermissions)
            
            # Explicitly import the module to avoid module load errors
            Import-Module Microsoft.PowerShell.Management -ErrorAction SilentlyContinue
            Import-Module Microsoft.PowerShell.Security -ErrorAction SilentlyContinue
            
            $ACL = Get-Acl -Path $LocalPath
            
            # Add the required permissions for each account
            foreach ($permission in $SharePermissions) {
                $existingRule = $ACL.Access | Where-Object { 
                    $_.IdentityReference.Value -eq $permission.Account -and 
                    $_.FileSystemRights -eq $permission.AccessRight 
                }
                
                if (-not $existingRule) {
                    $Rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                        $permission.Account, 
                        $permission.AccessRight, 
                        "ContainerInherit, ObjectInherit", 
                        "None", 
                        "Allow"
                    )
                    $ACL.AddAccessRule($Rule)
                }
            }
            
            # Define groups to remove for security
            $groupsToRemove = @(
                "Everyone",
                "BUILTIN\Users",
                "NT AUTHORITY\Authenticated Users",
                "Domain Users"
            )
            
            # Check if we need to remove any of these groups
            $needsRemoval = $ACL.Access | Where-Object { 
                $identity = $_.IdentityReference.Value
                $groupsToRemove | Where-Object { $identity -match [regex]::Escape($_) }
            }
            
            if ($needsRemoval) {
                # Disable inheritance and copy existing rules to allow removal
                $ACL.SetAccessRuleProtection($true, $true)
                
                # Remove unwanted group access from NTFS
                $rulesToRemove = $ACL.Access | Where-Object { 
                    $identity = $_.IdentityReference.Value
                    $groupsToRemove | Where-Object { $identity -match [regex]::Escape($_) }
                }
                
                foreach ($rule in $rulesToRemove) {
                    $ACL.RemoveAccessRule($rule) | Out-Null
                }
            }
            
            Set-ACL -Path $LocalPath -AclObject $ACL -ErrorAction Stop
        } -ArgumentList $LocalPath, $SharePermissions -ErrorAction Stop
        
        Write-LogMessage -Level "Success" -Message "Applied NTFS permissions for $ComputerName"
        
    } catch {
        Write-LogMessage -Level "Warning" -Message "Failed to update NTFS permissions for $ComputerName : $($_.Exception.Message)"
    }
}

# --------------- Initialize Environment --------------- #
Clear-Host

Write-LogMessage -Level "Info" -Message "Starting Surveillance Share Build Process"

# Create output directory if needed and clean up old logs
if (-not (Test-Path $Config.OutputLocation)) {
    try {
        New-Item -ItemType Directory -Path $Config.OutputLocation -ErrorAction Stop | Out-Null
        Write-LogMessage -Level "Success" -Message "Created output directory: $($Config.OutputLocation)"
    } catch {
        Write-LogMessage -Level "Error" -Message "Failed to create output directory: $($_.Exception.Message)"
        exit 1
    }
} else {
    # Remove all existing log and output files
    try {
        Remove-Item "$($Config.OutputLocation)\*.txt" -Force -ErrorAction SilentlyContinue
        Write-LogMessage -Level "Info" -Message "Cleaned up old log files from $($Config.OutputLocation)"
    } catch {
        Write-LogMessage -Level "Warning" -Message "Failed to clean up old log files: $($_.Exception.Message)"
    }
}

# --------------- Pull List of Computers --------------- #

Write-LogMessage -Level "Info" -Message "Searching SURV OUs for computers"
$computerInfo = Get-ComputersFromAllOUs -OUs $Config.OrganizationalUnits
$computers = $computerInfo | Sort-Object Name | Select-Object -ExpandProperty Name

# --------------- Test Connectivity --------------- #

Write-LogMessage -Level "Info" -Message "Testing connectivity to $($computers.Count) computers"
foreach ($computer in $computers) {
    try {
        if (Test-Connection -Quiet -Count $Config.ConnectionTestCount -ComputerName $computer -ErrorAction Stop) {
            Write-LogMessage -Level "Success" -Message "Computer $computer is reachable"
            $script:aliveComputers += $computer
        } else {
            Write-LogMessage -Level "Warning" -Message "Computer $computer is not reachable"
            $script:deadComputers += $computer
        }
    } catch {
        Write-LogMessage -Level "Warning" -Message "Computer $computer is not reachable: $($_.Exception.Message)"
        $script:deadComputers += $computer
    }
}

Write-LogMessage -Level "Info" -Message "Found $($script:aliveComputers.Count) reachable computers out of $($computers.Count) total"

# --------------- Process Each Computer & Ensure Share Exists --------------- #

Write-LogMessage -Level "Info" -Message "Processing shares for $($script:aliveComputers.Count) reachable computers"

foreach ($computer in $script:aliveComputers) {
    $session = $null
    
    # Calculate share details
    $shareName = $computer.Substring(1,4) + "_corp"
    $localPath = "D:\" + $shareName
    $sharePath = "\\" + $computer + "\" + $shareName
    
    Write-LogMessage -Level "Info" -Message "Processing $computer - Share: $sharePath"
    
    try {
        # Create remote session and verify PowerShell remoting is available
        try {
            $session = New-PSSession -ComputerName $computer -ErrorAction Stop
            
            # Test if PowerShell remoting is working properly
            $remotingTest = Invoke-Command -Session $session -ScriptBlock {
                return $true
            } -ErrorAction Stop
            
            if (-not $remotingTest) {
                throw "PowerShell remoting test failed"
            }
            
        } catch {
            Write-LogMessage -Level "Error" -Message "Failed to create PSSession or verify remoting on $computer : $($_.Exception.Message)"
            $script:failedShares += "$computer - PowerShell remoting unavailable"
            continue
        }
        
        # Check if share already exists locally on remote computer
        $shareExists = Invoke-Command -Session $session -ScriptBlock {
            param($ShareName)
            $share = Get-SmbShare -Name $ShareName -ErrorAction SilentlyContinue
            return $null -ne $share
        } -ArgumentList $shareName -ErrorAction Stop
        
        if ($shareExists) {
            Write-LogMessage -Level "Info" -Message "Share already exists on $computer : $shareName"
            
            # Apply/verify permissions using consolidated function
            Set-SharePermissions -Session $session -ShareName $shareName -LocalPath $localPath `
                -SharePermissions $Config.SharePermissions -ComputerName $computer
            
            $script:successfulShares += "$computer - $sharePath (Updated)"
            Write-LogMessage -Level "Success" -Message "Applied permissions to existing share for $computer"
            
            # Clean up and continue to next computer
            Remove-SessionSafely -Session $session
            continue
        }
        
        # Share doesn't exist, need to create it
        Write-LogMessage -Level "Warning" -Message "Share not found on $computer. Attempting to create"
        
        # Create SMB share on remote computer
        try {
            Invoke-Command -Session $session -ScriptBlock {
                param($ShareName, $LocalPath)
                
                # Check if local path exists, create if needed
                if (-not (Test-Path $LocalPath)) {
                    New-Item -ItemType Directory -Path $LocalPath -Force -ErrorAction Stop | Out-Null
                }
                
                # Create the share
                New-SmbShare -Name $ShareName -Path $LocalPath -ErrorAction Stop
                
            } -ArgumentList $shareName, $localPath -ErrorAction Stop
            
            Write-LogMessage -Level "Success" -Message "Created SMB share on $computer : $shareName"
            
        } catch {
            Write-LogMessage -Level "Error" -Message "Failed to create SMB share on $computer : $($_.Exception.Message)"
            Remove-SessionSafely -Session $session
            $script:failedShares += "$computer - Failed to create share"
            continue
        }
        
        # Verify share was created locally
        $shareCreated = Invoke-Command -Session $session -ScriptBlock {
            param($ShareName)
            $share = Get-SmbShare -Name $ShareName -ErrorAction SilentlyContinue
            return $null -ne $share
        } -ArgumentList $shareName -ErrorAction Stop
        
        if (-not $shareCreated) {
            Write-LogMessage -Level "Error" -Message "Share creation reported success but verification failed for $shareName on $computer"
            Remove-SessionSafely -Session $session
            $script:failedShares += "$computer - Share created but not verified"
            continue
        }
        
        # Configure permissions using consolidated function
        Set-SharePermissions -Session $session -ShareName $shareName -LocalPath $localPath `
            -SharePermissions $Config.SharePermissions -ComputerName $computer
        
        $script:successfulShares += "$computer - $sharePath (Created)"
        Write-LogMessage -Level "Success" -Message "Successfully created and configured share for $computer"
        
    } catch {
        Write-LogMessage -Level "Error" -Message "Failed to process $computer : $($_.Exception.Message)"
        $script:failedShares += "$computer - $($_.Exception.Message)"
    } finally {
        if ($session) {
            Remove-SessionSafely -Session $session
        }
    }
}

# --------------- Output Results --------------- #

Write-LogMessage -Level "Success" -Message "Share build process completed"
Write-LogMessage -Level "Info" -Message "Successful: $($script:successfulShares.Count) | Failed: $($script:failedShares.Count) | Unreachable: $($script:deadComputers.Count)"

# Write output files
try {
    $computers | Out-File "$($Config.OutputLocation)\AllComputers.txt"
    $script:aliveComputers | Out-File "$($Config.OutputLocation)\ReachableComputers.txt"
    $script:deadComputers | Out-File "$($Config.OutputLocation)\UnreachableComputers.txt"
    $script:successfulShares | Out-File "$($Config.OutputLocation)\SuccessfulShares.txt"
    $script:failedShares | Out-File "$($Config.OutputLocation)\FailedShares.txt"
    
    Write-LogMessage -Level "Success" -Message "Output files written to $($Config.OutputLocation)"
} catch {
    Write-LogMessage -Level "Warning" -Message "Failed to write output files: $($_.Exception.Message)"
}

Write-LogMessage -Level "Info" -Message "Process completed. Check log file: $($Config.LogFilePath)"