#######################################################################################
#
#   Build Surveillance Share (Local Execution)
#   Intent: Run locally on surveillance computers via SCCM deployment. Verifies the
#       computer is in a SURV OU, ensures the required SMB share exists with proper
#       permissions, and validates external accessibility from a test server.
#   Author: Matthew Wurtz
#   Date: 12/8/2025
#
#######################################################################################

# --------------- Script Configuration --------------- #
$Config = @{
    # File and Directory Paths
    LogFilePath         = "C:\Drivers\SURV\BuildShare_Local.log"
    
    # ADSI Configuration
    OrganizationalUnits = @(
        "OU=SURV,OU=Shared_Use,OU=Endpoints,DC=dds,DC=dillards,DC=net",
        "OU=SURV,OU=Shared_Use,OU=Win11,OU=Endpoints,DC=dds,DC=dillards,DC=net",
        "OU=SURV,OU=Shared_Use,OU=WildWest,OU=Endpoints,DC=dds,DC=dillards,DC=net"
    )
    
    # Share Configuration
    SharePermissionAccount  = "DDS\FW-Milestone"
    ShareAccessRight        = "Read"
    
    # Test Server for External Validation
    TestServer              = "vcanz441"
}

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

Function Test-ComputerInSURVOU {
    [CmdletBinding()]
    param()
    
    try {
        $computerName = $env:COMPUTERNAME
        $searcher = [ADSISearcher]::new()
        $searcher.Filter = "(&(objectClass=computer)(name=$computerName))"
        
        $result = $searcher.FindOne()
        
        if (-not $result) {
            Write-LogMessage -Level "Error" -Message "Computer $computerName not found in Active Directory"
            return $false
        }
        
        $distinguishedName = $result.Properties["distinguishedname"][0]
        Write-LogMessage -Level "Info" -Message "Computer DN: $distinguishedName"
        
        # Check if the DN contains any of our SURV OUs
        $inSURVOU = $false
        foreach ($ou in $Config.OrganizationalUnits) {
            # Extract the OU path from the LDAP string
            $ouPath = $ou -replace "LDAP://", ""
            if ($distinguishedName -match [regex]::Escape($ouPath)) {
                $inSURVOU = $true
                Write-LogMessage -Level "Success" -Message "Computer is in SURV OU: $ouPath"
                break
            }
        }
        
        if (-not $inSURVOU) {
            Write-LogMessage -Level "Warning" -Message "Computer is not in any configured SURV OU"
            return $false
        }
        
        return $true
        
    } catch {
        Write-LogMessage -Level "Error" -Message "Failed to verify OU membership: $($_.Exception.Message)"
        return $false
    }
}

Function Set-LocalSharePermissions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ShareName,
        
        [Parameter(Mandatory)]
        [string]$LocalPath,
        
        [Parameter(Mandatory)]
        [string]$PermissionAccount,
        
        [Parameter(Mandatory)]
        [string]$AccessRight
    )
    
    # Configure SMB share permissions
    try {
        # Grant correct access
        Grant-SmbShareAccess -Name $ShareName -AccountName $PermissionAccount -AccessRight $AccessRight -Force -ErrorAction Stop
        
        # Remove Everyone access from share
        $currentAccess = Get-SmbShareAccess -Name $ShareName -ErrorAction SilentlyContinue
        $everyoneAccess = $currentAccess | Where-Object { $_.AccountName -eq "Everyone" }
        if ($everyoneAccess) {
            Revoke-SmbShareAccess -Name $ShareName -AccountName "Everyone" -Force -ErrorAction SilentlyContinue
        }
        
        Write-LogMessage -Level "Success" -Message "Applied SMB permissions for share $ShareName"
        
    } catch {
        Write-LogMessage -Level "Warning" -Message "Failed to update SMB share permissions: $($_.Exception.Message)"
    }

    # Configure NTFS permissions
    try {
        $ACL = Get-Acl -Path $LocalPath
        
        # Add the required permission if not present
        $existingRule = $ACL.Access | Where-Object { 
            $_.IdentityReference.Value -match "FW-Milestone" -and 
            $_.FileSystemRights -eq $AccessRight 
        }
        
        if (-not $existingRule) {
            $Rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                $PermissionAccount, 
                $AccessRight, 
                "ContainerInherit, ObjectInherit", 
                "None", 
                "Allow"
            )
            $ACL.AddAccessRule($Rule)
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
        
        Write-LogMessage -Level "Success" -Message "Applied NTFS permissions for $LocalPath"
        
    } catch {
        Write-LogMessage -Level "Warning" -Message "Failed to update NTFS permissions: $($_.Exception.Message)"
    }
}

# --------------- Step 1: Verify Computer is in SURV OU --------------- #

Write-LogMessage -Level "Info" -Message "Verifying computer is in a SURV OU"

if (-not (Test-ComputerInSURVOU)) {
    Write-LogMessage -Level "Error" -Message "Computer is not in a SURV OU. Exiting script."
    exit 0  # Exit successfully since this is expected behavior for non-SURV computers
}

# --------------- Step 2: Calculate Share Details --------------- #

$computerName = $env:COMPUTERNAME
$shareName = $computerName.Substring(1,4) + "_corp"
$localPath = "D:\$shareName"
$sharePath = "\\$computerName\$shareName"

Write-LogMessage -Level "Info" -Message "Share configuration - Name: $shareName, Path: $localPath"

# --------------- Step 3: Verify or Create Share --------------- #

# Check if share exists
$shareExists = Get-SmbShare -Name $shareName -ErrorAction SilentlyContinue

if ($shareExists) {
    Write-LogMessage -Level "Info" -Message "Share $shareName already exists"
} else {
    Write-LogMessage -Level "Warning" -Message "Share $shareName not found. Creating share..."
    
    try {
        # Create local directory if it doesn't exist
        if (-not (Test-Path $localPath)) {
            New-Item -ItemType Directory -Path $localPath -Force -ErrorAction Stop | Out-Null
            Write-LogMessage -Level "Success" -Message "Created directory: $localPath"
        }
        
        # Create the SMB share
        New-SmbShare -Name $shareName -Path $localPath -ErrorAction Stop | Out-Null
        Write-LogMessage -Level "Success" -Message "Created SMB share: $shareName"
        
        # Verify share was created
        $shareExists = Get-SmbShare -Name $shareName -ErrorAction SilentlyContinue
        if (-not $shareExists) {
            throw "Share creation reported success but verification failed"
        }
        
    } catch {
        Write-LogMessage -Level "Error" -Message "Failed to create share: $($_.Exception.Message)"
        exit 1
    }
}

# --------------- Step 4: Apply Permissions --------------- #

Write-LogMessage -Level "Info" -Message "Applying permissions to share $shareName"

Set-LocalSharePermissions -ShareName $shareName -LocalPath $localPath `
    -PermissionAccount $Config.SharePermissionAccount -AccessRight $Config.ShareAccessRight

# --------------- Step 5: Test External Accessibility --------------- #

Write-LogMessage -Level "Info" -Message "Testing share accessibility from $($Config.TestServer)"

try {
    $testResult = Invoke-Command -ComputerName $Config.TestServer -ScriptBlock {
        param($SharePath)
        
        $accessible = Test-Path $SharePath -ErrorAction SilentlyContinue
        return $accessible
        
    } -ArgumentList $sharePath -ErrorAction Stop
    
    if ($testResult) {
        Write-LogMessage -Level "Success" -Message "Share $sharePath is accessible from $($Config.TestServer)"
    } else {
        Write-LogMessage -Level "Warning" -Message "Share $sharePath exists but is not accessible from $($Config.TestServer)"
    }
    
} catch {
    Write-LogMessage -Level "Warning" -Message "Failed to test share accessibility from $($Config.TestServer): $($_.Exception.Message)"
}

# --------------- Complete --------------- #

Write-LogMessage -Level "Success" -Message "Local share build process completed for $computerName"
exit 0
