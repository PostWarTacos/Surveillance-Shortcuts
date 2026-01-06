# Surveillance Shortcuts

PowerShell scripts for automating the creation and management of network shortcuts to surveillance computer shares.

## Overview

This collection of scripts connects to Active Directory to retrieve surveillance computer information and creates shortcuts to network shares hosted on those computers. The scripts include functionality for testing network connectivity, creating file shares, and scheduling automated tasks.

## Scripts

### Build-SURV-Shortcuts.ps1
Main script that connects to ADSI (Active Directory Service Interfaces) to pull a list of surveillance computers and creates shortcuts to network shares on each computer. Features include:
- ADSI query to retrieve surveillance computers from multiple OUs
- Network connectivity testing before creating shortcuts
- Automated share creation and permission configuration
- Logging functionality
- API integration for store information

### Build-Share-Local.ps1
**Intended for SCCM Deployment**: This script is designed to run locally on surveillance computers via SCCM task sequences, as SCCM executes scripts directly on the target machine. It performs the following:
- Verifies the computer is located in a SURV organizational unit
- Creates or validates the existence of local SMB shares
- Configures SMB share permissions (Everyone with Full access for share-level permissions)
- Configures NTFS permissions (restricted to administrators and FW-Milestone for actual security)
- Tests external share accessibility from a designated test server

**Security Model**: Uses a two-layer permission approach where SMB shares grant broad access at the share level, while NTFS permissions provide the actual security restrictions.

### Build-Share-Remote.ps1
Remotely connects to surveillance computers across the network to create and configure file shares. Features include:
- PowerShell remoting to manage shares on remote computers
- Network connectivity testing before attempting configuration
- SMB share creation with Everyone Full access (share level)
- NTFS permission hardening (restricted to administrators and FW-Milestone)
- Consolidated permission management function
- No UNC path testing to avoid false failures from NTFS restrictions

**Security Model**: Implements the same two-layer approach as the local script, ensuring consistent security across all surveillance shares.

### Create-ScheduledTask.ps1
Sets up a scheduled task to automatically run the shortcut creation scripts at specified intervals.

## Requirements

- Windows PowerShell 5.1 or later
- Active Directory access
- Appropriate network permissions
- Administrative privileges (for share creation and scheduled tasks)

## Configuration

The main script includes a configuration section where you can customize:
- Shortcut location paths
- Icon paths
- Log file locations
- API endpoints
- ADSI organizational units
- Network connection test parameters
- Share permissions

## Usage

Run the main script to create shortcuts:
```powershell
.\Build-SURV-Shortcuts.ps1
```

For automated execution, use the scheduled task script:
```powershell
.\Create-ScheduledTask.ps1
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

PostWarTacos
