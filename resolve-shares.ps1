clear
$CN = "WRIVE-SURVEG88F"
$share = "$($CN.Substring(1,4))_corp"

invoke-command -ComputerName $CN {
param($share)
    Grant-SmbShareAccess $share -AccountName dds\desktop-admin -AccessRight Full -Force | Out-Null
    Grant-SmbShareAccess $share -AccountName dds\fw-milestone -AccessRight Read -Force | Out-Null
} -ArgumentList $share

# Check Share Perm
Invoke-Command -ComputerName $CN {
param($share)
    get-smbshareaccess $share
} -argumentlist $share

# Check NTFS Perm
Invoke-Command -ComputerName $CN {
param($share)
    get-acl D:\$share | fl accesstostring
} -argumentlist $share

