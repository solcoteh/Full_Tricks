# General Command ✅
```ps
Get-Help # like 'man' in linux
Get-Command # show all command
Get-Location # like 'pwd' in linux
Get-Help Get-FileHash # like 'man md5sum' in linux
Get-FileHash -Algorithm MD5 .\file.txt # like 'md5sum file.txt' in linux
Get-NetIPAddress # get the IP address info
```
# Variable ✅
```ps
$name = command 
$name.Count # for Count command result 
```
# Enumeration ✅
## Local-Users-Enumeration ✡️
### Find-Local-Users-Sid
```ps
Get-LocalUser # like who OR users in linux
Get-LocalUser | Select Name, SID  # Find Sid users 
```
### Find-Local-Users-Not-password-required
```ps
Get-LocalUser | Where-Object { $_.PasswordRequired -eq $false }
```

## Active-Directory-Users-Enumeration ✡️
### Find-Active-Directory-Users-Sid
```ps
Get-ADUser -Filter * | Select Name, SID
Get-ADUser -Identity username | Select Name, SID
```
### Find-Active-Directory-Not-password-required
```ps
Get-ADUser -Filter {PasswordNotRequired -eq $true}
```

# decode Base64 with PowerShell ✅
```ps
$base64String = 
"SGVsbG8gd29ybGQh" OR cat .\file.txt OR Get-Content -Path file.txt -Raw

# Convert Base64 string to byte array
$bytes = [Convert]::FromBase64String($base64String) OR $bytes = [Convert]::FromBase64String((cat file.txt)) 

$decodedString = [System.Text.Encoding]::UTF8.GetString($bytes) # Convert byte array to a plain text string
$decodedString # Output the decoded string
```
