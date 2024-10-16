# General Command ✅
```ps
Get-Help # like 'man' in linux
Get-Command # show all command
Get-Location # like 'pwd' in linux
Get-Content .\file.txt # like "cat" in linux
Get-Process # like "ps aux" in linux
Get-Acl c:/ # find owner directory  
Start-Process # like "open" in linux
Copy-Item # like "cp" in linux
Move-Item # like "mv" in linux
| findstr # like "grep" in linux
| Out-File # like ">" in linux
Get-SMBShare # show share directory
Get-Help Get-FileHash # like 'man md5sum' in linux
Get-FileHash -Algorithm MD5 .\file.txt # like 'md5sum file.txt' in linux
<command> | measure 
```
https://book.hacktricks.xyz/windows-hardening/basic-powershell-for-pentesters

https://book.hacktricks.xyz/windows-hardening/basic-powershell-for-pentesters/powerview

# Variable ✅
```ps
$name = <command> 
$name.Count # for Count command result 
```
# Enumeration ✅
## Local-Users-Enumeration ✡️
### Find-Local-Users-Sid ⚙️
```ps
Get-LocalUser # like who OR users in linux
Get-LocalUser | Select Name, SID  # Find Sid users 
```
### Find-Local-Users-Not-password-required ⚙️
```ps
Get-LocalUser | Where-Object { $_.PasswordRequired -eq $false }
Get-LocalUser | Where-Object -Property PasswordRequired -Match false
```
## Active-Directory-Users-Enumeration ✡️
### Find-Active-Directory-Users-Sid ⚙️
```ps
Get-ADUser -Filter * | Select Name, SID
Get-ADUser -Identity username | Select Name, SID
```
### Find-Active-Directory-Not-password-required ⚙️
```ps
Get-ADUser -Filter {PasswordNotRequired -eq $true}
```
## Get-IP-address-info ✡️
```ps
Get-NetIPAddress
```
## Find-Port-listening ✡️
```ps
netstat -an | Select-String 'LISTENING'
Get-NetTCPConnection | Where-Object { $_.State -eq 'Listen' }
GEt-NetTCPConnection | Where-Object -Property State -Match Listen | measure
```
## Find-Patch-or-update ✡️
```ps
Get-hotfix
```
### Find-patch-with-specific-ID ⚙️
```ps
Get-Hotfix -Id KB4023834
Get-HotFix | Where-Object { $_.HotFixID -eq 'KB4023834' }
```
## Find-file ✡️
```ps
# like find / -name "*.bak*" 2>/dev/null in linux
Get-ChildItem -Include *.bak* -Path C:\  -File -Recurse -ErrorAction SilentlyContinue 
---------------
# like grep 'API_KEY' ./  2>/dev/null in linux
Get-ChildItem C:\ -Recurse | Select-String -pattern "API_KEY"
Get-ChildItem -Path C:\ -Recurse -ErrorAction SilentlyContinue | Select-String "API_KEY"
``` 
## ScheduledTask ✡️ 
```ps
Get-ScheduledTask 
Get-ScheduledTask -TaskName new-sched-task
```
# decode Base64 with PowerShell ✅
```ps
certutil.exe -decode "C:\Users\Administrator\Desktop\b64.txt" decode.txt
Get-Content .\decode.txt
------------
$base64String = 
"SGVsbG8gd29ybGQh" OR cat .\file.txt OR Get-Content -Path file.txt -Raw

# Convert Base64 string to byte array
$bytes = [Convert]::FromBase64String($base64String) OR $bytes = [Convert]::FromBase64String((cat file.txt)) 

$decodedString = [System.Text.Encoding]::UTF8.GetString($bytes) # Convert byte array to a plain text string
$decodedString # Output the decoded string
```
