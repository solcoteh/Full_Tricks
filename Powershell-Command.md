# General Command ✅
```powershell
Get-Help # like 'man' in linux
Get-Help -examples Get-Content # like 'man' in linux

Select-String -Path ".\captain-hat.txt" -Pattern "hat" # like grep 
2>$null # like 2>/dev/null
Get-ChildItem | Select-Object Name,Length 
Get-ChildItem | Sort-Object Length # sort by size
Get-ChildItem | Where-Object -Property Length -gt 100 
Get-ChildItem | Where-Object -Property "Name" -like "ship*"  
Get-ChildItem | Where-Object -Property "Extension" -eq ".txt"  # show only ".txt" extension file  

Get-Service | Select-Object Name,DisplayName | Select-String -Pattern "A merry life and a short one."

Get-Alias # show like alias in linux
Find-Module -Name "PowerShell*"  # like "apt search" in linux
Install-Module -Name "PowerShellGet" # like apt install in linux
Write-Output # like echo in linux
Get-ChildItem # like ls in linux
Set-Location # like cd in linux
Get-Command # show all command
Get-Location # like 'pwd' in linux
Get-Content .\file.txt # like "cat" in linux

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


# PowerShell-Alias ✅
```powershell
gc -> Get-Content
cat -> Get-Content
type -> Get-Content

cd -> Set-Location
sl -> Set-Location
chdir -> Set-Location

md -> mkdir

cp -> Copy-Item
cpi -> Copy-Item
copy -> Copy-Item


mv -> Move-Item
mi -> Move-Item
move -> Move-Item


rm -> Remove-Item
del -> Remove-Item
rmdir -> Remove-Item

echo -> Write-Output
write -> Write-Output

ls -> Get-ChildItem
dir -> Get-ChildItem

cls -> Clear-Host
clear -> Clear-Host

wget -> Invoke-WebRequest
curl -> Invoke-WebRequest

cli -> Clear-Item

fhx -> Format-Hex 

set -> Set-Variable

kill -> Stop-Process

man -> help

sal -> Set-Alias
nal -> New-Alias
gal -> Get-Alias
ipal -> Import-Alias

h -> Get-History
ghy -> Get-History
history -> Get-History

gi -> Get-Item
glu -> Get-LocalUser


ihy -> Invoke-History
```
# Variable ✅
```powershell
$name = <command> 
$name.Count # for Count command result 
```
# Enumeration ✅
## Local-Users-Enumeration ✡️
### Find-Local-Users-Sid ⚙️
```powershell
Get-LocalUser # like who OR users in linux
Get-LocalUser | Select Name, SID  # Find Sid users 
```
### Find-Local-Users-Not-password-required ⚙️
```powershell
Get-LocalUser | Where-Object { $_.PasswordRequired -eq $false }
Get-LocalUser | Where-Object -Property PasswordRequired -Match false
```
## PS-Enumeration ✡️
```powershell
Get-Process 
Get-Service
```
## Active-Directory-Users-Enumeration ✡️
### Find-Active-Directory-Users-Sid ⚙️
```powershell
Get-ADUser -Filter * | Select Name, SID
Get-ADUser -Identity username | Select Name, SID
```
### Find-Active-Directory-Not-password-required ⚙️
```powershell
Get-ADUser -Filter {PasswordNotRequired -eq $true}
```
## Get-IP-address-info-&-Config ✡️
```powershell
ipconfig 
Get-NetIPAddress
Get-NetTCPConnection
Get-NetIPConfiguration
```
## Get-Comprehensive-System-Information ✡️
```powershell
systeminfo 
Get-ComputerInfo
```
## Find-Port-listening ✡️
```powershell
netstat -an | Select-String 'LISTENING'
Get-NetTCPConnection | Where-Object { $_.State -eq 'Listen' }
GEt-NetTCPConnection | Where-Object -Property State -Match Listen | measure
```
## Find-Patch-or-update ✡️
```powershell
Get-hotfix
```
### Find-patch-with-specific-ID ⚙️
```powershell
Get-Hotfix -Id KB4023834
Get-HotFix | Where-Object { $_.HotFixID -eq 'KB4023834' }
```
## Find-file ✡️
```powershell
# like find / -name "*.bak*" 2>/dev/null in linux
Get-ChildItem -Include *.bak* -Path C:\  -File -Recurse -ErrorAction SilentlyContinue 
---------------
# like grep 'API_KEY' ./  2>/dev/null in linux
Get-ChildItem C:\ -Recurse | Select-String -pattern "API_KEY"
Get-ChildItem -Path C:\ -Recurse -ErrorAction SilentlyContinue | Select-String "API_KEY"
``` 
## ScheduledTask ✡️ 
```powershell
Get-ScheduledTask 
Get-ScheduledTask -TaskName new-sched-task
```
# decode Base64 with PowerShell ✅
```powershell
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

# *-Item Command ✅
## New-Item ✡️ 
```powershell
New-Item -Path "c:\Mobin" -ItemType "Directory" # Create a directory 
New-Item -Path "c:\Mobin\flag.txt" -ItemType "File" # Create a empty file in a dir
New-Item -Path "c:\Mobin\ -Name "flag.txt" -ItemType "file" -Value "solcoteh{B005_b4_7o}" # Create a file with value in a dir
```
## Copy-Item ✡️ 
```powershell
Copy-Item -Path "c:\mobin\flag.txt -Destination ".\captain-cabin\captain-hat2.txt" # like cp in linux
```
## Remove-Item ✡️ 
```powershell
Remove-Item -Path "c:\Mobin" # Remove a directory 
Remove-Item -Path ""c:\Mobin\flag.txt" # Remove a file
```

# Install-Tools-in-PowerShell ✅
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

choco install netcat
```


