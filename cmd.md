# General Command ✅
```cmd
set # like env in linux
ver # determine the operating system (OS) version.
systeminfo # list various information about the system such as OS information, system details, processor and memory
driverquery | more # more like less in linux
driverquery # displays a list of installed device drivers.

findstr "flag{}" "flag.txt" # like grep 

shutdown /s # can shut down a system
shutdown /r # reboot system
```
# Network Command ✅
```cmd
netstat -abon 
ipconfig
ipconfig /all
ping target_name
tracert target_name
nslookup example.com 1.1.1.1


sc stop "service name" 
sc start "service name" 
```
# File and Disk Management 
```cmd
move 
type
tree 
del or erase # like rm in linux
mkdir directory_name
rmdir directory_name
cd # like pwd in linux
dir # like ls in linux
dir /a # Displays hidden and system files as well.
dir /s # Displays files in the current directory and all subdirectories.
chkdsk # checks the file system and disk volumes for errors and bad sectors.
sfc /scannow # scans system files for corruption and repairs them if possible.
```

# Task and Process Management ✅
```cmd
tasklist
tasklist /?
tasklist /FI "imagename eq sshd.exe"
taskkill /PID target_pid 
```
