
# Create Custom Rules in John

## Add a Custom Rule to john Tool config file
```bash
sudo nano /etc/john/john.conf
append '[List.Rules:NameRule]' end of the file
```
## The structure of creating rules
```bash
Az - append to the end of the words from Wordlist 
A0 - append to before the word Wordlist
$X - append character X to the word
$[0-9] - append character 0-9 to the word
```
**More:** [Full john structure rule](https://www.openwall.com/john/doc/RULES.shtml)
## Example
```bash
Hash Type : MD5
Hash : 44cbd7b32e750b7b3aa1ff6e9a379d65
Password : 98mobinFd5
```
### My Rule For Exploit 
```bash
[List.Rules:myrule]
A0"[0-9][0-9]"Az"[A-F][a-f][0-9]"
```
### Command Run For Exploit
```
john --format=Raw-MD5 --rules=myrule --wordlist=mywordlist hashfile.txt
```
### MyWordlist
```bash
ali
sosan
mobin
yaqma
mehdi
```

<img src="https://github.com/solcoteh/Full_Tricks/blob/Tricks/John-Rule.PNG" width="1000">
