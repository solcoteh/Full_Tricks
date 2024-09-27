
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
```
**More:** [Full john structure rule](https://www.openwall.com/john/doc/RULES.shtml)
## Example
```bash
Hash Type : MD5
Hash : 44cbd7b32e750b7b3aa1ff6e9a379d65
Password : 98mobinFd5
```
### my Rule for exploit 
```bash
[List.Rules:myrule]
A0"[0-9][0-9]"Az"[A-F][a-f][0-9]"
```
### command Run for exploit
```
john --format=Raw-MD5 --rules=myrule --wordlist=mywordlist hashfile.txt
```
### mywordlist
```bash
ali
sosan
mobin
yaqma
mehdi
```

<img src="https://github.com/solcoteh/Full_Tricks/blob/Tricks/John-Rule.PNG" width="1000">
