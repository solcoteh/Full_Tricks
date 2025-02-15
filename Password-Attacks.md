# Password-Attacks ✅
## Types of passwords for attack ✅
```c
Default Passwords wordlists
Weak Passwords wordlists
Leaked Passwords wordlists
Combine multiple wordlists
Customized Wordlists
```
## Types of attacks to break the password ✅
```c
Guessing Attack
Dictionary attack
Brute-Force attack
Combination attack
Rule-Based  attacks
Custom Rules-Based attack
Password spray attack
```
## Generate-passwords-Tricks ✅
```c
# Combine multiple passwords generator
cat WordList1.txt WordList2.txt WordList3.txt > combined_list.txt
sort combined_list.txt | uniq -u > cleaned_combined_list.txt
----------------------------------
# Custom WordList generator with site target
https://github.com/digininja/CeWL
----------------------------------
username_generator # # User WordList generator
https://github.com/shroudri/username_generator
----------------------------------
# Keyspace technique
cupp -h
crunch -h
```
# Create Custom Rules in John ✅
## Add a Custom Rule to john Tool config file 💡
```bash
sudo nano /etc/john/john.conf
append '[List.Rules:NameRule]' end of the file
```
## The structure of creating rules 💡
```bash
Az - append to the end of the words from Wordlist 
A0 - append to before the word Wordlist
$X - append character X to the word
$[0-9] - append character 0-9 to the word
```
**More:** [Full john structure rule](https://www.openwall.com/john/doc/RULES.shtml)
## Example 📌
```bash
Hash Type : MD5
Hash : 44cbd7b32e750b7b3aa1ff6e9a379d65
Password : 98mobinFd5
```
### My Rule For Exploit 📌
```bash
[List.Rules:myrule]
A0"[0-9][0-9]"Az"[A-F][a-f][0-9]"
```
### Command Run For Exploit 📌
```
john --format=Raw-MD5 --rules=myrule --wordlist=mywordlist hashfile.txt
```
### MyWordlist 💡
```bash
ali
sosan
mobin
yaqma
mehdi
```

<img src="https://github.com/solcoteh/Full_Tricks/blob/Tricks/John-Rule.PNG" width="1000">
