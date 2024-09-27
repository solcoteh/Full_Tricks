
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
