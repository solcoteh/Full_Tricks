# Flag_finder ✅
```bash
grep -iR "THM{" / 2>/dev/null # flag 
grep -iR "THM{" / 2>/dev/null # flag 
grep -iR "VEhN" / 2>/dev/null # base64
grep -iR "galf" / 2>/dev/null # reverse
grep -iR "NhEV" / 2>/dev/null # reverse base64

grep -REi '[0-9a-f]{32}' . 2>/dev/null  # hash
grep -REi 'flag{[0-9a-f]{32}}' . 2>/dev/null  # flag hash

find / -name "*flag*"  -ls 2>/dev/null
find / -type f -name "*flag.txt" -o -name ".flag*" -o -name "flag" -o -name "user.txt" -o -name "root.txt"  -ls 2>/dev/null
```
## Important-Word ✅
```bash
flag
pass
password
{user}
```
## Important-Dir ✅
```bash
/var
/opt
/srv
/mnt
/home
/media
```
