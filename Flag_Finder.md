```bash
grep -iR "THM{" / 2>/dev/null          # flag prefix
grep -R  "VEhN" / 2>/dev/null          # base64
grep -RE '[0-9a-f]{32}' . 2>/dev/null  # hash
find / -name "*flag*"  -ls 2>/dev/null
find / -type f -name "*flag.txt" -o -name ".flag*" -o -name "flag" -o -name "user.txt" -o -name "root.txt"  -ls 2>/dev/null
```
