```ps
Get-Help # like 'man' in linux
Get-Command # show all command
Get-Location # like 'pwd' in linux
Get-Help Get-FileHash # like 'man md5sum' in linux
Get-FileHash -Algorithm MD5 .\file.txt # like 'md5sum file.txt' in linux
```
#  decode Base64 with PowerShell ✅
```ps
$base64String = "SGVsbG8gd29ybGQh"  OR $base64String = cat .\file.txt
$bytes = [Convert]::FromBase64String($base64String) # Convert Base64 string to byte array
$decodedString = [System.Text.Encoding]::UTF8.GetString($bytes) # Convert byte array to a plain text string
$decodedString # Output the decoded string
```
