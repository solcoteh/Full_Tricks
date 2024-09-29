#### Change and write in king.txt
```bash
# change directory to locate king.txt
cd C:\Users\Administrator\king-server\
icacls king.txt /inheritance:d # To disable inheritance
icacls king.txt /inheritance:e # To enable inheritance
# write username to king.txt and change permissions 
icacls king.txt /grant Everyone:(F)
attrib -a -s -r -i -h king.txt & echo solcoteh > king.txt & attrib +a +s +r +i king.txt
```
#### Remove Permissions
```bash
cd C:\Users\Administrator\king-server\

icacls king.txt # show All permissions
icacls king.txt /remove Everyone
icacls king.txt /remove Administrator
icacls king.txt /remove "NT AUTHORITY\IUSR"
icacls king.txt /remove "NT AUTHORITY\SYSTEM"
icacls king.txt /remove BUILTIN\Administrators
icacls king.txt /remove KingOfTheDomain\Administrator
```
#### Allow Permissions
```bash
cd C:\Users\Administrator\king-server\

icacls king.txt /grant Everyone:(F)
icacls king.txt /grant "NT AUTHORITY\IUSR":(R)

icacls king.txt /grant Administrator:(F)
icacls king.txt /grant "NT AUTHORITY\SYSTEM":(F)
icacls king.txt /grant BUILTIN\Administrators:(F)
icacls king.txt /grant KingOfTheDomain\Administrator:(F)
```
#### Deny Permissions
```bash
cd C:\Users\Administrator\king-server\

icacls king.txt /deny  Everyone:(WD)
icacls king.txt /deny  Administrator:(WD)
icacls king.txt /deny  "NT AUTHORITY\SYSTEM":(WD)
icacls king.txt /deny  BUILTIN\Administrators:(WD)
icacls king.txt /deny  KingOfTheDomain\Administrator:(WD)
```
