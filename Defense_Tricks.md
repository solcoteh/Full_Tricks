# Defense/Patching Linux Box
## Check list Defense
    1- /etc/sudoers &  /etc/sudoers.d/
    2- Crontab 
    3- SUID 
    4- shadow + passwd (should be not writeable)
    5- change password  and username (web + linux )
    6- web server config
    7- id_rsa OR ssh key
    8- smb & ftp = anonymous
    9- nfs = Enable root_squash
    10 - File information
    11- umask= 22 in all service 
    12- mysql default password
    13- sudo !pwdfeedback
    14- change default  port service (ssh + ftp + smb + mysql + oracle)
    15- kill another user shell

## Suid_Fix
```bash
find / -perm /4000 2>/dev/null
chmod -s /usr/bin/pkexec
```
