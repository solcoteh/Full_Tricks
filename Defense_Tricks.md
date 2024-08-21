# Defense/Patching Linux Box
## Check list Defense
    01- /etc/sudoers &  /etc/sudoers.d/
    02- Crontab 
    03- SUID 
    04- shadow + passwd (should be not writeable)
    05- change password  and username (web + linux )
    06- web server config
    07- id_rsa OR ssh key
    08- smb & ftp = anonymous
    09- nfs = Enable root_squash
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
