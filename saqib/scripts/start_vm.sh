#!/bin/bash
umount /mnt/lvmsnapshot/vgpool/win7x86
lvremove -f /dev/mapper/vgpool-win7x86--snapshot--lvmsnapshot
sudo /home/saqib/lvmsnapshot-master/lvmsnapshot.sh -d -c /home/saqib/lvmsnapshot-master/lvmsnapshot.xen.example.conf create win7x86
#replacement="disk = [\"phy:\/dev\/mapper\/vgpool-win7x86--snapshot--lvmsnapshot,hda,w\", \"file:\/home\/saqib\/sample_iso\/sample_"$i".iso,hdc:cdrom,r\"]"
#sed -i "${index}s/.*/${replacement}/" /home/saqib/win7.cfg
xl create /home/saqib/win7.cfg
sleep 30 #wait for 25 second to boot
var_id=$(xl list | tail -1 |  awk '{print $2}')
echo $var_id
"/home/saqib/Sprint 2/drakvuf-master/src/drakvuf" -r /root/windows-x86.rekall.json -d $var_id -o csv -x poolmon -x objmon -x exmon -x filetracer -x filedelete -x ssdtmon -x socketmon -x regmon -x cpuidmon -x procmon -x debugmon
