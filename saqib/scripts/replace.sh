iso_number=1
index=23
#disk = ['phy:/dev/mapper/vgpool-win7x86--snapshot--lvmsnapshot,hda,w', 'file:/home/saqib/wumpbin-1.iso,hdc:cdrom,r']
replacement="disk = [\"phy:\/dev\/mapper\/vgpool-win7x86--snapshot--lvmsnapshot,hda,w\", \"file:\/home\/saqib\/sample_iso\/sample_"$iso_number".iso,hdc:cdrom,r\"]"
echo ${replacement}
sed -i "${index}s/.*/${replacement}/" win7.cfg
