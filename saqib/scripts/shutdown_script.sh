explorer_pid=$(vmi-process-list win7-x86 | grep explorer.exe | cut -d " " -f2 | cut -d "]" -f1)
vm_id=$(xl list | tail -1 |  awk '{print $2}')
echo $explorer_pid
echo vm_id
echo $1
echo $2

if [ "$2" -eq 0 ];then
   "/home/saqib/Sprint 2/drakvuf-master/src/injector" -r /root/windows-x86.rekall.json -d /root/windows-x86.rekall.json -d $vm_id -i $explorer_pid -e "taskkill /F /PID $1" -m createproc
elif [ "$2" -eq 1 ]
then
	PID=$(ps aux | grep "/home/saqib/Sprint 2/drakvuf-master/src/drakvuf" | head -1 | awk '{print $2}')
	kill $PID
	xl destroy $vm_id
	sleep 15
else
   echo "Unknown option"
fi
