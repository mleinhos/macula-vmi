import zmq
#import Queue
import json
import time
from threading import Thread
import threading

# send 1000 api calls at a time
API_CALL_SEQ_LENGTH = 5

ctx1 = zmq.Context()
# send pid & api call to controller
sock_sub1 = ctx1.socket(zmq.PAIR)
sock_sub1.connect("tcp://127.0.0.1:5555")
print "[+] Start socket sending api,pid to controller..."


while True:
	with open("malicious.txt","r") as f:
		for line in f.readlines():
			# syscall,1 0xba9e11a0,svchost.exe,0,ntoskrnl.exe,NtQuerySystemInformation,4,IN,SYSTEM_INFORMATION_CLASS,SystemInformationClass,0x53,,,OUT,PVOID,SystemInformation,0x1b7f50,,,IN,ULONG,SystemInformationLength,0x10,,,OUT,PULONG,ReturnLength,0x0,,
			line = line.strip()
			sock_sub1.send(line)
			time.sleep(1)

