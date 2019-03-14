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

# listen verdict from controller
sock_sub2 = ctx1.socket(zmq.PAIR)
sock_sub2.bind("tcp://*:5556")
print "[+] Start socket to listen from controller to get verdict..."

# Dict maintain the process based api call sequence
processes = {}

def send_api_logs_to_controller():
	while True:
		with open("malicious.txt","r") as f:
			for line in f.readlines():
				# syscall,1 0xba9e11a0,svchost.exe,0,ntoskrnl.exe,NtQuerySystemInformation,4,IN,SYSTEM_INFORMATION_CLASS,SystemInformationClass,0x53,,,OUT,PVOID,SystemInformation,0x1b7f50,,,IN,ULONG,SystemInformationLength,0x10,,,OUT,PULONG,ReturnLength,0x0,,
				line = line.strip()
				fields = line.split(",")
				pid = fields[2] # process name for now
				api_call = fields[5]
				print "[+] Get pid:%s api_call:%s from VMI." % (str(pid), api_call)
				if pid in processes:
					api_call_seq = processes[pid]
					# api call size hit threshold send to controller
					if len(api_call_seq) == API_CALL_SEQ_LENGTH - 1:
						api_call_seq.append(api_call)
						print "[+] For PID:%s , reach to api call sequence size limit: %d, send the sequence to Controller:" % (str(pid), API_CALL_SEQ_LENGTH)
						print api_call_seq
						sock_sub1.send(json.dumps({pid: api_call_seq}))
						# clean process which sent to controller already
						print "[+] Clean the process queue for PID: %s" % str(pid)
						processes.pop(pid, None)
					# api call size not enough, keep adding
					else: 
						api_call_seq.append(api_call)
						print "[+] For PID:%s, current sequence:" % str(pid)
						print api_call_seq
						processes[pid] = api_call_seq
				# keep tracking a new process
				else:
					api_call_seq = [api_call]
					print "[+] New process PID (%s) in the queue" % str(pid)
					print "[+] For PID:%s, current sequence:" % str(pid)
					print api_call_seq
					processes[pid] = api_call_seq

				time.sleep(1)

def receive_verdict_controller():
	while True:
		msg = sock_sub2.recv()
		msg = json.loads(msg)
		verdict = msg["verdict"]
		print "[+] Receive verdict from controller %s for PID %s" % (verdict, msg["pid"]) 

# Empty list for worker threads
worker_threads = []

# Create a thread for the sending queue and append it to the list of worker threads
log_send_thread = threading.Thread(target=send_api_logs_to_controller)
worker_threads.append(log_send_thread)
# Start thread
log_send_thread.start()
print "[+] Start log send thread..."

# Create a thread for the receiving queue and append to the list of worker_threads
verdict_rec_thread = threading.Thread(target=receive_verdict_controller)
worker_threads.append(verdict_rec_thread)
verdict_rec_thread.start()
print "[+] Start verdict recv thread..."