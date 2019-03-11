# IMPORTS
import posix_ipc
import time
from threading import Thread
import threading
import time

# Create Message Queues
log_sender_ipc_queue_name = "/rcv_log_ipc_queue"
log_sender_ipc_queue = posix_ipc.MessageQueue(log_sender_ipc_queue_name)

verdict_rcv_ipc_queue_name = "/verdict_send_ipc_queue"
verdict_rcv_ipc_queue = posix_ipc.MessageQueue(verdict_rcv_ipc_queue_name)

#This function recv api call from syscall and save it in sys_call_queue
def send_api_logs_to_controller():
	with open("malicious.txt", "r") as file:
		logs = file.readlines()
	while True:
		for log in logs:
		    # log = "syscall,1 0xba9e41a0,svchost.exe,0,ntoskrnl.exe,NtDelayExecution,2,IN,BOOLEAN,Alertable,0x0,,,IN,PLARGE_INTEGER,DelayInterval,0xb5fa0c,,"
			log_sender_ipc_queue.send(log, True)
			time.sleep(0.05)

def receive_verdict_controller():
	while True:
		verdict = verdict_rcv_ipc_queue.receive()
		print(verdict)

# Empty list for worker threads
worker_threads = []

# Create a thread for the sending queue and append it to the list of worker threads
log_send_thread = threading.Thread(target=send_api_logs_to_controller)
worker_threads.append(log_send_thread)
# Start thread
log_send_thread.start()

# Create a thread for the receiving queue and append to the list of worker_threads
verdict_rec_thread = threading.Thread(target=receive_verdict_controller)
worker_threads.append(verdict_rec_thread)
verdict_rec_thread.start()
