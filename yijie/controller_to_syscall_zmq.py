import zmq
import Queue
from threading import Thread
import threading
import json
import time

sys_call_queue = Queue.Queue()
verdict_queue = Queue.Queue()

ctx1 = zmq.Context()
# listen to vmi logs with pid & api call
sock_sub1 = ctx1.socket(zmq.PAIR)
sock_sub1.bind("tcp://*:5555")
print "[+] Start socket listening from syscall side..."

# send verdict back to syscall module
sock_sub2 = ctx1.socket(zmq.PAIR)
sock_sub2.connect("tcp://127.0.0.1:5556")
print "[+] Start socket sending verdict to syscall side..."


#This function recv api call from syscall and save it in sys_call_queue
def receive_api_logs_from_sycall_plugin():
	while True:
		msg = sock_sub1.recv()
		msg = json.loads(msg) # {1: "NtClose"}
		print "[+] Receive log from syscall:"
		print msg
		sys_call_queue.put(msg)

def send_verdict():
	while True:
		verdict_json = verdict_queue.get()
		#verdict_send_ipc_queue.send(verdict_json)
		sock_sub2.send(json.dumps(verdict_json))
		print "[+] Sending verdict back to syscall side:"
		print verdict_json
		verdict_queue.task_done()

def log_processing():
	n_logs = 5
	print "[+] Loaded model..."
	while True:

		#processing logs for simulation lets send log after each 60 seconds
		time.sleep(0.05)
		#read 100(Threadshold) logs from sys_call_queue
		#call = sys_call_queue.get().decode("utf-8").split(",")[5]
		msg = sys_call_queue.get()
		call_seq = []
		pid = 0
		for k,v in msg.iteritems():
			call_seq = v
			pid = k
			break
		print type(call_seq)
		print call_seq

		if len(call_seq) == n_logs:
			print "[+] Anomaly Detected for PID:%s" % str(pid)
			verdict = {"pid":pid, "verdict":1} # hardcoded for test
			# put verdic json into verdict_queue, send__verdic will automaticaly consume queue
			verdict_queue.put(verdict)

worker_threads = []

log_rcv_thread = threading.Thread(target=receive_api_logs_from_sycall_plugin)
worker_threads.append(log_rcv_thread)
log_rcv_thread.start()
print "[+] Start log recv thread..."

verdict_sending_thread = threading.Thread(target=send_verdict)
worker_threads.append(verdict_sending_thread)
verdict_sending_thread.start()
print "[+] Start sending verdict thread..."

log_processing_thread = threading.Thread(target=log_processing)
worker_threads.append(log_processing_thread)
log_processing_thread.start()
print "[+] Start log processing thread..."
