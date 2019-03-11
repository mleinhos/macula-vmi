import posix_ipc
import time
from threading import Thread
import threading
import queue as Queue
import hashlib, random 
import numpy as np
from joblib import load as load_model
from sklearn.decomposition import PCA
from sklearn.feature_extraction.text import CountVectorizer

sys_call_queue = Queue.Queue()
verdict_queue = Queue.Queue()


log_rcv_ipc_queue_name = "/rcv_log_ipc_queue"
log_rcv_ipc_queue = posix_ipc.MessageQueue(log_rcv_ipc_queue_name)

verdict_send_ipc_queue_name = "/verdict_send_ipc_queue"
verdict_send_ipc_queue = posix_ipc.MessageQueue(verdict_send_ipc_queue_name)



#This function recv api call from syscall and save it in sys_call_queue
def receive_api_logs_from_sycall_plugin():
	while True:
		log, _ = log_rcv_ipc_queue.receive()
		# print(log)
		sys_call_queue.put(log)



def send_verdict():
	while True:
		verdict_json = verdict_queue.get()
		verdict_send_ipc_queue.send(verdict_json)
		verdict_queue.task_done()



def log_processing():
	pca = load_model("pca.joblib")
	vectorizer = load_model("vectorizer.joblib")
	threshold = load_model("threshold.joblib")
	n_logs = 1000
	print("Loaded model")
	seq = []
	while True:

		#processing logs for simulation lets send log after each 60 seconds
		time.sleep(0.05)
		#read 100(Threadshold) logs from sys_call_queue
		#call = sys_call_queue.get().decode("utf-8").split(",")[5]
		call = sys_call_queue.get().decode("utf-8").split(",")[6]
		print(type(call))
		print(call)

		seq.append(call)

		del(call)

		if len(seq) == n_logs:
			print(seq)
			seq_vec = vectorizer.transform(seq)
			print(seq_vec)
			print(seq_vec.shape)

			event_count = seq_vec.sum(axis=0)
			print(event_count.shape)

			pca_transformed_data = pca.transform(event_count)
			pca_reconstructed_data = pca.inverse_transform(pca_transformed_data)
			reconstruction_loss = np.square(event_count - pca_reconstructed_data).mean()

			# print("\n\n\n")
			# print(pca_transformed_data)
			# print(pca_transformed_data.shape)

			print("\n\n\n")
			print(pca_reconstructed_data)
			print(pca_reconstructed_data.shape)

			print("\n\n\nLOSS\n-------------\n")
			print(reconstruction_loss)

			if reconstruction_loss >= threshold:
				print("Anomaly Detected")

				hsh = "fdsfa"
				# #generate verdict
				verdict = '''{ "verdict": 1, "kill_vm": 1, "Event_list": [{"Event": "Anomaly Detected", "API_count": %s, "API_list": %s, "API_hash": %s}]}''' % (n_logs, seq, hsh)
				verdict = '''{ "verdict": 1, "kill_vm": 1, "Event_list": [{"Event": "Anomaly Detected", "API_count": %s, "API_hash": %s}]}''' % (n_logs, hsh)
				# #put verdic json into verdict_queue, send__verdic will automaticaly consume queue
				verdict_queue.put(verdict)

			seq = []


worker_threads = []


log_rcv_thread = threading.Thread(target=receive_api_logs_from_sycall_plugin)
worker_threads.append(log_rcv_thread)
log_rcv_thread.start()

verdict_sending_thread = threading.Thread(target=send_verdict)
worker_threads.append(verdict_sending_thread)
verdict_sending_thread.start()

log_processing_thread = threading.Thread(target=log_processing)
worker_threads.append(log_processing_thread)
log_processing_thread.start()




#simulation of actual scanrio
