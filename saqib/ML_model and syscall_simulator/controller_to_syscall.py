import posix_ipc


log_rcv_ipc_queue_name = "/rcv_log_ipc_queue"

verdict_send_ipc_queue_name = "/verdict_send_ipc_queue"


mq = posix_ipc.MessageQueue(log_rcv_ipc_queue_name, posix_ipc.O_CREX)

mq2 = posix_ipc.MessageQueue(verdict_send_ipc_queue_name, posix_ipc.O_CREX)








