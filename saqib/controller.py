import threading
import Queue
import json
import os
import hashlib
from collections import OrderedDict
import zmq  # test use

ctx1 = zmq.Context()
# listen to vmi logs without any filteration
sock_sub1 = ctx1.socket(zmq.PAIR)
sock_sub1.bind("tcp://*:5555")
print "[+] Start socket listening from syscall side..."

worker_threads = []
# Unique APIs
uniqApis = set()
processQueues = {}
Proccess_api_queue = Queue.Queue()
black_list_queue = Queue.Queue()
verdict_queue = Queue.Queue()

BLACKLIST_FILE = 'blacklist_test.json'
BLACKLIST_CACHE = OrderedDict()  # order is based on time. older one will be replaced.
BLACKLIST_SIZE_MAX = 5  # confiurable max blacklist size. 5 is for test
API_SEQUENCE_SIZE = 10  # 10 is for test, change to 1000
TEST_MODE = True


# Incase ML model doesnot work this is hardcoded function
def backup_verdict(process_name):
    HCPL = ["svchost", "mal", "malicious"]

    if process_name in HCPL:
        return True
    else:
        return False


def kill_pid(pid):
    print 'killing PID'
    # kill Pid


#Handle Verdict from ML mode, In sperate thread when there is verdict just push into verdict_queue it will be processes here
def handle_verdict():
    while True:
        verdict = verdict_queue.get()
        #Call kill_pid from here


# Black listing code

def load_blacklist(file=BLACKLIST_FILE):
    """Load the blacklist json file into cache (dict)
    Sample blacklist file:
    {
        'hash1': [NtCreate, NtClose, ... , NtQuerySystemInformation],
        'hash2': [NtClose, NtQuerySystemInfomration, ... , NtDelayExecution],
        ... ,
        ...
        'hash_max_size': [NtClose, NtCreate, ... , NtClose]
    }
    Each record has 1000 sequence of APIs.

    Args:
        file: string
    """
    global BLACKLIST_CACHE
    if not os.path.isfile(file):
        # blacklist file doen't exist, create an empty one
        print '[+] create an empty blacklist file'
        open(file, 'a').close()

    try:
        f = open(file, 'r')
    except Exception as e:
        print '[-] Could not open blacklist file: %s' % str(e)
        return

    try:
        BLACKLIST_CACHE = json.loads(f.read(), object_pairs_hook=OrderedDict)  # load the blacklist in order
    except Exception as e:
        print '[-] Could not load blacklist object into cache: %s' % str(e)

    f.close()


def cal_hash(api_sequence):
    """Calculate the hash of the api sequence

    Args:
        api_sequence: list.  1000 api calls
    Return:
        md5 hash: string.
    """
    m = hashlib.md5()
    m.update(','.join([api for api in api_sequence]))
    return m.hexdigest()


def is_match_in_blacklist(api_seq_hash):
    """Match if certain sequence is in blacklist

    Args:
        api_sequence: list

    Return:
        Boolean. Match is True, not match is False
    """
    global BLACKLIST_CACHE
    return api_seq_hash in BLACKLIST_CACHE


def update_blacklist_file(file):
    """Update the blacklist file on file system with json object.
    Blacklist size has an upper limit, if the size hit the threshold,
    we will replace the latest api sequence with the oldest one in the file.

    Args:
        file: string
    """
    global BLACKLIST_CACHE
    try:
        f = open(file, 'w')
    except Exception as e:
        print '[-] Could not open blacklist file: %s' % str(e)
        return

    try:
        json.dump(BLACKLIST_CACHE, f)
        print '[+] Updated blacklist file'
    except Exception as e:
        print '[-] Could not update blacklist file: %s' % str(e)
    f.close()


def update_blacklist(api_seq_hash, api_sequence):
    """Update the cache. If size is full, remove the first record
    and append the new one to the last of OrderedDict

    Args:
        api_seq_hash: string
        api_sequence: list
    """
    global BLACKLIST_CACHE
    assert len(BLACKLIST_CACHE) <= BLACKLIST_SIZE_MAX
    if api_seq_hash not in BLACKLIST_CACHE:  # sanity check
        if len(BLACKLIST_CACHE) == BLACKLIST_SIZE_MAX:
            print "[+] Update blacklist: remove oldest record in the blacklist."
            BLACKLIST_CACHE.popitem(last=False)  # remove the first item
        print "[+] Update blacklist: append the new sequence at last"
        BLACKLIST_CACHE[api_seq_hash] = api_sequence


# Function for handling Thread, will be called each time we have queue of 1000
def black_list():
    while True:
        json_sample = black_list_queue.get()
        driver(json_sample)


def driver(json_sample):
    """
    This function interact with process Queues which hit the size threshold 1000

    Args:
        pid: integer/string?
        api_sequence: list of apis
    """
    pid = json_sample["pid"]
    api_sequence = json_sample["api_sequence"]
    assert len(api_sequence) == API_SEQUENCE_SIZE  # check the api sequence size
    # 1. load blacklist
    # Since blacklist file could be changed after each process,
    # so everytime a process is full, blacklist will be loaded again.
    load_blacklist(BLACKLIST_FILE)
    print '[+] Loaded %d records from blacklist file' % len(BLACKLIST_CACHE)

    # 2. Check the sequence in the blacklist
    api_seq_hash = cal_hash(api_sequence)
    if is_match_in_blacklist(api_seq_hash):
        print "[+] Found matching sequence for process[%d] in the blacklist" % int(pid)
        print "[+] Initiating Process Termination..."
    # kill process with pid
    # ...
    # empty the queue

    else:
        print "[+] No matching in blacklist, send to ML for processing..."
        # send to ML model and retain the queue
        # Please add your code here and use queue to send me verdict


# Prepare JSON as required by Yijie blacklisting module
def gen_JSON(api_list, proc_name):
    data = {}

    data['api_sequence'] = api_list
    data['pid'] = proc_name
    json_data = json.dumps(data)
    return json_data


def Process_queue():
    while True:
        proc_name = Proccess_api_queue.get()
        l = list(processQueues[proc_name].queue)
        black_list_queue.put(gen_JSON(l, proc_name))
        # For now am not keeping this queue i am saving it first in list, driver function will receive list
        with processQueues[proc_name].mutex:
            processQueues[proc_name].queue.clear()


# This function recv api call from syscall and save it in sys_call_queue
def receive_api_logs_from_sycall_plugin():
    while True:
        # Receive Log, Please test this
        log = sock_sub1.recv()
        # print(log)

        # Process log and get the Proces and API name
        procName, apiName = log.split(",")[3], log.split(",")[6]
        # print("Process:", procName)
        # print("API:", apiName)

        # Check if process was already being tracked
        if procName not in uniqApis:
            print "[+] New Process Found, Monitoring Now..."
            uniqApis.add(procName)
            processQueues[procName] = Queue.Queue()
            processQueues[procName].put(apiName)
        # processQueues[procName]
        # processQueues[procName].append(apiName)
        else:
            processQueues[procName].put(apiName)
            # print list(processQueues[procName].queue)
            if processQueues[procName].qsize() == 1000:
                Proccess_api_queue.put(procName)


worker_threads = []


def main():
    print "[+] Initiating new Thread for Recieving syscall logs..."
    log_rcv_thread = threading.Thread(target=receive_api_logs_from_sycall_plugin)
    worker_threads.append(log_rcv_thread)
    log_rcv_thread.start()

    print "[+] Initiating new Thread for processing logs from syscall plugin..."
    log_processing_thread = threading.Thread(target=Process_queue)
    worker_threads.append(log_processing_thread)
    log_processing_thread.start()

    print "[+] Initiating new Thread for processing logs from syscall plugin..."
    verdict_handling_thread = threading.Thread(target=handle_verdict)
    worker_threads.append(verdict_handling_thread)
    log_processing_thread.start()


if __name__ == '__main__':
    main()
