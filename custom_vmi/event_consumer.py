#
#  Synchronized subscriber
#
import time
import zmq
import struct


syscall_ct = dict() # map PID --> calls seen

def main():
    context = zmq.Context()

    # First, connect our subscriber socket
    subscriber = context.socket(zmq.PAIR)
    subscriber.connect('tcp://localhost:5555')
    #subscriber.setsockopt(zmq.SUBSCRIBE, b'')

    time.sleep(1)

    requestor = context.socket(zmq.PAIR)
    #requestor.connect('tcp://localhost:5556')
    requestor.bind ('tcp://*:5556')
    
    
    # Second, synchronize with publisher
    #syncclient = context.socket(zmq.REQ)
    #syncclient.connect('tcp://localhost:5562')

    # send a synchronization request
    #syncclient.send(b'')

    # wait for synchronization reply
    #syncclient.recv()

    # Third, get our updates and report how many we got
    nbr = 0
    while True:
        msg = subscriber.recv()
        if msg == b'END':
            break
        try:
            msgstr = msg.decode()
        except UnicodeDecodeError as e:
            # skip it
            print ("Encountered invalid encoding")
            continue

        print (msgstr)
        nbr += 1

        # pull out the pid
        comm =  msgstr[ msgstr.find('proc=') + 5 : ].split()[0]
        pid = int( msgstr[ msgstr.find('pid=') + 4 : ].split()[0])

        syscall_ct[pid] = syscall_ct.get(pid,0) + 1

        if comm == 'w' and syscall_ct[pid] > 50:
            print ("Attempting to kill pid {}".format(pid))
            requestor.send (struct.pack("=l", pid), 0)

        #if nbr % 10 == 0:
        #    print ("Sending value on request channel")
        #    requestor.send (struct.pack("=l", 33333), 0) #zmq.DONTWAIT)

    print ('Received %d updates' % nbr)
    

if __name__ == '__main__':
    main()
