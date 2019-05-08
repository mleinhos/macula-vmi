#
#  Synchronized subscriber
#
import time
import zmq
import struct

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
        print(msg)
        nbr += 1

        if nbr % 10 == 0:
            print ("Sending value on request channel")
            requestor.send (struct.pack("=l", 33333), 0) #zmq.DONTWAIT)

    print ('Received %d updates' % nbr)
    

if __name__ == '__main__':
    main()
