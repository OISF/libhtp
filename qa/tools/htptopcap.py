import sys
import binascii
from threading import Thread
import time
import socket

# Create a pcap from a htp test file
# Launches a server on port 8080
# Launches a client in another thread that connects to it
# Both client and server read the htp test file
# And they send and receive data as described (without analysing it)
# So, you need to capture traffic on port 8080 while running the script

def removeOneEOL(s):
    r = s
    if r[-1] == '\n':
        r = r[:-1]
        if r[-1] == '\r':
            r = r[:-1]
    return r


class ServerThread(Thread):

    def __init__(self, filename):
        Thread.__init__(self)
        self.filename = filename

    def run(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 8080))
        s.listen(1)
        conn, addr = s.accept()
        f = open(self.filename)
        state = 0
        sending = ""
        receiving = ""

        for l in f.readlines():
            # change of state
            if l.rstrip() == "<<<" or l.rstrip() == ">>>":
                # Receiving or sending buffer
                if state == 1:
                    conn.send(removeOneEOL(sending))
                    print "server sent", len(removeOneEOL(sending))
                elif state == 2:
                    data = conn.recv(len(removeOneEOL(receiving)))
                    print "server recvd", len(data)
                if l.rstrip() == "<<<":
                    state = 1
                    sending = ""
                elif l.rstrip() == ">>>":
                    state = 2
                    receiving = ""
            else:
                if state == 1:
                    sending += l
                elif state == 2:
                    receiving += l

        # Receiving or sending last buffer
        if state == 1:
            conn.send(sending)
            print "server sent", len(sending)
        elif state == 2:
            data = conn.recv(len(receiving))
            print "server recvd", len(data)
        conn.close()
        s.close()
        f.close()


class ClientThread(Thread):

    def __init__(self, filename):
        Thread.__init__(self)
        self.filename = filename

    def run(self):
        time.sleep(1)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("127.0.0.1", 8080))
        f = open(self.filename)
        state = 0
        sending = ""
        receiving = ""

        for l in f.readlines():
            if l.rstrip() == "<<<" or l.rstrip() == ">>>":
                if state == 1:
                    s.send(removeOneEOL(sending))
                    print "client sent", len(removeOneEOL(sending))
                elif state == 2:
                    data = s.recv(len(removeOneEOL(receiving)))
                    print "client recvd", len(data)
                if l.rstrip() == "<<<":
                    state = 2
                    receiving = ""
                elif l.rstrip() == ">>>":
                    state = 1
                    sending = ""
            else:
                if state == 1:
                    sending += l
                elif state == 2:
                    receiving += l

        if state == 1:
            s.send(sending)
            print "client sent", len(sending)
        elif state == 2:
            data = s.recv(len(receiving))
            print "client recvd", len(data)
        s.close()
        f.close()

t1 = ServerThread(sys.argv[1])
t2 = ClientThread(sys.argv[1])

# Launch threads
t1.start()
t2.start()

# Wait for threads to finish
t1.join()
t2.join()
