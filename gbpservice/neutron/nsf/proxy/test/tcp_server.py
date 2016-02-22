import socket
import sys
import time
import eventlet
eventlet.monkey_patch()
from eventlet import event
from eventlet import greenpool
from eventlet import greenthread
import os
import sys
import threading


class ThreadPool(object):

    def __init__(self, pool_size=10):
        self.pool = greenpool.GreenPool(pool_size)

    def dispatch(self, callback, *args, **kwargs):
        t = self.pool.spawn(callback, *args, **kwargs)
        # t.link(self.thread_done, thread=t)

    def thread_done(self, *args, **kwargs):
        print "Thread Done !"


class TcpClient:

    def __init__(self):
        # Create a TCP/IP socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Connect the socket to the port where the server is listening
        server_address = ('192.168.2.154', 5674)
        print >>sys.stderr, 'connecting to %s port %s' % server_address
        self.sock.connect(server_address)

    def send(self, msg):
        self.sock.sendall(msg)

    def recv(self, arg, **kwargs):
        server = kwargs.get('server')
        while True:
            msg = self.sock.recv(16)
            server.send(msg)


class TcpServer:

    def __init__(self, client):
        self.client = client
        # Create a TCP/IP socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connection = None

        # Bind the socket to the port
        server_address = ('0.0.0.0', 5674)
        print >>sys.stderr, 'starting up on %s port %s' % server_address
        self.sock.bind(server_address)

    def listen(self):
        # Listen for incoming connections
        self.sock.listen(100)

    def accept(self):
        self.connection, client_address = self.sock.accept()
        print "New connection (%s) from address (%s)" % (
            self.connection,
            client_address)
        return self.connection, client_address

    def run(self, client):
        loop = True
        while loop:
            try:
                # Receive the data in small chunks and retransmit it
                while True:
                    data = client.recv(16)
                    # print >>sys.stderr, 'received "%s"' % data
                    if data:
                        # print >>sys.stderr, 'sending data back to the client'
                        client.send(data)
                        # connection.sendall(data)
                    else:
                        # print >>sys.stderr, 'no more data from',
                        # client_address
                        loop = False
                        break
            except Exception as e:
                # print "Exception",e
                client.close()
                loop = False
                break
            finally:
                loop = False
                # Clean up the connection
                client.close()

    def send(self, msg):
        if self.connection:
            self.connection.sendall(msg)

if __name__ == "__main__":
    tp = ThreadPool()

    # client = TcpClient()
    # server = TcpServer(client)
    server = TcpServer(None)
    server.listen()
    # tp.dispatch(client.recv, None, server=server)
    while True:
        client, client_address = server.accept()
        tp.dispatch(server.run, client)

    while True:
        print "Hi, its not me"
