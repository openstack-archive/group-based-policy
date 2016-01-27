import socket
import threading
import os
import sys
import time
from gbservice.neutron.nsf.core.threadpool import ThreadPool
from gbpservice.neutron.nsf.proxy import cfg as proxy_cfg


class TcpClient:

    def __init__(self):
        # Create a TCP/IP socket
        self.loop = True
        # self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock = socket.socket()
        # Connect the socket to the port where the server is listening
        self.server_address = (
            proxy_cfg.rest_server_address, proxy_cfg.rest_server_port)

    def connect(self):
        print >>sys.stderr, 'connecting to %s port %s' % self.server_address
        self.sock.settimeout(1)
        try:
            self.sock.connect(self.server_address)
        except socket.error, exc:
            print "Caught exception socket.error : %s" % exc
            return False
        return True

    def send(self, msg):
        try:
            self.sock.sendall(msg)
        except socket.error, exc:
            # print "Caught exception socket.error : %s" % exc
            self.sock.close()

    def close(self):
        self.loop = False
        self.sock.close()

    def recv(self, arg, **kwargs):
        server = kwargs.get('server')
        client = kwargs.get('client')
        while self.loop:
            try:
                msg = self.sock.recv(16)
                if msg:
                    client.send(msg)

                else:
                    server.close(client, self)
                    return False
            except socket.error, exc:
                server.close(client, self)
                return False


class ThreadedServer(object):

    def __init__(self):
        server_address = proxy_cfg.unix_bind_path
        self.threadpool = ThreadPool(proxy_cfg.thread_pool_size)
        # Make sure the socket does not already exist
        try:
            os.unlink(server_address)
        except OSError:
            if os.path.exists(server_address):
                raise

        # Create a UDS socket
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

        # Bind the socket to the port
        print >>sys.stderr, 'starting up on %s' % server_address
        self.sock.bind(server_address)

    def recv(self, tcpclient,  client):
        return tcpclient.recv(None, server=self, client=client)

    def listen(self):
        self.sock.listen(5)
        while True:
            client, address = self.sock.accept()
            self.threadpool.dispatch(self.listenToClient, client, address)

    def listenToClient(self, client, address):
        size = 16
        tcpclient = TcpClient()
        tcpclient.connect()
        recv_thread = threading.Thread(
            target=self.recv, args=(tcpclient, client,))
        recv_thread.start()
        while tcpclient.loop:
            try:
                data = client.recv(size)
                if data:
                    tcpclient.send(data)
                    print data
                else:
                    tcpclient.close()
                    recv_thread.join()
                    client.close()
                    return False

            except:
                print "error"
                tcpclient.close()
                recv_thread.join()
                client.close()
                return False
        tcpclient.close()
        client.close()
        return False

    def close(self, client, tcpclient):
        print "closing"
        tcpclient.close()
        client.close()
        self.threadpool.stop()
        return False


def main():
    ThreadedServer().listen()
