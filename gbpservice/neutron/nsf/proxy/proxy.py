import select
import socket
import threading
import os
import sys
import time
import argparse
import ConfigParser
from gbpservice.neutron.nsf_ahmed.core.threadpool import ThreadPool

CHANNEL_IDLE_TIME=30 #In seconds
IDLE_TIME_OUT=None

class Configuration(object):
    def __init__(self, filee):
        config = ConfigParser.ConfigParser()
        config.read(filee)

        self.thread_pool_size = config.getint('OPTIONS', 'thread_pool_size')
        self.unix_bind_path = config.get('OPTIONS', 'unix_bind_path')
        self.rest_server_address = config.get('OPTIONS', 'rest_server_address')
        self.rest_server_port = config.getint('OPTIONS', 'rest_server_port')
        self.max_connections = config.getint('OPTIONS', 'max_connections')

class UnixServer(object):
    def __init__(self, conf, proxy):
        self.proxy = proxy
        self.bind_path = conf.unix_bind_path
        self.max_connections = conf.max_connections
        # Make sure the socket does not already exist
        try:
            os.unlink(self.bind_path)
        except OSError:
            if os.path.exists(self.bind_path):
                raise

        # Create a UDS socket
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

        # Bind the socket to the port
        print >>sys.stderr, 'starting up on %s' % self.bind_path
        self.socket.bind(self.bind_path)
        self.socket.listen(self.max_connections)

    def listen(self):
        client, address = self.socket.accept()
        self.proxy.new_client(client, address)

class TcpClient(object):
    def __init__(self, conf, proxy):
        self.proxy = proxy
        self.server_address = conf.rest_server_address
        self.server_port = conf.rest_server_port
        # Connect the socket to the port where the server is listening
        self.server = (self.server_address, self.server_port)

    def connect(self):
        sock = socket.socket()
        print >>sys.stderr, 'connecting to %s port %s' % self.server
        sock.settimeout(CHANNEL_IDLE_TIME)
        try:
            sock.connect(self.server)
        except socket.error, exc:
            print "Caught exception socket.error : %s" % exc
            return sock,False
        return sock,True

class ProxyConnection(object):
    def __init__(self, proxy, unixclient, tcpclient):
        self.proxy = proxy
        self.unixclient = unixclient
        self.tcpclient  = tcpclient
        self.loop = True

    def _close(self, unixsocket, tcpsocket):
        if unixsocket:
            unixsocket.close()
        if tcpsocket:
            tcpsocket.close()
    
    def proxy_unix(self, unixsocket, tcpsocket, **kwargs):
        unixsocket.settimeout(MIN_IDLE_TIME)
        while True:
            try:
                data = unixsocket.recv(16)
                if data:
                    tcpsocket.send(data)
                else:
                    self._close(unixsocket, None)
            except socket.error:
                self._close(unixsocket, None)
                break

    def proxy_tcp(self, unixsocket, tcpsocket, **kwargs):
        tcpsocket.settimeout(MIN_IDLE_TIME)
        while True:
            try:
                data = tcpsocket.recv(16)
                if data:
                    unixsocket.send(data)
                else:
                    self._close(unixsocket, None)
            except socket.error:
                self._close(None, tcpsocket)
                break

   def run(self, arg, **kwargs):
        unixsocket = self.unixclient
        tcpsocket,connected  = self.tcpclient.connect()

        if not connected:
            unixsocket.close()
            tcpsocket.close()
        else:
            self.proxy.proxy(self, unixsocket, tcpsocket)

class Proxy(object):
    def __init__(self, conf):
        self.conf = conf
        self.tpool = ThreadPool(conf.thread_pool_size)
        #Be a server and wait for connections from the client
        self.server = UnixServer(conf, self)
        self.client = TcpClient(conf, self)

    def start(self):
        while True:
            print "Listening for unix client connections"
            self.server.listen()

    def new_client(self, socket, address):
        ProxyConnection(self, socket, self.client).run(socket)

    def proxy(self, pc, unixsocket, tcpsocket):
        self.tpool.dispatch(pc.proxy_tcp, unixsocket, tcpsocket)
        self.tpool.dispatch(pc.proxy_unix, unixsocket, tcpsocket)

def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument('-config-file', "--config-file", action="store", dest='config_file')
    args = parser.parse_args(sys.argv[1:])
    conf = Configuration(args.config_file)
    Proxy(conf).start()

if __name__ == "__main__":
    main(sys.argv[1:])
