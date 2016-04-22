#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import argparse
import ConfigParser
from gbpservice.nfp.core import common as nfp_common
import os
import Queue
from Queue import Empty
import socket
import sys
import threading
import time

from oslo_log import log as logging

from neutron.common import config as n_common_config

LOGGER = logging.getLogger(__name__)
LOG = nfp_common.log

# Queue of proxy connections which workers will handle
ConnQ = Queue.Queue(maxsize=0)

tcp_open_connection_count = 0
tcp_close_connection_count = 0


class ConnectionIdleTimeOut(Exception):

    '''
    Exception raised when connection is idle for configured timeout
    '''
    pass


"""
parsing the proxy configuration file
"""


class Configuration(object):

    def __init__(self, filee):
        config = ConfigParser.ConfigParser()
        config.read(filee)

        self.thread_pool_size = config.getint('OPTIONS', 'thread_pool_size')
        self.unix_bind_path = config.get('OPTIONS', 'unix_bind_path')
        self.rest_server_address = config.get('OPTIONS', 'rest_server_address')
        self.rest_server_port = config.getint('OPTIONS', 'rest_server_port')
        self.max_connections = config.getint('OPTIONS', 'max_connections')
        self.worker_threads = config.getint('OPTIONS', 'worker_threads')
        self.connect_max_wait_timeout = config.getfloat(
            'OPTIONS', 'connect_max_wait_timeout')
        self.idle_max_wait_timeout = config.getfloat(
            'OPTIONS', 'idle_max_wait_timeout')
        self.idle_min_wait_timeout = config.getfloat(
            'OPTIONS', 'idle_min_wait_timeout')

"""
Class to create Unix Listener
"""


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
        LOG(LOGGER, 'INFO', (sys.stderr,
                             'starting up on %s' % self.bind_path))
        self.socket.bind(self.bind_path)
        self.socket.listen(self.max_connections)

    def listen(self):
        client, address = self.socket.accept()
        self.proxy.new_client(client, address)


"""
Class to create TCP client Connection if
TCP server is alive
"""


class TcpClient(object):

    def __init__(self, conf, proxy):
        self.conf = conf
        self.proxy = proxy
        self.server_address = conf.rest_server_address
        self.server_port = conf.rest_server_port
        # Connect the socket to the port where the server is listening
        self.server = (self.server_address, self.server_port)

    def connect(self):
        sock = socket.socket()
        LOG(LOGGER, 'INFO', (sys.stderr,
                             'connecting to %s port %s' % self.server))
        sock.settimeout(self.conf.connect_max_wait_timeout)
        try:
            sock.connect(self.server)
        except socket.error as exc:
            LOG(LOGGER, 'ERROR', "Caught exception socket.error : %s" % exc)
            return sock, False
        return sock, True


"""
ADT for proxy connection
"""


class Connection(object):

    def __init__(self, conf, socket):
        self._socket = socket
        self._idle_wait = conf.idle_min_wait_timeout
        self._idle_timeout = conf.idle_max_wait_timeout
        self._idle_count_max = (self._idle_timeout / self._idle_wait)
        self._idle_count = 0

    def _tick(self):
        self._idle_count += 1

    def _timedout(self):
        if self._idle_count > self._idle_count_max:
            raise ConnectionIdleTimeOut

    def idle(self):
        self._tick()
        self._timedout()

    def idle_reset(self):
        self._idle_count = 0

    def recv(self):
        self._socket.settimeout(self._idle_wait)
        try:
            data = self._socket.recv(1024)
            if data and len(data):
                self.idle_reset()
                return data
            self.idle()
        except socket.timeout:
            self.idle()
        return None

    def send(self, data):
        self._socket.send(data)

    def close(self):
        self._socket.close()

    def identify(self):
        return self._socket.fileno()


"""
ADT for Proxy Connection Object
Each Connection Object is pair of Unix Socket and
TCP Client Socket
"""


class ProxyConnection(object):

    def __init__(self, conf, unix_socket, tcp_socket):
        self._unix_conn = Connection(conf, unix_socket)
        self._tcp_conn = Connection(conf, tcp_socket)

    def close(self):
        self._unix_conn.close()
        self._tcp_conn.close()

    def _proxy(self, rxconn, txconn):
        data = rxconn.recv()
        if data:
            txconn.send(data)

    def run(self):
        try:
            self._proxy(self._unix_conn, self._tcp_conn)
            self._proxy(self._tcp_conn, self._unix_conn)
            return True
        except Exception:
            self._unix_conn.close()
            self._tcp_conn.close()
            return False

    def identify(self):
        return '%d:%d' % (
            self._unix_conn.identify(),
            self._tcp_conn.identify())


"""
ADT for proxy Worker
"""


class Worker(object):

    def run(self):
        """
        Worker thread will pop the Proxy Connection Object
        from Connection Queue and Perform send and receive
        operations. If the connection is ideal upto ideal_max_timeout
        it will not push the Object into connection queue so Proxy Connection
        Object is automatically destroy, otherwise it will again
        push the Object in connection Queue
        """
        while True:
            try:
                pc = ConnQ.get()
                if pc.run():
                    ConnQ.put(pc)
            except Empty:
                pass
            time.sleep(0)


"""
ADT to  Run the configurator proxy,
        accept the Unix Client request,
        Check REST Server is reachable or not,
        Try to establish TCP Client Connection to REST

"""


class Proxy(object):

    def __init__(self, conf):
        self.conf = conf
        # Be a server and wait for connections from the client
        self.server = UnixServer(conf, self)
        self.client = TcpClient(conf, self)

    def start(self):
        """Run each worker in new thread"""

        for i in range(self.conf.worker_threads):
            t = threading.Thread(target=Worker().run)
            t.daemon = True
            t.start()
        while True:
            self.server.listen()

    def new_client(self, unixsocket, address):
        """Establish connection with the tcp server"""

        tcpsocket, connected = self.client.connect()
        if not connected:
            LOG(LOGGER, 'ERROR', "Proxy -> Could not connect with tcp server")
            unixsocket.close()
            tcpsocket.close()
        else:
            pc = ProxyConnection(self.conf, unixsocket, tcpsocket)
            ConnQ.put(pc)


def main(argv):
    n_common_config.setup_logging()
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-config-file', "--config-file", action="store", dest='config_file')
    args = parser.parse_args(sys.argv[1:])
    conf = Configuration(args.config_file)
    Proxy(conf).start()
