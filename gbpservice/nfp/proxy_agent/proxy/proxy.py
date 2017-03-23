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

import eventlet
eventlet.monkey_patch()

from gbpservice._i18n import _
from gbpservice.nfp.core import log as nfp_logging
import os
from oslo_config import cfg as oslo_config
from oslo_log import log as oslo_logging
import socket
import sys
import time


oslo_logging.register_options(oslo_config.CONF)

if not hasattr(oslo_config.CONF, 'module'):
    module_opts = [
        oslo_config.StrOpt('module',
                           default='proxy',
                           help='component name for logging.')]
    oslo_config.CONF.register_opts(module_opts)

LOG = nfp_logging.getLogger(__name__)

# Queue of proxy connections which workers will handle
ConnQ = eventlet.queue.Queue(maxsize=0)

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

    def __init__(self, conf):
        self.unix_bind_path = conf.proxy.unix_bind_path
        self.max_connections = conf.proxy.max_connections
        self.worker_threads = conf.proxy.worker_threads
        self.connect_max_wait_timeout = conf.proxy.connect_max_wait_timeout
        self.idle_max_wait_timeout = conf.proxy.idle_max_wait_timeout
        self.idle_min_wait_timeout = conf.proxy.idle_min_wait_timeout
        self.rest_server_address = conf.proxy.nfp_controller_ip
        self.rest_server_port = conf.proxy.nfp_controller_port


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
        message = 'starting up on %s' % self.bind_path
        LOG.info(message)
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
        message = 'connecting to %s port %s' % self.server
        LOG.info(message)
        sock.settimeout(self.conf.connect_max_wait_timeout)
        try:
            sock.connect(self.server)
        except socket.error as exc:
            message = "Caught exception socket.error : %s" % exc
            LOG.error(message)
            return sock, False
        return sock, True


"""
ADT for proxy connection
"""


class Connection(object):

    def __init__(self, conf, socket, type='unix'):
        self._socket = socket
        self._idle_wait = conf.idle_min_wait_timeout
        self._idle_timeout = conf.idle_max_wait_timeout
        self._idle_count_max = (self._idle_timeout / self._idle_wait)
        self._idle_count = 0
        self._start_time = time.time()
        self._end_time = time.time()
        self.type = type
        self.socket_id = self._socket.fileno()

    def _tick(self):
        self._idle_count += 1

    def _timedout(self):
        if self._idle_count > self._idle_count_max:
            self._end_time = time.time()
            raise ConnectionIdleTimeOut(
                _("Connection (%(conn)d) - "
                "stime (%(start_time)s) - etime (%(end_time)s) - "
                "idle_count (%(idle)d) idle_count_max(%(idle_max)d)") %
                {'conn': self.identify(),
                 'start_time': self._start_time,
                 'end_time': self._end_time,
                 'idle': self._idle_count,
                 'idle_max': self._idle_count_max})

    def idle(self):
        self._tick()
        self._timedout()

    def idle_reset(self):
        self._idle_count = 0
        self._start_time = time.time()

    def _wait(self, timeout):
        if self.type == 'unix':
            eventlet.sleep(timeout)
            self._socket.setblocking(0)
        else:
            self._socket.settimeout(timeout)

    def recv(self):
        self._wait(self._idle_wait)
        try:
            data = self._socket.recv(1024)
            if data and len(data):
                self.idle_reset()
                return data
            self.idle()
        except socket.timeout:
            self.idle()
        except socket.error:
            self.idle()
        return None

    def send(self, data):
        self._socket.setblocking(1)
        self._socket.sendall(data)
        self._socket.setblocking(0)

    def close(self):
        message = "Closing Socket - %d" % (self.identify())
        LOG.debug(message)
        try:
            self._socket.shutdown(socket.SHUT_RDWR)
            self._socket.close()
        except Exception as exc:
            message = "%s - exception while closing - %s" % (
                self.identify(), str(exc))
            LOG.error(message)

    def identify(self):
        return self.socket_id


"""
ADT for Proxy Connection Object
Each Connection Object is pair of Unix Socket and
TCP Client Socket
"""


class ProxyConnection(object):

    def __init__(self, conf, unix_socket, tcp_socket):
        self._unix_conn = Connection(conf, unix_socket, type='unix')
        self._tcp_conn = Connection(conf, tcp_socket, type='tcp')
        message = "New Proxy - Unix - %d, TCP - %d" % (
            self._unix_conn.identify(), self._tcp_conn.identify())
        LOG.debug(message)

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
        except Exception as exc:
            message = "%s" % (exc)
            LOG.debug(message)
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
                call = True
                while call:
                    call = pc.run()
            except eventlet.queue.Empty:
                pass
            eventlet.sleep(0)


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
            eventlet.spawn_n(Worker().run)
        while True:
            self.server.listen()

    def new_client(self, unixsocket, address):
        """Establish connection with the tcp server"""

        tcpsocket, connected = self.client.connect()
        if not connected:
            message = "Proxy -> Could not connect with tcp server"
            LOG.error(message)
            unixsocket.close()
            tcpsocket.close()
        else:
            pc = ProxyConnection(self.conf, unixsocket, tcpsocket)
            ConnQ.put(pc)

PROXY_OPTS = [
    oslo_config.IntOpt(
        'max_connections',
        default=10,
        help='Max num of client connections'
    ),
    oslo_config.IntOpt(
        'worker_threads',
        default=10,
        help='Number of threads to be used.'
    ),
    oslo_config.FloatOpt(
        'connect_max_wait_timeout',
        default=10,
        help='Max time to wait for connect.'
    ),
    oslo_config.FloatOpt(
        'idle_max_wait_timeout',
        default=10,
        help='Max time to keep idle channel open.'
    ),
    oslo_config.FloatOpt(
        'idle_min_wait_timeout',
        default=10,
        help='Minimum time to wait on idle channel.'
    ),
    oslo_config.StrOpt(
        'unix_bind_path',
        default='/var/run/uds_socket',
        help='Path for unix server to bind.'
    ),
    oslo_config.StrOpt(
        'nfp_controller_ip',
        default='172.16.0.3',
        help='NFP controllers ip address'
    ),
    oslo_config.IntOpt(
        'nfp_controller_port',
        default='8070',
        help='NFP controllers port num'
    )
]


def main(argv):
    oslo_config.CONF.register_opts(PROXY_OPTS, 'proxy')
    oslo_config.CONF(args=sys.argv[1:])
    oslo_logging.setup(oslo_config.CONF, 'nfp')
    conf = Configuration(oslo_config.CONF)
    Proxy(conf).start()
