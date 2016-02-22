import socket
import os
import sys
"""
Abstracte class wrapovers rpc methods with underlying unix implementation
"""
UNIX_PATH = './uds_socket'


class RpcCallback(object):

    def __init__(self):
        super(RpcCallback, self).__init__()


class Service(object):

    def __init__(self, host, topic, manager=None, serializer=None):
        super(Service, self).__init__()
        self.host = host
        self.topic = topic
        self.mgr = manager
        # Create a thread group
        self.tp = ThreadPool()

    def start(self):
        pass


class UnixClient(object):

    def __init__(self):
        # Create a UDS socket
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
