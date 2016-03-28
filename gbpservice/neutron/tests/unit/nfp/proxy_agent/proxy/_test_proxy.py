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

from gbpservice.nfp.proxy_agent.proxy import proxy
import multiprocessing
from multiprocessing import Process
import os
import signal
import socket
import sys
import threading
import time
import unittest

rxcount = 0
txcount = 0
connection_count = 0
threadLock = threading.Lock()
threads = []

# REVISIT (mak): enable these test cases.
# need to remove starting of servers in UTs

"""
class to start TCP server based on testcase needs
"""


class TcpServer(object):

    def __init__(self, server_address):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_address = server_address
        print('[TCP]starting up the TCP server on %s port %s' %
              (self.server_address))
        self.sock.bind(self.server_address)
        self.count = 0

    def test_one_start(self):
        """
        TCP server for ideal_max_timeout check
        """
        self.sock.listen(1)
        print('[TCP] Waiting for a connection')
        self.count = 0
        timer = 0
        connection, client_address = self.sock.accept()
        while True:
            try:
                self.count += 1
                data = connection.recv(16)
                print('[TCP] Received %s from %s"' % (
                    data, client_address))
                if data:
                    print('[TCP] sending back to the Unix client')
                    connection.sendall(data)
                else:
                    time.sleep(30)
                    timer += 1
                if timer:
                    connection.shutdown(socket.SHUT_RDWR)
                    connection.close()
                    sys.exit(0)
            except socket.error as err:
                connection.close()
                sys.exit(0)
                print(err)
        connection.close()

    def test_two_start(self):
        """
        TCP server for single connection with multiple messages
        Server is down after receiving 20 messages
        """
        self.sock.listen(1)
        print('[TCP] Waiting for a connection')
        self.count = 0
        connection, client_address = self.sock.accept()

        while self.count < 20:
            try:
                self.count += 1
                data = connection.recv(16)
                print('[TCP] Received %s from %s"' % (
                    data, client_address))
                if data:
                    print('[TCP] sending back to the Unix client')
                    connection.sendall(data)
            except socket.error as err:
                print(err)
                connection.close()
                sys.exit(0)
        connection.close()

    def test_three_start(self):
        """
        TCP server for multiple connections check
        """
        self.sock.listen(100)
        print('[TCP]waiting for a connection')

        while True:
            connection, client_address = self.sock.accept()
            self.count += 1
            try:

                data = connection.recv(16)
                print('[TCP]Received "%s on %s "' % (
                      data, client_address))
                if data:
                    print('[TCP]sending back to the Unix client')
                    connection.sendall(data)
            except socket.error as err:
                print(err)
                connection.close()
        connection.close()


"""
Class to create Unix client based on test case
"""


class UnixClient(object):

    def __init__(self, test_count=0):
        self.test_count = test_count

    def single_unix_client(self):
        """
        method to start the single client and send two
        messages with ideal_max_timeout difference.
        """
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server_address = '/tmp/uds_socket_%d' % (self.test_count)
        try:
            sock.connect(server_address)
            print('Connected to proxy')
        except socket.error as err:
            print(err)
            return 0
        try:
            count = 0
            while True:
                count += 1
                if count == 2:
                    # send the second message after some time so
                    # proxy can destroy the connection object
                    time.sleep(40)
                message = "Hi count " + str(count)
                print('[Unix]Sending Message %s' % message)
                sock.sendall(message)
                data = sock.recv(100)
                print('[Unix] Received message from TCP : %s') % data
        except socket.error as err:
            print(err)
            return 1
        finally:
            print("[Unix]closing %s socket" % sock)
            sock.close()

    def unix_client_msg_flooding(self):
        """
        method to start single unix client and
        send multiple messages
        """
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server_address = '/tmp/uds_socket_%d' % (self.test_count)
        try:
            sock.connect(server_address)
            print('[Unix]Connected to proxy')
        except socket.error as err:
            print(err)
            return 0
        try:
            count = 0
            while True:
                count += 1
                time.sleep(.1)
                message = "Hi count " + str(count)
                print('[Unix]Sending Message %s' % message)
                sock.sendall(message)
                data = sock.recv(100)
                print('[Unix] Received message from TCP : %s' % data)
        except socket.error as err:
            print(err)
            return 1
        finally:
            print('[Unix]closing %s socket' % sock)
            sock.close()

    def multiple_unix_connections(self):
        """
        method to start the multiple unix clients
        Each connection is started as separate thread
        """
        threadLock.acquire()
        global connection_count
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

        # Connect the socket to the port where the server is listening
        server_address = '/tmp/uds_socket_%d' % (self.test_count)
        try:
            sock.connect(server_address)
            print('[Unix]Connected to proxy')
            connection_count += 1
        except socket.error as err:
            print(err)
            print('[Unix] closing Connection')
            connection_count -= 1
            sock.close()
            threadLock.release()
            return

        while True:
            global txcount
            txcount += 1
            message = 'Hi'
            print('[Unix]Sending message: %s' % message)
            try:
                sock.sendall(message)
            except socket.error as err:
                print(err)
                print('[Unix] closing Connection')
                connection_count -= 1
                sock.close()
                threadLock.release()
                return

            try:
                data = sock.recv(50)
                global rxcount
                rxcount += 1
                print('[Unix] Received message %s' % data)
            except socket.error as err:
                print(err)
                print('[Unix] closing Connection')
                connection_count -= 1
                sock.close()
                threadLock.release()
                return
                threadLock.release()
                time.sleep(.2)

        print("[Thread %d] Closing " % self.t_id)
        connection_count -= 1
        threadLock.release()
        return

"""
Descriptor class for Thread
"""


class ThreadStart(threading.Thread):

    def __init__(self, t_id, test_count=0):
        self.t_id = t_id
        self.test_count = test_count
        threading.Thread.__init__(self)

    def run(self):
        """
        method to create new unix client as with thread
        """
        UnixClient(test_count=self.test_count).multiple_unix_connections()


class TestConfiguration(object):

    def __init__(self, test_count):
        self.thread_pool_size = 10
        self.unix_bind_path = '/tmp/uds_socket_%d' % (test_count)
        self.max_connections = 10
        self.rest_server_address = '11.0.0.3'
        self.rest_server_port = 8070
        self.worker_threads = 40
        self.connect_max_wait_timeout = 10
        self.idle_max_wait_timeout = 10
        self.idle_min_wait_timeout = 0.1

"""
Class to Initiate the Configurator Proxy
"""


class ProxyStart(object):

    def __init__(self, test_count=0):
        # Need to change with absolute path
        self.conf = TestConfiguration(test_count)

    def run(self, server):
        """
        method to run the proxy server with configurations
        paramter
        :param server: port address
        """
        self.conf.rest_server_address = server[0]
        self.conf.rest_server_port = server[1]
        proxy.Proxy(self.conf).start()


"""
Unit test class
"""


class TestConfProxy(unittest.TestCase):

    def test_ideal_max_timeout(self):
        """
        method to test the ideal_max_timeout is
        expired of connection
        """
        return_val = 0
        server_address = ('0.0.0.0', 5674)
        tcp_process = Process(target=TcpServer(server_address).test_one_start)
        tcp_process.demon = True
        tcp_process.start()
        time.sleep(2)

        proxy_obj = Process(target=ProxyStart(
            test_count=0).run, args=(server_address,))
        proxy_obj.start()
        time.sleep(5)

        return_val = UnixClient(test_count=0).single_unix_client()

        tcp_process.join()
        os.kill(proxy_obj.pid, signal.SIGKILL)

        self.assertEqual(return_val, 1)

    def test_connection_broken(self):
        """
        method to test single connection keep sending
        messages and tcp server is down after recivin
        some messages
        """

        return_val = 0
        server_address = ('0.0.0.0', 5675)
        tcp_process = Process(target=TcpServer(server_address).test_two_start)
        tcp_process.demon = True
        tcp_process.start()
        time.sleep(2)

        proxy_obj = Process(target=ProxyStart(
            test_count=1).run, args=(server_address,))
        proxy_obj.start()
        time.sleep(5)

        return_val = UnixClient(test_count=1).unix_client_msg_flooding()

        tcp_process.join()
        os.kill(proxy_obj.pid, signal.SIGKILL)

        self.assertEqual(return_val, 1)

    def test_multiple_connections(self):
        """
        method to test multiple proxy connections
        """
        try:
            server_address = ('0.0.0.0', 5676)
            tcp_process = Process(target=TcpServer(
                server_address).test_three_start)
            tcp_process.demon = True
            tcp_process.start()
            time.sleep(5)

            proxy_obj = Process(target=ProxyStart(test_count=2).run,
                                args=(server_address,))
            proxy_obj.start()
            time.sleep(5)
        except multiprocessing.ProcessError:
            pass

        for i in range(2):
            t = ThreadStart(i, test_count=2)
            threads.append(t)
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        time.sleep(5)
        os.kill(tcp_process.pid, signal.SIGKILL)
        os.kill(proxy_obj.pid, signal.SIGKILL)

        self.assertEqual(connection_count, 0)


if __name__ == '__main__':
    unittest.main()
