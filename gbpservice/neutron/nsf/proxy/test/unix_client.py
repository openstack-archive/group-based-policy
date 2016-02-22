import socket
import sys
import time

count = 0
rxcount = 0
txcount = 0


class Client(object):

    def run(self, arg, **kwargs):
        # Create a UDS socket
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

        # Connect the socket to the port where the server is listening
        server_address = '/tmp/uds_socket'
        # print >>sys.stderr, 'connecting to %s' % server_address
        try:
            sock.connect(server_address)
            print 'Connected socket (%s) to (%s)' % (sock, server_address)
        except socket.error, msg:
            print >>sys.stderr, msg
            sys.exit(1)
        try:
            # Send data
            global txcount
            txcount += 1
            # message = 'This is the message.  It will be repeated. (%d)'
            # %(count)
            message = 'Hi'
            # print >>sys.stderr, 'sending "%s"' % message
            print 'Sending message (%s) to (%s) count (%d)' % (
                message, sock, txcount)
            sock.sendall(message)

            amount_received = 0
            amount_expected = len(message)

            recvd = ""
            while amount_received < amount_expected:
                data = sock.recv(16)
                amount_received += len(data)
                recvd += data
                # print >>sys.stderr, 'received "%s"' % data
            global rxcount
            rxcount += 1
            print 'Recieved message (%s) from (%s) count (%d)' % (
                message, sock, rxcount)

        finally:
            # time.sleep(10)
            # print >>sys.stderr, 'closing socket'
            print 'Closing socket (%s)' % (sock)
            sock.close()

import time
import eventlet
eventlet.monkey_patch()
from eventlet import event
from eventlet import greenpool
from eventlet import greenthread
import os
import sys
import threading


def _thread_done(gt, *args, **kwargs):
    kwargs['pool'].thread_done(kwargs['thread'])


class Thread(object):

    def __init__(self, thread, pool):
        self.thread = thread
        self.thread.link(_thread_done, pool=pool, thread=self)

    def stop(self):
        self.thread.kill()

    def wait(self):
        return self.thread.wait()

    def link(self, func, *args, **kwargs):
        self.thread.link(func, *args, **kwargs)


class ThreadPool(object):

    def __init__(self, thread_pool_size=10):
        self.pool = greenpool.GreenPool(thread_pool_size)
        self.threads = []

    def dispatch(self, callback, *args, **kwargs):
        gt = self.pool.spawn(callback, *args, **kwargs)
        th = Thread(gt, self)
        self.threads.append(th)
        return th

    def thread_done(self, thread):
        self.threads.remove(thread)

    def stop(self):
        current = greenthread.getcurrent()
        # Iterate over a copy of self.threads so thread_done doesn't
        # modify the list while we're iterating
        for x in self.threads[:]:
            if x is current:
                # don't kill the current thread.
                continue
            try:
                x.stop()
            except Exception as ex:
                print ex

    def wait(self):
        current = greenthread.getcurrent()

        # Iterate over a copy of self.threads so thread_done doesn't
        # modify the list while we're iterating
        for x in self.threads[:]:
            if x is current:
                continue
            try:
                x.wait()
            except eventlet.greenlet.GreenletExit:
                pass
            except Exception as ex:
                print ex


tpool = ThreadPool(10)
# while True:
for i in range(200):
    tpool.dispatch(Client().run, None)
    time.sleep(0.1)
