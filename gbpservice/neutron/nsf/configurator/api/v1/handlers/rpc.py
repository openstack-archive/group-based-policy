import eventlet
import time
import threading
import sys
import os
from multiprocessing import Process, Queue, Lock

from oslo_config import cfg
import oslo_messaging

from neutron.agent.common import config
from neutron.common import config as common_config
from neutron.common import rpc as n_rpc



class FwaasRpc(object):
    """RPC client for Firewall"""

    API_VERSION = '1.0'

    def __init__(self, topic):
        
        self.topic = topic
        target = oslo_messaging.Target(
                topic=self.topic,
                version=self.API_VERSION)
        n_rpc.init(cfg.CONF)
        self.client = n_rpc.get_client(target)

    def create_firewall(self, context, firewall, host):
        cctxt = self.client.prepare(server=host)
        return cctxt.cast(
            self,
            'create_firewall',
            firewall=firewall,
            host=host)
        

    def update_firewall(self, context, firewall, host):
        cctxt = self.client.prepare(server=host)
        return cctxt.cast(
            self,
            'update_firewall',
            firewall=firewall,
            host=host)
        

    def delete_firewall(self, context, firewall, host):
        cctxt = self.client.prepare(server=host)
        return cctxt.cast(
            self,
            'delete_firewall',
            firewall=firewall,
            host=host)
    
    def to_dict(self):
        return {}      

