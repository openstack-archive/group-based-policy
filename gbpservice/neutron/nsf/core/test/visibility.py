import os
import sys
import ast
import json
import time

from oslo_log import log as logging
from gbpservice.neutron.nsf.core.main import ServiceController
from gbpservice.neutron.nsf.core.main import Event
from gbpservice.neutron.nsf.core.main import RpcAgent
from gbpservice.neutron.nsf.core import periodic_task as core_periodic_task
from oslo_config import cfg
import oslo_messaging as messaging
from neutron.common import rpc as n_rpc

LOG = logging.getLogger(__name__)

VISIBILITY_RPC_TOPIC = "visiblity_topic"


def rpc_init(sc, conf):
    rpcmgr = RpcManager(conf, sc)
    agent = RpcAgent(
        sc,
        host=cfg.CONF.host,
        topic=VISIBILITY_RPC_TOPIC,
        manager=rpcmgr
    )
    sc.register_rpc_agents([agent])


def events_init(sc):
    evs = [
        Event(id='SERVICE_CREATE', handler=Agent(sc)),
        Event(id='SERVICE_DELETE', handler=Agent(sc)),
        Event(id='SERVICE_DUMMY_EVENT', handler=Agent(sc))]
    sc.register_events(evs)


def module_init(sc, conf):
    events_init(sc)
    rpc_init(sc, conf)


def unit_test(conf, sc):
    for i in range(0, 1):
        test_service_create(conf, sc)


def test_service_create(conf, sc):
    '''
    Write the unit test logic here
    '''
    service1 = {'id': 'sc2f2b13-e284-44b1-9d9a-2597e216271a',
                'tenant': '40af8c0695dd49b7a4980bd1b47e1a1b',
                'servicechain': 'sc2f2b13-e284-44b1-9d9a-2597e2161c',
                'servicefunction': 'sf2f2b13-e284-44b1-9d9a-2597e216561d',
                'vip_id': '13948da4-8dd9-44c6-adef-03a6d8063daa',
                'service_vendor': 'haproxy',
                'service_type': 'loadbalancer',
                'ip': '192.168.20.199'
                }
    # Collector(service).create()
    ev = sc.event(id='SERVICE_CREATE', data=service1,
                  binding_key=service1['id'],
                  key=service1['id'], serialize=True)
    sc.rpc_event(ev)
    service2 = {'id': 'sc2f2b13-e284-44b1-9d9a-2597e216272a',
                'tenant': '40af8c0695dd49b7a4980bd1b47e1a2b',
                'servicechain': 'sc2f2b13-e284-44b1-9d9a-2597e216562c',
                'servicefunction': 'sf2f2b13-e284-44b1-9d9a-2597e216562d',
                'mac_address': 'fa:16:3e:3f:93:05',
                'service_vendor': 'vyos',
                'service_type': 'firewall',
                'ip': '192.168.20.197'
                }
    ev = sc.event(id='SERVICE_CREATE', data=service2,
                  binding_key=service2['id'],
                  key=service2['id'], serialize=True)
    sc.rpc_event(ev)
    service3 = {'id': 'sc2f2b13-e284-44b1-9d9a-2597e216273a',
                'tenant': '40af8c0695dd49b7a4980bd1b47e1a2b',
                'servicechain': 'sc2f2b13-e284-44b1-9d9a-2597e216563c',
                'servicefunction': 'sf2f2b13-e284-44b1-9d9a-2597e216563d',
                'mac_address': 'fa:16:3e:3f:93:05',
                'service_vendor': 'vyos',
                'service_type': 'vpn',
                'ip': '192.168.20.197'
                }

    ev = sc.event(id='SERVICE_CREATE', data=service3,
                  binding_key=service3['id'],
                  key=service3['id'], serialize=True)
    sc.rpc_event(ev)

    time.sleep(5)
    ev = sc.event(id='SERVICE_DELETE', data=service1,
                  binding_key=service1['id'],
                  key=service1['id'], serialize=True)
    sc.rpc_event(ev)

    ev = sc.event(id='SERVICE_DUMMY_EVENT', key='dummy_event')
    sc.rpc_event(ev)


class Collector(object):

    def __init__(self, service):
        self._service = service

    def create(self):
        pass
        # RSyslogConfigure().configure_rsyslog_as_client(**self._service)
        # Filebeat(**self._service).configure()

    def delete(self):
        pass
        # Filebeat(**self._service).delete_configure()


class RpcManager(object):
    RPC_API_VERSION = '1.0'
    target = messaging.Target(version=RPC_API_VERSION)

    def __init__(self, conf, sc):
        super(RpcManager, self).__init__()
        self.conf = conf
        self._sc = sc

    def service_created(self, context, **kwargs):
        pass
        # service = kwargs.get('service')
        # service = ast.literal_eval(json.dumps(kwargs.get('arg')))
        # Collector(service).create()
        # ev = self._sc.event(id='SERVICE_CREATE', data=service)
        # self._sc.rpc_event(ev, service['id'])

    def service_deleted(self, context, **kwargs):
        pass
        # service = kwargs.get('service')
        # service = ast.literal_eval(json.dumps(kwargs.get('arg')))
        # Collector(service).delete()
        # ev = self._sc.event(id='SERVICE_DELETE', data=service, handler=None)
        # self._sc.rpc_event(ev, service['id'])


class Agent(core_periodic_task.PeriodicTasks):

    def __init__(self, sc):
        self._sc = sc

    def handle_poll_event(self, ev):
        self._handle_poll_event(ev)

    def handle_event(self, ev):
        LOG.debug("Process ID :%d" % (os.getpid()))
        if ev.id == 'SERVICE_CREATE':
            self._handle_create_event(ev)
        elif ev.id == 'SERVICE_DELETE':
            self._handle_delete_event(ev)
        elif ev.id == 'SERVICE_DUMMY_EVENT':
            self._handle_dummy_event(ev)

    def _handle_create_event(self, ev):
        '''
        Driver logic here.
        '''
        self._sc.event_done(ev)
        self._sc.poll_event(ev)

    def _handle_dummy_event(self, ev):
        self._sc.poll_event(ev, max_times=2)

    def _handle_delete_event(self, ev):
        '''
        Driver logic here.
        '''
        self._sc.event_done(ev)
        self._sc.poll_event_done(ev)

    @core_periodic_task.periodic_task(event='SERVICE_CREATE', spacing=1)
    def service_create_poll_event(self, ev):
        LOG.debug("Poll event (%s)" %(str(ev)))
        print "Decorator Poll event %s" %(ev.key)

    @core_periodic_task.periodic_task(event='SERVICE_DUMMY_EVENT', spacing=10)
    def service_dummy_poll_event(self, ev):
        LOG.debug("Poll event (%s)" %(str(ev)))
        print "Decorator Poll event %s" %(ev.key)

    def _handle_poll_event(self, ev):
        '''
        Driver logic here
        '''
        LOG.debug("Poll event (%s)" %(str(ev)))
        print "Poll event %s" %(ev.key)
        # stats_driver = OCStatsDriver()
        # stats_driver.get_and_store_stats(**ev.data)
