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

from neutron import context

from gbpservice.contrib.nfp.configurator.agents import agent_base
from gbpservice.contrib.nfp.configurator.lib import data_filter
from gbpservice.contrib.nfp.configurator.lib import lb_constants
from gbpservice.contrib.nfp.configurator.lib import utils
from gbpservice.nfp.core import event as nfp_event
from gbpservice.nfp.core import log as nfp_logging
from gbpservice.nfp.core import module as nfp_api

LOG = nfp_logging.getLogger(__name__)


class LBaasRpcSender(data_filter.Filter):
    """Implements LBaaS response path to Neutron plugin.

    Methods of this class are invoked by LBaasEventHandler class
    and also by driver class for sending response from driver to
    the LBaaS Neutron plugin.

    """
    def __init__(self, sc):
        self.notify = agent_base.AgentBaseNotification(sc)

    def get_logical_device(self, pool_id, context):
        """ Calls data filter library to get logical device from pool_id.

        :param pool_id: Neutron LBaaS pool id
        :param context: RPC context

        Returns: logical_device

        """
        return self.call(
            context,
            self.make_msg(
                'get_logical_device',
                pool_id=pool_id
            )
        )

    def update_status(self, obj_type, obj_id, status, agent_info, obj=None):
        """ Enqueues the response from LBaaS operation to neutron plugin.

        :param obj_type: Neutron LBaaS object type
        :param obj_id: Neutron LBaaS object id
        :param status: Neutron LBaaS object status to be set
        :param agent_info: Agent info which carries context which is needed
                           in config_orch to send response back to *aaS plugin
        :param obj: Neutron LBaaS object

        Returns: None

        """

        msg = {'info': {'service_type': lb_constants.SERVICE_TYPE,
                        'context': agent_info['context']},
               'notification': [{'resource': agent_info['resource'],
                                 'data': {'obj_type': obj_type,
                                          'obj_id': obj_id,
                                          'notification_type': 'update_status',
                                          'status': status,
                                          obj_type: obj}}]
               }
        self.notify._notification(msg)

    def update_pool_stats(self, pool_id, stats, context, pool=None):
        """ Enqueues the response from LBaaS operation to neutron plugin.

        :param pool_id: Neutron LBaaS pool id
        :param stats: statistics of that pool
        :param context: RPC context

        Returns: None
        """
        msg = {'info': {'service_type': lb_constants.SERVICE_TYPE,
                        'context': context.to_dict()},
               'notification': [{'resource': 'pool',
                                 'data': {'pool_id': pool_id,
                                          'stats': stats,
                                          'notification_type': (
                                                        'update_pool_stats'),
                                          'pool': pool_id}}]
               }
        self.notify._notification(msg)

    def vip_deleted(self, vip, status, agent_info):
        """ Enqueues the response from LBaaS operation to neutron plugin.

        :param vip: Neutron LBaaS vip resource
        :param status: Neutron LBaaS vip resource status
        :param agent_info: Agent info which carries context which is needed
                           in config_orch to send response back to *aaS plugin

        Returns: None
        """
        msg = {'info': {'service_type': lb_constants.SERVICE_TYPE,
                        'context': agent_info['context']},
               'notification': [{'resource': agent_info['resource'],
                                 'data': {'vip_id': vip['id'],
                                          'vip': vip,
                                          'notification_type': 'vip_deleted',
                                          'status': status}}]
               }
        self.notify._notification(msg)


class LBaaSRpcManager(agent_base.AgentBaseRPCManager):
    """Implements APIs invoked by configurator for processing RPC messages.

    RPC client of configurator module receives RPC messages from REST server
    and invokes the API of this class. The instance of this class is registered
    with configurator module using register_service_agent API. Configurator
    module identifies the service agent object based on service type and
    invokes one of the methods of this class to configure the device.

    """

    def __init__(self, sc, conf):
        """Instantiates child and parent class objects.

        :param sc: Service Controller object that is used for interfacing
        with core service controller.
        :param conf: Configuration object that is used for configuration
        parameter access.

        """

        super(LBaaSRpcManager, self).__init__(sc, conf)

    def _send_event(self, event_id, data, serialize=False, binding_key=None,
                    key=None):
        """Posts an event to framework.

        :param event_id: Unique identifier for the event
        :param data: event data
        :param serialize: boolean value used to serialize the event
        :param binding_key: binding key to be used for serialization
        :param key: event key

        Returns: None

        """

        ev = self.sc.new_event(id=event_id, data=data)
        ev.key = key
        ev.serialize = serialize
        ev.binding_key = binding_key
        self.sc.post_event(ev)

    def create_vip(self, context, vip):
        """Enqueues event for worker to process create vip request.

        :param context: RPC context
        :param vip: vip resource to be created

        Returns: None

        """
        arg_dict = {'context': context,
                    'vip': vip,
                    }
        self._send_event(lb_constants.EVENT_CREATE_VIP, arg_dict,
                         serialize=True, binding_key=vip['pool_id'],
                         key=vip['id'])

    def update_vip(self, context, old_vip, vip):
        """Enqueues event for worker to process update vip request.

        :param context: RPC context
        :param old_vip: old vip resource to be updated
        :param vip: new vip resource

        Returns: None

        """
        arg_dict = {'context': context,
                    'old_vip': old_vip,
                    'vip': vip,
                    }
        self._send_event(lb_constants.EVENT_UPDATE_VIP, arg_dict,
                         serialize=True, binding_key=vip['pool_id'],
                         key=vip['id'])

    def delete_vip(self, context, vip):
        """Enqueues event for worker to process delete vip request.

        :param context: RPC context
        :param vip: vip resource to be deleted

        Returns: None

        """
        arg_dict = {'context': context,
                    'vip': vip,
                    }
        self._send_event(lb_constants.EVENT_DELETE_VIP, arg_dict,
                         serialize=True, binding_key=vip['pool_id'],
                         key=vip['id'])

    def create_pool(self, context, pool, driver_name):
        """Enqueues event for worker to process create pool request.

        :param context: RPC context
        :param pool: pool resource to be created
        :param driver_name: service vendor driver name

        Returns: None

        """
        arg_dict = {'context': context,
                    'pool': pool,
                    'driver_name': driver_name,
                    }
        self._send_event(lb_constants.EVENT_CREATE_POOL, arg_dict,
                         serialize=True, binding_key=pool['id'],
                         key=pool['id'])

    def update_pool(self, context, old_pool, pool):
        """Enqueues event for worker to process update pool request.

        :param context: RPC context
        :param old_pool: old pool resource to be updated
        :param pool: new pool resource

        Returns: None

        """
        arg_dict = {'context': context,
                    'old_pool': old_pool,
                    'pool': pool,
                    }
        self._send_event(lb_constants.EVENT_UPDATE_POOL, arg_dict,
                         serialize=True, binding_key=pool['id'],
                         key=pool['id'])

    def delete_pool(self, context, pool):
        """Enqueues event for worker to process delete pool request.

        :param context: RPC context
        :param pool: pool resource to be deleted

        Returns: None

        """
        arg_dict = {'context': context,
                    'pool': pool,
                    }
        self._send_event(lb_constants.EVENT_DELETE_POOL, arg_dict,
                         serialize=True, binding_key=pool['id'],
                         key=pool['id'])

    def create_member(self, context, member):
        """Enqueues event for worker to process create member request.

        :param context: RPC context
        :param member: member resource to be created

        Returns: None

        """
        arg_dict = {'context': context,
                    'member': member,
                    }
        self._send_event(lb_constants.EVENT_CREATE_MEMBER, arg_dict,
                         serialize=True, binding_key=member['pool_id'],
                         key=member['id'])

    def update_member(self, context, old_member, member):
        """Enqueues event for worker to process update member request.

        :param context: RPC context
        :param old_member: old member resource to be updated
        :param member: new member resource

        Returns: None

        """
        arg_dict = {'context': context,
                    'old_member': old_member,
                    'member': member,
                    }
        self._send_event(lb_constants.EVENT_UPDATE_MEMBER, arg_dict,
                         serialize=True, binding_key=member['pool_id'],
                         key=member['id'])

    def delete_member(self, context, member):
        """Enqueues event for worker to process delete member request.

        :param context: RPC context
        :param member: member resource to be deleted

        Returns: None

        """
        arg_dict = {'context': context,
                    'member': member,
                    }
        self._send_event(lb_constants.EVENT_DELETE_MEMBER, arg_dict,
                         serialize=True, binding_key=member['pool_id'],
                         key=member['id'])

    def create_pool_health_monitor(self, context, health_monitor, pool_id):
        """Enqueues event for worker to process create health monitor request.

        :param context: RPC context
        :param health_monitor: health_monitor resource to be created
        :param pool_id: pool_id to which health monitor is associated

        Returns: None

        """
        arg_dict = {'context': context,
                    'health_monitor': health_monitor,
                    'pool_id': pool_id,
                    }
        self._send_event(lb_constants.EVENT_CREATE_POOL_HEALTH_MONITOR,
                         arg_dict, serialize=True, binding_key=pool_id,
                         key=health_monitor['id'])

    def update_pool_health_monitor(self, context, old_health_monitor,
                                   health_monitor, pool_id):
        """Enqueues event for worker to process update health monitor request.

        :param context: RPC context
        :param old_health_monitor: health_monitor resource to be updated
        :param health_monitor: new health_monitor resource
        :param pool_id: pool_id to which health monitor is associated

        Returns: None

        """
        arg_dict = {'context': context,
                    'old_health_monitor': old_health_monitor,
                    'health_monitor': health_monitor,
                    'pool_id': pool_id,
                    }
        self._send_event(lb_constants.EVENT_UPDATE_POOL_HEALTH_MONITOR,
                         arg_dict, serialize=True, binding_key=pool_id,
                         key=health_monitor['id'])

    def delete_pool_health_monitor(self, context, health_monitor, pool_id):
        """Enqueues event for worker to process delete health monitor request.

        :param context: RPC context
        :param health_monitor: health_monitor resource to be deleted
        :param pool_id: pool_id to which health monitor is associated

        Returns: None

        """
        arg_dict = {'context': context,
                    'health_monitor': health_monitor,
                    'pool_id': pool_id,
                    }
        self._send_event(lb_constants.EVENT_DELETE_POOL_HEALTH_MONITOR,
                         arg_dict, serialize=True, binding_key=pool_id,
                         key=health_monitor['id'])

    def agent_updated(self, context, payload):
        """Enqueues event for worker to process agent updated request.

        :param context: RPC context
        :param payload: payload

        Returns: None

        """
        arg_dict = {'context': context,
                    'payload': payload}
        self._send_event(lb_constants.EVENT_AGENT_UPDATED, arg_dict)


class LBaaSEventHandler(agent_base.AgentBaseEventHandler,
                        nfp_api.NfpEventHandler):
    """Implements event handlers and their helper methods.

    Object of this class is registered with the event class of core service
    controller. Based on the event key, handle_event method of this class is
    invoked by core service controller.

    """
    instance_mapping = {}

    def __init__(self, sc, drivers, rpcmgr):
        self.sc = sc
        self.drivers = drivers
        self.rpcmgr = rpcmgr
        self.plugin_rpc = LBaasRpcSender(sc)

        """REVISIT (pritam):
        Remove neutron context dependency. As of now
        because config agent needs context in notification, and internal
        poll event like collect_stats() does not have context, creating
        context here, but should get rid of this in future.
        """
        self.context = context.get_admin_context_without_session()

    def _get_driver(self, service_vendor):
        """Retrieves service driver instance based on service type
        and service vendor.

        :param service_vendor: service vendor

        Returns: Service driver instance

        """
        driver = lb_constants.SERVICE_TYPE + service_vendor
        return self.drivers[driver]

    def handle_event(self, ev):
        """Processes generated events in worker context.

        Processes following events.
        - create pool
        - update pool
        - delete pool
        - create vip
        - update vip
        - delete vip
        - create member
        - update member
        - delete member
        - create pool health monitor
        - update pool health monitor
        - delete pool health monitor
        - agent updated
        Enqueues responses into notification queue.

        Returns: None

        """
        msg = ("Starting handling event %s" % (ev.id))
        LOG.info(msg)
        try:
            method = getattr(self, "_%s" % (ev.id.lower()))
            method(ev)
        except Exception as err:
            msg = ("Failed to handle event %s. Reason is %s"
                   % (ev.id, str(err).capitalize()))
            LOG.error(msg)
        finally:
            if ev.id == lb_constants.EVENT_COLLECT_STATS:
                """Do not say event done for this event as it is
                   to be executed forever
                """
                pass
            else:
                msg = ("Successfully handled event %s" % (ev.id))
                LOG.info(msg)
                self.sc.event_complete(ev)

    def _handle_event_vip(self, ev, operation):
        data = ev.data
        context = data['context']
        vip = data['vip']
        agent_info = ev.data['context'].pop('agent_info')
        service_vendor = agent_info['service_vendor']
        driver = self._get_driver(service_vendor)

        try:
            if operation == lb_constants.CREATE:
                driver.create_vip(vip, context)
            elif operation == lb_constants.UPDATE:
                old_vip = data['old_vip']
                driver.update_vip(old_vip, vip, context)
            elif operation == lb_constants.DELETE:
                driver.delete_vip(vip, context)
                self.plugin_rpc.vip_deleted(vip,
                                            lb_constants.ACTIVE, agent_info)
                return  # Don't update object status for delete operation
        except Exception:
            if operation == lb_constants.DELETE:
                msg = ("Failed to delete vip %s" % (vip['id']))
                self.plugin_rpc.vip_deleted(vip,
                                            lb_constants.ACTIVE, agent_info)
                LOG.warn(msg)
            else:
                self.plugin_rpc.update_status('vip', vip['id'],
                                              lb_constants.ERROR,
                                              agent_info, vip)
        else:
            self.plugin_rpc.update_status('vip', vip['id'],
                                          lb_constants.ACTIVE,
                                          agent_info, vip)

    def _create_vip(self, ev):
        self._handle_event_vip(ev, lb_constants.CREATE)

    def _update_vip(self, ev):
        self._handle_event_vip(ev, lb_constants.UPDATE)

    def _delete_vip(self, ev):
        self._handle_event_vip(ev, lb_constants.DELETE)

    def _handle_event_pool(self, ev, operation):
        data = ev.data
        context = data['context']
        pool = data['pool']
        agent_info = context.pop('agent_info')
        service_vendor = agent_info['service_vendor']
        try:
            if operation == lb_constants.CREATE:
                driver_name = data['driver_name']
                driver_id = driver_name + service_vendor
                if (driver_id) not in self.drivers.keys():
                    msg = ('No device driver on agent: %s.' % (driver_name))
                    LOG.error(msg)
                    self.plugin_rpc.update_status('pool', pool['id'],
                                                  lb_constants.ERROR,
                                                  agent_info, pool)
                    return
                driver = self.drivers[driver_id]
                driver.create_pool(pool, context)
                LBaaSEventHandler.instance_mapping[pool['id']] = driver_name
            elif operation == lb_constants.UPDATE:
                old_pool = data['old_pool']
                driver = self._get_driver(service_vendor)  # pool['id'])
                driver.update_pool(old_pool, pool, context)
            elif operation == lb_constants.DELETE:
                driver = self._get_driver(service_vendor)  # pool['id'])
                driver.delete_pool(pool, context)
                del LBaaSEventHandler.instance_mapping[pool['id']]
                return  # Don't update object status for delete operation
        except Exception:
            if operation == lb_constants.DELETE:
                msg = ("Failed to delete pool %s" % (pool['id']))
                LOG.warn(msg)
                del LBaaSEventHandler.instance_mapping[pool['id']]
            else:
                self.plugin_rpc.update_status('pool', pool['id'],
                                              lb_constants.ERROR,
                                              agent_info, pool)
        else:
            self.plugin_rpc.update_status('pool', pool['id'],
                                          lb_constants.ACTIVE,
                                          agent_info, pool)

    def _create_pool(self, ev):
        self._handle_event_pool(ev, lb_constants.CREATE)

    def _update_pool(self, ev):
        self._handle_event_pool(ev, lb_constants.UPDATE)

    def _delete_pool(self, ev):
        self._handle_event_pool(ev, lb_constants.DELETE)

    def _handle_event_member(self, ev, operation):
        data = ev.data
        context = data['context']
        member = data['member']
        agent_info = ev.data['context'].pop('agent_info')
        service_vendor = agent_info['service_vendor']
        driver = self._get_driver(service_vendor)  # member['pool_id'])
        try:
            if operation == lb_constants.CREATE:
                driver.create_member(member, context)
            elif operation == lb_constants.UPDATE:
                old_member = data['old_member']
                driver.update_member(old_member, member, context)
            elif operation == lb_constants.DELETE:
                driver.delete_member(member, context)
                return  # Don't update object status for delete operation
        except Exception:
            if operation == lb_constants.DELETE:
                msg = ("Failed to delete member %s" % (member['id']))
                LOG.warn(msg)
            else:
                self.plugin_rpc.update_status('member', member['id'],
                                              lb_constants.ERROR,
                                              agent_info, member)
        else:
            self.plugin_rpc.update_status('member', member['id'],
                                          lb_constants.ACTIVE,
                                          agent_info, member)

    def _create_member(self, ev):
        self._handle_event_member(ev, lb_constants.CREATE)

    def _update_member(self, ev):
        self._handle_event_member(ev, lb_constants.UPDATE)

    def _delete_member(self, ev):
        self._handle_event_member(ev, lb_constants.DELETE)

    def _handle_event_pool_health_monitor(self, ev, operation):
        data = ev.data
        context = data['context']
        agent_info = context.pop('agent_info')
        health_monitor = data['health_monitor']
        pool_id = data['pool_id']
        service_vendor = agent_info['service_vendor']
        driver = self._get_driver(service_vendor)  # (pool_id)
        assoc_id = {'pool_id': pool_id,
                    'monitor_id': health_monitor['id']}
        try:
            if operation == lb_constants.CREATE:
                driver.create_pool_health_monitor(health_monitor, pool_id,
                                                  context)
            elif operation == lb_constants.UPDATE:
                old_health_monitor = data['old_health_monitor']
                driver.update_pool_health_monitor(old_health_monitor,
                                                  health_monitor, pool_id,
                                                  context)
            elif operation == lb_constants.DELETE:
                driver.delete_pool_health_monitor(health_monitor, pool_id,
                                                  context)
                return  # Don't update object status for delete operation
        except Exception:
            if operation == lb_constants.DELETE:
                msg = ("Failed to delete pool health monitor."
                       " assoc_id: %s" % (assoc_id))
                LOG.warn(msg)
            else:
                self.plugin_rpc.update_status(
                    'health_monitor', assoc_id, lb_constants.ERROR,
                    agent_info, health_monitor)
        else:
            self.plugin_rpc.update_status(
                'health_monitor', assoc_id, lb_constants.ACTIVE,
                agent_info, health_monitor)

    def _create_pool_health_monitor(self, ev):
        self._handle_event_pool_health_monitor(ev, lb_constants.CREATE)

    def _update_pool_health_monitor(self, ev):
        self._handle_event_pool_health_monitor(ev, lb_constants.UPDATE)

    def _delete_pool_health_monitor(self, ev):
        self._handle_event_pool_health_monitor(ev, lb_constants.DELETE)

    def _agent_updated(self, ev):
        """ REVISIT(pritam): Implement this method """
        return None

    def _collect_stats(self, ev):
        self.sc.poll_event(ev)

    @nfp_api.poll_event_desc(event=lb_constants.EVENT_COLLECT_STATS,
                             spacing=60)
    def collect_stats(self, ev):
        for pool_id, driver_name in LBaaSEventHandler.instance_mapping.items():
            driver_id = lb_constants.SERVICE_TYPE + driver_name
            driver = self.drivers[driver_id]
            try:
                stats = driver.get_stats(pool_id)
                if stats:
                    self.plugin_rpc.update_pool_stats(pool_id, stats,
                                                      self.context)
            except Exception:
                msg = ("Error updating statistics on pool %s" % (pool_id))
                LOG.error(msg)


def events_init(sc, drivers, rpcmgr):
    """Registers events with core service controller.

    All the events will come to handle_event method of class instance
    registered in 'handler' field.

    :param drivers: Driver instances registered with the service agent
    :param rpcmgr: Instance to receive all the RPC messages from configurator
    module.

    Returns: None

    """
    ev_ids = [lb_constants.EVENT_CREATE_POOL, lb_constants.EVENT_UPDATE_POOL,
              lb_constants.EVENT_DELETE_POOL,

              lb_constants.EVENT_CREATE_VIP, lb_constants.EVENT_UPDATE_VIP,
              lb_constants.EVENT_DELETE_VIP,

              lb_constants.EVENT_CREATE_MEMBER,
              lb_constants.EVENT_UPDATE_MEMBER,
              lb_constants.EVENT_DELETE_MEMBER,

              lb_constants.EVENT_CREATE_POOL_HEALTH_MONITOR,
              lb_constants.EVENT_UPDATE_POOL_HEALTH_MONITOR,
              lb_constants.EVENT_DELETE_POOL_HEALTH_MONITOR,

              lb_constants.EVENT_AGENT_UPDATED,
              lb_constants.EVENT_COLLECT_STATS
              ]

    evs = []
    for ev_id in ev_ids:
        ev = nfp_event.Event(id=ev_id, handler=LBaaSEventHandler(sc, drivers,
                                                                 rpcmgr))
        evs.append(ev)
    sc.register_events(evs)


def load_drivers(sc, conf):
    """Imports all the driver files.

    Returns: Dictionary of driver objects with a specified service type and/or
    vendor name

    """
    cutils = utils.ConfiguratorUtils()
    drivers = cutils.load_drivers(lb_constants.DRIVERS_DIR)

    plugin_rpc = LBaasRpcSender(sc)

    for service_type, dobj in drivers.iteritems():
        '''LB Driver constructor needs plugin_rpc as a param'''
        instantiated_dobj = dobj(plugin_rpc=plugin_rpc, conf=conf)
        drivers[service_type] = instantiated_dobj

    return drivers


def register_service_agent(cm, sc, conf, rpcmgr):
    """Registers Loadbalaner service agent with configurator module.

    :param cm: Instance of configurator module
    :param sc: Instance of core service controller
    :param conf: Instance of oslo configuration
    :param rpcmgr: Instance containing RPC methods which are invoked by
    configurator module on corresponding RPC message arrival

    """

    service_type = lb_constants.SERVICE_TYPE
    cm.register_service_agent(service_type, rpcmgr)


def init_agent(cm, sc, conf):
    """Initializes Loadbalaner agent.

    :param cm: Instance of configuration module
    :param sc: Instance of core service controller
    :param conf: Instance of oslo configuration

    """

    try:
        drivers = load_drivers(sc, conf)
    except Exception as err:
        msg = ("Loadbalaner agent failed to load service drivers. Reason:%s"
               % (str(err).capitalize()))
        LOG.error(msg)
        raise err
    else:
        msg = ("Loadbalaner agent loaded service"
               " drivers successfully.")
        LOG.debug(msg)

    rpcmgr = LBaaSRpcManager(sc, conf)

    try:
        events_init(sc, drivers, rpcmgr)
    except Exception as err:
        msg = ("Loadbalaner agent failed to initialize events. Reason:%s"
               % (str(err).capitalize()))
        LOG.error(msg)
        raise err
    else:
        msg = ("Loadbalaner agent initialized"
               " events successfully.")
        LOG.debug(msg)

    try:
        register_service_agent(cm, sc, conf, rpcmgr)
    except Exception as err:
        msg = ("Failed to register Loadbalaner agent with"
               " configurator module. Reason:%s" % (str(err).capitalize()))
        LOG.error(msg)
        raise err
    else:
        msg = ("Loadbalaner agent registered with configuration"
               " module successfully.")
        LOG.debug(msg)


def _start_collect_stats(sc):
    """Enqueues poll event for worker to collect pool stats periodically.
       Agent keeps map of pool_id:driver. As part of handling this event,
       stats for pool_id is requested from agent inside service vm
    """

    arg_dict = {}
    ev = sc.new_event(id=lb_constants.EVENT_COLLECT_STATS, data=arg_dict)
    sc.post_event(ev)


def init_agent_complete(cm, sc, conf):
    # _start_collect_stats(sc)
    msg = ("Initialization of loadbalancer agent completed.")
    LOG.info(msg)
