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

import os

from neutron._i18n import _LI

from gbpservice.contrib.nfp.configurator.agents import agent_base
from gbpservice.contrib.nfp.configurator.lib import data_filter
from gbpservice.contrib.nfp.configurator.lib import lbv2_constants as lb_const
from gbpservice.contrib.nfp.configurator.lib import utils
from gbpservice.nfp.common import exceptions
from gbpservice.nfp.core import event as nfp_event
from gbpservice.nfp.core import log as nfp_logging
from gbpservice.nfp.core import module as nfp_api

LOG = nfp_logging.getLogger(__name__)

""" Implements LBaaS response path to Neutron plugin.
Methods of this class are invoked by the LBaaSV2EventHandler class and also
by driver class for sending response from driver to the LBaaS Neutron plugin.
"""


class LBaaSV2RpcSender(data_filter.Filter):

    def __init__(self, sc):
        self.notify = agent_base.AgentBaseNotification(sc)

    def update_status(self, obj_type, obj_id, root_lb_id,
                      provisioning_status, operating_status,
                      agent_info, obj=None):
        """ Enqueues the response from LBaaS V2 operation to neutron plugin.

        :param obj_type: object type
        :param obj_id: object id
        :param root_lb_id: root loadbalancer id
        :param provisioning_status: an enum of ('ACTIVE', 'PENDING_CREATE',
        'PENDING_UPDATE', 'PENDING_DELETE', 'ERROR')
        :param operating_status:  an enum of
        ('ONLINE', 'OFFLINE', 'DEGRADED', 'ERROR')

        """

        msg = {'info': {'service_type': lb_const.SERVICE_TYPE,
                        'context': agent_info['context']},
               'notification': [{'resource': agent_info['resource'],
                                 'data':{'obj_type': obj_type,
                                         'obj_id': obj_id,
                                         'notification_type': 'update_status',
                                         'root_lb_id': root_lb_id,
                                         'provisioning_status':
                                             provisioning_status,
                                         'operating_status':
                                             operating_status,
                                         obj_type: obj}}]
               }
        LOG.info(_LI("Sending Notification 'Update Status' "
                     "for resource: %(resource)s with Provisioning status:"
                     "%(p_status)s and Operating status:%(o_status)s"),
                 {'resource': agent_info['resource'],
                  'p_status': provisioning_status,
                  'o_status': operating_status})
        self.notify._notification(msg)

    # REVISIT(jiahao): need to revisit how lbaasv2 update lb stats,
    # will add in visibility patch
    def update_pool_stats(self, pool_id, stats, context, pool=None):
        """ Enqueues the response from LBaaS operation to neutron plugin.

        :param pool_id: pool id
        :param stats: statistics of that pool

        """
        msg = {'info': {'service_type': lb_const.SERVICE_TYPE,
                        'context': context.to_dict()},
               'notification': [{'resource': 'pool',
                                 'data': {'pool_id': pool_id,
                                          'stats': stats,
                                          'notification_type': (
                                              'update_pool_stats'),
                                          'pool': pool_id}}]
               }
        LOG.info(_LI("Sending Notification 'Update Pool Stats' "
                     "for pool: %(pool_id)s with stats:%(stats)s"),
                 {'pool_id': pool_id,
                  'stats': stats})
        self.notify._notification(msg)


"""Implements APIs invoked by configurator for processing RPC messages.

RPC client of configurator module receives RPC messages from REST server
and invokes the API of this class. The instance of this class is registered
with configurator module using register_service_agent API. Configurator module
identifies the service agent object based on service type and invokes ones of
the methods of this class to configure the device.

"""


class LBaaSv2RpcManager(agent_base.AgentBaseRPCManager):

    def __init__(self, sc, conf):
        """Instantiates child and parent class objects.

        :param sc: Service Controller object that is used for interfacing
        with core service controller.
        :param conf: Configuration object that is used for configuration
        parameter access.

        """

        super(LBaaSv2RpcManager, self).__init__(sc, conf)

    def _send_event(self, event_id, data, serialize=False, binding_key=None,
                    key=None):
        """Posts an event to framework.

        :param event_id: Unique identifier for the event
        :param event_key: Event key for serialization
        :param serialize: Serialize the event
        :param binding_key: binding key to be used for serialization
        :param key: event key

        """

        ev = self.sc.new_event(id=event_id, data=data)
        ev.key = key
        ev.sequence = serialize
        ev.binding_key = binding_key
        self.sc.post_event(ev)

    def create_loadbalancer(self, context, loadbalancer, driver_name):
        """Enqueues event for worker to process create loadbalancer request.

        :param context: RPC context
        :param loadbalancer: loadbalancer resource to be created

        Returns: None

        """
        LOG.info(_LI("Received request 'Create Loadbalancer' for LB:%(lb)s "
                     "with driver:%(driver_name)s"),
                 {'lb': loadbalancer['id'],
                  'driver_name': driver_name})
        arg_dict = {'context': context,
                    lb_const.LOADBALANCER: loadbalancer,
                    'driver_name': driver_name
                    }
        self._send_event(lb_const.EVENT_CREATE_LOADBALANCER_V2, arg_dict,
                         serialize=True, binding_key=loadbalancer['id'],
                         key=loadbalancer['id'])

    def update_loadbalancer(self, context, old_loadbalancer, loadbalancer):
        """Enqueues event for worker to process update loadbalancer request.

        :param context: RPC context
        :param old_loadbalancer: old loadbalancer resource to be updated
        :param loadbalancer: new loadbalancer resource

        Returns: None

        """
        old_val, new_val = self.get_diff_of_dict(
            old_loadbalancer, loadbalancer)
        arg_dict = {'context': context,
                    lb_const.OLD_LOADBALANCER: old_loadbalancer,
                    lb_const.LOADBALANCER: loadbalancer,
                    }
        LOG.info(_LI("Received request 'Update Loadbalancer' for LB:%(lb)s "
                     "with new Param:%(new_val)s and old Param:%(old_val)s"),
                 {'lb': loadbalancer['id'],
                  'new_val': new_val,
                  'old_val': old_val})
        self._send_event(lb_const.EVENT_UPDATE_LOADBALANCER_V2, arg_dict,
                         serialize=True, binding_key=loadbalancer['id'],
                         key=loadbalancer['id'])

    def delete_loadbalancer(self, context, loadbalancer):
        """Enqueues event for worker to process delete loadbalancer request.

        :param context: RPC context
        :param loadbalancer: loadbalancer resource to be deleted

        Returns: None

        """
        LOG.info(_LI("Received request 'Delete Loadbalancer' for LB:%(lb)s "),
                 {'lb': loadbalancer['id']})

        arg_dict = {'context': context,
                    lb_const.LOADBALANCER: loadbalancer,
                    }
        self._send_event(lb_const.EVENT_DELETE_LOADBALANCER_V2, arg_dict,
                         serialize=True, binding_key=loadbalancer['id'],
                         key=loadbalancer['id'])

    def create_listener(self, context, listener):
        """Enqueues event for worker to process create listener request.

        :param context: RPC context
        :param listener: listener resource to be created

        Returns: None

        """
        LOG.info(_LI("Received request 'Create Listener' for LB:%(lb)s "),
                 {'lb': listener['loadbalancer_id']})
        arg_dict = {'context': context,
                    lb_const.LISTENER: listener,
                    }
        self._send_event(lb_const.EVENT_CREATE_LISTENER_V2, arg_dict,
                         serialize=True,
                         binding_key=listener['loadbalancer_id'],
                         key=listener['id'])

    def update_listener(self, context, old_listener, listener):
        """Enqueues event for worker to process update listener request.

        :param context: RPC context
        :param old_listener: old listener resource to be updated
        :param listener: new listener resource

        Returns: None

        """
        old_val, new_val = self.get_diff_of_dict(old_listener, listener)
        LOG.info(_LI("Received request 'Update Listener' for Listener:"
                     "%(listener)s in LB:%(lb_id)s with new Param:"
                     "%(new_val)s and old Param:%(old_val)s"),
                 {'lb_id': listener['loadbalancer_id'],
                  'listener': listener['id'],
                  'old_val': old_val,
                  'new_val': new_val})
        arg_dict = {'context': context,
                    lb_const.OLD_LISTENER: old_listener,
                    lb_const.LISTENER: listener,
                    }
        self._send_event(lb_const.EVENT_UPDATE_LISTENER_V2, arg_dict,
                         serialize=True,
                         binding_key=listener['loadbalancer_id'],
                         key=listener['id'])

    def delete_listener(self, context, listener):
        """Enqueues event for worker to process delete listener request.

        :param context: RPC context
        :param listener: listener resource to be deleted

        Returns: None

        """
        LOG.info(_LI("Received request 'Delete Listener' for LB:%(lb)s "),
                 {'lb': listener['loadbalancer_id']})
        arg_dict = {'context': context,
                    lb_const.LISTENER: listener,
                    }
        self._send_event(lb_const.EVENT_DELETE_LISTENER_V2, arg_dict,
                         serialize=True,
                         binding_key=listener['loadbalancer_id'],
                         key=listener['id'])

    def create_pool(self, context, pool):
        """Enqueues event for worker to process create pool request.

        :param context: RPC context
        :param pool: pool resource to be created

        Returns: None

        """
        LOG.info(_LI("Received request 'Create Pool' for Pool:%(pool_id)s "),
                 {'pool_id': pool['id']})
        arg_dict = {'context': context,
                    lb_const.POOL: pool
                    }
        # REVISIT(jiahao) M:N pool is not yet implemented.
        self._send_event(lb_const.EVENT_CREATE_POOL_V2, arg_dict,
                         serialize=True,
                         binding_key=pool['loadbalancer_id'],
                         key=pool['id'])

    def update_pool(self, context, old_pool, pool):
        """Enqueues event for worker to process update pool request.

        :param context: RPC context
        :param old_pool: old pool resource to be updated
        :param pool: new pool resource

        Returns: None

        """
        old_val, new_val = self.get_diff_of_dict(old_pool, pool)
        LOG.info(_LI("Received request 'Update Pool' for Pool:%(pool)s "
                     "in LB:%(lb_id)s with new Param:%(new_val)s and "
                     "old Param:%(old_val)s"),
                 {'pool': pool['id'],
                  'lb_id': pool['loadbalancer_id'],
                  'old_val': old_val,
                  'new_val': new_val})
        arg_dict = {'context': context,
                    lb_const.OLD_POOL: old_pool,
                    lb_const.POOL: pool,
                    }
        self._send_event(lb_const.EVENT_UPDATE_POOL_V2, arg_dict,
                         serialize=True,
                         binding_key=pool['loadbalancer_id'],
                         key=pool['id'])

    def delete_pool(self, context, pool):
        """Enqueues event for worker to process delete pool request.

        :param context: RPC context
        :param pool: pool resource to be deleted

        Returns: None

        """
        LOG.info(_LI("Received request 'Delete Pool' for Pool:%(pool_id)s "),
                 {'pool_id': pool['id']})
        arg_dict = {'context': context,
                    lb_const.POOL: pool,
                    }
        self._send_event(lb_const.EVENT_DELETE_POOL_V2, arg_dict,
                         serialize=True,
                         binding_key=pool['loadbalancer_id'],
                         key=pool['id'])

    def create_member(self, context, member):
        """Enqueues event for worker to process create member request.

        :param context: RPC context
        :param member: member resource to be created

        Returns: None

        """
        LOG.info(_LI("Received request 'Create Member' for Pool:%(pool_id)s "),
                 {'pool_id': member['pool_id']})
        arg_dict = {'context': context,
                    lb_const.MEMBER: member,
                    }
        self._send_event(lb_const.EVENT_CREATE_MEMBER_V2, arg_dict,
                         serialize=True,
                         binding_key=member[lb_const.POOL]['loadbalancer_id'],
                         key=member['id'])

    def update_member(self, context, old_member, member):
        """Enqueues event for worker to process update member request.

        :param context: RPC context
        :param old_member: old member resource to be updated
        :param member: new member resource

        Returns: None

        """
        old_val, new_val = self.get_diff_of_dict(old_member, member)
        LOG.info(_LI("Received request 'Update Member' for Member:"
                     "%(member_id)s in Pool:%(pool_id)s with new Param:"
                     "%(new_val)s and old Param:%(old_val)s"),
                 {'pool_id': member['pool_id'],
                  'member_id': member['id'],
                  'old_val': old_val,
                  'new_val': new_val})
        arg_dict = {'context': context,
                    lb_const.OLD_MEMBER: old_member,
                    lb_const.MEMBER: member,
                    }
        self._send_event(lb_const.EVENT_UPDATE_MEMBER_V2, arg_dict,
                         serialize=True,
                         binding_key=member[lb_const.POOL]['loadbalancer_id'],
                         key=member['id'])

    def delete_member(self, context, member):
        """Enqueues event for worker to process delete member request.

        :param context: RPC context
        :param member: member resource to be deleted

        Returns: None

        """
        LOG.info(_LI("Received request 'Delete Member' for Pool:"
                     "%(pool_id)s "),
                 {'pool_id': member['pool_id']})
        arg_dict = {'context': context,
                    lb_const.MEMBER: member,
                    }
        self._send_event(lb_const.EVENT_DELETE_MEMBER_V2, arg_dict,
                         serialize=True,
                         binding_key=member[lb_const.POOL]['loadbalancer_id'],
                         key=member['id'])

    def create_healthmonitor(self, context, healthmonitor):
        """Enqueues event for worker to process create health monitor request.

        :param context: RPC context
        :param health_monitor: health_monitor resource to be created
        :param pool_id: pool_id to which health monitor is associated

        Returns: None

        """
        LOG.info(_LI("Received request 'Create Pool Health Monitor' for"
                     "Health monitor:%(hm)s"),
                 {'hm': healthmonitor['id']})
        arg_dict = {'context': context,
                    lb_const.HEALTHMONITOR: healthmonitor
                    }
        self._send_event(lb_const.EVENT_CREATE_HEALTH_MONITOR_V2,
                         arg_dict, serialize=True,
                         binding_key=healthmonitor[lb_const.POOL][
                             'loadbalancer_id'],
                         key=healthmonitor['id'])

    def update_healthmonitor(self, context, old_healthmonitor, healthmonitor):
        """Enqueues event for worker to process update health monitor request.

        :param context: RPC context
        :param old_health_monitor: health_monitor resource to be updated
        :param health_monitor: new health_monitor resource
        :param pool_id: pool_id to which health monitor is associated

        Returns: None

        """
        old_val, new_val = self.get_diff_of_dict(
            old_healthmonitor, healthmonitor)
        LOG.info(_LI("Received request 'Update Pool Health Monitor' for "
                     "Health monitor:%(hm)s with new Param:%(new_val)s and "
                     "old Param:%(old_val)s"),
                 {'hm': healthmonitor['id'],
                  'old_val': old_val,
                  'new_val': new_val})
        arg_dict = {'context': context,
                    lb_const.OLD_HEALTHMONITOR: old_healthmonitor,
                    lb_const.HEALTHMONITOR: healthmonitor
                    }
        self._send_event(lb_const.EVENT_UPDATE_HEALTH_MONITOR_V2,
                         arg_dict, serialize=True,
                         binding_key=healthmonitor[lb_const.POOL][
                             'loadbalancer_id'],
                         key=healthmonitor['id'])

    def delete_healthmonitor(self, context, healthmonitor):
        """Enqueues event for worker to process delete health monitor request.

        :param context: RPC context
        :param health_monitor: health_monitor resource to be deleted
        :param pool_id: pool_id to which health monitor is associated

        Returns: None

        """
        LOG.info(_LI("Received request 'Delete Pool Health Monitor' for "
                     "Health monitor:%(hm)s"),
                 {'hm': healthmonitor['id']})
        arg_dict = {'context': context,
                    lb_const.HEALTHMONITOR: healthmonitor
                    }
        self._send_event(lb_const.EVENT_DELETE_HEALTH_MONITOR_V2,
                         arg_dict, serialize=True,
                         binding_key=healthmonitor[lb_const.POOL][
                             'loadbalancer_id'],
                         key=healthmonitor['id'])

    def agent_updated(self, context, payload):
        """Enqueues event for worker to process agent updated request.

        :param context: RPC context
        :param payload: payload

        Returns: None

        """
        LOG.info(_LI("Received request 'Agent Updated' "))
        arg_dict = {'context': context,
                    'payload': payload}
        self._send_event(lb_const.EVENT_AGENT_UPDATED_V2, arg_dict)


"""Implements event handlers and their helper methods.

Object of this class is registered with the event class of core service
controller. Based on the event key, handle_event method of this class is
invoked by core service controller.

"""


class LBaaSV2EventHandler(agent_base.AgentBaseEventHandler,
                          nfp_api.NfpEventHandler):
    instance_mapping = {}

    def __init__(self, sc, drivers, rpcmgr):
        self.sc = sc
        self.drivers = drivers
        self.rpcmgr = rpcmgr
        self.plugin_rpc = LBaaSV2RpcSender(sc)

    def _get_driver(self, driver_name):
        """Retrieves service driver object based on service type input.

        Currently, service drivers are identified with service type. Support
        for single driver per service type is provided. When multi-vendor
        support is going to be provided, the driver should be selected based
        on both service type and vendor name.

        :param service_type: Service type - loadbalancer

        Returns: Service driver instance

        """
        driver = lb_const.SERVICE_TYPE + driver_name
        return self.drivers[driver]

    def _root_loadbalancer_id(self, obj_type, obj_dict):
        """Returns the loadbalancer id this instance is attached to."""

        try:
            # For Mitaka
            if obj_type == lb_const.LOADBALANCER:
                lb = obj_dict['id']
            elif obj_type == lb_const.LISTENER:
                lb = obj_dict[lb_const.LOADBALANCER]['id']
            elif obj_type == lb_const.L7POLICY:
                lb = obj_dict[lb_const.LISTENER][lb_const.LOADBALANCER]['id']
            elif obj_type == lb_const.L7RULE:
                lb = obj_dict['policy'][lb_const.LISTENER][
                    lb_const.LOADBALANCER]['id']
            elif obj_type == lb_const.POOL:
                lb = obj_dict[lb_const.LOADBALANCER]['id']
            elif obj_type == lb_const.SNI:
                lb = obj_dict[lb_const.LISTENER][lb_const.LOADBALANCER]['id']
            else:
                # Pool Member or Health Monitor
                lb = obj_dict[lb_const.POOL][lb_const.LOADBALANCER]['id']
            # For Liberty
            # if obj_type == lb_const.LOADBALANCER:
            #     lb = obj_dict['id']
            # elif obj_type == lb_const.LISTENER:
            #     lb = obj_dict[lb_const.LOADBALANCER]['id']
            # elif obj_type == lb_const.POOL:
            #     lb = obj_dict[lb_const.LISTENER][lb_const.LOADBALANCER]['id']
            # elif obj_type == lb_const.SNI:
            #     lb = obj_dict[lb_const.LISTENER][lb_const.LOADBALANCER]['id']
            # else:
            #     # Pool Member or Health Monitor
            #     lb = obj_dict[lb_const.POOL][lb_const.LISTENER][
            #         lb_const.LOADBALANCER]['id']
        except Exception:
            raise exceptions.IncompleteData(
                'Root loadbalancer id was not found')
        else:
            return lb

    def handle_event(self, ev):
        """Processes the generated events in worker context.

        Processes the following events.
        - create loadbalancer
        - update loadbalancer
        - delete loadbalancer
        - create listener
        - update listener
        - delete listener
        - create pool
        - update pool
        - delete pool
        - create member
        - update member
        - delete member
        - create health monitor
        - update health monitor
        - delete health monitor
        - agent updated
        Enqueues responses into notification queue.

        Returns: None

        """
        msg = ("Handling event '%s' " % (ev.id))
        LOG.info(msg)
        try:
            msg = ("Worker process with ID: %s starting "
                   "to handle task: %s of topic: %s. "
                   % (os.getpid(), ev.id, lb_const.LBAAS_AGENT_RPC_TOPIC))
            LOG.debug(msg)

            method = getattr(self, "_%s" % (ev.id.lower()))
            method(ev)
        except Exception as err:
            msg = ("Failed to perform the operation: %s. %s"
                   % (ev.id, str(err).capitalize()))
            LOG.error(msg)
        finally:
            if ev.id == lb_const.EVENT_COLLECT_STATS_V2:
                """Do not say event done for collect stats as it is
                   to be executed forever
                """
                pass
            else:
                msg = ("Calling event done for event '%s' " % (ev.id))
                LOG.info(msg)
                self.sc.event_complete(ev)

    def _handle_event_loadbalancer(self, ev, operation):
        data = ev.data
        context = data['context']
        loadbalancer = data[lb_const.LOADBALANCER]
        root_lb_id = self._root_loadbalancer_id(
            lb_const.LOADBALANCER, loadbalancer)
        agent_info = ev.data['context'].get('agent_info')
        service_vendor = agent_info['service_vendor']

        try:
            if operation == lb_const.CREATE:
                driver_name = data['driver_name']
                driver_id = driver_name + service_vendor
                if (driver_id) not in self.drivers.keys():
                    msg = ('No device driver on agent: %s.' % (driver_name))
                    LOG.error(msg)
                    self.plugin_rpc.update_status(
                        lb_const.LOADBALANCER, loadbalancer['id'], root_lb_id,
                        lb_const.ERROR, lb_const.OFFLINE, agent_info,
                        None)
                    return
                driver = self.drivers[driver_id]
                driver.load_balancer.create(context, loadbalancer)
                LBaaSV2EventHandler.instance_mapping[loadbalancer['id']] \
                    = driver_name
            elif operation == lb_const.UPDATE:
                old_loadbalancer = data[lb_const.OLD_LOADBALANCER]
                driver = self._get_driver(service_vendor)
                driver.load_balancer.update(context,
                                            old_loadbalancer, loadbalancer)
            elif operation == lb_const.DELETE:
                driver = self._get_driver(service_vendor)
                driver.load_balancer.delete(context, loadbalancer)
                del LBaaSV2EventHandler.instance_mapping[loadbalancer['id']]
                return  # Don't update object status for delete operation
        except Exception:
            if operation == lb_const.DELETE:
                msg = (
                    "Failed to delete loadbalancer %s" % (loadbalancer['id']))
                LOG.warn(msg)
                del LBaaSV2EventHandler.instance_mapping[loadbalancer['id']]
            else:
                self.plugin_rpc.update_status(
                    lb_const.LOADBALANCER, loadbalancer['id'], root_lb_id,
                    lb_const.ERROR, lb_const.OFFLINE,
                    agent_info, None)
        else:
            self.plugin_rpc.update_status(
                lb_const.LOADBALANCER, loadbalancer['id'], root_lb_id,
                lb_const.ACTIVE, lb_const.ONLINE,
                agent_info, None)

    def _create_loadbalancer_v2(self, ev):
        self._handle_event_loadbalancer(ev, lb_const.CREATE)

    def _update_loadbalancer_v2(self, ev):
        self._handle_event_loadbalancer(ev, lb_const.UPDATE)

    def _delete_loadbalancer_v2(self, ev):
        self._handle_event_loadbalancer(ev, lb_const.DELETE)

    def _handle_event_listener(self, ev, operation):
        data = ev.data
        context = data['context']
        listener = data[lb_const.LISTENER]
        root_lb_id = self._root_loadbalancer_id(lb_const.LISTENER, listener)
        agent_info = ev.data['context'].get('agent_info')
        service_vendor = agent_info['service_vendor']
        driver = self._get_driver(service_vendor)

        try:
            if operation == lb_const.CREATE:
                driver.listener.create(context, listener)
            elif operation == lb_const.UPDATE:
                old_listener = data[lb_const.OLD_LISTENER]
                driver.listener.update(context, old_listener, listener)
            elif operation == lb_const.DELETE:
                driver.listener.delete(context, listener)
                return  # Don't update object status for delete operation
        except Exception:
            if operation == lb_const.DELETE:
                msg = ("Failed to delete listener %s" % (listener['id']))
                LOG.warn(msg)
            else:
                self.plugin_rpc.update_status(
                    lb_const.LISTENER, listener['id'], root_lb_id,
                    lb_const.ERROR, lb_const.OFFLINE,
                    agent_info, None)
        else:
            self.plugin_rpc.update_status(
                lb_const.LISTENER, listener['id'], root_lb_id,
                lb_const.ACTIVE, lb_const.ONLINE,
                agent_info, None)

    def _create_listener_v2(self, ev):
        self._handle_event_listener(ev, lb_const.CREATE)

    def _update_listener_v2(self, ev):
        self._handle_event_listener(ev, lb_const.UPDATE)

    def _delete_listener_v2(self, ev):
        self._handle_event_listener(ev, lb_const.DELETE)

    def _handle_event_pool(self, ev, operation):
        data = ev.data
        context = data['context']
        pool = data[lb_const.POOL]
        root_lb_id = self._root_loadbalancer_id(lb_const.POOL, pool)
        agent_info = ev.data['context'].get('agent_info')
        service_vendor = agent_info['service_vendor']
        driver = self._get_driver(service_vendor)

        try:
            if operation == lb_const.CREATE:
                driver.pool.create(context, pool)
            elif operation == lb_const.UPDATE:
                old_pool = data[lb_const.OLD_POOL]
                driver.pool.update(context, old_pool, pool)
            elif operation == lb_const.DELETE:
                driver.pool.delete(context, pool)
                return  # Don't update object status for delete operation
        except Exception:
            if operation == lb_const.DELETE:
                msg = "Failed to delete pool %s" % (pool['id'])
                LOG.warn(msg)
            else:
                self.plugin_rpc.update_status(
                    lb_const.POOL, pool['id'], root_lb_id,
                    lb_const.ERROR, lb_const.OFFLINE,
                    agent_info, None)
        else:
            self.plugin_rpc.update_status(
                lb_const.POOL, pool['id'], root_lb_id,
                lb_const.ACTIVE, lb_const.ONLINE,
                agent_info, None)

    def _create_pool_v2(self, ev):
        self._handle_event_pool(ev, lb_const.CREATE)

    def _update_pool_v2(self, ev):
        self._handle_event_pool(ev, lb_const.UPDATE)

    def _delete_pool_v2(self, ev):
        self._handle_event_pool(ev, lb_const.DELETE)

    def _handle_event_member(self, ev, operation):
        data = ev.data
        context = data['context']
        member = data[lb_const.MEMBER]
        root_lb_id = self._root_loadbalancer_id(lb_const.MEMBER, member)
        agent_info = ev.data['context'].get('agent_info')
        service_vendor = agent_info['service_vendor']
        driver = self._get_driver(service_vendor)  # member['pool_id'])
        try:
            if operation == lb_const.CREATE:
                driver.member.create(context, member)
            elif operation == lb_const.UPDATE:
                old_member = data[lb_const.OLD_MEMBER]
                driver.member.update(context, old_member, member)
            elif operation == lb_const.DELETE:
                driver.member.delete(context, member)
                return  # Don't update object status for delete operation
        except Exception:
            if operation == lb_const.DELETE:
                msg = ("Failed to delete member %s" % (member['id']))
                LOG.warn(msg)
            else:
                self.plugin_rpc.update_status(
                    lb_const.MEMBER, member['id'], root_lb_id,
                    lb_const.ERROR, lb_const.OFFLINE,
                    agent_info, None)
        else:
            self.plugin_rpc.update_status(
                lb_const.MEMBER, member['id'], root_lb_id,
                lb_const.ACTIVE, lb_const.ONLINE,
                agent_info, None)

    def _create_member_v2(self, ev):
        self._handle_event_member(ev, lb_const.CREATE)

    def _update_member_v2(self, ev):
        self._handle_event_member(ev, lb_const.UPDATE)

    def _delete_member_v2(self, ev):
        self._handle_event_member(ev, lb_const.DELETE)

    def _handle_event_health_monitor(self, ev, operation):
        data = ev.data
        context = data['context']
        healthmonitor = data[lb_const.HEALTHMONITOR]
        root_lb_id = self._root_loadbalancer_id(
            lb_const.HEALTHMONITOR, healthmonitor)
        agent_info = context.get('agent_info')
        service_vendor = agent_info['service_vendor']
        driver = self._get_driver(service_vendor)  # (pool_id)

        pool_id = healthmonitor[lb_const.POOL]['id']
        assoc_id = {'pool_id': pool_id,
                    'monitor_id': healthmonitor['id']}
        try:
            if operation == lb_const.CREATE:
                driver.health_monitor.create(context, healthmonitor)
            elif operation == lb_const.UPDATE:
                old_healthmonitor = data[lb_const.OLD_HEALTHMONITOR]
                driver.health_monitor.update(context, old_healthmonitor,
                                             healthmonitor)
            elif operation == lb_const.DELETE:
                driver.health_monitor.delete(context, healthmonitor)
                return  # Don't update object status for delete operation
        except Exception:
            if operation == lb_const.DELETE:
                msg = ("Failed to delete pool health monitor."
                       " assoc_id: %s" % (assoc_id))
                LOG.warn(msg)
            else:
                self.plugin_rpc.update_status(
                    lb_const.HEALTHMONITOR, healthmonitor['id'], root_lb_id,
                    lb_const.ERROR, lb_const.OFFLINE,
                    agent_info, None)
        else:
            self.plugin_rpc.update_status(
                lb_const.HEALTHMONITOR, healthmonitor['id'], root_lb_id,
                lb_const.ACTIVE, lb_const.ONLINE,
                agent_info, None)

    def _create_health_monitor_v2(self, ev):
        self._handle_event_health_monitor(ev, lb_const.CREATE)

    def _update_health_monitor_v2(self, ev):
        self._handle_event_health_monitor(ev, lb_const.UPDATE)

    def _delete_health_monitor_v2(self, ev):
        self._handle_event_health_monitor(ev, lb_const.DELETE)

    def _agent_updated(self, ev):
        """ REVISIT(pritam): Support """
        return None

    def _collect_stats(self, ev):
        self.sc.poll_event(ev)

    @nfp_api.poll_event_desc(event=lb_const.EVENT_COLLECT_STATS_V2,
                             spacing=60)
    def collect_stats_v2(self, ev):
        for pool_id, driver_name in \
                LBaaSV2EventHandler.instance_mapping.items():
            driver_id = lb_const.SERVICE_TYPE + driver_name
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
    ev_ids = [lb_const.EVENT_CREATE_LOADBALANCER_V2,
              lb_const.EVENT_UPDATE_LOADBALANCER_V2,
              lb_const.EVENT_DELETE_LOADBALANCER_V2,

              lb_const.EVENT_CREATE_LISTENER_V2,
              lb_const.EVENT_UPDATE_LISTENER_V2,
              lb_const.EVENT_DELETE_LISTENER_V2,

              lb_const.EVENT_CREATE_POOL_V2, lb_const.EVENT_UPDATE_POOL_V2,
              lb_const.EVENT_DELETE_POOL_V2,

              lb_const.EVENT_CREATE_MEMBER_V2,
              lb_const.EVENT_UPDATE_MEMBER_V2,
              lb_const.EVENT_DELETE_MEMBER_V2,

              lb_const.EVENT_CREATE_HEALTH_MONITOR_V2,
              lb_const.EVENT_UPDATE_HEALTH_MONITOR_V2,
              lb_const.EVENT_DELETE_HEALTH_MONITOR_V2,

              lb_const.EVENT_AGENT_UPDATED_V2,
              lb_const.EVENT_COLLECT_STATS_V2
              ]

    evs = []
    for ev_id in ev_ids:
        ev = nfp_event.Event(id=ev_id, handler=LBaaSV2EventHandler(
            sc, drivers, rpcmgr))
        evs.append(ev)
    sc.register_events(evs)


def load_drivers(sc, conf):
    """Imports all the driver files.

    Returns: Dictionary of driver objects with a specified service type and/or
    vendor name

    """
    cutils = utils.ConfiguratorUtils(conf)
    drivers = cutils.load_drivers(lb_const.SERVICE_TYPE)

    plugin_rpc = LBaaSV2RpcSender(sc)

    for service_type, dobj in drivers.iteritems():
        '''LB Driver constructor needs plugin_rpc as a param'''
        instantiated_dobj = dobj(plugin_rpc=plugin_rpc, conf=conf)
        drivers[service_type] = instantiated_dobj

    return drivers


def register_service_agent(cm, sc, conf, rpcmgr):
    """Registers Loadbalaner V2 service agent with configurator module.

    :param cm: Instance of configurator module
    :param sc: Instance of core service controller
    :param conf: Instance of oslo configuration
    :param rpcmgr: Instance containing RPC methods which are invoked by
    configurator module on corresponding RPC message arrival

    """

    service_type = lb_const.SERVICE_TYPE
    cm.register_service_agent(service_type, rpcmgr)


def init_agent(cm, sc, conf):
    """Initializes Loadbalaner V2 agent.

    :param cm: Instance of configuration module
    :param sc: Instance of core service controller
    :param conf: Instance of oslo configuration

    """

    try:
        drivers = load_drivers(sc, conf)
    except Exception as err:
        msg = ("Loadbalaner V2 agent failed to load service drivers. %s"
               % (str(err).capitalize()))
        LOG.error(msg)
        raise err
    else:
        msg = ("Loadbalaner V2 agent loaded service"
               " drivers successfully.")
        LOG.debug(msg)

    rpcmgr = LBaaSv2RpcManager(sc, conf)

    try:
        events_init(sc, drivers, rpcmgr)
    except Exception as err:
        msg = ("Loadbalaner V2 agent failed to initialize events. %s"
               % (str(err).capitalize()))
        LOG.error(msg)
        raise err
    else:
        msg = ("Loadbalaner V2 agent initialized"
               " events successfully.")
        LOG.debug(msg)

    try:
        register_service_agent(cm, sc, conf, rpcmgr)
    except Exception as err:
        msg = ("Failed to register Loadbalaner V2 agent with"
               " configurator module. %s" % (str(err).capitalize()))
        LOG.error(msg)
        raise err
    else:
        msg = ("Loadbalaner V2 agent registered with configuration"
               " module successfully.")
        LOG.debug(msg)


def _start_collect_stats(sc):
    """Enqueues poll event for worker to collect pool stats periodically.
       Agent keeps map of pool_id:driver. As part of handling this event,
       stats for pool_id is requested from agent inside service vm
    """

    arg_dict = {}
    ev = sc.new_event(id=lb_const.EVENT_COLLECT_STATS_V2, data=arg_dict)
    sc.post_event(ev)


def init_agent_complete(cm, sc, conf):
    # _start_collect_stats(sc)
    msg = ("Initialization of loadbalancer agent v2 completed.")
    LOG.info(msg)
