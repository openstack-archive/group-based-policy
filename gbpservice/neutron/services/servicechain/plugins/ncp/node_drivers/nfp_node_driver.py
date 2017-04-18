# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import eventlet
import sys
import threading
import time

from keystoneclient import exceptions as k_exceptions
from keystoneclient.v2_0 import client as keyclient
from neutron._i18n import _LE
from neutron._i18n import _LI
from neutron.common import exceptions as n_exc
from neutron.common import rpc as n_rpc
from neutron.db import model_base
from neutron.plugins.common import constants as pconst
from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging
from oslo_serialization import jsonutils
from oslo_utils import excutils
import sqlalchemy as sa
from sqlalchemy.orm.exc import NoResultFound

from gbpservice.common import utils
from gbpservice.neutron.services.grouppolicy.common import constants as gconst
from gbpservice.neutron.services.servicechain.plugins.ncp import (
    exceptions as exc)
from gbpservice.neutron.services.servicechain.plugins.ncp import (
    model as ncp_model)
from gbpservice.neutron.services.servicechain.plugins.ncp import driver_base
from gbpservice.neutron.services.servicechain.plugins.ncp import plumber_base
from gbpservice.nfp.common import constants as nfp_constants
from gbpservice.nfp.common import topics as nfp_rpc_topics


NFP_NODE_DRIVER_OPTS = [
    cfg.BoolOpt('is_service_admin_owned',
                help=_("Parameter to indicate whether the Service VM has to "
                       "be owned by the Admin"),
                default=False),
    cfg.IntOpt('service_create_timeout',
               default=nfp_constants.SERVICE_CREATE_TIMEOUT,
               help=_("Seconds to wait for service creation "
                      "to complete")),
    cfg.IntOpt('service_delete_timeout',
               default=nfp_constants.SERVICE_DELETE_TIMEOUT,
               help=_("Seconds to wait for service deletion "
                      "to complete")),
]
# REVISIT(ashu): Can we use is_service_admin_owned config from RMD
cfg.CONF.register_opts(NFP_NODE_DRIVER_OPTS, "nfp_node_driver")


LOG = logging.getLogger(__name__)

# REVISIT: L2 insertion not supported
GATEWAY_PLUMBER_TYPE = [pconst.FIREWALL, pconst.VPN]
nfp_context_store = threading.local()


class InvalidServiceType(exc.NodeCompositionPluginBadRequest):
    message = _("The NFP Node driver only supports the services "
                "VPN, Firewall and LB in a Service Chain")


class ServiceProfileRequired(exc.NodeCompositionPluginBadRequest):
    message = _("A Service profile is required in Service node")


class NodeVendorMismatch(exc.NodeCompositionPluginBadRequest):
    message = _("The NFP Node driver only handles nodes which have service "
                "profile with vendor name %(vendor)s")


class DuplicateServiceTypeInChain(exc.NodeCompositionPluginBadRequest):
    message = _("The NFP Node driver does not support duplicate "
                "service types in same chain")


class RequiredProfileAttributesNotSet(exc.NodeCompositionPluginBadRequest):
    message = _("The required attributes in service profile are not present")


class InvalidNodeOrderInChain(exc.NodeCompositionPluginBadRequest):
    message = _("The NFP Node driver does not support the order "
                "of nodes defined in the current service chain spec, "
                "order should be : %(node_order)s")


class UnSupportedServiceProfile(exc.NodeCompositionPluginBadRequest):
    message = _("The NFP Node driver does not support this service "
                "profile with service type %(service_type)s and vendor "
                "%(vendor)s")


class UnSupportedInsertionMode(exc.NodeCompositionPluginBadRequest):
    message = _("The NFP Node driver supports only L3 Insertion "
                "mode")


class ServiceInfoNotAvailableOnUpdate(n_exc.NeutronException):
    message = _("Service information is not available with Service Manager "
                "on node update")


class VipNspNotSetonProvider(n_exc.NeutronException):
    message = _("Network Service policy for VIP IP address is not configured "
                "on the Providing Group")


class NodeInstanceDeleteFailed(n_exc.NeutronException):
    message = _("Node instance delete failed in NFP Node driver")


class NodeInstanceCreateFailed(n_exc.NeutronException):
    message = _("Node instance create failed in NFP Node driver")


class NodeInstanceUpdateFailed(n_exc.NeutronException):
    message = _("Node instance update failed in NFP Node driver")


class ServiceNodeInstanceNetworkFunctionMapping(model_base.BASEV2):
    """ServiceChainInstance to NFP network function mapping."""

    __tablename__ = 'ncp_node_instance_network_function_mappings'
    sc_instance_id = sa.Column(sa.String(36),
                               nullable=False, primary_key=True)
    sc_node_id = sa.Column(sa.String(36),
                           nullable=False, primary_key=True)
    network_function_id = sa.Column(sa.String(36),
                                    nullable=False, primary_key=True)


class NFPClientApi(object):
    """ Client side of the NFP Framework user """

    RPC_API_VERSION = '1.0'

    def __init__(self, topic):
        target = oslo_messaging.Target(
            topic=topic, version=self.RPC_API_VERSION)
        self.client = n_rpc.get_client(target)

    def create_network_function(self, context, network_function):
        LOG.info(_LI("Sending RPC CREATE NETWORK FUNCTION to Service "
                     "Orchestrator for tenant:%(tenant_id)s with "
                     "service profile:%(service_profile_id)s"),
                 {'tenant_id': network_function['tenant_id'],
                  'service_profile_id': network_function[
                     'service_profile']['id']})
        cctxt = self.client.prepare(
            fanout=False, topic=nfp_rpc_topics.NFP_NSO_TOPIC)
        return cctxt.call(
            context,
            'create_network_function',
            network_function=network_function)

    def delete_network_function(self, context, network_function_id):
        LOG.info(_LI("Sending RPC DELETE NETWORK FUNCTION to Service "
                     "Orchestrator for NF:"
                     "%(network_function_id)s"),
                 {'network_function_id': network_function_id})
        cctxt = self.client.prepare(version=self.RPC_API_VERSION)
        return cctxt.call(
            context,
            'delete_network_function',
            network_function_id=network_function_id)

    def update_network_function(self, context, network_function_id, config):
        LOG.info(_LI("Sending RPC UPDATE NETWORK FUNCTION to Service "
                     "Orchestrator for NF:"
                     "%(network_function_id)s"),
                 {'network_function_id': network_function_id})
        cctxt = self.client.prepare(version=self.RPC_API_VERSION)
        return cctxt.call(
            context,
            'update_network_function',
            network_function_id=network_function_id,
            config=config)

    def get_network_function(self, context, network_function_id):
        LOG.debug("Sending RPC GET NETWORK FUNCTION to Service "
                  "Orchestrator for NF: %s" % network_function_id)
        cctxt = self.client.prepare(version=self.RPC_API_VERSION)
        return cctxt.call(
            context,
            'get_network_function',
            network_function_id=network_function_id)

    def consumer_ptg_added_notification(self, context, network_function_id,
                                        policy_target_group):
        LOG.info(_LI("Sending RPC CONSUMER PTG ADDED NOTIFICATION to Service "
                     "Orchestrator for NF:"
                     "%(network_function_id)s"),
                 {'network_function_id': network_function_id})
        cctxt = self.client.prepare(version=self.RPC_API_VERSION)
        return cctxt.call(context,
                          'consumer_ptg_added_notification',
                          network_function_id=network_function_id,
                          policy_target_group=policy_target_group)

    def consumer_ptg_removed_notification(self, context, network_function_id,
                                          policy_target_group):
        LOG.info(_LI("Sending RPC CONSUMER PTG REMOVED NOTIFICATION to "
                     " Service Orchestrator for NF:%(network_function_id)s"),
                 {'network_function_id': network_function_id})
        cctxt = self.client.prepare(version=self.RPC_API_VERSION)
        return cctxt.call(context,
                          'consumer_ptg_removed_notification',
                          network_function_id=network_function_id,
                          policy_target_group=policy_target_group)

    def policy_target_added_notification(self, context, network_function_id,
                                         policy_target):
        LOG.info(_LI("Sending RPC POLICY TARGET ADDED NOTIFICATION to "
                     "Service Orchestrator for NF:%(network_function_id)s"),
                 {'network_function_id': network_function_id})
        cctxt = self.client.prepare(version=self.RPC_API_VERSION)
        return cctxt.call(context,
                          'policy_target_added_notification',
                          network_function_id=network_function_id,
                          policy_target=policy_target)

    def policy_target_removed_notification(self, context, network_function_id,
                                           policy_target):
        LOG.info(_LI("Sending RPC POLICY TARGET REMOVED NOTIFICATION to "
                     "Service Orchestrator for NF:%(network_function_id)s"),
                 {'network_function_id': network_function_id})
        cctxt = self.client.prepare(version=self.RPC_API_VERSION)
        return cctxt.call(context,
                          'policy_target_removed_notification',
                          network_function_id=network_function_id,
                          policy_target=policy_target)

    def get_plumbing_info(self, context, node_driver_ctxt):
        LOG.info(_LI("Sending RPC GET PLUMBING INFO to Service Orchestrator "))
        request_info = dict(profile=node_driver_ctxt.current_profile,
                            tenant_id=node_driver_ctxt.provider['tenant_id'],
                            provider=node_driver_ctxt.provider)
        cctxt = self.client.prepare(version=self.RPC_API_VERSION)
        return cctxt.call(context, 'get_plumbing_info',
                          request_info=request_info)


class NFPContext(object):

    @staticmethod
    def store_nfp_context(sc_instance_id, **context):
        if not hasattr(nfp_context_store, 'context'):
            nfp_context_store.context = {}

        # Considering each store request comes with one entry
        if not nfp_context_store.context.get(sc_instance_id):
            NFPContext._initialise_attr(sc_instance_id)
        nfp_context_store.context[sc_instance_id].update(context)

    @staticmethod
    def clear_nfp_context(sc_instance_id):
        if not hasattr(nfp_context_store, 'context'):
            return
        if nfp_context_store.context.get(sc_instance_id):
            del nfp_context_store.context[sc_instance_id]

    @staticmethod
    def get_nfp_context(sc_instance_id):
        if not hasattr(nfp_context_store, 'context'):
            return {}
        if nfp_context_store.context.get(sc_instance_id):
            return nfp_context_store.context[sc_instance_id]
        return {}

    @staticmethod
    def _initialise_attr(sc_instance_id):
        context = {'sc_node_count': 0,
                   'sc_gateway_type_nodes': [],
                   'network_functions': [],
                   'update': False}
        if nfp_context_store.context:
            nfp_context_store.context.update({sc_instance_id: context})
        else:
            nfp_context_store.context = {sc_instance_id: context}


class NFPNodeDriver(driver_base.NodeDriverBase):
    SUPPORTED_SERVICE_TYPES = [
        pconst.LOADBALANCER, pconst.FIREWALL, pconst.VPN,
        pconst.LOADBALANCERV2]
    vendor_name = nfp_constants.NFP_VENDOR.upper()
    required_heat_resources = {
        pconst.LOADBALANCERV2: ['OS::Neutron::LBaaS::LoadBalancer',
                                'OS::Neutron::LBaaS::Listener',
                                'OS::Neutron::LBaaS::Pool'],
        pconst.LOADBALANCER: ['OS::Neutron::LoadBalancer',
                              'OS::Neutron::Pool'],
        pconst.FIREWALL: ['OS::Neutron::Firewall',
                          'OS::Neutron::FirewallPolicy'],
        pconst.VPN: ['OS::Neutron::VPNService'],
    }
    initialized = False

    def __init__(self):
        super(NFPNodeDriver, self).__init__()
        self._lbaas_plugin = None

    @property
    def name(self):
        return self._name

    def initialize(self, name):
        self.initialized = True
        self._name = name
        if cfg.CONF.nfp_node_driver.is_service_admin_owned:
            self.resource_owner_tenant_id = self._resource_owner_tenant_id()
        else:
            self.resource_owner_tenant_id = None
        self._setup_rpc()

    def _setup_rpc(self):
        self.nfp_notifier = NFPClientApi(nfp_rpc_topics.NFP_NSO_TOPIC)

    def _parse_service_flavor_string(self, service_flavor_str):
        service_details = {}
        if ',' not in service_flavor_str:
            service_details['device_type'] = 'nova'
            service_details['service_vendor'] = service_flavor_str
        else:
            service_flavor_dict = dict(item.split('=') for item
                                       in service_flavor_str.split(','))
            service_details = {key.strip(): value.strip() for key, value
                               in service_flavor_dict.iteritems()}
        return service_details

    def get_plumbing_info(self, context):
        plumbing_request = {}
        context._plugin_context = self._get_resource_owner_context(
            context._plugin_context)
        service_type = context.current_profile['service_type']

        service_flavor_str = context.current_profile['service_flavor']
        service_details = self._parse_service_flavor_string(service_flavor_str)
        if service_details['device_type'] == 'None':
            if not NFPContext.get_nfp_context(context.instance['id']):
                nfp_context = NFPContext.store_nfp_context(
                    context.instance['id'])
            return {}
        # Management PTs are managed by NFP since it supports hosting multiple
        # logical services in a single device
        # plumber will return stitching network PT instead of consumer
        # as chain is instantiated while creating provider group.
        if service_type in GATEWAY_PLUMBER_TYPE:
            gateway_type_node = {'service_type': service_type,
                                 'context': {}}
            nfp_context = NFPContext.get_nfp_context(context.instance['id'])
            if nfp_context:
                if len(nfp_context['sc_gateway_type_nodes']):
                    LOG.info(_LI(
                        "Not requesting plumber for PTs for service type "
                        "%(service_type)s"), {'service_type': service_type})
                    if not nfp_context['update']:
                        nfp_context['sc_gateway_type_nodes'].append(
                            gateway_type_node)
                        NFPContext.store_nfp_context(
                            context.instance['id'],
                            sc_gateway_type_nodes=(
                                nfp_context['sc_gateway_type_nodes']))
                        return {}
                if not nfp_context['update']:
                    nfp_context['sc_gateway_type_nodes'].append(
                        gateway_type_node)
                    NFPContext.store_nfp_context(
                        context.instance['id'],
                        sc_gateway_type_nodes=(
                            nfp_context['sc_gateway_type_nodes']))
                    plumbing_request = self.nfp_notifier.get_plumbing_info(
                        context._plugin_context, context)
            else:
                NFPContext.store_nfp_context(
                    context.instance['id'],
                    sc_gateway_type_nodes=[gateway_type_node])
                plumbing_request = self.nfp_notifier.get_plumbing_info(
                    context._plugin_context, context)

        else:  # Loadbalancer which is one arm
            NFPContext.store_nfp_context(
                context.instance['id'])
            plumbing_request = self.nfp_notifier.get_plumbing_info(
                context._plugin_context, context)

        LOG.info(_LI("Requesting plumber for PTs for "
                     "service type %(service_type)s with "
                     "%(plumbing_request)s "),
                 {'plumbing_request': plumbing_request,
                  'service_type': service_type})
        return plumbing_request

    def validate_create(self, context):
        if not context.current_profile:
            raise ServiceProfileRequired()
        if (not context.current_profile['vendor'] or not
            context.current_profile['insertion_mode'] or not
            context.current_profile['service_type'] or not
                context.current_profile['service_flavor']):
            raise RequiredProfileAttributesNotSet()
        if context.current_profile['vendor'] != self.vendor_name:
            raise NodeVendorMismatch(vendor=self.vendor_name)
        if (context.current_profile['insertion_mode'].lower() !=
                nfp_constants.L3_INSERTION_MODE):
            raise UnSupportedInsertionMode()
        if context.current_profile['service_type'] not in (
                self.SUPPORTED_SERVICE_TYPES):
            raise InvalidServiceType()
        self._is_node_order_in_spec_supported(context)

    def validate_update(self, context):
        NFPContext.store_nfp_context(context.instance['id'],
                                     update=True)
        if not context.original_node:  # PT create/delete notifications
            return
        if context.current_node and not context.current_profile:
            raise ServiceProfileRequired()
        if context.current_profile['vendor'] != self.vendor_name:
            raise NodeVendorMismatch(vendor=self.vendor_name)
        if (context.current_profile['insertion_mode'].lower() !=
                nfp_constants.L3_INSERTION_MODE):
            raise UnSupportedInsertionMode()
        if context.current_profile['service_type'] not in (
                self.SUPPORTED_SERVICE_TYPES):
            raise InvalidServiceType()

    def create(self, context):
        try:
            context._plugin_context = self._get_resource_owner_context(
                context._plugin_context)
            network_function_id = self._create_network_function(context)
        except Exception:
            # NFPContext.clear_nfp_context(context.instance['id'])
            exc_type, exc_value, exc_traceback = sys.exc_info()
            message = "Traceback: %s" % (exc_value)
            LOG.error(message)
            network_function_id = ''

        finally:
            self._set_node_instance_network_function_map(
                context.plugin_session, context.current_node['id'],
                context.instance['id'], network_function_id)

        self._wait_for_node_operation_completion(
            context, network_function_id,
            nfp_constants.CREATE)

    def _wait_for_node_operation_completion(self, context,
                                            network_function_id, operation):
        nfp_context = NFPContext.get_nfp_context(context.instance['id'])
        nfp_context['sc_node_count'] -= 1
        nfp_context['network_functions'].append(network_function_id)

        if nfp_context['sc_node_count'] != 0:
            NFPContext.store_nfp_context(context.instance['id'], **nfp_context)
        else:
            network_functions = nfp_context['network_functions']
            nf_elapsed_time_map = {}
            nf_status_map = {}
            if operation == nfp_constants.DELETE:
                timeout = cfg.CONF.nfp_node_driver.service_delete_timeout
            else:
                timeout = cfg.CONF.nfp_node_driver.service_create_timeout
            for nf in network_functions:
                nf_elapsed_time_map[nf] = 0
                LOG.info(_LI("STARTED POLLING for %(operation)s network "
                             "function for NF:%(network_function_id)s"),
                         {'operation': operation,
                          'network_function_id': nf})
            complete_msg = ("COMPLETED POLLING for %s network function for NF:"
                            % operation)
            while network_functions:
                for nf in network_functions[:]:
                    elapsed = nf_elapsed_time_map[nf]
                    if elapsed >= timeout:
                        network_functions.remove(nf)
                        nf_status_map[nf] = 'TIMEDOUT'
                        msg = complete_msg + "%s, status: TIMEDOUT" % nf
                        LOG.info(msg)
                    else:
                        b_time = time.time()
                        status = self._poll_for_network_function(context, nf,
                                                                 operation)
                        e_time = time.time()
                        if 'PENDING' in status:
                            nf_elapsed_time_map[nf] += (e_time - b_time)
                        else:
                            nf_status_map[nf] = status
                            network_functions.remove(nf)
                            msg = complete_msg + "%s, status:%s" % (nf, status)
                            LOG.info(msg)
                eventlet.sleep(15)
                for nf in network_functions:
                    nf_elapsed_time_map[nf] += 15

            NFPContext.clear_nfp_context(context.instance['id'])

            all_success = True
            for network_function_id, status in nf_status_map.iteritems():
                LOG.info(
                    _LI("Got %(operation)s network function result for NF:"
                        "%(network_function_id)s with status:%(status)s"),
                    {'network_function_id': network_function_id,
                     'operation': operation,
                     'status': status})
                if status == nfp_constants.ERROR or status == 'TIMEDOUT':
                    all_success = False
            if not all_success:
                if operation == nfp_constants.DELETE:
                    raise NodeInstanceDeleteFailed()
                else:
                    raise NodeInstanceCreateFailed()

    def _poll_for_network_function(self, context,
                                   network_function_id, operation):

        try:
            network_function = self.nfp_notifier.get_network_function(
                context.plugin_context, network_function_id)
            if not network_function:
                if operation == nfp_constants.DELETE:
                    return "DELETED"
                return nfp_constants.ERROR
            return network_function['status']
        except Exception as e:
            msg = "Failed to retrieve network function(nf-%s) - %r" % (
                network_function_id, e)
            LOG.error(msg)
            return nfp_constants.ERROR

    def update(self, context):
        NFPContext.clear_nfp_context(context.instance['id'])
        context._plugin_context = self._get_resource_owner_context(
            context._plugin_context)
        network_function_map = self._get_node_instance_network_function_map(
            context.plugin_session,
            context.current_node['id'],
            context.instance['id'])

        if not all([network_function_map, context.original_node.get('config'),
                    context.current_node.get('config')]):
            return

        network_function_id = network_function_map.network_function_id
        self._update(context, network_function_id)

        self._wait_for_network_function_operation_completion(
            context, network_function_id, operation=nfp_constants.UPDATE)

    def _get_node_count(self, context):
        current_specs = context.relevant_specs
        node_list = []
        for spec in current_specs:
            node_list.extend(spec['nodes'])
        NFPContext.store_nfp_context(context.instance['id'],
                                     sc_node_count=len(node_list))
        return len(node_list)

    def delete(self, context):
        nfp_context = (
            NFPContext.get_nfp_context(context.instance['id']))
        if nfp_context and not nfp_context.get('sc_node_count'):
            nfp_context['sc_node_count'] = self._get_node_count(context)

        context._plugin_context = self._get_resource_owner_context(
            context._plugin_context)
        network_function_map = self._get_node_instance_network_function_map(
            context.plugin_session,
            context.current_node['id'],
            context.instance['id'])
        network_function_id = None
        if network_function_map:
            self._delete_node_instance_network_function_map(
                context.plugin_session,
                context.current_node['id'],
                context.instance['id'])
            network_function_id = network_function_map.network_function_id

        if network_function_id:
            try:
                self.nfp_notifier.delete_network_function(
                    context=context.plugin_context,
                    network_function_id=(
                        network_function_map.network_function_id))
            except Exception:
                # NFPContext.clear_nfp_context(context.instance['id'])
                LOG.exception(_LE("Delete Network service Failed"))
                exc_type, exc_value, exc_traceback = sys.exc_info()
                message = "Traceback: %s" % (exc_value)
                LOG.error(message)

        self._update_ptg(context)
        self._wait_for_node_operation_completion(context, network_function_id,
                                                 nfp_constants.DELETE)

    def update_policy_target_added(self, context, policy_target):
        if context.current_profile['service_type'] in [pconst.LOADBALANCER,
                                                       pconst.LOADBALANCERV2]:
            if self._is_service_target(policy_target):
                return
            context._plugin_context = self._get_resource_owner_context(
                context._plugin_context)
            network_function_map =\
                self._get_node_instance_network_function_map(
                    context.plugin_session,
                    context.current_node['id'],
                    context.instance['id'])
            if network_function_map:
                network_function_id = network_function_map.network_function_id
                self.nfp_notifier.policy_target_added_notification(
                    context.plugin_context, network_function_id, policy_target)
                self._wait_for_network_function_operation_completion(
                    context, network_function_id,
                    operation=nfp_constants.UPDATE)

    def update_policy_target_removed(self, context, policy_target):
        if context.current_profile['service_type'] in [pconst.LOADBALANCER,
                                                       pconst.LOADBALANCERV2]:
            if self._is_service_target(policy_target):
                return
            context._plugin_context = self._get_resource_owner_context(
                context._plugin_context)
            network_function_map = (
                self._get_node_instance_network_function_map(
                    context.plugin_session,
                    context.current_node['id'],
                    context.instance['id']))

            if network_function_map:
                network_function_id = network_function_map.network_function_id
                self.nfp_notifier.policy_target_removed_notification(
                    context.plugin_context, network_function_id, policy_target)
                self._wait_for_network_function_operation_completion(
                    context, network_function_id,
                    operation=nfp_constants.UPDATE)

    def notify_chain_parameters_updated(self, context):
        pass  # We are not using the classifier specified in redirect Rule

    def update_node_consumer_ptg_added(self, context, policy_target_group):

        # When a group is created which is both consumer and provider.
        # method is invoked for stitching group too.. ignoring.
        if policy_target_group.get('proxied_group_id'):
            return
        if context.current_profile['service_type'] == pconst.FIREWALL:
            context._plugin_context = self._get_resource_owner_context(
                context._plugin_context)
            network_function_map = (
                self._get_node_instance_network_function_map(
                    context.plugin_session,
                    context.current_node['id'],
                    context.instance['id']))

            if network_function_map:
                network_function_id = network_function_map.network_function_id
                self.nfp_notifier.consumer_ptg_added_notification(
                    context.plugin_context,
                    network_function_id,
                    policy_target_group)
                self._wait_for_network_function_operation_completion(
                    context, network_function_id,
                    operation=nfp_constants.UPDATE)

    def update_node_consumer_ptg_removed(self, context, policy_target_group):
        # When a group is created which is both consumer and provider.
        # method is invoked for stitching group too.. ignoring.
        if policy_target_group.get('proxied_group_id'):
            return
        if context.current_profile['service_type'] == pconst.FIREWALL:
            context._plugin_context = self._get_resource_owner_context(
                context._plugin_context)
            network_function_map = (
                self._get_node_instance_network_function_map(
                    context.plugin_session,
                    context.current_node['id'],
                    context.instance['id']))

            if network_function_map:
                network_function_id = network_function_map.network_function_id
                self.nfp_notifier.consumer_ptg_removed_notification(
                    context.plugin_context,
                    network_function_id,
                    policy_target_group)
                self._wait_for_network_function_operation_completion(
                    context, network_function_id,
                    operation=nfp_constants.UPDATE)

    def policy_target_group_updated(self, context, old_ptg, current_ptg):
        if not (old_ptg and current_ptg):
            return
        if current_ptg['description']:
            desc = current_ptg['description'].split(':')
            if 'opflex_eoc' in desc:
                if (set(old_ptg[
                        'provided_policy_rule_sets']).symmetric_difference(
                            set(current_ptg['provided_policy_rule_sets']))):
                    pts = context.gbp_plugin.get_policy_targets(
                        context.plugin_context,
                        filters={'port_id': [desc[-1]]})
                    (pt,) = pts
                    filters = {'description': [current_ptg['description']]}
                    ptgs = context.gbp_plugin.get_policy_target_groups(
                        context.plugin_context, filters)
                    prs = []
                    for ptg in ptgs:
                        prs += ptg['provided_policy_rule_sets']
                    context.gbp_plugin.update_policy_target_group(
                        context.plugin_context,
                        pt['policy_target_group_id'],
                        {'policy_target_group':
                         {'provided_policy_rule_sets':
                          dict((x, '') for x in prs)}})

    def _wait_for_network_function_operation_completion(self, context,
                                                        network_function_id,
                                                        operation):
        if not network_function_id:
            raise NodeInstanceCreateFailed()

        time_waited = 0
        network_function = None
        timeout = cfg.CONF.nfp_node_driver.service_create_timeout

        while time_waited < timeout:
            network_function = self.nfp_notifier.get_network_function(
                context.plugin_context, network_function_id)
            LOG.debug("Got %s nf result for NF: %s with status:%s,"
                      "time waited: %s" % (
                          network_function_id, operation,
                          time_waited, network_function['status']))
            if not network_function:
                LOG.error(_LE("Failed to retrieve network function"))
                eventlet.sleep(5)
                time_waited = time_waited + 5
                continue
            else:
                if time_waited == 0:
                    LOG.info(_LI("STARTED POLLING for %(operation)s network "
                                 "function for NF:%(network_function_id)s "
                                 "with initial result: %(result)s "),
                             {'operation': operation,
                              'network_function_id': network_function_id,
                              'result': network_function})
            if (network_function['status'] == nfp_constants.ACTIVE or
                    network_function['status'] == nfp_constants.ERROR):
                LOG.info(_LI("COMPLETED POLLING for  %(operation)s network "
                             "function for NF:%(network_function_id)s "),
                         {'network_function_id': network_function_id,
                          'operation': operation})
                break
            eventlet.sleep(5)
            time_waited = time_waited + 5

        LOG.info(_LI("Got %(operation)s network function result for NF:"
                     "%(network_function_id)s with status:%(status)s"),
                 {'network_function_id': network_function_id,
                  'operation': operation,
                  'status': network_function['status']})

        if network_function['status'] != nfp_constants.ACTIVE:
            LOG.error(_LE("%(operation)s network function:"
                          "%(network_function)s "
                          "failed. Status: %(status)s"),
                      {'network_function': network_function_id,
                       'status': network_function['status'],
                       'operation': operation})
            if operation.lower() == nfp_constants.CREATE:
                raise NodeInstanceCreateFailed()
            elif operation.lower() == nfp_constants.UPDATE:
                raise NodeInstanceUpdateFailed()

    def _is_service_target(self, policy_target):
        if policy_target['name'] and (policy_target['name'].startswith(
                plumber_base.SERVICE_TARGET_NAME_PREFIX) or
                policy_target['name'].startswith('tscp_endpoint_service') or
                policy_target['name'].startswith('vip_pt')):
            return True
        else:
            return False

    def _resource_owner_tenant_id(self):
        user, pwd, tenant, auth_url = utils.get_keystone_creds()
        keystoneclient = keyclient.Client(username=user, password=pwd,
                                          auth_url=auth_url)
        try:
            tenant = keystoneclient.tenants.find(name=tenant)
            return tenant.id
        except k_exceptions.NotFound:
            with excutils.save_and_reraise_exception(reraise=True):
                LOG.error(_LE('No tenant with name %(tenant)s exists.'),
                          {'tenant': tenant})
        except k_exceptions.NoUniqueMatch:
            with excutils.save_and_reraise_exception(reraise=True):
                LOG.error(_LE('Multiple tenants matches found for %(tenant)s'),
                          {'tenant': tenant})

    def _get_resource_owner_context(self, plugin_context):
        # REVISIT(AKASH) Need to revisit as this api is not needed
        # with present scenarios
        '''
        if cfg.CONF.nfp_node_driver.is_service_admin_owned:
            resource_owner_context = plugin_context.elevated()
            resource_owner_context.tenant_id = self.resource_owner_tenant_id
            user, pwd, ignore_tenant, auth_url = utils.get_keystone_creds()
            keystoneclient = keyclient.Client(username=user, password=pwd,
                                              auth_url=auth_url)
            resource_owner_context.auth_token = keystoneclient.get_token(
                self.resource_owner_tenant_id)
            return resource_owner_context
        else:
            return plugin_context
        '''
        return plugin_context

    def _update(self, context, network_function_id):
        if (context.original_node['config'] != context.current_node['config']):
            try:
                self.nfp_notifier.update_network_function(
                    context=context.plugin_context,
                    network_function_id=network_function_id,
                    config=context.current_node['config'])
            except Exception:
                LOG.exception(_LE("Update Network service Failed for "
                                  "network function: %(nf_id)s"),
                              {'nf_id': network_function_id})
        else:
            LOG.info(_LI("No action to take on update"))

    def _get_service_chain_specs(self, context):
        current_specs = context.relevant_specs
        for spec in current_specs:
            filters = {'id': spec['nodes']}
            nodes = context.sc_plugin.get_servicechain_nodes(
                context.plugin_context, filters)
            for node in nodes:
                profile = context.sc_plugin.get_service_profile(
                    context.plugin_context, node['service_profile_id'])
                node['sc_service_profile'] = profile
            spec['sc_nodes'] = nodes
        return current_specs

    def _sc_head_gateway_node_service_targets(self, context,
                                              service_type, relationships):
        current_specs = context.relevant_specs
        service_targets = []
        for spec in current_specs:
            filters = {'id': spec['nodes']}
            nodes = context.sc_plugin.get_servicechain_nodes(
                context.plugin_context, filters)
            for node in nodes:
                profile = context.sc_plugin.get_service_profile(
                    context.plugin_context, node['service_profile_id'])
                if (profile['service_type'] != service_type and
                        profile['service_type'] in GATEWAY_PLUMBER_TYPE):
                    for relationship in relationships:
                        service_targets.extend(ncp_model.get_service_targets(
                            context.session,
                            servicechain_instance_id=context.instance['id'],
                            servicechain_node_id=node['id'],
                            relationship=relationship))
        return service_targets

    def _get_service_targets(self, context):
        service_type = context.current_profile['service_type']
        provider_service_targets = []
        consumer_service_targets = []
        service_flavor_str = context.current_profile['service_flavor']
        service_details = self._parse_service_flavor_string(service_flavor_str)
        nfp_context = NFPContext.get_nfp_context(context.instance['id'])
        is_gateway_type = False
        global GATEWAY_PLUMBER_TYPE
        if service_type in GATEWAY_PLUMBER_TYPE:
            for gateway_node in nfp_context['sc_gateway_type_nodes']:
                if gateway_node['context']:
                    service_target_info = gateway_node['context']
                    return service_target_info
            is_gateway_type = True

        service_targets = context.get_service_targets()
        # Bug with NCP. For create, its not setting service targets in context

        if not service_targets:
            service_targets = context.get_service_targets(update=True)

        if not service_targets and is_gateway_type:
            relationships = [nfp_constants.PROVIDER, nfp_constants.CONSUMER]
            service_targets = self._sc_head_gateway_node_service_targets(
                context,
                service_type,
                relationships)

        for service_target in service_targets:
            if service_target.relationship == nfp_constants.CONSUMER:
                consumer_service_targets.append(service_target)
            elif service_target.relationship == nfp_constants.PROVIDER:
                provider_service_targets.append(service_target)

        LOG.debug("provider targets: %s consumer targets %s" % (
            provider_service_targets, consumer_service_targets))
        if (service_details['device_type'] != 'None' and (
            not provider_service_targets or (
                service_type in [pconst.FIREWALL, pconst.VPN]
                and not consumer_service_targets))):
            LOG.error(_LE("Service Targets are not created for the Node "
                          "of service_type %(service_type)s"),
                      {'service_type': service_type})
            raise Exception("Service Targets are not created for the Node")

        if (not consumer_service_targets and
                not provider_service_targets):
            return {}

        service_target_info = {
            'provider_ports': [],
            'provider_subnet': None,
            'provider_pts': [],
            'provider_pt_objs': [],
            'provider_ptg': [],
            'consumer_ports': [],
            'consumer_subnet': None,
            'consumer_pts': [],
            'consumer_pt_objs': [],
            'consumer_ptg': []}

        for service_target in provider_service_targets:
            policy_target = context.gbp_plugin.get_policy_target(
                context.plugin_context, service_target.policy_target_id)
            policy_target_group = context.gbp_plugin.get_policy_target_group(
                context.plugin_context,
                policy_target['policy_target_group_id'])
            port = context.core_plugin.get_port(
                context.plugin_context, policy_target['port_id'])
            port['ip_address'] = port['fixed_ips'][0]['ip_address']
            subnet = context.core_plugin.get_subnet(
                context.plugin_context, port['fixed_ips'][0]['subnet_id'])
            service_target_info['provider_ports'].append(port)
            service_target_info['provider_subnet'] = subnet
            service_target_info['provider_pts'].append(policy_target['id'])
            service_target_info['provider_pt_objs'].append(policy_target)
            service_target_info['provider_ptg'].append(policy_target_group)

        for service_target in consumer_service_targets:
            policy_target = context.gbp_plugin.get_policy_target(
                context.plugin_context, service_target.policy_target_id)
            policy_target_group = context.gbp_plugin.get_policy_target_group(
                context.plugin_context,
                policy_target['policy_target_group_id'])
            port = context.core_plugin.get_port(
                context.plugin_context, policy_target['port_id'])
            port['ip_address'] = port['fixed_ips'][0]['ip_address']
            subnet = context.core_plugin.get_subnet(
                context.plugin_context, port['fixed_ips'][0]['subnet_id'])
            service_target_info['consumer_ports'].append(port)
            service_target_info['consumer_subnet'] = subnet
            service_target_info['consumer_pts'].append(policy_target['id'])
            service_target_info['consumer_pt_objs'].append(policy_target)
            service_target_info['consumer_ptg'].append(policy_target_group)

        for gateway_node in nfp_context['sc_gateway_type_nodes']:
            if gateway_node['service_type'] == service_type:
                gateway_node['context'] = service_target_info
        NFPContext.store_nfp_context(context.instance['id'],
                                     **nfp_context)
        return service_target_info

    # Needs a better algorithm
    def _is_node_order_in_spec_supported(self, context):
        current_specs = context.relevant_specs
        service_type_list_in_chain = []
        node_list = []
        for spec in current_specs:
            node_list.extend(spec['nodes'])

        for node_id in node_list:
            node_info = context.sc_plugin.get_servicechain_node(
                context.plugin_context, node_id)
            profile = context.sc_plugin.get_service_profile(
                context.plugin_context, node_info['service_profile_id'])
            service_type_list_in_chain.append(profile['service_type'])

        if len(service_type_list_in_chain) != len(
                set(service_type_list_in_chain)):
            raise DuplicateServiceTypeInChain()

        allowed_chain_combinations = [
            [pconst.VPN],
            [pconst.VPN, pconst.FIREWALL],
            [pconst.VPN, pconst.LOADBALANCER],
            [pconst.VPN, pconst.FIREWALL, pconst.LOADBALANCER],
            [pconst.VPN, pconst.FIREWALL, pconst.LOADBALANCERV2],
            [pconst.FIREWALL],
            [pconst.FIREWALL, pconst.LOADBALANCER],
            [pconst.FIREWALL, pconst.LOADBALANCERV2],
            [pconst.LOADBALANCER],
            [pconst.LOADBALANCERV2]]

        if service_type_list_in_chain not in allowed_chain_combinations:
            raise InvalidNodeOrderInChain(
                node_order=allowed_chain_combinations)

        NFPContext.store_nfp_context(context.instance['id'],
                                     sc_node_count=len(node_list))

    def _get_consumers_for_provider(self, context, provider):
        '''
        {
            consuming_ptgs_details: [{'ptg': <>, 'subnets': <>}]
            consuming_eps_details: []
        }
        '''

        consuming_ptgs = []
        consuming_ptgs_details = []
        consuming_eps_details = []

        filters = {'id': provider['provided_policy_rule_sets']}
        provided_prs = context.gbp_plugin.get_policy_rule_sets(
            context.plugin_context, filters=filters)
        redirect_prs = None
        for prs in provided_prs:
            filters = {'id': prs['policy_rules']}
            policy_rules = context.gbp_plugin.get_policy_rules(
                context.plugin_context, filters=filters)
            for policy_rule in policy_rules:
                filters = {'id': policy_rule['policy_actions'],
                           'action_type': [gconst.GP_ACTION_REDIRECT]}
                policy_actions = context.gbp_plugin.get_policy_actions(
                    context.plugin_context, filters=filters)
                if policy_actions:
                    redirect_prs = prs
                    break

        if not redirect_prs:
            LOG.error(_LE("Redirect rule doesn't exist in policy target rule "
                          " set"))
            return consuming_ptgs_details, consuming_eps_details

        consuming_ptg_ids = redirect_prs['consuming_policy_target_groups']
        consuming_ep_ids = redirect_prs['consuming_external_policies']
        if consuming_ptg_ids:
            consuming_ptgs = context.gbp_plugin.get_policy_target_groups(
                context.plugin_context, filters={'id': consuming_ptg_ids})
        if consuming_ep_ids:
            consuming_eps_details = context.gbp_plugin.get_external_policies(
                context.plugin_context, filters={'id': consuming_ep_ids})

        for ptg in consuming_ptgs:
            subnet_ids = ptg['subnets']
            subnets = context.core_plugin.get_subnets(
                context.plugin_context, filters={'id': subnet_ids})
            consuming_ptgs_details.append({'ptg': ptg, 'subnets': subnets})

        return consuming_ptgs_details, consuming_eps_details

    def _create_network_function(self, context):
        """
        nfp_create_nf_data :-

        {'resource_owner_context': <>,
         'service_chain_instance': <>,
         'service_chain_node': <>,
         'service_profile': <>,
         'service_config': context.current_node.get('config'),
         'provider': {'pt':<>, 'ptg':<>, 'port':<>, 'subnet':<>},
         'consumer': {'pt':<>, 'ptg':<>, 'port':<>, 'subnet':<>},
         'management': {'pt':<>, 'ptg':<>, 'port':<>, 'subnet':<>},
         'management_ptg_id': <>,
         'network_function_mode': nfp_constants.GBP_MODE,
         'tenant_id': <>,
         'consuming_ptgs_details': [],
         'consuming_eps_details': []
        }

        """
        nfp_create_nf_data = {}

        sc_instance = context.instance
        service_targets = self._get_service_targets(context)

        consuming_ptgs_details = []
        consuming_eps_details = []
        if service_targets:
            consuming_ptgs_details, consuming_eps_details = \
                self._get_consumers_for_provider(
                    context,
                    service_targets['provider_ptg'][0])

        if context.current_profile['service_type'] in [pconst.LOADBALANCER,
                                                       pconst.LOADBALANCERV2]:
            config_param_values = sc_instance.get('config_param_values', {})
            if config_param_values:
                config_param_values = jsonutils.loads(config_param_values)
            vip_ip = config_param_values.get('vip_ip')
            if not vip_ip:
                raise VipNspNotSetonProvider()

            if service_targets:
                for provider_port in service_targets['provider_ports']:
                    provider_port['allowed_address_pairs'] = [
                        {'ip_address': vip_ip}]
                    port = {
                        'port': provider_port
                    }
                    context.core_plugin.update_port(
                        context.plugin_context, provider_port['id'], port)

        provider = {
            'pt': service_targets.get('provider_pt_objs', []),
            'ptg': service_targets.get('provider_ptg', []),
            'port': service_targets.get('provider_ports', []),
            'subnet': service_targets.get('provider_subnet', None),
            'port_model': nfp_constants.GBP_PORT,
            'port_classification': nfp_constants.PROVIDER}

        consumer_pt = None
        consumer_ptg = None
        consumer_ports = None

        if service_targets.get('consumer_pt_objs'):
            consumer_pt = service_targets.get('consumer_pt_objs')
        if service_targets.get('consumer_ptg'):
            consumer_ptg = service_targets.get('consumer_ptg')
        if service_targets.get('consumer_ports'):
            consumer_ports = service_targets.get('consumer_ports')

        consumer = {
            'pt': consumer_pt,
            'ptg': consumer_ptg,
            'port': consumer_ports,
            'subnet': service_targets.get('consumer_subnet', None),
            'port_model': nfp_constants.GBP_PORT,
            'port_classification': nfp_constants.CONSUMER}

        management = {
            'pt': None,
            'ptg': None,
            'port': None,
            'subnet': None,
            'port_model': nfp_constants.GBP_NETWORK,
            'port_classification': nfp_constants.MANAGEMENT}

        service_chain_specs = self._get_service_chain_specs(context)

        nfp_create_nf_data = {
            'resource_owner_context': context._plugin_context.to_dict(),
            'service_chain_instance': sc_instance,
            'service_chain_node': context.current_node,
            'service_profile': context.current_profile,
            'service_config': context.current_node.get('config'),
            'provider': provider,
            'consumer': consumer,
            'management': management,
            'management_ptg_id': sc_instance['management_ptg_id'],
            'network_function_mode': nfp_constants.GBP_MODE,
            'tenant_id': context.provider['tenant_id'],
            'consuming_ptgs_details': consuming_ptgs_details,
            'consuming_eps_details': consuming_eps_details,
            'service_chain_specs': service_chain_specs}
        LOG.info(_LI("Received Call CREATE NETWORK FUNCTION for tenant: "
                     "%(tenant_id)s with service profile:"
                     "%(service_profile)s"),
                 {'tenant_id': nfp_create_nf_data['tenant_id'],
                  'service_profile': nfp_create_nf_data['service_profile']})
        return self.nfp_notifier.create_network_function(
            context.plugin_context, network_function=nfp_create_nf_data)['id']

    def _set_node_instance_network_function_map(
            self, session, sc_node_id, sc_instance_id, network_function_id):
        with session.begin(subtransactions=True):
            sc_node_instance_ns_map = (
                ServiceNodeInstanceNetworkFunctionMapping(
                    sc_node_id=sc_node_id,
                    sc_instance_id=sc_instance_id,
                    network_function_id=network_function_id))
            session.add(sc_node_instance_ns_map)

    def _get_node_instance_network_function_map(self, session, sc_node_id=None,
                                                sc_instance_id=None):
        try:
            with session.begin(subtransactions=True):
                query = session.query(
                    ServiceNodeInstanceNetworkFunctionMapping)
                if sc_node_id:
                    query = query.filter_by(sc_node_id=sc_node_id)
                if sc_instance_id:
                    query = query.filter_by(sc_instance_id=sc_instance_id)
                return query.first()
        except NoResultFound:
            return None

    def _delete_node_instance_network_function_map(self, session, sc_node_id,
                                                   sc_instance_id):
        with session.begin(subtransactions=True):
            sc_node_instance_ns_maps = (
                session.query(ServiceNodeInstanceNetworkFunctionMapping).
                filter_by(sc_node_id=sc_node_id).
                filter_by(sc_instance_id=sc_instance_id).
                all())
            for sc_node_instance_ns_map in sc_node_instance_ns_maps:
                session.delete(sc_node_instance_ns_map)

    def _update_ptg(self, context):
        if hasattr(context, 'provider') and context.provider['description']:
            gateway_desc = 'opflex_eoc' in context.provider[
                'description'].split(':')
            if gateway_desc:
                pts = context.gbp_plugin.get_policy_targets(
                    context.plugin_context,
                    filters={'port_id': [context.provider[
                        'description'].split(':')][-1]})
                (pt,) = pts
                filters = {'description': [context.provider['description']]}
                ptgs = context.gbp_plugin.get_policy_target_groups(
                    context.plugin_context, filters)
                prs = []
                for ptg in ptgs:
                    prs += ptg['provided_policy_rule_sets']
                context.gbp_plugin.update_policy_target_group(
                    context.plugin_context,
                    pt['policy_target_group_id'],
                    {'policy_target_group':
                     {'provided_policy_rule_sets':
                      dict((x, '') for x in prs)}})
