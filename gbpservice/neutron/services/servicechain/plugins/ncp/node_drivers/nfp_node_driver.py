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
from eventlet import greenpool

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
from gbpservice.neutron.services.servicechain.plugins.ncp import (
    exceptions as exc)
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
               default=600,
               help=_("Seconds to wait for service creation "
                      "to complete")),
    cfg.IntOpt('service_delete_timeout',
               default=120,
               help=_("Seconds to wait for service deletion "
                      "to complete")),
]
# REVISIT(ashu): Can we use is_service_admin_owned config from RMD
cfg.CONF.register_opts(NFP_NODE_DRIVER_OPTS, "nfp_node_driver")


LOG = logging.getLogger(__name__)


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
        cctxt = self.client.prepare(
            fanout=False, topic=nfp_rpc_topics.NFP_NSO_TOPIC)
        return cctxt.call(
            context,
            'create_network_function',
            network_function=network_function)

    def delete_network_function(self, context, network_function_id):
        cctxt = self.client.prepare(version=self.RPC_API_VERSION)
        return cctxt.call(
            context,
            'delete_network_function',
            network_function_id=network_function_id)

    def update_network_function(self, context, network_function_id, config):
        cctxt = self.client.prepare(version=self.RPC_API_VERSION)
        return cctxt.call(
            context,
            'update_network_function',
            network_function_id=network_function_id,
            config=config)

    def get_network_function(self, context, network_function_id):
        cctxt = self.client.prepare(version=self.RPC_API_VERSION)
        return cctxt.call(
            context,
            'get_network_function',
            network_function_id=network_function_id)

    def consumer_ptg_added_notification(self, context, network_function_id,
                                        policy_target_group):
        cctxt = self.client.prepare(version=self.RPC_API_VERSION)
        return cctxt.call(context,
                   'consumer_ptg_added_notification',
                   network_function_id=network_function_id,
                   policy_target_group=policy_target_group)

    def consumer_ptg_removed_notification(self, context, network_function_id,
                                          policy_target_group):
        cctxt = self.client.prepare(version=self.RPC_API_VERSION)
        return cctxt.call(context,
                   'consumer_ptg_removed_notification',
                   network_function_id=network_function_id,
                   policy_target_group=policy_target_group)

    def policy_target_added_notification(self, context, network_function_id,
                                         policy_target):
        cctxt = self.client.prepare(version=self.RPC_API_VERSION)
        return cctxt.call(context,
                   'policy_target_added_notification',
                   network_function_id=network_function_id,
                   policy_target=policy_target)

    def policy_target_removed_notification(self, context, network_function_id,
                                           policy_target):
        cctxt = self.client.prepare(version=self.RPC_API_VERSION)
        return cctxt.call(context,
                   'policy_target_removed_notification',
                   network_function_id=network_function_id,
                   policy_target=policy_target)


class NFPNodeDriver(driver_base.NodeDriverBase):
    SUPPORTED_SERVICE_TYPES = [
        pconst.LOADBALANCER, pconst.FIREWALL, pconst.VPN,
        pconst.LOADBALANCERV2]
    SUPPORTED_SERVICE_VENDOR_MAPPING = {
        pconst.LOADBALANCERV2: [nfp_constants.HAPROXY_LBAASV2],
        pconst.LOADBALANCER: [nfp_constants.HAPROXY_VENDOR],
        pconst.FIREWALL: [nfp_constants.VYOS_VENDOR, nfp_constants.NFP_VENDOR],
        pconst.VPN: [nfp_constants.VYOS_VENDOR],
    }
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
        self.thread_pool = greenpool.GreenPool(10)
        self.active_threads = []
        self.sc_node_count = 0

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
        context._plugin_context = self._get_resource_owner_context(
            context._plugin_context)
        service_type = context.current_profile['service_type']

        service_flavor_str = context.current_profile['service_flavor']
        service_details = self._parse_service_flavor_string(service_flavor_str)
        if service_details['device_type'] == 'None':
            return {}
        # Management PTs are managed by NFP since it supports hosting multiple
        # logical services in a single device
        plumbing_request = {'management': [], 'provider': [{}],
                            'consumer': [{}]}

        if service_type in [pconst.FIREWALL, pconst.VPN]:
            plumbing_request['plumbing_type'] = (
                    nfp_constants.GATEWAY_TYPE)
        else:  # Loadbalancer which is one arm
            plumbing_request['consumer'] = []
            plumbing_request['plumbing_type'] = (
                    nfp_constants.ENDPOINT_TYPE)

        LOG.info(_LI("Requesting plumber for %(plumbing_request)s PTs for "
                   "service type %(service_type)s"),
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
        service_vendor = self._parse_service_flavor_string(
            context.current_profile['service_flavor'])['service_vendor']
        if (service_vendor.lower() not in
            self.SUPPORTED_SERVICE_VENDOR_MAPPING[
                context.current_profile['service_type']]):
            raise UnSupportedServiceProfile(
                service_type=context.current_profile['service_type'],
                vendor=context.current_profile['vendor'])
        self._is_node_order_in_spec_supported(context)

    def validate_update(self, context):
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
        service_vendor = self._parse_service_flavor_string(
            context.current_profile['service_flavor'])['service_vendor']
        if (service_vendor.lower() not in
            self.SUPPORTED_SERVICE_VENDOR_MAPPING[
                context.current_profile['service_type']]):
            raise UnSupportedServiceProfile(
                service_type=context.current_profile['service_type'],
                vendor=context.current_profile['vendor'])

    def _wait(self, thread):
        try:
            result = thread.wait()
            return result
        except Exception as e:
            self.active_threads = []
            raise e

    def create(self, context):
        try:
            context._plugin_context = self._get_resource_owner_context(
                context._plugin_context)
            network_function_id = self._create_network_function(context)
            self._set_node_instance_network_function_map(
                context.plugin_session, context.current_node['id'],
                context.instance['id'], network_function_id)
        except Exception as e:
            self.sc_node_count -= 1
            raise e

        # Check for NF status in a separate thread
        LOG.debug("Spawning thread for nf ACTIVE poll")

        gth = self.thread_pool.spawn(
            self._wait_for_network_function_operation_completion,
            context, network_function_id, operation=nfp_constants.CREATE)

        self.active_threads.append(gth)

        LOG.debug("Active Threads count (%d), sc_node_count (%d)" % (
            len(self.active_threads), self.sc_node_count))

        self.sc_node_count -= 1

        # At last wait for the threads to complete, success/failure/timeout
        if self.sc_node_count == 0:
            self.thread_pool.waitall()
            # Get the results
            for gth in self.active_threads:
                self._wait(gth)
            self.active_threads = []

    def update(self, context):
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

    def delete(self, context):
        context._plugin_context = self._get_resource_owner_context(
            context._plugin_context)
        network_function_map = self._get_node_instance_network_function_map(
            context.plugin_session,
            context.current_node['id'],
            context.instance['id'])

        if not network_function_map:
            return

        network_function_id = network_function_map.network_function_id
        try:
            self.nfp_notifier.delete_network_function(
                context=context.plugin_context,
                network_function_id=network_function_id)
        except Exception:
            LOG.exception(_LE("Delete Network service Failed"))

        self._wait_for_network_function_delete_completion(
            context, network_function_id)
        self._delete_node_instance_network_function_map(
            context.plugin_session,
            context.current_node['id'],
            context.instance['id'])

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

    def _wait_for_network_function_delete_completion(self, context,
                                                     network_function_id):
        time_waited = 0
        network_function = None
        while time_waited < cfg.CONF.nfp_node_driver.service_delete_timeout:
            network_function = self.nfp_notifier.get_network_function(
                context.plugin_context, network_function_id)
            if not network_function:
                break
            eventlet.sleep(5)
            time_waited = time_waited + 5

        if network_function:
            LOG.error(_LE("Delete network function %(network_function)s "
                          "failed"),
                      {'network_function': network_function_id})
            raise NodeInstanceDeleteFailed()

    def _wait_for_network_function_operation_completion(self, context,
                                                        network_function_id,
                                                        operation):
        time_waited = 0
        network_function = None
        timeout = cfg.CONF.nfp_node_driver.service_create_timeout
        while time_waited < timeout:
            network_function = self.nfp_notifier.get_network_function(
                context.plugin_context, network_function_id)
            if not network_function:
                LOG.error(_LE("Failed to retrieve network function"))
                eventlet.sleep(5)
                time_waited = time_waited + 5
                continue
            else:
                LOG.info(_LI("%(operation)s network function result: "
                             "%(network_function)s"),
                         {'network_function': network_function,
                          'operation': operation})
            if (network_function['status'] == nfp_constants.ACTIVE or
                network_function['status'] == nfp_constants.ERROR):
                break
            eventlet.sleep(5)
            time_waited = time_waited + 5

        LOG.info(_LI("%(operation)s Got network function result: "
                     "%(network_function)s"),
                 {'network_function': network_function,
                  'operation': operation})

        if network_function['status'] != nfp_constants.ACTIVE:
            LOG.error(_LE("%(operation)s network function"
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
                LOG.error(_LE('No tenant with name %s exists.'), tenant)
        except k_exceptions.NoUniqueMatch:
            with excutils.save_and_reraise_exception(reraise=True):
                LOG.error(_LE('Multiple tenants matches found for %s'), tenant)

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

    def _get_service_targets(self, context):
        service_type = context.current_profile['service_type']
        provider_service_targets = []
        consumer_service_targets = []
        service_flavor_str = context.current_profile['service_flavor']
        service_details = self._parse_service_flavor_string(service_flavor_str)
        service_targets = context.get_service_targets()
        # Bug with NCP. For create, its not setting service targets in context
        if not service_targets:
            service_targets = context.get_service_targets(update=True)

        if not service_targets:
            return {}

        for service_target in service_targets:
            if service_target.relationship == nfp_constants.CONSUMER:
                consumer_service_targets.append(service_target)
            elif service_target.relationship == nfp_constants.PROVIDER:
                provider_service_targets.append(service_target)
        LOG.debug("provider targets: %s consumer targets %s" % (
            provider_service_targets, consumer_service_targets))
        if (service_details['device_type'] != 'None' and (
            not provider_service_targets or (service_type in
            [pconst.FIREWALL, pconst.VPN] and not consumer_service_targets))):
                LOG.error(_LE("Service Targets are not created for the Node "
                            "of service_type %(service_type)s"),
                          {'service_type': service_type})
                raise Exception("Service Targets are not created for the Node")

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

        self.sc_node_count = len(node_list)

    def _get_consumers_for_provider(self, context, provider):
        '''
        {
            consuming_ptgs_details: [{'ptg': <>, 'subnets': <>}]
            consuming_eps_details: []
        }
        '''

        consuming_ptgs_details = []
        consuming_eps_details = []

        if not provider['provided_policy_rule_sets']:
            return consuming_ptgs_details, consuming_eps_details

        provided_prs_id = provider['provided_policy_rule_sets'][0]
        provided_prs = context.gbp_plugin.get_policy_rule_set(
            context.plugin_context, provided_prs_id)
        consuming_ptg_ids = provided_prs['consuming_policy_target_groups']
        consuming_ep_ids = provided_prs['consuming_external_policies']

        consuming_ptgs = context.gbp_plugin.get_policy_target_groups(
                context.plugin_context, filters={'id': consuming_ptg_ids})
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
                self._get_consumers_for_provider(context,
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
            'pt': service_targets.get('provider_pt_objs', [None])[0],
            'ptg': service_targets.get('provider_ptg', [None])[0],
            'port': service_targets.get('provider_ports', [None])[0],
            'subnet': service_targets.get('provider_subnet', None),
            'port_model': nfp_constants.GBP_PORT,
            'port_classification': nfp_constants.PROVIDER}

        consumer_pt = None
        consumer_ptg = None
        consumer_ports = None

        if service_targets.get('consumer_pt_objs'):
            consumer_pt = service_targets.get('consumer_pt_objs')[0]
        if service_targets.get('consumer_ptg'):
            consumer_ptg = service_targets.get('consumer_ptg')[0]
        if service_targets.get('consumer_ports'):
            consumer_ports = service_targets.get('consumer_ports')[0]

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
            'consuming_eps_details': consuming_eps_details}

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
