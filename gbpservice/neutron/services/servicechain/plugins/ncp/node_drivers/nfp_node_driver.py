# Copyright (c) 2016 OpenStack Foundation.
#
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
                "of nodes defined in the current service chain spec")


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


class ServiceNodeInstanceNetworkFunctionMapping(model_base.BASEV2):
    """ServiceChainInstance to NFP network function mapping."""

    __tablename__ = 'ncp_node_instance_network_function_mappings'
    sc_instance_id = sa.Column(sa.String(36),
                               nullable=False, primary_key=True)
    sc_node_id = sa.Column(sa.String(36),
                           nullable=False, primary_key=True)
    network_function_id = sa.Column(sa.String(36),
                                   nullable=False, primary_key=True)


# These callback apis are not used today, This is supposed to be used when
# GBP supports asynchronous operations
class NFPCallbackApi(object):
    RPC_API_VERSION = "1.0"
    target = oslo_messaging.Target(version=RPC_API_VERSION)

    def __init__(self, node_driver):
        self.node_driver = node_driver

    def network_function_created(self, context, network_function):
        pass

    def network_function_deleted(self, context, network_function):
        pass


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
        # cctxt.cast(context, 'create_service', service_info=service_info)

    def delete_network_function(self, context, network_function_id):
        cctxt = self.client.prepare(version=self.RPC_API_VERSION)
        return cctxt.call(
            context,
            'delete_network_function',
            network_function_id=network_function_id)

    def get_network_function(self, context, network_function_id):
        cctxt = self.client.prepare(version=self.RPC_API_VERSION)
        return cctxt.call(
            context,
            'get_network_function',
            network_function_id=network_function_id)

    def consumer_ptg_added_notification(self, context, network_function_id,
                                        policy_target_group):
        cctxt = self.client.prepare(version=self.RPC_API_VERSION)
        cctxt.cast(context,
                   'consumer_ptg_added_notification',
                   network_function_id=network_function_id,
                   policy_target_group=policy_target_group)
        '''
        return cctxt.call(
            context,
            'consumer_ptg_added_notification',
            network_function_id=network_function_id,
            policy_target_group=policy_target_group)
        '''

    def consumer_ptg_removed_notification(self, context, network_function_id,
                                          policy_target_group):
        cctxt = self.client.prepare(version=self.RPC_API_VERSION)
        cctxt.cast(context,
                   'consumer_ptg_removed_notification',
                   network_function_id=network_function_id,
                   policy_target_group=policy_target_group)
        '''
        return cctxt.call(
            context,
            'consumer_ptg_removed_notification',
            network_function_id=network_function_id,
            policy_target_group=policy_target_group)
        '''

    def policy_target_added_notification(self, context, network_function_id,
                                         policy_target):
        cctxt = self.client.prepare(version=self.RPC_API_VERSION)
        cctxt.cast(context,
                   'policy_target_added_notification',
                   network_function_id=network_function_id,
                   policy_target=policy_target)
        '''
        return cctxt.call(
            context,
            'policy_target_added_notification',
            network_function_id=network_function_id,
            policy_target=policy_target)
        '''

    def policy_target_removed_notification(self, context, network_function_id,
                                           policy_target):
        cctxt = self.client.prepare(version=self.RPC_API_VERSION)
        cctxt.cast(context,
                   'policy_target_removed_notification',
                   network_function_id=network_function_id,
                   policy_target=policy_target)
        '''
        return cctxt.call(
            context,
            'policy_target_removed_notification',
            network_function_id=network_function_id,
            policy_target=policy_target)
        '''


class NFPNodeDriver(driver_base.NodeDriverBase):
    SUPPORTED_SERVICE_TYPES = [
        pconst.LOADBALANCER, pconst.FIREWALL, pconst.VPN]
    SUPPORTED_SERVICE_VENDOR_MAPPING = {
        pconst.LOADBALANCER: ["haproxy"],
        pconst.FIREWALL: ["vyos"],
        pconst.VPN: ["vyos"],
    }
    vendor_name = 'NFP'
    required_heat_resources = {
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
        self._setup_rpc_listeners()
        self._setup_rpc()

    def _setup_rpc_listeners(self):
        self.endpoints = [NFPCallbackApi(self)]
        self.topic = nfp_rpc_topics.NFP_NODE_DRIVER_CALLBACK_TOPIC
        self.conn = n_rpc.create_connection(new=True)
        self.conn.create_consumer(self.topic, self.endpoints, fanout=False)
        return self.conn.consume_in_threads()

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
            plumbing_request['plumbing_type'] = 'gateway'
        else:  # Loadbalancer which is one arm
            plumbing_request['consumer'] = []
            plumbing_request['plumbing_type'] = 'endpoint'

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
        if context.current_profile['insertion_mode'].lower() != "l3":
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
        if context.current_profile['insertion_mode'].lower() != "l3":
            raise UnSupportedInsertionMode()
        if context.current_profile['service_type'] not in (
            self.SUPPORTED_SERVICE_TYPES):
            raise InvalidServiceType()
        if (context.current_profile['service_flavor'].lower() not in
            self.SUPPORTED_SERVICE_VENDOR_MAPPING[
                context.current_profile['service_type']]):
            raise UnSupportedServiceProfile(
                service_type=context.current_profile['service_type'],
                vendor=context.current_profile['vendor'])

    def create(self, context):
        context._plugin_context = self._get_resource_owner_context(
            context._plugin_context)
        network_function_id = self._create_network_function(context)
        self._set_node_instance_network_function_map(
            context.plugin_session, context.current_node['id'],
            context.instance['id'], network_function_id)
        self._wait_for_network_function_create_completion(
            context, network_function_id)

    def update(self, context):
        context._plugin_context = self._get_resource_owner_context(
            context._plugin_context)
        self._update(context)

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
        if context.current_profile['service_type'] == pconst.LOADBALANCER:
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

    def update_policy_target_removed(self, context, policy_target):
        if context.current_profile['service_type'] == pconst.LOADBALANCER:
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

    def _wait_for_network_function_create_completion(self, context,
                                                     network_function_id):
        time_waited = 0
        network_function = None
        while time_waited < cfg.CONF.nfp_node_driver.service_create_timeout:
            network_function = self.nfp_notifier.get_network_function(
                context.plugin_context, network_function_id)
            if not network_function:
                LOG.error(_LE("Failed to retrieve network function"))
                eventlet.sleep(5)
                time_waited = time_waited + 5
                continue
            else:
                LOG.info(_LI("Create network function result: "
                             "%(network_function)s"),
                         {'network_function': network_function})
            if (network_function['status'] == 'ACTIVE' or
                network_function['status'] == 'ERROR'):
                break
            eventlet.sleep(5)
            time_waited = time_waited + 5

        if network_function['status'] != 'ACTIVE':
            LOG.error(_LE("Create network function %(network_function)s "
                          "failed. Status: %(status)s"),
                      {'network_function': network_function_id,
                       'status': network_function['status']})
            raise NodeInstanceCreateFailed()

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

    def _update(self, context, pt_added_or_removed=False):
        if context.current_profile['service_type'] == pconst.LOADBALANCER:
            if (not context.original_node or
                context.original_node == context.current_node):
                LOG.info(_LI("No action to take on update"))
                return
        self.nfp_notifier.update_service_config()

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
        for service_target in service_targets:
            if service_target.relationship == 'consumer':
                consumer_service_targets.append(service_target)
            elif service_target.relationship == 'provider':
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

        service_target_info = {'provider_ports': [], 'provider_pts': [],
                               'consumer_ports': [], 'consumer_pts': []}
        for service_target in provider_service_targets:
            policy_target = context.gbp_plugin.get_policy_target(
                context.plugin_context, service_target.policy_target_id)
            port = context.core_plugin.get_port(
                context.plugin_context, policy_target['port_id'])
            service_target_info['provider_ports'].append(port)
            service_target_info['provider_pts'].append(policy_target['id'])

        for service_target in consumer_service_targets:
            policy_target = context.gbp_plugin.get_policy_target(
                context.plugin_context, service_target.policy_target_id)
            port = context.core_plugin.get_port(
                context.plugin_context, policy_target['port_id'])
            service_target_info['consumer_ports'].append(port)
            service_target_info['consumer_pts'].append(policy_target['id'])

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
            [pconst.FIREWALL],
            [pconst.FIREWALL, pconst.LOADBALANCER],
            [pconst.LOADBALANCER]]
        if service_type_list_in_chain not in allowed_chain_combinations:
            raise InvalidNodeOrderInChain()

    def _create_network_function(self, context):
        sc_instance = context.instance
        service_targets = self._get_service_targets(context)
        if context.current_profile['service_type'] == pconst.LOADBALANCER:
            config_param_values = sc_instance.get('config_param_values', {})
            if config_param_values:
                config_param_values = jsonutils.loads(config_param_values)
            vip_ip = config_param_values.get('vip_ip')
            if not vip_ip:
                raise VipNspNotSetonProvider()

            for provider_port in service_targets['provider_ports']:
                provider_port['allowed_address_pairs'] = [
                    {'ip_address': vip_ip}]
                port = {
                    'port': provider_port
                }
                context.core_plugin.update_port(
                    context.plugin_context, provider_port['id'], port)

        port_info = []
        if service_targets.get('provider_pts'):
            # Device case, for Base mode ports won't be available.
            port_info = [
                {
                    'id': service_targets['provider_pts'][0],
                    'port_model': nfp_constants.GBP_PORT,
                    'port_classification': nfp_constants.PROVIDER,
                }
            ]
        if service_targets.get('consumer_ports'):
            port_info.append({
                'id': service_targets['consumer_pts'][0],
                'port_model': nfp_constants.GBP_PORT,
                'port_classification': nfp_constants.CONSUMER,
            })
        network_function = {
            'tenant_id': context.provider['tenant_id'],
            'service_chain_id': sc_instance['id'],
            'service_id': context.current_node['id'],
            'service_profile_id': context.current_profile['id'],
            'management_ptg_id': sc_instance['management_ptg_id'],
            'service_config': context.current_node.get('config'),
            'port_info': port_info,
            'network_function_mode': nfp_constants.GBP_MODE,
        }

        return self.nfp_notifier.create_network_function(
            context.plugin_context, network_function=network_function)['id']

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
