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

from gbpservice.contrib.nfp.config_orchestrator.common import (
    topics as a_topics)
from gbpservice.nfp.core import log as nfp_logging
from gbpservice.nfp.lib import transport
from gbpservice.nfp.orchestrator.openstack import openstack_driver

from neutron.common import constants as n_constants
from neutron.common import rpc as n_rpc
from neutron.common import topics as n_topics

import oslo_messaging as messaging

LOG = nfp_logging.getLogger(__name__)


def prepare_request_data(context, resource, resource_type,
                         resource_data, service_vendor=None):

    request_data = {'info': {
        'context': context,
        'service_type': resource_type,
        'service_vendor': service_vendor
    },

        'config': [{
            'resource': resource,
            'resource_data': resource_data
        }]
    }

    return request_data


def _filter_data(routers, networks, filters):
    # filter routers and networks data and formulate
    # dictionary of subnets, routers and ports for the
    # given tenant.
    tenant_id = filters['tenant_id'][0]
    _filtered_routers = []
    _filtered_subnets = []
    _filtered_ports = []
    _filtered_networks = []
    for router in routers:
        if router['tenant_id'] == tenant_id:
            _filtered_routers.append({'id': router['id']})
    for network in networks:
        if network['tenant_id'] == tenant_id:
            subnets = network['subnets']
            ports = network['ports']
            _filtered_networks.append(
                {'id': network['id'],
                 'tenant_id': network['tenant_id'],
                 'provider:segmentation_id': network[
                     'provider:segmentation_id'],
                 'provider:network_type': network[
                     'provider:network_type'],
                 'shared': network['shared'],
                 'router:external': network['router:external']})
            for subnet in subnets:
                if subnet['tenant_id'] == tenant_id:
                    _filtered_subnets.append(
                        {'id': subnet['id'],
                         'cidr': subnet['cidr'],
                         'gateway_ip': subnet['gateway_ip'],
                         'network_id': subnet['network_id']})
            for port in ports:
                if port['tenant_id'] == tenant_id:
                    _filtered_ports.append(
                        {'id': port['id'],
                         'fixed_ips': port['fixed_ips'],
                         'binding:host_id': port['binding:host_id'],
                         'network_id': port['network_id']})

    return {'subnets': _filtered_subnets,
            'routers': _filtered_routers,
            'ports': _filtered_ports,
            'networks': _filtered_networks}


def get_core_context(context, filters, config):
    #routers = get_routers(context, config.host)
    routers = []
    networks = get_networks(context, config)
    return _filter_data(routers, networks, filters)


def get_routers(context, host):
    target = messaging.Target(topic=n_topics.L3PLUGIN, version='1.0')
    client = n_rpc.get_client(target)
    cctxt = client.prepare()
    return cctxt.call(context, 'sync_routers', host=host,
                      router_ids=None)


def get_dhcp_agent_host(config):
    try:
        neutronclient = openstack_driver.NeutronClient(config)
        keystoneclient = openstack_driver.KeystoneClient(config)
        token = keystoneclient.get_admin_token()
        filters = {'agent_type': 'DHCP agent', 'alive': True}
        agents = neutronclient.get_agents(token, filters)
        if agents:
            return agents[0].get('host', None)
    except Exception as exc:
        LOG.error("Failed to get dhcp agent host : %(exc)s",
                  {'exc': exc})


def get_networks(context, config):
    host = get_dhcp_agent_host(config)
    if not host:
        return []
    target = messaging.Target(
        topic=n_topics.PLUGIN,
        namespace=n_constants.RPC_NAMESPACE_DHCP_PLUGIN,
        version='1.0')
    client = n_rpc.get_client(target)
    cctxt = client.prepare(version='1.1')
    return cctxt.call(context, 'get_active_networks_info',
                      host=host)


def _prepare_structure(network_function_details, ports_info,
                       mngmt_port_info, monitor_port_info):
    return {'nfi_ports_map': {
        network_function_details[
            'network_function_instance'][
            'id']: ports_info},
            'nfi_nfd_map': {
                network_function_details[
                    'network_function_instance'][
                    'id']: {
                    'nfd': network_function_details[
                        'network_function_device'],
                    'nfd_mgmt_port': mngmt_port_info,
                    'nfd_monitoring_port': None,
                    'nfd_monitoring_port_network': network_function_details[
                        'network_function_device'][
                            'monitoring_port_network']}},
            'nfi': [network_function_details['network_function_instance']],
            'nf': network_function_details['network_function']
            }


def get_network_function_details(context, network_function_id):
    network_function_details = None
    try:
        rpc_nso_client = transport.RPCClient(a_topics.NFP_NSO_TOPIC)
        network_function_details = rpc_nso_client.cctxt.call(
            context,
            'get_network_function_details',
            network_function_id=network_function_id)
        msg = (" %s " % (network_function_details))
        LOG.debug(msg)
        return network_function_details['network_function']

    except Exception as e:
        LOG.error("Failed to get network function details of "
                  "network_function_id %(network_function_id)s : %(ex)s ",
                  {'ex': e, 'network_function_id': network_function_id})


def get_network_function_map(context, network_function_id):
    request_data = None
    try:
        rpc_nso_client = transport.RPCClient(a_topics.NFP_NSO_TOPIC)
        nf_context = rpc_nso_client.cctxt.call(
            context,
            'get_network_function_context',
            network_function_id=network_function_id)

        network_function_details = nf_context['network_function_details']
        ports_info = nf_context['ports_info']
        mngmt_port_info = nf_context['mngmt_port_info']
        monitor_port_info = nf_context['monitor_port_info']

        request_data = _prepare_structure(network_function_details, ports_info,
                                          mngmt_port_info, monitor_port_info)
        msg = (" %s " % (request_data))
        LOG.debug(msg)
        return request_data
    except Exception as e:
        LOG.error("Failed to get network function map of "
                  "network_function_id %(network_function_id)s : %(ex)s ",
                  {'ex': e, 'network_function_id': network_function_id})
        return request_data
