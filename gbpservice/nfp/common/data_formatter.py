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

import copy

from gbpservice.nfp.common import constants as const

''' The generic data format that is common for device and
service configuration.

'''

NFP_DATA_FORMAT = {
    'config': [{
        'resource': '',
        'resource_data': {
            'tenant_id': '',
            'nfds': [{
                'role': 'master',
                'svc_mgmt_fixed_ip': '',
                'networks': [{
                    'type': '',
                    'cidr': '',
                    'gw_ip': '',
                    'ports': [{
                        'fixed_ip': '',
                        'floating_ip': '',
                        'mac': ''}]  # ports
                        }]  # networks
                      }]  # nfds
                    }  # resource_data
            }]  # config
        }  # NFP_DATA_FORMAT


def _fill_service_specific_info(nfd, device_data, **kwargs):
    ''' Service specific data formatting is done here.

    :param nfd: A partly built nested dict from NFP_DATA_FORMAT
    :param device_data: Device data dictionary
    :param kwargs: service specific arguments

    Returns: nfd dict

    '''

    network_schema = kwargs.get('network_schema')
    resource_type = kwargs.get('resource_type')
    provider_network = nfd['networks'][0]
    provider_port = provider_network['ports'][0]

    if resource_type == const.FIREWALL:
        nfd['svc_mgmt_fixed_ip'] = device_data.get('vm_management_ip')
        provider_port['mac'] = device_data.get('provider_ptg_info')[0]
    elif resource_type == const.VPN:
        stitching_network = nfd['networks'][1]
        stitching_port = stitching_network['ports'][0]
        nfd['svc_mgmt_fixed_ip'] = device_data.get('fip')
        provider_network['cidr'] = device_data.get('tunnel_local_cidr')
        stitching_port['fixed_ip'] = device_data.get('fixed_ip')
        stitching_port['floating_ip'] = device_data.get('user_access_ip')
        stitching_network['cidr'] = device_data.get('stitching_cidr')
        stitching_network['gw_ip'] = device_data.get('stitching_gateway')
        management_network = copy.deepcopy(network_schema)
        management_network['type'] = const.MANAGEMENT
        management_network['gw_ip'] = device_data.get('mgmt_gw_ip')
        nfd['networks'].append(management_network)
    elif resource_type == const.LOADBALANCERV2:
        nfd['svc_mgmt_fixed_ip'] = device_data.get('floating_ip')
        provider_port['mac'] = device_data.get('provider_interface_mac')
    return nfd


def get_network_function_info(device_data, resource_type):
    ''' Returns a generic configuration format for both device
    and service configuration.

    :param device_data: Data to be formatted. Type: dict
    :param resource_type: (healthmonitor/device_config/firewall/
    vpn/loadbalancer/loadbalancerv2)

    Return: dictionary

    '''

    SERVICE_TYPES = [const.FIREWALL, const.VPN,
                     const.LOADBALANCERV2]
    config = copy.deepcopy(NFP_DATA_FORMAT)

    mgmt_ip = device_data.get('mgmt_ip_address')
    tenant_id = device_data.get('tenant_id')
    provider_ip = device_data.get('provider_ip')
    provider_mac = device_data.get('provider_mac')
    provider_cidr = device_data.get('provider_cidr')
    stitching_ip = device_data.get('consumer_ip')
    stitching_mac = device_data.get('consumer_mac')
    stitching_cidr = device_data.get('consumer_cidr')
    stitching_gateway_ip = device_data.get('consumer_gateway_ip')

    resource_data = config['config'][0]['resource_data']
    resource_data['tenant_id'] = tenant_id

    nfd = resource_data['nfds'][0]
    nfd['role'] = 'master'
    nfd['svc_mgmt_fixed_ip'] = mgmt_ip

    if resource_type == const.HEALTHMONITOR_RESOURCE:
        nfd['periodicity'] = device_data.get('periodicity')
        nfd['periodic_polling_reason'] = const.DEVICE_TO_BECOME_DOWN
        nfd['vmid'] = device_data['id']
        config['config'][0]['resource'] = const.HEALTHMONITOR_RESOURCE
        return config

    provider_network = nfd['networks'][0]
    network_schema = copy.deepcopy(provider_network)
    provider_network['type'] = const.PROVIDER
    provider_network['cidr'] = provider_cidr
    provider_network['gw_ip'] = ''
    stitching_network = copy.deepcopy(network_schema)
    stitching_network['type'] = const.STITCHING
    stitching_network['cidr'] = stitching_cidr
    stitching_network['gw_ip'] = stitching_gateway_ip
    nfd['networks'].append(stitching_network)

    provider_port = provider_network['ports'][0]
    provider_port['fixed_ip'] = provider_ip
    provider_port['floating_ip'] = ''
    provider_port['mac'] = provider_mac
    stitching_port = stitching_network['ports'][0]
    stitching_port['fixed_ip'] = stitching_ip
    stitching_port['floating_ip'] = ''
    stitching_port['mac'] = stitching_mac

    if resource_type in SERVICE_TYPES:
        nfd = _fill_service_specific_info(nfd, device_data,
                                          network_schema=network_schema,
                                          resource_type=resource_type)
        resource_data['nfs'] = resource_data.pop('nfds')
        return config['config'][0]['resource_data']

    config['config'][0]['resource'] = const.INTERFACE_RESOURCE
    config['config'].append(config['config'][0].copy())
    config['config'][1]['resource'] = const.ROUTES_RESOURCE

    return config
