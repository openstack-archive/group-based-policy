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

from gbpservice.contrib.nfp.configurator.lib import constants as const
from gbpservice.nfp.core import log as nfp_logging

LOG = nfp_logging.getLogger(__name__)


class ServiceAgentDemuxer(object):
    """Implements supporting methods for configurator module.

    Provides methods that take configurator API request data and helps
    configurator to de-multiplex the API calls to different service agents
    and drivers.

    Format of request data for network device configuration API:
    request_data {
        info {
            version: <v1/v2/v3>
        }
        config [
            {
                'resource': <healthmonitor/routes/interfaces>,
                'kwargs': <resource parameters>
            },
            {
            'resource': <healthmonitor/routes/interfaces>,
            'kwargs': <resource parameters>
            }, ...
        ]
    }
    Format of request data for network service configuration API:
    request_data {
        info {
            version: <v1/v2/v3>
            type: <firewall/vpn/loadbalancer>
        }
        config [
            {
                'resource': <healthmonitor/routes/interfaces>,
                'kwargs': <resource parameters>
            },
            {
            'resource': <healthmonitor/routes/interfaces>,
            'kwargs': <resource parameters>
            }, ...
        ]
    }

    """

    def __init__(self):
        pass

    def get_service_type(self, request_data):
        """Retrieves service type from request data.

        :param request_data: API input data (format specified at top of file)

        Returns:
        (1) "firewall"/"vpn"/"loadbalancer"
        (2) "generic_config" if service_type field is absent in request_data
        (3) "invalid" if any other service type is provided in request_data

        """

        # Get service type based on the fact that for some request data
        # formats the 'type' key is absent. Check for invalid types
        service_type = request_data['info'].get('service_type').lower()
        return service_type

    def get_service_agent_info(self, operation, resource_type,
                               request_data, is_generic_config):
        """Prepares information for service agent consumption.

        :param operation: create/delete/update
        :param resource_type: firewall/vpn/loadbalancer/generic_config
        :param request_data: API input data (format specified at top of file)

        Returns: List with the following format.
        sa_info_list [
            {
                'context': <context dictionary>
                'resource_type': <firewall/vpn/loadbalancer/generic_config>
                'method': <*aas RPC methods/generic configuration methods>
                'kwargs' <kwargs taken from request data of API>
            }
        ]

        """

        sa_info_list = []
        vendor_map = {const.FIREWALL: const.VYOS,
                      const.LOADBALANCER: const.HAPROXY,
                      const.VPN: const.VYOS,
                      const.LOADBALANCERV2: const.HAPROXY_LBAASV2}

        service_vendor = request_data['info']['service_vendor']
        if str(service_vendor) == 'None':
            service_vendor = vendor_map[resource_type]

        service_feature = request_data['info'].get('service_feature')
        if not service_feature:
            service_feature = ''

        for config_data in request_data['config']:
            sa_info = {}

            resource_type_to_method_map = {
                const.FIREWALL: (operation + '_' + config_data['resource']),
                const.VPN: ('vpnservice_updated'),
                const.LOADBALANCER: (operation + '_' + config_data[
                    'resource']),
                const.LOADBALANCERV2: (operation + '_' + config_data[
                    'resource']),
                const.NFP_SERVICE: ('run' + '_' + const.NFP_SERVICE),
                const.GENERIC_CONFIG: {
                    const.CREATE: ('configure_' + config_data[
                        'resource']),
                    const.UPDATE: ('update_' + config_data['resource']),
                    const.DELETE: ('clear_' + config_data['resource'])}}

            context = request_data['info']['context']

            data = config_data['resource_data']
            if not data:
                return None

            resource = config_data['resource']
            is_nfp_svc = True if resource in const.NFP_SERVICE_LIST else False

            if is_generic_config:
                method = resource_type_to_method_map[
                    const.GENERIC_CONFIG][operation]
            else:
                if is_nfp_svc:
                    resource_type = const.NFP_SERVICE
                try:
                    method = resource_type_to_method_map[resource_type]
                except Exception:
                    method = 'handle_config'

            sa_info.update({'method': method,
                            'resource_data': data,
                            'agent_info': {
                                # This is the API context
                                'context': context,
                                'service_vendor': service_vendor.lower(),
                                'service_feature': service_feature,
                                'resource_type': resource_type.lower(),
                                'resource': resource.lower()},
                            'is_generic_config': is_generic_config})

            sa_info_list.append(sa_info)

        if is_nfp_svc:
            resource_type = const.NFP_SERVICE
        elif is_generic_config:
            resource_type = const.GENERIC_CONFIG

        return sa_info_list, resource_type
