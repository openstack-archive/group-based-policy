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

from neutron._i18n import _LE

from gbpservice.nfp.common import constants as nfp_constants
from gbpservice.nfp.common import exceptions
from gbpservice.nfp.orchestrator.drivers import (
    orchestration_driver_base as odb
)

from gbpservice.nfp.core import log as nfp_logging
LOG = nfp_logging.getLogger(__name__)


class HaproxyOrchestrationDriver(odb.OrchestrationDriverBase):

    def __init__(self, config=None, supports_device_sharing=True,
                 supports_hotplug=True, max_interfaces=10):
        super(HaproxyOrchestrationDriver, self).__init__(
            config,
            supports_device_sharing=supports_device_sharing,
            supports_hotplug=supports_hotplug,
            max_interfaces=max_interfaces)
        self.service_vendor = 'Haproxy'

    @odb._set_network_handler
    def get_network_function_device_config_info(self, device_data,
                                                network_handler=None):
        """ Get the configuration information for NFD

        :param device_data: NFD
        :type device_data: dict

        :returns: None -- On Failure
        :returns: dict -- It has the following scheme
        {
            'config': [
                {
                    'resource': 'interfaces',
                    'resource_data': {
                        ...
                    }
                },
                {
                    'resource': 'routes',
                    'resource_data': {
                        ...
                    }
                }
            ]
        }

        :raises: exceptions.IncompleteData
        """
        if (
            any(key not in device_data
                for key in ['service_details',
                            'mgmt_ip_address',
                            'ports']) or

            type(device_data['service_details']) is not dict or

            any(key not in device_data['service_details']
                for key in ['service_vendor',
                            'device_type',
                            'network_mode']) or

            type(device_data['ports']) is not list or

            any(key not in port
                for port in device_data['ports']
                for key in ['id',
                            'port_classification',
                            'port_model'])
        ):
            raise exceptions.IncompleteData()

        try:
            token = (device_data['token']
                     if device_data.get('token')
                     else self.identity_handler.get_admin_token())
        except Exception:
            self._increment_stats_counter('keystone_token_get_failures')
            LOG.error(_LE('Failed to get token'
                          ' for get device config info operation'))
            return None

        provider_ip = None
        provider_mac = None
        provider_cidr = None
        consumer_ip = None
        consumer_mac = None
        consumer_cidr = None
        consumer_gateway_ip = None

        for port in device_data['ports']:
            if port['port_classification'] == nfp_constants.PROVIDER:
                try:
                    (provider_ip, provider_mac, provider_cidr, dummy) = (
                            network_handler.get_port_details(token, port['id'])
                    )
                except Exception:
                    self._increment_stats_counter('port_details_get_failures')
                    LOG.error(_LE('Failed to get provider port details'
                                  ' for get device config info operation'))
                    return None
            elif port['port_classification'] == nfp_constants.CONSUMER:
                try:
                    (consumer_ip, consumer_mac, consumer_cidr,
                     consumer_gateway_ip) = (
                            network_handler.get_port_details(token, port['id'])
                    )
                except Exception:
                    self._increment_stats_counter('port_details_get_failures')
                    LOG.error(_LE('Failed to get consumer port details'
                                  ' for get device config info operation'))
                    return None

        return {
            'config': [
                {
                    'resource': 'interfaces',
                    'resource_data': {
                        'mgmt_ip': device_data['mgmt_ip_address'],
                        'provider_ip': provider_ip,
                        'provider_cidr': provider_cidr,
                        'provider_interface_index': 2,
                        'stitching_ip': consumer_ip,
                        'stitching_cidr': consumer_cidr,
                        'stitching_interface_index': 3,
                        'provider_mac': provider_mac,
                        'stitching_mac': consumer_mac,
                    }
                },
                {
                    'resource': 'routes',
                    'resource_data': {
                        'mgmt_ip': device_data['mgmt_ip_address'],
                        'source_cidrs': ([provider_cidr, consumer_cidr]
                                         if consumer_cidr
                                         else [provider_cidr]),
                        'destination_cidr': consumer_cidr,
                        'gateway_ip': consumer_gateway_ip,
                        'provider_interface_index': 2
                    }
                }
            ]
        }
