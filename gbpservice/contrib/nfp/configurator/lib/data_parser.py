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
from gbpservice.nfp.core import log as nfp_logging

LOG = nfp_logging.getLogger(__name__)


class DataParser(object):
    ''' A library to parse device and service configuration and
    transform them into a dictionary of key-value pairs

    '''

    def __init__(self):
        pass

    def parse_data(self, resource, data):
        ''' Parser function exposed to the configurator modules.

        :param resource: Resource name (HEALTHMONITOR/INTERFACES/ROUTES/
        FIREWALL/LOADBALANCER/LOADBALANCERV2/VPN)
        :param data: Resource data dictionary in case of device configuration
        and context in case of service configuration

        Returns: a dictionary if nfds/nfs contains a single element else
                 a list of dictionaries where each dictionary corresponds
                 to each element in nfds/nfs
        '''

        config_data_list = []

        if data.get('nfds'):
            tenant_id = data['tenant_id']
            nf_config_list = data['nfds']
        elif data.get('resource_data'):
            tenant_id = data['resource_data']['tenant_id']
            nf_config_list = data['resource_data']['nfs']
        else:
            msg = ("The given schema of data dictionary is not supported "
                   "by the data parser library. Returning the input. "
                   "Input data is: %s" % data)
            LOG.debug(msg)
            return data

        for nf_config in nf_config_list:
            self.resource_data = {}
            self.resource_data.update({
                'tenant_id': tenant_id,
                'role': nf_config['role'],
                'mgmt_ip': nf_config['svc_mgmt_fixed_ip']})

            self._parse_config_data(nf_config, resource)
            config_data_list.append(copy.deepcopy(self.resource_data))

        return (config_data_list[0]
                if len(config_data_list) == 1
                else config_data_list)

    def _parse_config_data(self, nfd, resource):
        if resource.lower() == const.HEALTHMONITOR_RESOURCE:
            return self.resource_data.update(
                {'periodicity': nfd['periodicity'],
                 'vmid': nfd['vmid']})

        networks = nfd['networks']
        for network in networks:
            prefix = network['type']
            port = network['ports'][0]
            self.resource_data.update({
                (prefix + '_cidr'): network['cidr'],
                (prefix + '_ip'): port['fixed_ip'],
                (prefix + '_floating_ip'): port['floating_ip'],
                (prefix + '_mac'): port['mac'],
                (prefix + '_gw_ip'): network['gw_ip']})

        vips = nfd.get('vips')
        if not vips:
            return
        for vip in vips:
            prefix = vip['type'] + '_vip'
            self.resource_data.update({
                (prefix + '_ip'): vip['ip'],
                (prefix + '_mac'): vip['mac']})
