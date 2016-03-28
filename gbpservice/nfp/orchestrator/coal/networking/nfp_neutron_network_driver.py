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

from gbpservice.nfp.orchestrator.openstack import openstack_driver
from gbpservice.nfp.orchestrator.coal.networking import(
    nfp_network_driver_base as ndb
)


class NFPNeutronNetworkDriver(ndb.NFPNetworkDriverBase):
    def __init__(self, config):
        self.network_handler = openstack_driver.NeutronClient(config)

    def setup_traffic_steering(self):
        pass

    def create_port(self, token, tenant_id, net_id, name=None):
        port = self.network_handler.create_port(token, tenant_id, net_id,
                                                attrs={'name': name})
        return port

    def delete_port(self, token, port_id):
        self.network_handler.delete_port(token, port_id)

    def get_port_id(self, token, port_id):
        return port_id

    def get_port_details(self, token, port_id):
        port = self.network_handler.get_port(token, port_id)

        # ip
        ip = port['port']['fixed_ips'][0]['ip_address']

        # mac
        mac = port['port']['mac_address']

        # gateway ip
        subnet_id = port['port']['fixed_ips'][0]['subnet_id']
        subnet = self.network_handler.get_subnet(token, subnet_id)
        cidr = subnet['subnet']['cidr']
        gateway_ip = subnet['subnet']['gateway_ip']

        return (ip, mac, cidr, gateway_ip)

    def set_promiscuos_mode(self, token, port_id):
        self.network_handler.update_port(token, port_id,
                                         security_groups=[],
                                         port_security_enabled=False)
