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

from gbpservice.nfp.lib import nfp_context_manager as nfp_ctx_mgr

from gbpservice.nfp.orchestrator.openstack import openstack_driver
from gbpservice.nfp.orchestrator.coal.networking import(
    nfp_network_driver_base as ndb
)


class NFPNeutronNetworkDriver(ndb.NFPNetworkDriverBase):

    def __init__(self, config):
        # self.network_handler = openstack_driver.NeutronClient(config)
        self.neutron_client = openstack_driver.NeutronClient(config)
        self.config = config

    def setup_traffic_steering(self):
        pass

    def create_port(self, token, tenant_id, net_id, name=None):
        with nfp_ctx_mgr.NeutronContextManager as ncm:
            port = ncm.retry(
                self.neutron_client.create_port,
                token, tenant_id, net_id,
                attrs={'name': name})
            return port

    def delete_port(self, token, port_id):
        with nfp_ctx_mgr.NeutronContextManager as ncm:
            ncm.retry(self.neutron_client.delete_port, token, port_id)

    def get_port_id(self, token, port_id):
        return port_id

    def update_port(self, token, port_id, port):
        with nfp_ctx_mgr.NeutronContextManager as ncm:
            port = ncm.retry(self.neutron_client.update_port,
                             token, port_id, **port)
        return port['port']

    def get_port_and_subnet_details(self, token, port_id):
        with nfp_ctx_mgr.NeutronContextManager as ncm:
            port = ncm.retry(self.neutron_client.get_port, token, port_id)

        # ip
        ip = port['port']['fixed_ips'][0]['ip_address']

        # mac
        mac = port['port']['mac_address']

        # gateway ip
        subnet_id = port['port']['fixed_ips'][0]['subnet_id']
        with nfp_ctx_mgr.NeutronContextManager as ncm:
            subnet = ncm.retry(
                self.neutron_client.get_subnet, token, subnet_id)
        cidr = subnet['subnet']['cidr']
        gateway_ip = subnet['subnet']['gateway_ip']

        return (ip, mac, cidr, gateway_ip, port, subnet)

    def get_port_details(self, token, port_id):
        with nfp_ctx_mgr.NeutronContextManager as ncm:
            port = ncm.retry(self.neutron_client.get_port, token, port_id)

        # ip
        ip = port['port']['fixed_ips'][0]['ip_address']

        # mac
        mac = port['port']['mac_address']

        # gateway ip
        subnet_id = port['port']['fixed_ips'][0]['subnet_id']
        with nfp_ctx_mgr.NeutronContextManager as ncm:
            subnet = ncm.retry(
                self.neutron_client.get_subnet, token, subnet_id)
        cidr = subnet['subnet']['cidr']
        gateway_ip = subnet['subnet']['gateway_ip']

        return (ip, mac, cidr, gateway_ip, port, subnet)

    def set_promiscuos_mode(self, token, port_id, enable_port_security):
        port_security = bool(enable_port_security)
        with nfp_ctx_mgr.NeutronContextManager as ncm:
            ncm.retry(self.neutron_client.update_port, token, port_id,
                      security_groups=[],
                      port_security_enabled=port_security)

    def get_service_profile(self, token, service_profile_id):
        return {}
