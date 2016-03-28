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
    nfp_neutron_network_driver as neutron_nd
)


class NFPGBPNetworkDriver(neutron_nd.NFPNeutronNetworkDriver):
    def __init__(self, config):
        self.config = config
        super(NFPGBPNetworkDriver, self).__init__(config)
        self.network_handler = openstack_driver.GBPClient(config)

    def setup_traffic_steering(self):
        pass

    def create_port(self, token, tenant_id, net_id, name=None):
        port = self.network_handler.create_policy_target(token, tenant_id,
                                                         net_id, name)
        return port

    def delete_port(self, token, port_id):
        self.network_handler.delete_policy_target(token, port_id)

    def get_port_id(self, token, port_id):
        pt = self.network_handler.get_policy_target(token, port_id)
        return pt['port_id']

    def update_port(self, token, port_id, port):
        pt = self.network_handler.update_policy_target(token, port_id,
                                                       port)
        return pt['port_id']

    def get_neutron_port_details(self, token, port_id):
        #self.network_handler = openstack_driver.NeutronClient(self.config)
        port_details = (
            super(NFPGBPNetworkDriver, self).get_port_and_subnet_details(
                token, port_id))
        #self.network_handler = openstack_driver.GBPClient(self.config)
        return port_details

    def get_port_details(self, token, port_id):
        _port_id = self.get_port_id(token, port_id)
        #self.network_handler = openstack_driver.NeutronClient(self.config)
        port_details = super(NFPGBPNetworkDriver, self).get_port_details(
                                                            token, _port_id)
        #self.network_handler = openstack_driver.GBPClient(self.config)
        return port_details

    def get_networks(self, token, filters):
        return self.network_handler.get_policy_target_groups(token,
                                                             filters=filters)

    def set_promiscuos_mode(self, token, port_id):
        port_id = self.get_port_id(token, port_id)
        #self.network_handler = openstack_driver.NeutronClient(self.config)
        super(NFPGBPNetworkDriver, self).set_promiscuos_mode(token, port_id)
        #self.network_handler = openstack_driver.GBPClient(self.config)

    def set_promiscuos_mode_fast(self, token, port_id):
        #self.network_handler = openstack_driver.NeutronClient(self.config)
        super(NFPGBPNetworkDriver, self).set_promiscuos_mode(token, port_id)
        #self.network_handler = openstack_driver.GBPClient(self.config)

    def get_service_profile(self, token, service_profile_id):
        return self.network_handler.get_service_profile(token,
                                                        service_profile_id)
