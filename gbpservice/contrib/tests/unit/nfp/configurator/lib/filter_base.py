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


from neutron.tests import base


class BaseTestCase(base.BaseTestCase):
    """ Defines all the dummy resources needed for test_filter.py
    """
    def __init__(self, *args, **kwargs):
        super(BaseTestCase, self).__init__(*args, **kwargs)
        self.service_info = {}

        self.desc1 = ["fip=1.203.1.108",
                      "tunnel_local_cidr=11.0.0.0/24",
                      "user_access_ip=1.203.2.101",
                      "fixed_ip=192.168.0.3", "standby_fip=",
                      "service_vendor=vyos",
                      "stitching_cidr=192.168.0.0/28",
                      "stitching_gateway=192.168.0.1",
                      "mgmt_gw_ip=120.0.0.1"]
        self.desc2 = ["fip=1.203.1.109",
                      "tunnel_local_cidr=12.0.0.0/24",
                      "user_access_ip=1.203.2.102",
                      "fixed_ip=192.168.0.4", "standby_fip=",
                      "service_vendor=vyos",
                      "stitching_cidr=192.168.0.0/28",
                      "stitching_gateway=192.168.1.1",
                      "mgmt_gw_ip=121.0.0.1"]
        self.name = ["aff8163b-f964-4ad7-a222-0e0a6e5593fe-8eacf5cf",
                     "-1e92-4e7b-90c4-cc68ef8c4e88"]

        self.ssl_vpn_connections = [{
                    "tenant_id": "5e67167662f94fd5987e12a68ea6c1d8",
                    "id": "b88b1d77-fbf8-45b5-adc3-9cd5169c7103",
                    "name": "ssl_vpn_connections1",
                    "admin_state_up": True,
                    "status": "ACTIVE",
                    "vpnservice_id": "19d22704-69ea-40c8-8bcf-2e1ffd697e33",
                    "credential_id": "8163b-f964-4ad7-a222-0e0a6e5593feaff",
                    "client_address_pool_cidr": "11.0.0.0/24"
                                     }]

        self.ports = [{
             "status": "ACTIVE",
             "name": "",
             "allowed_address_pairs": [],
             "admin_state_up": True,
             "network_id": "92f423a7-f44e-4726-b453-c8a1369a3ad0",
             "tenant_id": "5e67167662f94fd5987e12a68ea6c1d8",
             "extra_dhcp_opts": [],
             "binding:vnic_type": "normal",
             "device_owner": "network:dhcp",
             "mac_address": "fa:16:3e:01:19:11",
             "fixed_ips": [{
                     "subnet_id": "2670bdcd-1bcf-4b97-858d-ab0d621983cc",
                     "ip_address": "11.0.0.3"
                            },
                           {
                     "subnet_id": "94aee832-935b-4e23-8f90-b6a81b0195b1",
                     "ip_address": "192.168.0.2"
                            }],
             "id": "cfd9fcc0-c27b-478b-985e-8dd73f2c16e8",
             "security_groups": [],
             "device_id": ("dhcpf986c817-fd54-5bae-a8e4-e473b69100d2-"
                           "92f423a7-f44e-4726-b453-c8a1369a3ad0")
                       },
                      {
             "status": "ACTIVE",
             "name": ("aff8163b-f964-4ad7-a222-0e0a6e5593fe-"
                      "ea9ff596-51bc-4381-8aff-ee9f0ef7e319"),
             "allowed_address_pairs": [],
             "admin_state_up": True,
             "network_id": "0ced2567-47a0-4b67-be52-0e9695e8b0e6",
             "tenant_id": "5e67167662f94fd5987e12a68ea6c1d8",
             "extra_dhcp_opts": [],
             "binding:vnic_type": "normal",
             "device_owner": "network:router_interface",
             "mac_address": "fa:16:3e:1b:f2:44",
             "fixed_ips": [{
                    "subnet_id": "ea9ff596-51bc-4381-8aff-ee9f0ef7e319",
                    "ip_address": "11.0.3.2"
                            }],
             "id": "31df0d68-e9ea-4713-a629-29e6d87c2727",
             "security_groups": ["fb44b3f5-a319-4176-9e3b-361c5faafb66"],
             "device_id": "aff8163b-f964-4ad7-a222-0e0a6e5593fe"
                        },
                      {
             "status": "ACTIVE",
             "name": ";".join(self.name),
             "allowed_address_pairs": [],
             "admin_state_up": True,
             "network_id": "2e9652e8-bd95-472a-96b5-6a7939ae0f8d",
             "tenant_id": "5e67167662f94fd5987e12a68ea6c1d8",
             "extra_dhcp_opts": [],
             "binding:vnic_type": "normal",
             "device_owner": "network:router_interface",
             "mac_address": "fa:16:3e:49:44:b3",
             "fixed_ips": [{
                    "subnet_id": "8eacf5cf-1e92-4e7b-90c4-cc68ef8c4e88",
                    "ip_address": "11.0.4.2"
                            }],
             "id": "214eaa12-36c9-45b1-8fee-350ce2ff2dae",
             "security_groups": ["fb44b3f5-a319-4176-9e3b-361c5faafb66"],
             "device_id": "aff8163b-f964-4ad7-a222-0e0a6e5593fe"
                        }]

        self.subnets = [{
                    "name": "apic_owned_ew-consumer",
                    "enable_dhcp": True,
                    "network_id": "0ced2567-47a0-4b67-be52-0e9695e8b0e6",
                    "tenant_id": "5e67167662f94fd5987e12a68ea6c1d8",
                    "dns_nameservers": [],
                    "gateway_ip": "11.0.3.1",
                    "ipv6_ra_mode": None,
                    "allocation_pools": [{"start": "11.0.3.2",
                                          "end": "11.0.3.254"
                                          }],
                    "host_routes": [],
                    "ip_version": 4,
                    "ipv6_address_mode": None,
                    "cidr": "11.0.3.0/24",
                    "id": "ea9ff596-51bc-4381-8aff-ee9f0ef7e319"
                           },
                          {
                    "name": "apic_owned_ew-provider",
                    "enable_dhcp": True,
                    "network_id": "2e9652e8-bd95-472a-96b5-6a7939ae0f8d",
                    "tenant_id": "5e67167662f94fd5987e12a68ea6c1d8",
                    "dns_nameservers": [],
                    "gateway_ip": "11.0.4.1",
                    "ipv6_ra_mode": None,
                    "allocation_pools": [{"start": "11.0.4.2",
                                          "end": "11.0.4.254"
                                          }],
                    "host_routes": [],
                    "ip_version": 4,
                    "ipv6_address_mode": None,
                    "cidr": "11.0.4.0/24",
                    "id": "94aee832-935b-4e23-8f90-b6a81b0195b1"
                            }]

        self.routers = [{
             "status": "ACTIVE",
             "external_gateway_info": {
                        "network_id": (
                            "a413e04d-1431-4b21-8327-d4de25fa604b"),
                        "external_fixed_ips": [{
                                "subnet_id": (
                                    "fcc74b65-dafe-4b74-91fa-028dec8467a8"),
                                "ip_address": "169.254.2.148"
                                                }]},
             "name": "remote-vpn-client-pool-cidr-l3policy-Datacenter-Out",
             "admin_state_up": True,
             "tenant_id": "5e67167662f94fd5987e12a68ea6c1d8",
             "routes": [],
             "id": "61189c93-d8c7-46ff-b1b1-6a6db2b9ae0a"
                         },
                        {
             "status": "ACTIVE",
             "external_gateway_info": {
                        "network_id": (
                            "a413e04d-1431-4b21-8327-d4de25fa604b"),
                        "external_fixed_ips": [{
                                "subnet_id": (
                                    "fcc74b65-dafe-4b74-91fa-028dec8467a8"),
                                "ip_address": "169.254.2.150"
                                                }]},
             "name": "default-Datacenter-Out",
             "admin_state_up": True,
             "tenant_id": "5e67167662f94fd5987e12a68ea6c1d8",
             "routes": [],
             "id": "aff8163b-f964-4ad7-a222-0e0a6e5593fe"
                         }]

        self.vpnservices = [{
             "router_id": "aff8163b-f964-4ad7-a222-0e0a6e5593fe",
             "status": "ACTIVE",
             "name": "VPNService",
             "admin_state_up": True,
             "subnet_id": "94aee832-935b-4e23-8f90-b6a81b0195b1",
             "tenant_id": "5e67167662f94fd5987e12a68ea6c1d8",
             "id": "19d22704-69ea-40c8-8bcf-2e1ffd697e33",
             "description": ";".join(self.desc1)
                             },
                            {
             "router_id": "61189c93-d8c7-46ff-b1b1-6a6db2b9ae0a",
             "status": "ACTIVE",
             "name": "VPNService1",
             "admin_state_up": True,
             "subnet_id": "94aee832-935b-4e23-8f90-b6a81b0195b1",
             "tenant_id": "5e67167662f94fd5987e12a68ea6c1d8",
             "id": "19d22704-69ea-40c8-8bcf-2e1ffd697f44",
             "description": ";".join(self.desc2)
                              }]

        self.ipsecpolicies = [{
                "encapsulation_mode": "tunnel",
                "encryption_algorithm": "3des",
                "pfs": "group5",
                "lifetime":
                {"units": "seconds", "value": 3600},
                "name": "IPsecPolicy",
                "transform_protocol": "esp",
                "tenant_id": "5e67167662f94fd5987e12a68ea6c1d8",
                "id": "b88b1d77-fbf8-45b5-adc3-9cd5169c7102",
                "auth_algorithm": "sha1", "description": ""
                                 }]

        self.ikepolicies = [{
                "encryption_algorithm": "3des",
                "pfs": "group5",
                "name": "IKEPolicy",
                "phase1_negotiation_mode":
                "main", "lifetime":
                {"units": "seconds", "value": 3600},
                "tenant_id": "5e67167662f94fd5987e12a68ea6c1d8",
                "ike_version": "v1",
                "id": "ae1dd05c-ac66-45e5-868e-36f20c9aa222",
                "auth_algorithm": "sha1",
                "description": ""
                            }]

        self.ipsec_site_connections = [{
             "status": "INIT",
             "psk": "sapna",
             "initiator": "bi-directional",
             "name": "site_to_site_connection1",
             "admin_state_up": True,
             "tenant_id": "5e67167662f94fd5987e12a68ea6c1d8",
             "ipsecpolicy_id": "b88b1d77-fbf8-45b5-adc3-9cd5169c7102",
             "auth_mode": "psk",
             "peer_cidrs": ["11.0.1.0/24"],
             "mtu": 1500,
             "ikepolicy_id": "ae1dd05c-ac66-45e5-868e-36f20c9aa222",
             "dpd": {"action": "hold", "interval": 30, "timeout": 120},
             "route_mode": "static",
             "vpnservice_id": "19d22704-69ea-40c8-8bcf-2e1ffd697e33",
             "peer_address": "1.203.2.1",
             "peer_id": "1.203.2.1",
             "id": "9736cb21-4996-4dae-8e66-d13c24c44a8b",
             "description": ";".join(self.desc1)
                                         }]

        # update the below lists as per the future requirements
        self.firewalls = []
        self.firewall_policies = []
        self.firewall_rules = []

    def _test_get_vpn_info(self):
        """Prepares VPN service_info needed for VPN context

        Returns: VPN service info
        """
        self.service_info['vpnservices'] = self.vpnservices
        self.service_info['ikepolicies'] = self.ikepolicies
        self.service_info['ipsecpolicies'] = self.ipsecpolicies
        self.service_info['ipsec_site_conns'] = self.ipsec_site_connections
        self.service_info['ssl_vpn_conns'] = self.ssl_vpn_connections
        self.service_info['routers'] = self.routers
        self.service_info['subnets'] = self.subnets
        return self.service_info

    def _test_get_fw_info(self):
        """Prepares FW service_info needed for FW context

        Returns: FW service info
        """
        self.service_info['firewalls'] = self.firewalls
        self.service_info['firewall_policies'] = self.firewall_policies
        self.service_info['firewall_rules'] = self.firewall_rules
        return self.service_info
