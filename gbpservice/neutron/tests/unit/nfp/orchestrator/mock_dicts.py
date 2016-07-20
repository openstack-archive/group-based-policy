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


class DummyDictionaries(object):

    DEFAULT_LB_CONFIG = {
        u'heat_template_version': u'2013-05-23',
        u'description': u'Configuration for Haproxy Neutron LB service',
        u'parameters': {
            u'Subnet': {
                u'type': u'string',
                u'description': u'Pool Subnet-CIDR, on which VIP port created'
            },
            u'vip_ip': {
                u'type': u'string',
                u'description': u'VIP IP Address'
            },
            u'service_chain_metadata': {
                u'type': u'string',
                u'description': u'sc metadata'
            }
        },
        u'resources': {
            u'LoadBalancerPool': {
                u'type': u'OS::Neutron::Pool',
                u'properties': {
                    u'lb_method': u'ROUND_ROBIN',
                    u'protocol': u'TCP',
                    u'name': u'Haproxy pool-lb-chain',
                    u'admin_state_up': True,
                    u'subnet_id': {
                        u'get_param': u'Subnet'
                    },
                    u'vip': {
                        u'subnet': {
                            u'get_param': u'Subnet'
                        },
                        u'description': {
                            u'get_param': u'service_chain_metadata'
                        },
                        u'admin_state_up': True,
                        u'connection_limit': -1,
                        u'address': {
                            u'get_param': u'vip_ip'
                        },
                        u'protocol_port': 3939,
                        u'name': u'LoadBalancerPool vip-lb-chain'
                    },
                    u'provider': u'haproxy_on_vm',
                    u'monitors': [{u'get_resource': u'HealthMonitor'}],
                    u'description': u'Haproxy pool from template'
                }
            },
            u'HealthMonitor': {
                u'type': u'OS::Neutron::HealthMonitor',
                u'properties': {
                    u'delay': 20,
                    u'max_retries': 5,
                    u'type': u'PING',
                    u'timeout': 10,
                    u'admin_state_up': True
                }
            },
            u'LoadBalancer': {
                u'type': u'OS::Neutron::LoadBalancer',
                u'properties': {
                    u'protocol_port': 101,
                    u'pool_id': {
                        u'get_resource': u'LoadBalancerPool'
                    }
                }
            }
        }
    }

    DEFAULT_FW_CONFIG = {
        u'heat_template_version': u'2013-05-23',
        u'description': u'Template to deploy firewall',
        u'resources': {
            u'sc_firewall_rule3': {
                u'type': u'OS::Neutron::FirewallRule',
                u'properties': {
                    u'action': u'allow',
                    u'destination_port': u'82',
                    u'protocol': u'tcp', u'name': u'Rule_3'
                }
            },
            u'sc_firewall_rule2': {
                u'type': u'OS::Neutron::FirewallRule',
                u'properties': {
                    u'action': u'allow',
                    u'destination_port': u'81',
                    u'protocol': u'tcp', u'name': u'Rule_2'
                }
            },
            u'sc_firewall_rule1': {
                u'type': u'OS::Neutron::FirewallRule',
                u'properties': {
                    u'action': u'allow',
                    u'destination_port': u'80',
                    u'protocol': u'tcp',
                    u'name': u'Rule_1'
                }
            },
            u'sc_firewall_rule0': {
                u'type': u'OS::Neutron::FirewallRule',
                u'properties': {
                    u'action': u'allow',
                    u'destination_port': u'22',
                    u'protocol': u'tcp', u'name': u'Rule_0'
                }
            },
            u'sc_firewall_rule4': {
                u'type': u'OS::Neutron::FirewallRule',
                u'properties': {
                    u'action': u'allow',
                    u'protocol': u'icmp',
                    u'name': u'Rule_4'
                }
            },
            u'sc_firewall_policy': {
                u'type': u'OS::Neutron::FirewallPolicy',
                u'properties': {
                    u'name': u'',
                    u'firewall_rules': [
                         {u'get_resource': u'sc_firewall_rule0'},
                         {u'get_resource': u'sc_firewall_rule1'},
                         {u'get_resource': u'sc_firewall_rule2'},
                         {u'get_resource': u'sc_firewall_rule3'},
                         {u'get_resource': u'sc_firewall_rule4'}]
                }
            },
            u'sc_firewall': {
                u'type': u'OS::Neutron::Firewall',
                u'properties': {
                    u'firewall_policy_id': {
                         u'get_resource': u'sc_firewall_policy'
                    },
                    u'name': u'serviceVM_infra_FW',
                    u'description': {u'insert_type': u'east_west'}
                }
            }
        }
    }

    DEFAULT_VPN_CONFIG = {
        u'resources': {
            u'IKEPolicy': {
                u'type': u'OS::Neutron::IKEPolicy',
                u'properties': {
                    u'name': u'IKEPolicy',
                    u'auth_algorithm': u'sha1',
                    u'encryption_algorithm': u'3des',
                    u'pfs': u'group5',
                    u'lifetime': {
                        u'units': u'seconds',
                        u'value': 3600
                    },
                    u'ike_version': u'v1',
                    u'phase1_negotiation_mode': u'main'
                }
            },
            u'VPNService': {
                u'type': u'OS::Neutron::VPNService',
                u'properties': {
                    u'router_id': {
                        u'get_param': u'RouterId'
                    },
                    u'subnet_id': {
                        u'get_param': u'Subnet'
                    },
                    u'admin_state_up': u'true',
                    u'description': {
                        u'get_param': u'ServiceDescription'
                    },
                    u'name': u'VPNService'
                }
            },
            u'site_to_site_connection1': {
                u'type': u'OS::Neutron::IPsecSiteConnection',
                u'properties': {
                    u'psk': u'secret',
                    u'initiator': u'bi-directional',
                    u'name': u'site_to_site_connection1',
                    u'admin_state_up': u'true',
                    'description':
                        u'fip=1.103.1.20;tunnel_local_cidr=11.0.1.0/24;\
                        user_access_ip=1.103.2.20;fixed_ip=192.168.0.3;\
                        standby_fip=1.103.1.21;service_vendor=vyos;\
                        stitching_cidr=192.168.0.0/28;\
                        stitching_gateway=192.168.0.1;mgmt_gw_ip=120.0.0.1',
                    u'peer_cidrs': [u'11.0.0.0/24'],
                    u'mtu': 1500,
                    u'ikepolicy_id': {
                        u'get_resource': u'IKEPolicy'
                    },
                    u'dpd': {
                        u'interval': 30,
                        u'actions': u'hold',
                        u'timeout': 120
                    },
                    u'vpnservice_id': {
                        u'get_resource': u'VPNService'
                    },
                    u'peer_address': u'1.103.2.88',
                    u'peer_id': u'1.103.2.88',
                    u'ipsecpolicy_id': {
                        u'get_resource': u'IPsecPolicy'
                    }
                }
            },
            u'SSLVPNConnection': {
                u'type': u'OS::Neutron::SSLVPNConnection',
                u'properties': {
                    u'credential_id': u'',
                    u'client_address_pool_cidr': {
                        u'get_param': u'ClientAddressPoolCidr'
                    },
                    u'name': u'vtun0',
                    u'vpnservice_id': {
                        u'get_resource': u'VPNService'
                    },
                    u'admin_state_up': u'true'
                }
            },
            u'IPsecPolicy': {
                u'type': u'OS::Neutron::IPsecPolicy',
                u'properties': {
                    u'name': u'IPsecPolicy',
                    u'transform_protocol': u'esp',
                    u'auth_algorithm': u'sha1',
                    u'encapsulation_mode': u'tunnel',
                    u'encryption_algorithm': u'3des',
                    u'pfs': u'group5',
                    u'lifetime': {
                        u'units': u'seconds',
                        u'value': 3600
                    }
                }
            }
        }
    }

    appended_sc_firewall_policy = {
        u'type': u'OS::Neutron::FirewallPolicy',
        u'properties': {
            u'name': u'',
            u'firewall_rules': [
                {
                    u'get_resource': u'sc_firewall_rule0'
                },
                {u'get_resource': u'sc_firewall_rule1'},
                {u'get_resource': u'sc_firewall_rule2'},
                {u'get_resource': u'sc_firewall_rule3'},
                {u'get_resource': u'sc_firewall_rule4'},
                {'get_resource': 'node_driver_rule_2b86019a-45f7-44_1'},
                {'get_resource': 'node_driver_rule_2b86019a-45f7-44_2'},
                {'get_resource': 'node_driver_rule_2b86019a-45f7-44_3'},
                {'get_resource': 'node_driver_rule_2b86019a-45f7-44_4'},
                {'get_resource': 'node_driver_rule_2b86019a-45f7-44_5'},
            ]
        }
    }

    updated_sc_firewall_policy = {
        u'type': u'OS::Neutron::FirewallPolicy',
        u'properties': {
            u'name': u'-fw_redirect',
            u'firewall_rules': [
                {'get_resource': u'node_driver_rule_af6a8a58-1e25-49_1'},
                {'get_resource': u'node_driver_rule_af6a8a58-1e25-49_2'},
                {'get_resource': u'node_driver_rule_af6a8a58-1e25-49_3'},
                {'get_resource': u'node_driver_rule_af6a8a58-1e25-49_4'},
                {'get_resource': u'node_driver_rule_af6a8a58-1e25-49_5'},
            ]
        }
    }

    updated_template_sc_firewall_policy = {
        u'type': u'OS::Neutron::FirewallPolicy',
        u'properties': {
            u'name': u'',
            u'firewall_rules': [
                {'get_resource': u'node_driver_rule_af6a8a58-1e25-49_1'},
                {'get_resource': u'node_driver_rule_af6a8a58-1e25-49_2'},
                {'get_resource': u'node_driver_rule_af6a8a58-1e25-49_3'},
                {'get_resource': u'node_driver_rule_af6a8a58-1e25-49_4'},
                {'get_resource': u'node_driver_rule_af6a8a58-1e25-49_5'},
            ]
        }
    }

    policy_targets = {
        'policy_targets': [
            {'name': 'provider_0132c_00b93',
             'port_id': 'dde7d849-4c7c-4b48-8c21-f3f52c646fbe'}]
    }

    policy_target = {
        'policy_target': {
            'name': 'service_target_provider_0132c_00b93'
        }
    }

    port_info = {
        'port': {
            u'status': u'ACTIVE',
            u'binding:host_id': u'LibertyCompute',
            u'name': u'',
            u'allowed_address_pairs': [],
            u'admin_state_up': True,
            u'network_id': u'2286b432-a443-4cd3-be49-e354f531abe3',
            u'dns_name': u'',
            u'extra_dhcp_opts': [],
            u'mac_address': u'fa:16:3e:43:34:33',
            u'dns_assignment': [
                {u'hostname': u'host-42-0-0-13',
                 u'ip_address': u'42.0.0.13',
                 u'fqdn': u'host-42-0-0-13.openstacklocal.'
                 }],
            u'binding:vif_details': {
                u'port_filter': True,
                u'ovs_hybrid_plug': True
            },
            u'binding:vif_type': u'ovs',
            u'device_owner': u'compute:nova',
            u'tenant_id': u'f6b09b7a590642d8ac6de73df0ab0686',
            u'binding:profile': {},
            u'binding:vnic_type': u'normal',
            u'fixed_ips': [
                {u'subnet_id': u'b31cdafe-bdf3-4c19-b768-34d623d77d6c',
                 u'ip_address': u'42.0.0.13'}],
            u'id': u'dde7d849-4c7c-4b48-8c21-f3f52c646fbe',
            u'security_groups': [u'ad3b95a4-b5ce-4a95-9add-6ef2ee797e72'],
            u'device_id': u'36e9a6d9-ea04-4627-93c5-6f708368c070'
        }
    }
    provider_ptg = {
        u'shared': False,
        u'subnets': [u'a2702d68-6deb-425c-a266-e27b349e00ce'],
        u'proxy_group_id': None,
        u'description': u'',
        u'consumed_policy_rule_sets': [],
        u'network_service_policy_id': u'0cdf2cba-90f8-44da-84a5-876e582f6e35',
        u'tenant_id': u'8ae6701128994ab281dde6b92207bb19',
        u'service_management': False,
        u'provided_policy_rule_sets': ['7d4b1ef2-eb80-415d-ad13-abf0ea0c52f3'],
        u'policy_targets': [
            {'name': 'provider_0132c_00b93',
             'port_id': 'dde7d849-4c7c-4b48-8c21-f3f52c646fbe'}],
        u'proxy_type': None,
        u'proxied_group_id': None,
        u'l2_policy_id': u'120aa972-1b58-418d-aa5b-1d2f96612c49',
        u'id': u'af6a8a58-1e25-49c4-97a3-d5f50b3aa04b',
        u'name': u'fw_redirect'
    }

    consumer_ptg = {
        u'shared': False,
        u'subnets': [u'a2702d68-6deb-425c-a266-e27b349e00ce'],
        u'proxy_group_id': None,
        u'description': u'',
        u'consumed_policy_rule_sets': ['7d4b1ef2-eb80-415d-ad13-abf0ea0c52f3'],
        u'network_service_policy_id': u'0cdf2cba-90f8-44da-84a5-876e582f6e35',
        u'tenant_id': u'8ae6701128994ab281dde6b92207bb19',
        u'service_management': False,
        u'provided_policy_rule_sets': [],
        u'policy_targets': [
            {'name': 'provider_0132c_00b93',
             'port_id': 'dde7d849-4c7c-4b48-8c21-f3f52c646fbe'}],
        u'proxy_type': None,
        u'proxied_group_id': None,
        u'l2_policy_id': u'120aa972-1b58-418d-aa5b-1d2f96612c49',
        u'id': u'af6a8a58-1e25-49c4-97a3-d5f50b3aa04b',
        u'name': u'fw_redirect'
    }

    l3_policies = {
        u'l3_policies': [
            {u'tenant_id': '8ae6701128994ab281dde6b92207bb19',
             u'name': u'remote-vpn-client-pool-cidr-l3policy'}]
    }

    policy_rule_sets = {
        u'policy_rule_sets': [
            {u'id': u'7d4b1ef2-eb80-415d-ad13-abf0ea0c52f3',
             u'name': u'fw_redirect',
             u'policy_rules': [u'493788ad-2b9a-47b1-b04d-9096d4057fb5'],
             u'tenant_id': u'8ae6701128994ab281dde6b92207bb19',
             u'shared': False,
             u'consuming_policy_target_groups':
             [u'af6a8a58-1e25-49c4-97a3-d5f50b3aa04b'],
             u'consuming_external_policies': None}]
    }

    policy_rules = {
        u'policy_rules': [
            {u'id': u'493788ad-2b9a-47b1-b04d-9096d4057fb5',
             u'name': u'fw_redirect',
             u'policy_actions': [u'0bab5fa6-4f89-4e15-8363-dacc7d825466'],
             u'policy_classifier_id': u'8e5fc80f-7544-484c-82d0-2a5794c10664',
             u'tenant_id': u'8ae6701128994ab281dde6b92207bb19',
             u'shared': False}]
    }

    policy_actions = {
        u'policy_actions': [
            {u'id': u'0bab5fa6-4f89-4e15-8363-dacc7d825466',
             u'name': u'fw_redirect',
             u'action_value': u'1e83b288-4b56-4851-83e2-69c4365aa8e5',
             u'action_type': u'redirect',
             u'tenant_id': u'8ae6701128994ab281dde6b92207bb19',
             u'shared': False}]
    }

    policy_target_groups = {
        u'policy_target_groups': [
            {u'shared': False,
             u'subnets': [u'a2702d68-6deb-425c-a266-e27b349e00ce'],
             u'proxy_group_id': None,
             u'description': u'',
             u'consumed_policy_rule_sets': [],
             u'network_service_policy_id':
             u'0cdf2cba-90f8-44da-84a5-876e582f6e35',
             u'tenant_id': u'8ae6701128994ab281dde6b92207bb19',
             u'service_management': False,
             u'provided_policy_rule_sets':
                 ['7d4b1ef2-eb80-415d-ad13-abf0ea0c52f3'],
             u'policy_targets': [
                 {'name': 'provider_0132c_00b93',
                  'port_id': 'dde7d849-4c7c-4b48-8c21-f3f52c646fbe'}],
             u'proxy_type': None,
             u'proxied_group_id': None,
             u'l2_policy_id': u'120aa972-1b58-418d-aa5b-1d2f96612c49',
             u'id': u'af6a8a58-1e25-49c4-97a3-d5f50b3aa04b',
             u'name': u'fw_redirect'}]
    }

    subnet_info = {
        u'subnet': {
            u'name': u'lb-subnet',
            u'enable_dhcp': True,
            u'network_id': u'2286b432-a443-4cd3-be49-e354f531abe3',
            u'tenant_id': u'f6b09b7a590642d8ac6de73df0ab0686',
            u'dns_nameservers': [],
            u'ipv6_ra_mode': None,
            u'allocation_pools': [{
                u'start': u'42.0.0.2', u'end': u'42.0.0.254'}],
            u'gateway_ip': u'42.0.0.1',
            u'ipv6_address_mode': None,
            u'ip_version': 4,
            u'host_routes': [],
            u'cidr': u'42.0.0.0/24',
            u'id': u'b31cdafe-bdf3-4c19-b768-34d623d77d6c',
            u'subnetpool_id': None
        }
    }

    subnets_info = {
        u'subnets': [
            {u'name': u'lb-subnet',
             u'enable_dhcp': True,
             u'network_id': u'2286b432-a443-4cd3-be49-e354f531abe3',
             u'tenant_id': u'f6b09b7a590642d8ac6de73df0ab0686',
             u'dns_nameservers': [],
             u'ipv6_ra_mode': None,
             u'allocation_pools': [{
                 u'start': u'42.0.0.2', u'end': u'42.0.0.254'}],
             u'gateway_ip': u'42.0.0.1',
             u'ipv6_address_mode': None,
             u'ip_version': 4,
             u'host_routes': [],
             u'cidr': u'42.0.0.0/24',
             u'id': u'b31cdafe-bdf3-4c19-b768-34d623d77d6c',
             u'subnetpool_id': None}]
    }

    external_policies = {u'external_policies': {}}

    fw_template_properties = {
        'fw_rule_keys': [u'sc_firewall_rule3', u'sc_firewall_rule2',
                         u'sc_firewall_rule1', u'sc_firewall_rule0',
                         u'sc_firewall_rule4'],
        'name': u'2b8',
        'properties_key': 'properties',
        'resources_key': 'resources',
        'is_template_aws_version': False,
        'fw_policy_key': u'sc_firewall_policy'
    }

    pool_members = {
        'type': 'OS::Neutron::PoolMember',
        'properties': {
            'protocol_port': 101,
            'admin_state_up': True,
            'pool_id': {'get_resource': u'LoadBalancerPool'},
            'weight': 1,
            'address': u'42.0.0.13'
        }
    }

    fw_scn_config = "{\"heat_template_version\": \"2013-05-23\",\
        \"description\": \"Template to deploy firewall\", \"resources\":\
        {\"sc_firewall_rule3\": {\"type\": \"OS::Neutron::FirewallRule\",\
        \"properties\": {\"action\": \"allow\", \"destination_port\": \"82\",\
        \"protocol\": \"tcp\", \"name\": \"Rule_3\"}}, \"sc_firewall_rule2\":\
        {\"type\": \"OS::Neutron::FirewallRule\", \"properties\": {\"action\":\
        \"allow\", \"destination_port\": \"81\", \"protocol\": \"tcp\",\
        \"name\": \"Rule_2\"}}, \"sc_firewall_rule1\": {\"type\":\
        \"OS::Neutron::FirewallRule\", \"properties\": {\"action\": \"allow\",\
        \"destination_port\": \"80\", \"protocol\": \"tcp\", \"name\":\
        \"Rule_1\"}}, \"sc_firewall_rule0\": {\"type\":\
        \"OS::Neutron::FirewallRule\", \"properties\": {\"action\": \"allow\",\
        \"destination_port\": \"22\", \"protocol\": \"tcp\", \"name\":\
        \"Rule_0\"}}, \"sc_firewall_rule4\": {\"type\":\
        \"OS::Neutron::FirewallRule\", \"properties\": {\"action\": \"allow\",\
        \"protocol\": \"icmp\", \"name\": \"Rule_4\"}}, \"sc_firewall_policy\"\
        :{\"type\": \"OS::Neutron::FirewallPolicy\", \"properties\": {\"name\"\
        :\"\", \"firewall_rules\": [{\"get_resource\": \"sc_firewall_rule0\"},\
        {\"get_resource\": \"sc_firewall_rule1\"}, {\"get_resource\":\
        \"sc_firewall_rule2\"}, {\"get_resource\": \"sc_firewall_rule3\"},\
        {\"get_resource\": \"sc_firewall_rule4\"}]}}, \"sc_firewall\":\
        {\"type\": \"OS::Neutron::Firewall\", \"properties\":\
        {\"firewall_policy_id\": {\"get_resource\": \"sc_firewall_policy\"},\
        \"description\": \"{\'insert_type\': \'east_west\',\
        \'vm_management_ip\': u'192.168.20.138', \'provider_ptg_info\':\
        [\'fa:16:3e:28:7d:b2\']}\", \"name\": \"serviceVM_infra_FW\"}}}}"

    lb_scn_config = "{\"heat_template_version\": \"2013-05-23\",\
        \"description\": \"Configuration for F5 Neutron Loadbalacer service\",\
        \"parameters\": {\"Subnet\": {\"type\": \"string\", \"description\":\
        \"Pool Subnet CIDR, on which VIP port should be created\"},\
        \"service_chain_metadata\": {\"type\": \"string\", \"description\":\
        \"sc metadata\"}, \"vip_ip\": {\"type\": \"string\", \"description\":\
        \"VIP IP Address\"}}, \"resources\": {\"LoadBalancerPool\": {\"type\":\
        \"OS::Neutron::Pool\", \"properties\": {\"lb_method\":\
        \"ROUND_ROBIN\", \"protocol\": \"TCP\", \"name\": \"F5 LB pool\",\
        \"admin_state_up\": true, \"subnet_id\": {\"get_param\": \"Subnet\"},\
        \"vip\": {\"subnet\": {\"get_param\": \"Subnet\"}, \"description\":\
        {\"get_param\": \"service_chain_metadata\"}, \"admin_state_up\": true,\
        \"connection_limit\": -1, \"address\": {\"get_param\": \"vip_ip\"},\
        \"protocol_port\": 80, \"name\": \"LoadBalancerPool vip\"},\
        \"provider\": \"F5\", \"monitors\": [{\"get_resource\":\
        \"HealthMonitor\"}], \"description\": \"F5 LB pool from template\"}},\
        \"HealthMonitor\": {\"type\": \"OS::Neutron::HealthMonitor\",\
        \"properties\": {\"delay\": 20, \"max_retries\": 5, \"type\":\
        \"PING\", \"timeout\": 10, \"admin_state_up\": true}},\
        \"LoadBalancer\": {\"type\": \"OS::Neutron::LoadBalancer\",\
        \"properties\": {\"protocol_port\": 80, \"pool_id\": {\"get_resource\"\
        :\"LoadBalancerPool\"}}}}}"

    service_profile = {
        u'service_flavor': u'vyos',
        u'service_type': u'FIREWALL'
    }

    lb_service_profile = {
        u'service_flavor': u'haproxy',
        u'service_type': u'LOADBALANCER'
    }

    fw_service_chain_node = {
        u'id': u'012345678919',
        u'name': u'scn_fw',
        u'config': fw_scn_config
    }

    lb_service_chain_node = {
        u'id': u'012345678919',
        u'name': u'scn_lb',
        u'config': lb_scn_config
    }

    service_chain_instance = {
        u'id': u'7834569034456677',
        u'name': u'sci_fw'
    }

    consumer_port = {
        u'fixed_ips': [{
            u'ip_address': u'11.0.3.4',
            u'subnet_id': u'9876256378888333'
        }]
    }

    network_function_details = {
        'network_function': {
            'status': 'ACTIVE',
            'description': '',
            'heat_stack_id': '57d6b523-ae89-41cd-9b63-9bfb054a20b6',
            'tenant_id': 'ee27b1d0d7f04ac390ee7ec4b2fd5b13',
            'network_function_instances': [
                '4693118c-149a-46e7-b92c-cc729b536a2e'],
            'service_chain_id': '507988d2-4b46-4df4-99d2-746676500872',
            'service_id': '1200332d-b432-403b-8350-89b782256be5',
            'service_profile_id': 'ab3b704b-a7d9-4c55-ab43-57ed5e29867d',
            'id': '5ad7439b-7259-47cd-be88-36f641e0b5c8',
            'name': 'LOADBALANCER.haproxy.507988d2-4b46-4df4-99d2-746676500872'
        },
        'network_function_instance': {
            'status': 'ACTIVE',
            'name': 'LOADBALANCER.haproxy.507988d2-4b46-4df4-99d2-7466765002',
            'network_function_device_id': '3c3e502a-256e-4597-91a9-71902380c0',
            'tenant_id': 'ee27b1d0d7f04ac390ee7ec4b2fd5b13',
            'ha_state': None,
            'network_function_id': '5ad7439b-7259-47cd-be88-36f641e0b5c8',
            'port_info': ['8cdcc00b-b791-4039-a5b4-e4d8b3d59e9f'],
            'id': '4693118c-149a-46e7-b92c-cc729b536a2e',
            'description': None
        },
        'network_function_device': {
            'status': 'ACTIVE',
            'monitoring_port_network': None,
            'monitoring_port_id': None,
            'mgmt_ip_address': '11.0.0.27',
            'description': '',
            'service_vendor': None,
            'tenant_id': 'ee27b1d0d7f04ac390ee7ec4b2fd5b13',
            'max_interfaces': 10,
            'mgmt_port_id': '4497a287-d947-4845-af29-a9d6ad6515e9',
            'reference_count': 1,
            'interfaces_in_use': 2,
            'id': '3c3e502a-256e-4597-91a9-719023808ec0',
            'name': 'LOADBALANCER.haproxy.507988d2-4b46-4df4-99d2-7466765008'
        }
    }
