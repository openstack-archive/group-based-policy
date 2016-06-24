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

""" Implements fake objects for assertion.

"""


class VPNTestData(object):
    '''
    Class which contains the required dictionaries to perform
    vpn ipsec site conn
    '''

    def __init__(self):

        self.context_device = {'notification_data': {},
                               'resource': 'interfaces'}
        self.sc = 'sc'
        self.conf = 'conf'
        self.msg = 'msg'
        self.drivers = 'drivers'
        self.svc = {' ': ' '}
        self.vm_mgmt_ip = '192.168.20.75'
        self.service_vendor = 'vyos'
        self.source_cidrs = '11.0.0.0/24'
        self.destination_cidr = 'destination_cidr'
        self.gateway_ip = '11.0.0.254'
        self.url = 'http://192.168.20.75:8888'
        self.vpn_vpnsvc_error = [{
            'status': 'ERROR',
            'updated_pending_status': True,
            'id': '36cd27d5-8ad0-4ed7-8bbe-57c488a17835'}]
        self.vpn_vpnsvc_active = [{
            'status': 'ACTIVE',
            'updated_pending_status': True,
            'id': '36cd27d5-8ad0-4ed7-8bbe-57c488a17835'}]
        self.ipsec_vpnsvc_status = [{
            'status': 'ACTIVE',
            'ipsec_site_connections': {
                                    'ac3a0e54-cdf2-4ea7-ac2f-7c0225ab9af9': {
                                        'status': 'INIT',
                                        'updated_pending_status': True}},
            'updated_pending_status': False,
            'id': '36cd27d5-8ad0-4ed7-8bbe-57c488a17835'}]
        self.url_for_add_inte = "%s/add_rule" % self.url
        self.url_for_del_inte = "%s/delete_rule" % self.url
        self.url_for_del_stc_route = "%s/delete-stitching-route" % self.url
        self.url_for_add_src_route = "%s/add-source-route" % self.url
        self.url_for_del_src_route = "%s/delete-source-route" % self.url
        self.url_create_ipsec_conn = "%s/create-ipsec-site-conn" % self.url
        self.url_update_ipsec_conn = "%s/update-ipsec-site-conn" % self.url
        self.url_delete_ipsec_conn = (
            "%s/delete-ipsec-site-conn?peer_address=1.103.2.2" % self.url)
        self.url_create_ipsec_tunnel = "%s/create-ipsec-site-tunnel" % self.url
        self.url_delete_ipsec_tunnel = "%s/delete-ipsec-site-tunnel" % self.url
        self.url_get_ipsec_tunnel = "%s/get-ipsec-site-tunnel-state" % self.url
        self.data_for_interface = {"stitching_mac": "00:0a:95:9d:68:25",
                                   "provider_mac": "00:0a:95:9d:68:16"}
        self.data_for_add_src_route = [{"source_cidr": "1.2.3.4/24",
                                        "gateway_ip": "1.2.3.4/24"}]
        self.data_for_del_src_route = [{"source_cidr": "1.2.3.4/24"}]
        self.conn_id = 'ac3a0e54-cdf2-4ea7-ac2f-7c0225ab9af6'
        self.data_ = {"local_cidr": "11.0.6.0/24",
                      "peer_address": "1.103.2.2",
                      "peer_cidrs": ["141.0.0.1/24"]}
        self.data__ = {"local_cidr": "11.0.6.0/24",
                       "peer_address": "1.103.2.2",
                       "peer_cidr": "141.0.0.0/24"}
        self.timeout = 90

        self.ipsec_vpn_create = ['fip=192.168.20.75',
                                 'tunnel_local_cidr=11.0.6.0/24',
                                 'user_access_ip=1.103.2.172',
                                 'fixed_ip=192.168.0.3',
                                 'standby_fip=1.103.1.21',
                                 'service_vendor=vyos',
                                 'stitching_cidr=192.168.0.0/28',
                                 'stitching_gateway=192.168.0.1',
                                 'mgmt_gw_ip=30.0.0.254']

        self.ipsec_delete = ['fip=192.168.20.75',
                             'tunnel_local_cidr=11.0.2.0/24',
                             'user_access_ip=1.103.2.178',
                             'fixed_ip=192.168.0.2',
                             'standby_fip=', 'service_vendor=vyos',
                             'stitching_cidr=192.168.0.0/28',
                             'stitching_gateway=192.168.0.1',
                             'mgmt_gw_ip=30.0.0.254']

        self.ipsec_data = {
            'service': {
                'router_id': '73c64bb0-eab9-4f37-85d0-7c8b0c15ed06',
                'status': 'ACTIVE',
                'name': 'VPNService',
                'admin_state_up': True,
                'subnet_id': '7f42e3e2-80a6-4212-9f49-48194ba58fd9',
                'tenant_id': '9f1663d116f74a01991ad66aaa8756c5',
                'cidr': '30.0.0.0/28',
                'id': '36cd27d5-8ad0-4ed7-8bbe-57c488a17835',
                'description': (
                        ";".join(self.ipsec_vpn_create))},

            'siteconns': [
                {'connection': {
                    'status': 'INIT',
                    'psk': 'secret',
                    'initiator': 'bi-directional',
                    'access_ip': '1.103.2.172',
                    'name': 'IPsecSiteConnection',
                    'admin_state_up': True,
                    'stitching_fixed_ip': '192.168.0.3',
                    'tenant_id': '9f1663d116f74a01991ad66aaa8756c5',
                    'description': (
                            ";".join(self.ipsec_vpn_create)),
                    'auth_mode': 'psk',
                    'peer_cidrs': ['141.0.0.0/24'],
                    'mtu': 1500,
                    'ikepolicy_id': '31b79141-3d21-473f-b104-b811bb3ac1fd',
                    'dpd': {'action': 'hold',
                            'interval': 30,
                            'timeout': 120},
                    'route_mode': 'static',
                    'vpnservice_id': (
                        '36cd27d5-8ad0-4ed7-8bbe-57c488a17835'),
                    'peer_address': '1.103.2.2',
                    'peer_id': '192.168.104.228',
                    'id': 'ac3a0e54-cdf2-4ea7-ac2f-7c0225ab9af6',
                    'tunnel_local_cidr': '11.0.6.0/24',
                    'ipsecpolicy_id': (
                        'b45d99b8-c38b-44ce-9ec8-ba223a83fb46',)},

                 'ipsecpolicy': {
                    'encapsulation_mode': 'tunnel',
                    'encryption_algorithm': '3des',
                    'pfs': 'group5',
                    'tenant_id': '9f1663d116f74a01991ad66aaa8756c5',
                    'name': 'IPsecPolicy',
                    'transform_protocol': 'esp',
                    'lifetime': {'units': 'seconds', 'value': 3600},
                    'id': 'b45d99b8-c38b-44ce-9ec8-ba223a83fb46',
                    'auth_algorithm': 'sha1',
                    'description': 'My new IPsec policy',
                },

                    'ikepolicy': {
                    'encryption_algorithm': '3des',
                        'pfs': 'group5',
                        'name': 'IKEPolicy',
                        'tenant_id': '9f1663d116f74a01991ad66aaa8756c5',
                        'lifetime': {'units': 'seconds', 'value': 3600},
                        'description': 'My new IKE policy',
                        'ike_version': 'v1',
                        'id': '31b79141-3d21-473f-b104-b811bb3ac1fd',
                        'auth_algorithm': 'sha1',
                        'phase1_negotiation_mode': 'main',
                }}]}

        self.svc_context = {
            'service': {
                'router_id': '73c64bb0-eab9-4f37-85d0-7c8b0c15ed06',
                'status': 'ACTIVE',
                'name': 'VPNService',
                'admin_state_up': True,
                'subnet_id': '7f42e3e2-80a6-4212-9f49-48194ba58fd9',
                'tenant_id': '9f1663d116f74a01991ad66aaa8756c5',
                'cidr': '30.0.0.0/28',
                'id': '36cd27d5-8ad0-4ed7-8bbe-57c488a17835',
                'description': ";".join(self.ipsec_vpn_create),
            },
            'siteconns': [
                {'connection': {
                    'status': 'INIT',
                    'psk': 'secret',
                    'initiator': 'bi-directional',
                    'name': 'IPsecSiteConnection',
                    'admin_state_up': True,
                    'tenant_id': '9f1663d116f74a01991ad66aaa8756c5',
                    'description': ";".join(self.ipsec_vpn_create),
                    'auth_mode': 'psk',
                    'peer_cidrs': ['141.0.0.0/24'],
                    'mtu': 1500,
                    'ikepolicy_id': '31b79141-3d21-473f-b104-b811bb3ac1fd',
                    'dpd': {'action': 'hold',
                            'interval': 30,
                            'timeout': 120
                            },
                    'route_mode': 'static',
                    'vpnservice_id': (
                        '36cd27d5-8ad0-4ed7-8bbe-57c488a17835'),
                    'peer_address': '1.103.2.2',
                    'peer_id': '192.168.104.228',
                    'id': 'ac3a0e54-cdf2-4ea7-ac2f-7c0225ab9af6',
                    'ipsecpolicy_id': (
                        'b45d99b8-c38b-44ce-9ec8-ba223a83fb46'),
                },
                    'ipsecpolicy': {
                    'encapsulation_mode': 'tunnel',
                    'encryption_algorithm': '3des',
                    'pfs': 'group5',
                    'tenant_id': '9f1663d116f74a01991ad66aaa8756c5',
                    'name': 'IPsecPolicy',
                            'transform_protocol': 'esp',
                            'lifetime': {'units': 'seconds', 'value': 3600},
                            'id': 'b45d99b8-c38b-44ce-9ec8-ba223a83fb46',
                            'auth_algorithm': 'sha1',
                            'description': 'My new IPsec policy',
                },
                    'ikepolicy': {
                    'encryption_algorithm': '3des',
                    'pfs': 'group5',
                    'name': 'IKEPolicy',
                            'tenant_id': '9f1663d116f74a01991ad66aaa8756c5',
                            'lifetime': {'units': 'seconds', 'value': 3600},
                            'description': 'My new IKE policy',
                            'ike_version': 'v1',
                            'id': '31b79141-3d21-473f-b104-b811bb3ac1fd',
                            'auth_algorithm': 'sha1',
                            'phase1_negotiation_mode': 'main',
                }}]}

        self.subnet = [{
            'name': 'apic_owned_res_2b0f246b-b0fc-4731-9245-1bd9ac2bd373',
            'enable_dhcp': None,
            'network_id': 'b7432a1c-66a7-45ff-b317-4bbef9449740',
            'tenant_id': '9f1663d116f74a01991ad66aaa8756c5',
            'dns_nameservers': [],
            'gateway_ip': '192.168.0.1',
            'ipv6_ra_mode': None,
            'allocation_pools': [{'start': '192.168.0.2',
                                  'end': '192.168.0.14'}],
            'host_routes': [],
            'ip_version': 4,
            'ipv6_address_mode': None,
            'cidr': '30.0.0.0/28',
            'id': '7f42e3e2-80a6-4212-9f49-48194ba58fd9',
        }]

        self.vpnservice = [{
            'router_id': '73c64bb0-eab9-4f37-85d0-7c8b0c15ed06',
            'status': 'ACTIVE',
            'name': 'VPNService',
            'admin_state_up': True,
            'subnet_id': '7f42e3e2-80a6-4212-9f49-48194ba58fd9',
            'tenant_id': '9f1663d116f74a01991ad66aaa8756c5',
            'id': '36cd27d5-8ad0-4ed7-8bbe-57c488a17835',
            'description': ";".join(self.ipsec_vpn_create),
        }]
        self.ipsec_site_connection = [{
            'status': 'INIT',
            'psk': 'secret',
            'initiator': 'bi-directional',
            'name': 'IPsecSiteConnection',
            'admin_state_up': True,
            'tenant_id': '9f1663d116f74a01991ad66aaa8756c5',
            'auth_mode': 'psk',
            'peer_cidrs': ['141.0.0.0/24'],
            'mtu': 1500,
            'ikepolicy_id': '31b79141-3d21-473f-b104-b811bb3ac1fd',
            'vpnservice_id': (
                            '36cd27d5-8ad0-4ed7-8bbe-57c488a17835'),
            'dpd': {'action': 'hold',
                    'interval': 30,
                    'timeout': 120},
            'route_mode': 'static',
            'ipsecpolicy_id': (
                'b45d99b8-c38b-44ce-9ec8-ba223a83fb46'),
            'peer_address': '1.103.2.2',
            'peer_id': '192.168.104.228',
            'id': 'ac3a0e54-cdf2-4ea7-ac2f-7c0225ab9af6',
            'description': ";".join(self.ipsec_vpn_create),
        }]

        self.ipsec_site_connection_delete = [{
            u'status': u'INIT',
            u'psk': u'secret',
            u'initiator': u'bi-directional',
            u'name': u'site_to_site_connection1',
            u'admin_state_up': True,
            u'tenant_id': u'564aeb9ebd694468bfb79a69da887419',
            u'auth_mode': u'psk',
            u'peer_cidrs': [u'11.0.0.0/24'],
            u'mtu': 1500,
            u'ikepolicy_id': (
                u'7a88b9f4-70bf-4184-834d-6814f264d331'),
            u'vpnservice_id': (
                u'3d453be6-7ddc-4812-a4a7-3299f9d3d29e'),
            u'dpd': {u'action': u'hold',
                     u'interval': 30,
                     u'timeout': 120},
            u'route_mode': u'static',
            u'ipsecpolicy_id': (
                u'03839460-1519-46ab-a073-b74314c06ec3'),
            u'peer_address': u'1.103.2.2',
            u'peer_id': u'1.103.2.2',
                        u'id': u'4dae3c91-0d0a-4ba5-9269-d0deab653316',
                        u'description': ";".join(self.ipsec_delete),
        }]

        self.ikepolicies = [{
            'encryption_algorithm': '3des',
            'pfs': 'group5',
            'name': 'IKEPolicy',
            'phase1_negotiation_mode': 'main',
            'lifetime': {'units': 'seconds', 'value': 3600},
            'tenant_id': '9f1663d116f74a01991ad66aaa8756c5',
            'ike_version': 'v1',
            'id': '31b79141-3d21-473f-b104-b811bb3ac1fd',
            'auth_algorithm': 'sha1',
            'description': 'My new IKE policy',
        }]

        self.ipsecpolicies = [{
            'encapsulation_mode': 'tunnel',
            'encryption_algorithm': '3des',
            'pfs': 'group5',
            'lifetime': {'units': 'seconds', 'value': 3600},
            'name': 'IPsecPolicy',
            'transform_protocol': 'esp',
            'tenant_id': '9f1663d116f74a01991ad66aaa8756c5',
            'id': 'b45d99b8-c38b-44ce-9ec8-ba223a83fb46',
            'auth_algorithm': 'sha1',
            'description': 'My new IPsec policy',
        }]

        self.context = {
            'domain': None,
            'project_name': None,
            'tenant_name': u'services',
            'project_domain': None,
            'timestamp': '2016-03-03 09:19:05.381231',
            'auth_token': u'0711af29a389492cb799e096a003a760',
            'resource_uuid': None,
            'is_admin': True,
            'user': u'19e278f3c3fa43e3964b057bc73cf7d7',
            'tenant_id': '9f1663d116f74a01991ad66aaa8756c5',
            'read_only': False,
            'project_id': 'b',
            'user_id': 'a',
            'show_deleted': False,
            'roles': [u'admin', u'heat_stack_owner'],
            'user_identity': 'a b - - -',
            'tenant_id': u'9f1663d116f74a01991ad66aaa8756c5',
            'request_id': u'req-da8765fb-4eb4-4f4f-9ebb-843ad1d752bd',
            'user_domain': None,
            'user_name': u'neutron',
            'agent_info': {'context': {},
                           'resource': {}},

        }

    def make_service_context(self, operation_type=None):
        '''
        Prepares a simple service_info dictionary and appends it to
        context dictionary

        '''

        self.service_info = {}
        self.service_info.update({'vpnservices': self.vpnservice})
        if operation_type is None:
            self.service_info.update({'ikepolicies': self.ikepolicies})
            self.service_info.update({'ipsecpolicies': self.ipsecpolicies})
            self.service_info.update({'ipsec_site_conns': (
                self.ipsec_site_connection)})

        self.service_info.update({'subnets': self.subnet})
        self.context.update({'service_info': self.service_info})
        return self.context

    def _create_vpnservice_obj(self):
        '''
        Return the fake dictionary for vpnservice creation
        '''

        return {
            'rsrc_type': 'vpn_service',
            'rsrc_id': '36cd27d5-8ad0-4ed7-8bbe-57c488a17835',
            'resource': {
                'router_id': '73c64bb0-eab9-4f37-85d0-7c8b0c15ed06',
                'status': 'ACTIVE',
                'name': 'VPNService',
                'admin_state_up': True,
                'subnet_id': '7f42e3e2-80a6-4212-9f49-48194ba58fd9',
                'tenant_id': '9f1663d116f74a01991ad66aaa8756c5',
                'id': '36cd27d5-8ad0-4ed7-8bbe-57c488a17835',
                'description': ";".join(self.ipsec_vpn_create),
            },
            'svc_type': 'ipsec',
            'service_vendor': 'vyos',
            'reason': 'create',
        }

    def _create_ipsec_site_conn_obj(self):
        '''
        Return the fake dictionary for ipsec site conn creation
        '''

        return {
            'rsrc_type': 'ipsec_site_connection',
            'rsrc_id': 'ac3a0e54-cdf2-4ea7-ac2f-7c0225ab9af9',
            'resource': {
                'status': 'INIT',
                'psk': 'secret',
                'initiator': 'bi-directional',
                'name': 'IPsecSiteConnection',
                'admin_state_up': True,
                'tenant_id': '9f1663d116f74a01991ad66aaa8756c5',
                'auth_mode': 'psk',
                'peer_cidrs': ['141.0.0.1/24'],
                'mtu': 1500,
                'ikepolicy_id': '31b79141-3d21-473f-b104-b811bb3ac1fd',
                'vpnservice_id': (
                    '36cd27d5-8ad0-4ed7-8bbe-57c488a17835'),
                'dpd': {'action': 'hold',
                        'interval': 30,
                        'timeout': 120},
                'route_mode': 'static',
                'ipsecpolicy_id': (
                    'b45d99b8-c38b-44ce-9ec8-ba223a83fb46'),
                'peer_address': '1.103.2.2',
                'peer_id': '141.0.0.2',
                'id': 'ac3a0e54-cdf2-4ea7-ac2f-7c0225ab9af9',
                'description': ";".join(self.ipsec_vpn_create),
            },
            'svc_type': 'ipsec',
            'service_vendor': 'vyos',
            'reason': 'create',
        }

    def _delete_ipsec_site_conn_obj(self):
        '''
        Return the fake dictionary for ipsec site conn deletion
        '''

        return {
            u'rsrc_type': u'ipsec_site_connection',
            u'rsrc_id': u'4dae3c91-0d0a-4ba5-9269-d0deab653316',
            u'resource': {
                u'status': u'INIT',
                u'psk': u'secret',
                u'initiator': u'bi-directional',
                u'name': u'site_to_site_connection1',
                u'admin_state_up': True,
                u'tenant_id': u'564aeb9ebd694468bfb79a69da887419',
                u'auth_mode': u'psk',
                u'peer_cidrs': [u'11.0.0.0/24'],
                u'mtu': 1500,
                u'ikepolicy_id': (
                        u'7a88b9f4-70bf-4184-834d-6814f264d331'),
                u'vpnservice_id': (
                    u'3d453be6-7ddc-4812-a4a7-3299f9d3d29e'),
                u'dpd': {u'action': u'hold',
                         u'interval': 30,
                         u'timeout': 120},
                u'route_mode': u'static',
                u'ipsecpolicy_id': (
                    u'03839460-1519-46ab-a073-b74314c06ec3'),
                u'peer_address': u'1.103.2.2',
                u'peer_id': u'1.103.2.2',
                u'id': u'4dae3c91-0d0a-4ba5-9269-d0deab653315',
                u'description': ";".join(self.ipsec_delete),
            },
            u'svc_type': u'ipsec',
            u'service_vendor': u'vyos',
            u'reason': u'delete',
        }

    def _update_ipsec_site_conn_obj(self):
        '''
        Return the fake dictionary for ipsec site conn updation
        '''

        return {
            u'rsrc_type': u'ipsec_site_connection',
            u'rsrc_id': u'4dae3c91-0d0a-4ba5-9269-d0deab653316',
            u'resource': {
                u'status': u'INIT',
                u'psk': u'secret',
                u'initiator': u'bi-directional',
                u'name': u'site_to_site_connection1',
                u'admin_state_up': True,
                u'tenant_id': u'564aeb9ebd694468bfb79a69da887419',
                u'auth_mode': u'psk',
                u'peer_cidrs': [u'11.0.0.0/24'],
                u'mtu': 1500,
                u'ikepolicy_id': (
                        u'7a88b9f4-70bf-4184-834d-6814f264d331'),
                u'vpnservice_id': (
                    u'3d453be6-7ddc-4812-a4a7-3299f9d3d29e'),
                u'dpd': {u'action': u'hold',
                         u'interval': 30,
                         u'timeout': 120},
                u'route_mode': u'static',
                u'ipsecpolicy_id': (
                    u'03839460-1519-46ab-a073-b74314c06ec3'),
                u'peer_address': u'1.103.2.2',
                u'peer_id': u'1.103.2.2',
                u'id': u'4dae3c91-0d0a-4ba5-9269-d0deab653315',
                u'description': ";".join(self.ipsec_vpn_create),
            },
            u'svc_type': u'ipsec',
            u'service_vendor': u'vyos',
            u'reason': u'update',
        }

    def make_resource_data(self, operation=None, service_type=None):
        '''
        Prepares a simple resource_data dictionary of respective service
        '''
        if operation is 'delete':
            return self._delete_ipsec_site_conn_obj()
        if operation is 'update':
            return self._update_ipsec_site_conn_obj()

        if operation == 'create' and service_type == 'ipsec':
            return self._create_ipsec_site_conn_obj()
        else:
            return self._create_vpnservice_obj()

    def fake_resource_data(self):
        '''
        A sample keyword arguments for configurator
        Returns: resource_data
        '''
        resource_data = {'service_type': 'vpn',
                         'vm_mgmt_ip': '192.168.20.75',
                         'mgmt_ip': '192.168.20.75',
                         'source_cidrs': ['1.2.3.4/24'],
                         'destination_cidr': ['1.2.3.4/24'],
                         'gateway_ip': '1.2.3.4/24',
                         'titching_ip': '1.2.3.4/24',
                         'stitching_cidr': '1.2.3.4/24',
                         'provider_ip': '1.2.3.4/24',
                         'provider_ip': '1.2.3.4/24',
                         'provider_interface_position': '1',
                         'stitching_interface_position': '3',
                         'request_info': 'some_id',
                         'periodicity': 'initial',
                         'provider_mac': '00:0a:95:9d:68:16',
                         'stitching_mac': '00:0a:95:9d:68:25',
                         'context': {'notification_data': 'hello'}
                         }
        return resource_data


class FakeEvent(object):
    '''
    Implements a fake event class for process framework to use to create
    the fake event object.
    '''

    def __init__(self):
        self.dict_obj = VPNTestData()
        self.data = {
            'context': self.dict_obj.make_service_context(),
            'resource_data': self.dict_obj._create_ipsec_site_conn_obj()
        }
