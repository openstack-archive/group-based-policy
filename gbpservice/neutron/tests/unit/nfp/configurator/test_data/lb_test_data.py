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

""" This class provides data that is needed for calling methods of
agent and driver.

"""


class Foo(object):

    key = 'key'
    serialize = 'serialize'
    binding_key = 'binding_key'


class Context(object):
    def to_dict(self):
        return {}


class FakeObjects(object):

    sc = 'sc'
    context = {'notification_data': {},
               'resource': 'context_resource'}
    context_pool = {'notification_data': {},
                    'resource': 'vip'}
    conf = 'conf'
    rpcmgr = 'rpcmgr'
    nqueue = 'nqueue'
    drivers = ['haproxy']
    vip_context = {'notification_data': {}, 'resource': 'context_resource'}
    context_test = {'notification_data': {}, 'resource': 'context_resource'}
    method = {'CREATE_VIP': 'create_network_function_config',
              'DELETE_VIP': 'delete_network_function_config',
              'UPDATE_VIP': 'update_network_function_config',
              'CREATE_POOL': 'create_network_function_config',
              'DELETE_POOL': 'delete_network_function_config',
              'UPDATE_POOL': 'update_network_function_config',
              'CREATE_MEMBER': 'create_network_function_config',
              'DELETE_MEMBER': 'delete_network_function_config',
              'UPDATE_MEMBER': 'update_network_function_config',
              'CREATE_POOL_HEALTH_MONITOR': 'create_network_function_config',
              'DELETE_POOL_HEALTH_MONITOR': 'delete_network_function_config',
              'UPDATE_POOL_HEALTH_MONITOR': 'update_network_function_config'}

    def _get_context_logical_device(self):
        context_logical_device = {
            'service_info': {
                'pools': self._get_pool_object(),
                'vips': self._get_vip_object(),
                'members': self._get_member_object(),
                'health_monitors': self._get_hm_object(),
                'ports': self._get_ports_object(),
                'subnets': self._get_subnets_object()}}
        return context_logical_device

    def get_request_data_for_vip(self):
        """Returns request data needed for create_vip method.

        Returns: request_data

        """

        request_data = {
            "info": {'context': {"logging_context": {}},
                     'service_type': "loadbalancer",
                     'service_vendor': "haproxy",
                     },
            "config": [{
                "resource": "vip",
                "resource_data": {
                    "neutron_context": self.context,
                    "vip": self._get_vip_object()[0]
                }}]}
        return request_data

    def get_request_data_for_vip_update(self):
        """Returns request data needed for update_vip method.

        Returns: request_data

        """

        request_data = {
            "info": {'context': {"logging_context": {}},
                     'service_type': "loadbalancer",
                     'service_vendor': "haproxy",
                     },
            "config": [{
                "resource": "vip",
                "resource_data": {
                    "neutron_context": self.context,
                    "vip": self._get_vip_object()[0],
                    "old_vip": self._get_vip_object()[0]
                }}]}
        return request_data

    def get_request_data_for_create_pool(self):
        """Returns request data needed for create_pool method.

        Returns: request_data

        """

        request_data = {
            "info": {'context': {"logging_context": {}},
                     'service_type': "loadbalancer",
                     'service_vendor': "haproxy",
                     },
            "config": [{
                "resource": "pool",
                "resource_data": {
                    "neutron_context": self.context,
                    "pool": self._get_pool_object()[0],
                    "driver_name": "loadbalancer"
                }}]}
        return request_data

    def get_request_data_for_delete_pool(self):
        """Returns request data needed for delete_pool method.

        Returns: request_data

        """

        request_data = {
            "info": {'context': {"logging_context": {}},
                     'service_type': "loadbalancer",
                     'service_vendor': "haproxy",
                     },
            "config": [{
                "resource": "pool",
                "resource_data": {
                    "neutron_context": self.context,
                    "pool": self._get_pool_object()[0]
                }}]}
        return request_data

    def get_request_data_for_update_pool(self):
        """Returns request data needed for update_pool method.

        Returns: request_data

        """

        request_data = {
            "info": {'context': {"logging_context": {}},
                     'service_type': "loadbalancer",
                     'service_vendor': "haproxy",
                     },
            "config": [{
                "resource": "pool",
                "resource_data": {
                    "neutron_context": self.context,
                    "pool": self._get_pool_object()[0],
                    "old_pool": self._get_pool_object()[0]
                }}]}
        return request_data

    def get_request_data_for_member(self):
        """Returns request data needed for create_member method.

        Returns: request_data

        """

        request_data = {
            "info": {'context': {"logging_context": {}},
                     'service_type': "loadbalancer",
                     'service_vendor': "haproxy",
                     },
            "config": [{
                "resource": "member",
                "resource_data": {
                    "neutron_context": self.context,
                    "member": self._get_member_object()[0],
                }}]}
        return request_data

    def get_request_data_for_pool_hm(self):
        """Returns request data needed for create_pool_health_monitor method.

        Returns: request_data

        """

        request_data = {
            "info": {'context': {"logging_context": {}},
                     'service_type': "loadbalancer",
                     'service_vendor': "haproxy",
                     },
            "config": [{
                "resource": "pool_health_monitor",
                "resource_data": {
                    "neutron_context": self.context,
                    "health_monitor": self._get_hm_object()[0],
                    "pool_id": self._get_pool_object()[0]['id']
                }}]}
        return request_data

    def get_request_data_for_update_pool_hm(self):
        """Returns request data needed for update_pool_health_monitor method.

        Returns: request_data

        """

        request_data = {
            "info": {'context': {"logging_context": {}},
                     'service_type': "loadbalancer",
                     'service_vendor': "haproxy",
                     },
            "config": [{
                "resource": "pool_health_monitor",
                "resource_data": {
                    "neutron_context": self.context,
                    "health_monitor": self._get_hm_object()[0],
                    "pool_id": self._get_pool_object()[0]['id'],
                    "old_health_monitor": self._get_hm_object()[0]
                }}]}
        return request_data

    def get_request_data_for_update_member(self):
        """Returns request data needed for update_member method.

        Returns: request_data

        """

        request_data = {
            "info": {'context': {"logging_context": {}},
                     'service_type': "loadbalancer",
                     'service_vendor': "haproxy",
                     },
            "config": [{
                "resource": "member",
                "resource_data": {
                    "neutron_context": self.context,
                    "member": self._get_member_object()[0],
                    "old_member": self._get_member_object()[0]
                }}]}
        return request_data

    def _get_vip_object(self):
        """Returns objects that contains vip related information.

        Returns: vip

        """

        vip = [{"status": "ACTIVE",
                "protocol": "TCP",
                "description": '{"floating_ip": "192.168.100.149",'
                               '"provider_interface_mac":'
                               '"aa:bb:cc:dd:ee:ff"}',
                "address": "42.0.0.14",
                "protocol_port": 22,
                "port_id": "cfd9fcc0-c27b-478b-985e-8dd73f2c16e8",
                "id": "7a755739-1bbb-4211-9130-b6c82d9169a5",
                "status_description": None,
                "name": "lb-vip",
                "admin_state_up": True,
                "subnet_id": "b31cdafe-bdf3-4c19-b768-34d623d77d6c",
                "tenant_id": "f6b09b7a590642d8ac6de73df0ab0686",
                "connection_limit": -1,
                "pool_id": "6350c0fd-07f8-46ff-b797-62acd23760de",
                "session_persistence": None}]
        return vip

    def _get_pool_object(self):
        """Returns objects that contains pool related information.

        Returns: pool

        """

        pool = [{"status": "ACTIVE",
                 "lb_method": "ROUND_ROBIN",
                 "protocol": "TCP",
                 "description": "",
                 "health_monitors": [],
                 "members":
                 [
                     "4910851f-4af7-4592-ad04-08b508c6fa21"
                 ],
                 "status_description": None,
                 "id": "6350c0fd-07f8-46ff-b797-62acd23760de",
                 "vip_id": "7a755739-1bbb-4211-9130-b6c82d9169a5",
                 "name": "lb-pool",
                 "admin_state_up": True,
                 "subnet_id": "b31cdafe-bdf3-4c19-b768-34d623d77d6c",
                 "tenant_id": "f6b09b7a590642d8ac6de73df0ab0686",
                 "health_monitors_status": [],
                 "provider": "haproxy"}]
        return pool

    def _get_member_object(self):
        """Returns objects that contains member related information.

        Returns: member

        """

        member = [{
            "admin_state_up": True,
            "status": "ACTIVE",
            "status_description": None,
            "weight": 1,
            "address": "42.0.0.11",
            "tenant_id": "f6b09b7a590642d8ac6de73df0ab0686",
            "protocol_port": 80,
            "id": "4910851f-4af7-4592-ad04-08b508c6fa21",
            "pool_id": "6350c0fd-07f8-46ff-b797-62acd23760de"}]
        return member

    def _get_hm_object(self):
        """Returns objects that contains health_monitor related information.

        Returns: hm

        """

        hm = [{
            "admin_state_up": True,
            "tenant_id": "f6b09b7a590642d8ac6de73df0ab0686",
            "delay": 10,
            "max_retries": 3,
            "timeout": 10,
            "pools": [],
            "type": "PING",
                    "id": "c30d8a88-c719-4b93-aa64-c58efb397d86"
        }]
        return hm

    def _get_ports_object(self):
        """Returns objects that contains health_monitor related information.

        Returns: hm

        """

        ports = [{"status": "ACTIVE",
                  "name": "",
                  "allowed_address_pairs": [],
                  "admin_state_up": True,
                  "network_id": "92f423a7-f44e-4726-b453-c8a1369a3ad0",
                  "tenant_id": "5e67167662f94fd5987e12a68ea6c1d8",
                  "extra_dhcp_opts": [],
                  "binding:vnic_type": "normal",
                  "device_owner": "network:dhcp",
                  "mac_address": "fa:16:3e:01:19:11",
                  "fixed_ips": [
                      {
                          "subnet_id": "2670bdcd-1bcf-4b97-858d-ab0d621983cc",
                          "ip_address": "11.0.0.3"
                      },
                      {
                          "subnet_id": "94aee832-935b-4e23-8f90-b6a81b0195b1",
                          "ip_address": "192.168.0.2"
                      }
                  ],
                  "id": "cfd9fcc0-c27b-478b-985e-8dd73f2c16e8",
                  "security_groups": [],
                  "device_id": ("dhcpf986c817-fd54-5bae-a8e4-e473b69100d2-"
                                "92f423a7-f44e-4726-b453-c8a1369a3ad0")
                  }]
        return ports

    def _get_subnets_object(self):
        """Returns objects that contains health_monitor related information.

        Returns: hm

        """

        subnets = [{
            "name": "apic_owned_ew-consumer",
                    "enable_dhcp": True,
                    "network_id": "0ced2567-47a0-4b67-be52-0e9695e8b0e6",
                    "tenant_id": "5e67167662f94fd5987e12a68ea6c1d8",
                    "dns_nameservers": [],
                    "gateway_ip": "11.0.3.1",
                    "ipv6_ra_mode": None,
                    "allocation_pools": [
                        {
                            "start": "11.0.3.2",
                            "end": "11.0.3.254"
                        }
                    ],
            "host_routes": [],
            "ip_version": 4,
            "ipv6_address_mode": None,
            "cidr": "11.0.3.0/24",
                    "id": "ea9ff596-51bc-4381-8aff-ee9f0ef7e319"
        }]
        return subnets

""" This class provides all the data needed for event.

"""


class FakeEvent(object):

    def __init__(self):
        fo = FakeObjects()
        kwargs = {'key': 'value'}
        self.data = {
            'context': {'notification_data': {},
                        'resource': 'context_resource',
                        'agent_info': {'service_vendor': '',
                                       'context': {},
                                       'resource': ''
                                       }
                        },
            'vip': fo._get_vip_object()[0],
            'old_vip': fo._get_vip_object()[0],
            'pool': fo._get_pool_object()[0],
            'old_pool': fo._get_pool_object()[0],
            'member': fo._get_member_object()[0],
            'old_member': fo._get_member_object()[0],
            'health_monitor': fo._get_hm_object()[0],
            'old_health_monitor': fo._get_hm_object()[0],
            'pool_id': '6350c0fd-07f8-46ff-b797-62acd23760de',
            'driver_name': 'loadbalancer',
            'host': 'host',
            'kwargs': kwargs,
        }

""" This class provides assertion data for HaproxyOnVmDriverTestCase.

This class provides assertion data that is expected for mock method to
call by assert_called_with function. This assertion data is depend on
input data used to call method which uses mocking.

"""


class AssertionData(object):

    url = '192.168.100.149'
    port = '1234'
    header = {'Content-Type': 'application/json'}
    timeout = 30
    delete_vip_url = ('http://192.168.100.149:1234/backend/'
                      'bck:6350c0fd-07f8-46ff-b797-62acd23760de')

    create_vip_data = {"frnt:7a755739-1bbb-4211-9130-b6c82d9169a5":
                       {"option": {"tcplog": True},
                        "bind": "42.0.0.14:22",
                        "mode": "tcp",
                        "default_backend":
                            "bck:6350c0fd-07f8-46ff-b797-62acd23760de",
                        "provider_interface_mac": "aa:bb:cc:dd:ee:ff"
                        }
                       }

    create_vip_url = 'http://192.168.100.149:1234/frontend'
    create_vip_resources = 'backend/bck:6350c0fd-07f8-46ff-b797-62acd23760de'

    update_vip_data = {"option": {"tcplog": True},
                       "bind": "42.0.0.14:22",
                       "mode": "tcp",
                       "default_backend":
                           "bck:6350c0fd-07f8-46ff-b797-62acd23760de",
                       "provider_interface_mac": "aa:bb:cc:dd:ee:ff"
                       }

    update_vip_url = ('http://192.168.100.149:1234/frontend/frnt:'
                      '7a755739-1bbb-4211-9130-b6c82d9169a5')

    update_pool_data = {"mode": "tcp",
                        "balance": "roundrobin",
                        "option": {},
                        "timeout": {"check": "10s"},
                        "server": {
                            "srvr:4910851f-4af7-4592-ad04-08b508c6fa21":
                                ["42.0.0.11:80", "weight 1",
                                 "check inter 10s fall 3"]
                              },
                        }

    update_pool_url = ('http://192.168.100.149:1234/backend/bck:'
                       '6350c0fd-07f8-46ff-b797-62acd23760de')

    create_member_data = {"timeout": {},
                          "server":
                          {
                             "srvr:4910851f-4af7-4592-ad04-08b508c6fa21":
                             ["42.0.0.11:80", "weight 1",
                              "check inter 10s fall 3"],
                             "resource": []
                          }
                          }
    create_member_url = ('http://192.168.100.149:1234/backend/bck:'
                         '6350c0fd-07f8-46ff-b797-62acd23760de')

    delete_member_data = {"timeout": {},
                          "server": {"resource": []}
                          }

    delete_member_url = ('http://192.168.100.149:1234/backend/bck:'
                         '6350c0fd-07f8-46ff-b797-62acd23760de')

    update_member_data = create_member_data
    update_member_url = ('http://192.168.100.149:1234/backend/bck:'
                         '6350c0fd-07f8-46ff-b797-62acd23760de')

    create_hm_data = {"timeout": {"check": "10s"},
                      "server":
                      {
                         "srvr:4910851f-4af7-4592-ad04-08b508c6fa21": [],
                         "resource": []
                      }
                      }

    create_hm_url = ('http://192.168.100.149:1234/backend/bck:'
                     '6350c0fd-07f8-46ff-b797-62acd23760de')

    delete_hm_data = {"timeout": {},
                      "server":
                      {
                        "srvr:4910851f-4af7-4592-ad04-08b508c6fa21": [],
                        "resource": []
                      }
                      }

    delete_hm_url = ('http://192.168.100.149:1234/backend/bck:'
                     '6350c0fd-07f8-46ff-b797-62acd23760de')

    update_hm_data = create_hm_data
    update_hm_url = ('http://192.168.100.149:1234/backend/bck:'
                     '6350c0fd-07f8-46ff-b797-62acd23760de')
