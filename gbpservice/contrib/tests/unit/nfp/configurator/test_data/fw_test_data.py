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


class FakeObjects(object):
    """ Implements fake objects for assertion.

    """

    sc = 'sc'
    empty_dict = {}
    context = 'APIcontext'
    neutron_context = {'neutron context for *aaS': {}}
    fw_context = {
            'agent_info': {
                'resource': 'firewall',
                'service_vendor': 'vyos',
                'context': {'requester': 'device_orch',
                            'logging_context': {}},
                'resource_type': 'firewall'},
            'notification_data': {}, 'service_info': {},
            'resource': 'firewall'}
    firewall = 'firewall'
    host = 'host'
    conf = 'conf'
    kwargs = {'vmid': 'vmid'}
    rpcmgr = 'rpcmgr'
    drivers = 'drivers'
    provider_interface_position = 'provider_interface_position'
    data_for_interface = dict(provider_mac="00:0a:95:9d:68:16",
                              stitching_mac="00:0a:95:9d:68:16")
    data_for_add_src_route = {'source_cidr': "1.2.3.4/24",
                              'gateway_ip': "1.2.3.4"}
    data_for_del_src_route = {'source_cidr': '1.2.3.4/24'}
    timeout = 120

    def get_url_for_api(self, api):
        url = 'http://172.24.4.5:8888/'
        api_url_map = {
            'log_forward': 'configure-rsyslog-as-client',
            'add_static_ip': 'add_static_ip',
            'add_inte': 'add_rule',
            'del_inte': 'delete_rule',
            'add_src_route': 'add-source-route',
            'del_src_route': 'delete-source-route',
            'config_fw': 'configure-firewall-rule',
            'update_fw': 'update-firewall-rule',
            'delete_fw': 'delete-firewall-rule'}

        return url + api_url_map[api]

    def log_forward_data(self):
        return dict(server_ip={}, server_port={}, log_level={})

    def static_ip_data(self):
        return dict(
                    provider_ip="11.0.1.1",
                    provider_cidr="11.0.1.0/24",
                    provider_mac="00:0a:95:9d:68:16",
                    stitching_ip="192.168.0.3",
                    stitching_cidr="192.168.0.0/28",
                    stitching_mac="00:0a:95:9d:68:16",
                    provider_interface_position="2",
                    stitching_interface_position="3")

    def fake_request_data_generic_bulk(self):
        """ A sample bulk request data for generic APIs

        Returns: data which is the input for generic configuration
        RPC receivers of configurator.

        """

        request_data = {
            "info": {
                "service_type": "firewall",
                "service_vendor": "vyos",
                "context": {
                        "requester": "device_orch",
                        "logging_context": {}
                }
            },
            "config": [{
                "resource": "interfaces",
                "resource_data": {
                    "stitching_interface_index": 3,
                    "stitching_mac": "fa:16:3e:da:ca:4d",
                    "provider_ip": "11.0.1.1",
                    "mgmt_ip": "11.0.0.37",
                    "provider_interface_index": 2,
                    "stitching_cidr": "192.168.0.0/28",
                    "provider_mac": "fa:16:3e:d9:4c:33",
                    "provider_cidr": "11.0.1.0/24",
                    "stitching_ip": "192.168.0.3",
                }
            }, {
                "resource": "routes",
                "resource_data": {
                    "provider_interface_index": 2,
                    "provider_mac": "fa:16:3e:d9:4c:33",
                    "gateway_ip": "192.168.0.1",
                    "destination_cidr": "192.168.0.0/28",
                    "mgmt_ip": "11.0.0.37",
                    "source_cidrs": ["11.0.1.0/24", "192.168.0.0/28"]
                }
            }]
        }
        return request_data

    def fake_request_data_generic_single(self, routes=False):
        """ A sample single request data for generic APIs

        Returns: data which is the input for generic configuration
        RPC receivers of configurator.

        """

        request_data = self.fake_request_data_generic_bulk()
        request_data['config'].pop(0) if routes else (
                                            request_data['config'].pop(1))

        return request_data

    def fake_request_data_fw(self):
        """ A sample request data for FwaaS APIs

        Returns: data which is the input for firewall configuration
        RPC receivers of configurator.

        """

        request_data = {
            "info": {
                "service_type": "firewall",
                "service_vendor": "vyos",
                "context": {
                        "requester": "device_orch",
                        "logging_context": {}
                }
            },
            "config": [{
                "resource": "firewall",
                "resource_data": {
                    "neutron_context": {
                                    "notification_data": {},
                                    "resource": "firewall"
                                },
                    "firewall": self._fake_firewall_obj(),
                    "host": self.host}}]
                        }
        return request_data

    def fake_sa_req_list_fw(self):
        """ A sample data for firewall agent handlers

        Returns: data which is the input for event handler
        functions of firewall agent.

        """

        request_data = [{
                        "agent_info": {
                            "service_vendor": "vyos",
                            "resource": "firewall",
                            "context": {
                                "requester": "device_orch",
                                "logging_context": {}
                            },
                            "resource_type": "firewall"
                        },
                        "method": "create_firewall",
                        "resource_data": {
                            "firewall": {
                                "status": "PENDING_CREATE",
                                "router_ids": [
                                    "650bfd2f-7766-4a0d-839f-218f33e16998"
                                ],
                                "description": '{\
                                    "vm_management_ip": "172.24.4.5",\
                                    "provider_cidr": "11.0.1.0/24",\
                                    "service_vendor": "vyos"}',
                                "admin_state_up": True,
                                "firewall_policy_id":
                                    "c69933c1-b472-44f9-8226-30dc4ffd454c",
                                "tenant_id":
                                    "45977fa2dbd7482098dd68d0d8970117",
                                "id": "3b0ef8f4-82c7-44d4-a4fb-6177f9a21977",
                                "firewall_rule_list": True,
                                "name": ""
                            },
                            "neutron_context": {
                                "notification_data": {},
                                "resource": "firewall"
                            },
                            "host": "host"
                        },
                        "is_generic_config": False
                        }]

        return request_data

    def fake_sa_req_list(self):
        """ A sample data for generic config agent handlers

        Returns: data which is the input for generic config event
        handler functions of agents.

        """

        sa_req_list = [
                {
                    "agent_info": {
                        "service_vendor": "vyos",
                        "resource": "interfaces",
                        "context": {
                            "requester": "device_orch",
                            "logging_context": {}
                        },
                        "resource_type": "firewall"
                    },
                    "method": "configure_interfaces",
                    "resource_data": {
                        "stitching_interface_index": 3,
                        "stitching_mac": "fa:16:3e:da:ca:4d",
                        "provider_ip": "11.0.1.1",
                        "mgmt_ip": "11.0.0.37",
                        "provider_interface_index": 2,
                        "stitching_cidr": "192.168.0.0/28",
                        "provider_mac": "fa:16:3e:d9:4c:33",
                        "provider_cidr": "11.0.1.0/24",
                        "stitching_ip": "192.168.0.3"
                    },
                    "is_generic_config": True
                },
                {
                    "agent_info": {
                        "service_vendor": "vyos",
                        "resource": "routes",
                        "context": {
                            "requester": "device_orch",
                            "logging_context": {}
                        },
                        "resource_type": "firewall"
                    },
                    "method": "configure_routes",
                    "resource_data": {
                        "mgmt_ip": "11.0.0.37",
                        "gateway_ip": "192.168.0.1",
                        "provider_mac": "fa:16:3e:d9:4c:33",
                        "destination_cidr": "192.168.0.0/28",
                        "provider_interface_index": 2,
                        "source_cidrs": [
                            "11.0.1.0/24",
                            "192.168.0.0/28"
                        ]
                    },
                    "is_generic_config": True
                }]

        return sa_req_list

    def _fake_resource_data(self):
        """ A sample keyword arguments for configurator

        Returns: kwargs

        """

        resource_data = {
                    'fake_resource_data': 'data',
                    'periodicity': 'initial',
                    'provider_ip': '11.0.1.1',
                    'provider_cidr': '11.0.1.0/24',
                    'provider_mac': '00:0a:95:9d:68:16',
                    'stitching_ip': '192.168.0.3',
                    'stitching_cidr': '192.168.0.0/28',
                    'destination_cidr': '192.168.0.0/28',
                    'stitching_mac': '00:0a:95:9d:68:16',
                    'provider_interface_index': '2',
                    'stitching_interface_index': '3',
                    'mgmt_ip': '172.24.4.5',
                    'source_cidrs': ['1.2.3.4/24'],
                    'gateway_ip': '1.2.3.4'
                        }
        return resource_data

    def _fake_firewall_obj(self):
        """ A sample firewall resource object

        Returns: firewall object

        """

        firewall = {
                     "admin_state_up": True,
                     "description": "",
                     "firewall_policy_id": (
                                "c69933c1-b472-44f9-8226-30dc4ffd454c"),
                     "id": "3b0ef8f4-82c7-44d4-a4fb-6177f9a21977",
                     "name": "",
                     "status": "PENDING_CREATE",
                     "router_ids": [
                         "650bfd2f-7766-4a0d-839f-218f33e16998"
                     ],
                     "tenant_id": "45977fa2dbd7482098dd68d0d8970117",
                     "description": '{\
                                    "vm_management_ip": "172.24.4.5",\
                                    "provider_cidr": "11.0.1.0/24",\
                                    "service_vendor": "vyos"}',
                     "firewall_rule_list": True
                    }
        return firewall


class FakeEventFirewall(object):
    """ Implements a fake event class for firewall for
        process framework to use

    """

    def __init__(self):
        fo = FakeObjects()
        kwargs = fo._fake_resource_data()
        self.data = {
                    'context': {'neutron context for *aaS': {},
                                'agent_info': {
                                        'resource': 'healthmonitor',
                                        'notification_data': {},
                                        'service_type': 'firewall',
                                        'service_vendor': 'vyos',
                                        'context': 'APIcontext'}},
                    'firewall': fo._fake_firewall_obj(),
                    'host': fo.host,
                    'resource_data': kwargs}
        self.id = 'dummy'


class FakeEventGenericConfig(object):
    """ Implements a fake event class for generic config for
        process framework to use

    """

    def __init__(self):
        fo = FakeObjects()
        kwargs = fo._fake_resource_data()
        self.data = {
                    'context': {
                            'resource': 'healthmonitor',
                            'notification_data': {},
                            'resource_type': 'firewall',
                            'service_vendor': 'vyos',
                            'context': 'APIcontext'},
                    'firewall': fo._fake_firewall_obj(),
                    'host': fo.host,
                    'resource_data': kwargs}
        self.id = 'dummy'


class FakeEventGetNotifications(object):
    """ Implements a fake event class for notifications functionality
        for the process framework to use

    """

    def __init__(self):
        self.data = {'dummy_data': 'dummy_value'}
