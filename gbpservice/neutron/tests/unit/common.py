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

import re

from neutron.openstack.common import uuidutils
from neutron.plugins.common import constants

from gbpservice.neutron.extensions import group_policy as gpolicy
from gbpservice.neutron.extensions import servicechain as service_chain

_uuid = uuidutils.generate_uuid


class Attributes(object):

    resource_prefix_map = dict(
        (k, constants.COMMON_PREFIXES[constants.SERVICECHAIN])
        for k in service_chain.RESOURCE_ATTRIBUTE_MAP.keys())
    resource_prefix_map.update(dict(
        (k, constants.COMMON_PREFIXES[constants.GROUP_POLICY])
        for k in gpolicy.RESOURCE_ATTRIBUTE_MAP.keys()
    ))

    def __getattr__(self, item):
        p = re.compile('^get_(create|update)_(.+?)_'
                       '(default_|required_)?attrs$')
        match = p.search(item)
        if match and (self.get_resource_plural(match.group(2)) in
                      self.resource_prefix_map):
            return self.default
        raise AttributeError

    def gbp_attributes(func):
        def inner(self, **kwargs):
            attrs = func(self)
            attrs.update(kwargs)
            return attrs
        return inner

    @gbp_attributes
    def default(self):
        return {}

    @gbp_attributes
    def get_create_policy_target_default_attrs(self):
        return {'name': '', 'description': '', 'policy_target_group_id': None}

    @gbp_attributes
    def get_create_policy_target_attrs(self):
        return {'name': 'ep1', 'policy_target_group_id': _uuid(),
                'tenant_id': _uuid(), 'description': 'test policy_target'}

    @gbp_attributes
    def get_update_policy_target_attrs(self):
        return {'name': 'new_name'}

    @gbp_attributes
    def get_create_policy_target_group_default_attrs(self):
        return {'name': '', 'description': '', 'l2_policy_id': None,
                'provided_policy_rule_sets': {},
                'consumed_policy_rule_sets': {},
                'network_service_policy_id': None, 'shared': False}

    @gbp_attributes
    def get_create_policy_target_group_attrs(self):
        return {'name': 'ptg1', 'tenant_id': _uuid(),
                'description': 'test policy_target group',
                'l2_policy_id': _uuid(),
                'provided_policy_rule_sets': {_uuid(): None},
                'consumed_policy_rule_sets': {_uuid(): None},
                'network_service_policy_id': _uuid(),
                'shared': False}

    @gbp_attributes
    def get_update_policy_target_group_attrs(self):
        return {'name': 'new_name'}

    @gbp_attributes
    def get_create_l2_policy_default_attrs(self):
        return {'name': '', 'description': '', 'shared': False}

    @gbp_attributes
    def get_create_l2_policy_attrs(self):
        return {'name': 'l2p1', 'tenant_id': _uuid(),
                'description': 'test L2 policy', 'l3_policy_id': _uuid(),
                'shared': False}

    @gbp_attributes
    def get_update_l2_policy_attrs(self):
        return {'name': 'new_name'}

    @gbp_attributes
    def get_create_l3_policy_default_attrs(self):
        return {'name': '', 'description': '', 'ip_version': 4,
                'ip_pool': '10.0.0.0/8', 'subnet_prefix_length': 24,
                'external_segments': {}, 'shared': False}

    @gbp_attributes
    def get_create_l3_policy_attrs(self):
        return {'name': 'l3p1', 'tenant_id': _uuid(),
                'description': 'test L3 policy', 'ip_version': 6,
                'ip_pool': 'fd01:2345:6789::/48',
                'external_segments': {_uuid(): ['192.168.0.3']},
                'subnet_prefix_length': 64, 'shared': False}

    @gbp_attributes
    def get_update_l3_policy_attrs(self):
        return {'name': 'new_name'}

    @gbp_attributes
    def get_create_policy_action_default_attrs(self):
        return {'name': '',
                'description': '',
                'action_type': 'allow',
                'action_value': None,
                'shared': False}

    @gbp_attributes
    def get_create_policy_action_attrs(self):
        return {'name': 'pa1',
                'tenant_id': _uuid(),
                'description': 'test policy action',
                'action_type': 'redirect',
                'action_value': _uuid(),
                'shared': False}

    @gbp_attributes
    def get_update_policy_action_attrs(self):
        return {'name': 'new_name'}

    @gbp_attributes
    def get_create_policy_classifier_default_attrs(self):
        return {'name': '',
                'description': '',
                'protocol': None,
                'port_range': None,
                'direction': None,
                'shared': False}

    @gbp_attributes
    def get_create_policy_classifier_attrs(self):
        return {'name': 'pc1',
                'description': 'test policy classifier',
                'tenant_id': _uuid(),
                'protocol': 'tcp',
                'port_range': '100:200',
                'direction': 'in',
                'shared': False}

    @gbp_attributes
    def get_update_policy_classifier_attrs(self):
        return {'name': 'new_name'}

    @gbp_attributes
    def get_create_policy_rule_default_attrs(self):
        return {'name': '',
                'description': '',
                'enabled': True,
                'policy_actions': [],
                'shared': False}

    @gbp_attributes
    def get_create_policy_rule_attrs(self):
        return {'name': 'pr1',
                'description': 'test policy rule',
                'tenant_id': _uuid(),
                'enabled': True,
                'policy_classifier_id': _uuid(),
                'policy_actions': [_uuid()],
                'shared': False}

    @gbp_attributes
    def get_update_policy_rule_attrs(self):
        return {'name': 'new_name'}

    @gbp_attributes
    def get_create_policy_rule_set_default_attrs(self):
        return {'name': '',
                'description': '',
                'child_policy_rule_sets': [],
                'policy_rules': [],
                'shared': False}

    @gbp_attributes
    def get_create_policy_rule_set_attrs(self):
        return {'name': 'policy_rule_set1',
                'description': 'test policy_rule_set',
                'tenant_id': _uuid(),
                'child_policy_rule_sets': [_uuid()],
                'policy_rules': [_uuid()],
                'shared': False}

    @gbp_attributes
    def get_update_policy_rule_set_attrs(self):
        return {'name': 'new_name'}

    @gbp_attributes
    def get_create_network_service_policy_default_attrs(self):
        return {'name': '', 'description': '',
                'network_service_params': [], 'shared': False}

    @gbp_attributes
    def get_create_network_service_policy_attrs(self):
        return {'name': 'nsp1', 'tenant_id': _uuid(),
                'shared': False,
                'description': 'test Net Svc Policy',
                'network_service_params': [{'type': 'ip_single', 'name': 'vip',
                                            'value': 'self_subnet'}]}

    @gbp_attributes
    def get_update_network_service_policy_attrs(self):
        return {'name': 'new_name'}

    @gbp_attributes
    def get_create_external_policy_default_attrs(self):
        return {'name': '', 'description': '',
                'external_segments': [],
                'provided_policy_rule_sets': {},
                'consumed_policy_rule_sets': {},
                'shared': False}

    @gbp_attributes
    def get_create_external_policy_attrs(self):
        return {'name': 'ep1', 'tenant_id': _uuid(),
                'description': 'test ep',
                'external_segments': [_uuid()],
                'provided_policy_rule_sets': {_uuid(): None},
                'consumed_policy_rule_sets': {_uuid(): None},
                'shared': False}

    @gbp_attributes
    def get_update_external_policy_attrs(self):
        return {'name': 'new_name'}

    @gbp_attributes
    def get_create_external_segment_default_attrs(self):
        return {'name': '', 'description': '',
                'external_routes': [],
                'ip_version': 4,
                'cidr': '172.16.0.0/12',
                'port_address_translation': False,
                'shared': False}

    @gbp_attributes
    def get_create_external_segment_attrs(self):
        return {'name': 'es1', 'tenant_id': _uuid(),
                'description': 'test ep',
                'external_routes': [{'destination': '0.0.0.0/0',
                                     'nexthop': '192.168.0.1'}],
                'cidr': '192.168.0.0/24',
                'ip_version': 4, 'port_address_translation': True,
                'shared': False}

    @gbp_attributes
    def get_update_external_segment_attrs(self):
        return {'name': 'new_name'}

    @gbp_attributes
    def get_create_nat_pool_default_attrs(self):
        return {'name': '', 'description': '',
                'external_segment_id': None, 'ip_version': 4,
                'ip_pool': '172.16.0.0/16',
                'shared': False}

    @gbp_attributes
    def get_create_nat_pool_required_attrs(self):
        return {'ip_pool': '172.16.0.0/16'}

    @gbp_attributes
    def get_create_nat_pool_attrs(self):
        return {'name': 'es1', 'tenant_id': _uuid(),
                'description': 'test ep',
                'ip_version': 4,
                'ip_pool': '172.16.0.0/16',
                'external_segment_id': _uuid(),
                'shared': False}

    @gbp_attributes
    def get_update_nat_pool_attrs(self):
        return {'name': 'new_name'}

    # Service Chain
    @gbp_attributes
    def get_create_service_profile_default_attrs(self):
        return {'name': '', 'description': ''}

    @gbp_attributes
    def get_create_service_profile_attrs(self):
        return {
            'name': 'serviceprofile1',
            'service_type': 'FIREWALL',
            'description': 'test service profile',
        }

    @gbp_attributes
    def get_update_service_profile_attrs(self):
        return {
            'name': 'new_name',
        }

    @gbp_attributes
    def get_create_servicechain_node_default_attrs(self):
        return {
            'name': '',
            'description': '',
            'config': '{}',
            'service_type': None,
            'shared': False,
        }

    @gbp_attributes
    def get_create_servicechain_node_required_attrs(self):
        return {
            'config': '{}',
        }

    @gbp_attributes
    def get_create_servicechain_node_attrs(self):
        return {
            'name': 'servicechain1',
            'service_profile_id': _uuid(),
            'tenant_id': _uuid(),
            'description': 'test servicechain node',
            'config': '{}',
            'service_type': None,
            'shared': True,
        }

    @gbp_attributes
    def get_update_servicechain_node_attrs(self):
            return {
                'name': 'new_name',
                'config': 'new_config',
            }

    @gbp_attributes
    def get_create_servicechain_spec_default_attrs(self):
        return {
            'name': '',
            'description': '',
            'nodes': [],
            'shared': False,
        }

    @gbp_attributes
    def get_create_servicechain_spec_attrs(self):
        return {
            'name': 'servicechainspec1',
            'nodes': [_uuid(), _uuid()],
            'tenant_id': _uuid(),
            'description': 'test servicechain spec',
            'shared': True,
        }

    @gbp_attributes
    def get_update_servicechain_spec_attrs(self):
        return {
            'name': 'new_name',
            'nodes': [_uuid()]
        }

    @gbp_attributes
    def get_create_servicechain_instance_default_attrs(self):
        return {'name': '', 'description': '', 'config_param_values': "{}"}

    @gbp_attributes
    def get_create_servicechain_instance_attrs(self):
        return {
            'name': 'servicechaininstance1',
            'servicechain_specs': [_uuid()],
            'tenant_id': _uuid(),
            'provider_ptg_id': _uuid(),
            'consumer_ptg_id': _uuid(),
            'classifier_id': _uuid(),
            'config_param_values': "{}",
            'description': 'test servicechain instance'
        }

    def get_update_servicechain_instance_attrs(self):
        return {
            'name': 'new_name',
            'servicechain_specs': [_uuid()]
        }

    def get_resource_plural(self, resource):
        if resource.endswith('y'):
            resource_plural = resource.replace('y', 'ies')
        else:
            resource_plural = resource + 's'

        return resource_plural

    def _is_sc_resource(self, plural):
        return plural in self.resource_prefix_map

    def _is_gbp_resource(self, plural):
        return plural in self.resource_prefix_map


res = Attributes()
