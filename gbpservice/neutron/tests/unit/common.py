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

from neutron.openstack.common import uuidutils

_uuid = uuidutils.generate_uuid


def gbp_attributes(func):
    def inner(**kwargs):
        attrs = func()
        attrs.update(kwargs)
        return attrs
    return inner


@gbp_attributes
def get_create_policy_target_default_attrs():
    return {'name': '', 'description': '', 'policy_target_group_id': None}


@gbp_attributes
def get_create_policy_target_attrs():
    return {'name': 'ep1', 'policy_target_group_id': _uuid(),
            'tenant_id': _uuid(), 'description': 'test policy_target'}


@gbp_attributes
def get_update_policy_target_attrs():
    return {'name': 'new_name'}


@gbp_attributes
def get_create_policy_target_group_default_attrs():
    return {'name': '', 'description': '', 'l2_policy_id': None,
            'provided_policy_rule_sets': {},
            'consumed_policy_rule_sets': {},
            'network_service_policy_id': None, 'shared': False}


@gbp_attributes
def get_create_policy_target_group_attrs():
    return {'name': 'ptg1', 'tenant_id': _uuid(),
            'description': 'test policy_target group',
            'l2_policy_id': _uuid(),
            'provided_policy_rule_sets': {_uuid(): None},
            'consumed_policy_rule_sets': {_uuid(): None},
            'network_service_policy_id': _uuid(),
            'shared': False}


@gbp_attributes
def get_update_policy_target_group_attrs():
    return {'name': 'new_name'}


@gbp_attributes
def get_create_l2_policy_default_attrs():
    return {'name': '', 'description': '', 'shared': False}


@gbp_attributes
def get_create_l2_policy_attrs():
    return {'name': 'l2p1', 'tenant_id': _uuid(),
            'description': 'test L2 policy', 'l3_policy_id': _uuid(),
            'shared': False}


@gbp_attributes
def get_update_l2_policy_attrs():
    return {'name': 'new_name'}


@gbp_attributes
def get_create_l3_policy_default_attrs():
    return {'name': '', 'description': '', 'ip_version': 4,
            'ip_pool': '10.0.0.0/8', 'subnet_prefix_length': 24,
            'external_segments': {}, 'shared': False}


@gbp_attributes
def get_create_l3_policy_attrs():
    return {'name': 'l3p1', 'tenant_id': _uuid(),
            'description': 'test L3 policy', 'ip_version': 6,
            'ip_pool': 'fd01:2345:6789::/48',
            'external_segments': {_uuid(): ['192.168.0.3']},
            'subnet_prefix_length': 64, 'shared': False}


@gbp_attributes
def get_update_l3_policy_attrs():
    return {'name': 'new_name'}


@gbp_attributes
def get_create_policy_action_default_attrs():
    return {'name': '',
            'description': '',
            'action_type': 'allow',
            'action_value': None,
            'shared': False}


@gbp_attributes
def get_create_policy_action_attrs():
    return {'name': 'pa1',
            'tenant_id': _uuid(),
            'description': 'test policy action',
            'action_type': 'redirect',
            'action_value': _uuid(),
            'shared': False}


@gbp_attributes
def get_update_policy_action_attrs():
    return {'name': 'new_name'}


@gbp_attributes
def get_create_policy_classifier_default_attrs():
    return {'name': '',
            'description': '',
            'protocol': None,
            'port_range': None,
            'direction': None,
            'shared': False}


@gbp_attributes
def get_create_policy_classifier_attrs():
    return {'name': 'pc1',
            'description': 'test policy classifier',
            'tenant_id': _uuid(),
            'protocol': 'tcp',
            'port_range': '100:200',
            'direction': 'in',
            'shared': False}


@gbp_attributes
def get_update_policy_classifier_attrs():
    return {'name': 'new_name'}


@gbp_attributes
def get_create_policy_rule_default_attrs():
    return {'name': '',
            'description': '',
            'enabled': True,
            'policy_actions': [],
            'shared': False}


@gbp_attributes
def get_create_policy_rule_attrs():
    return {'name': 'pr1',
            'description': 'test policy rule',
            'tenant_id': _uuid(),
            'enabled': True,
            'policy_classifier_id': _uuid(),
            'policy_actions': [_uuid()],
            'shared': False}


@gbp_attributes
def get_update_policy_rule_attrs():
    return {'name': 'new_name'}


@gbp_attributes
def get_create_policy_rule_set_default_attrs():
    return {'name': '',
            'description': '',
            'child_policy_rule_sets': [],
            'policy_rules': [],
            'shared': False}


@gbp_attributes
def get_create_policy_rule_set_attrs():
    return {'name': 'policy_rule_set1',
            'description': 'test policy_rule_set',
            'tenant_id': _uuid(),
            'child_policy_rule_sets': [_uuid()],
            'policy_rules': [_uuid()],
            'shared': False}


@gbp_attributes
def get_update_policy_rule_set_attrs():
    return {'name': 'new_name'}


@gbp_attributes
def get_create_network_service_policy_default_attrs():
    return {'name': '', 'description': '',
            'network_service_params': [], 'shared': False}


@gbp_attributes
def get_create_network_service_policy_attrs():
    return {'name': 'nsp1', 'tenant_id': _uuid(),
            'shared': False,
            'description': 'test Net Svc Policy',
            'network_service_params': [{'type': 'ip_single', 'name': 'vip',
                                        'value': 'self_subnet'}]}


@gbp_attributes
def get_update_network_service_policy_attrs():
    return {'name': 'new_name'}


@gbp_attributes
def get_create_external_policy_default_attrs():
    return {'name': '', 'description': '',
            'external_segments': [],
            'provided_policy_rule_sets': {},
            'consumed_policy_rule_sets': {},
            'shared': False}


@gbp_attributes
def get_create_external_policy_attrs():
    return {'name': 'ep1', 'tenant_id': _uuid(),
            'description': 'test ep',
            'external_segments': [_uuid()],
            'provided_policy_rule_sets': {_uuid(): None},
            'consumed_policy_rule_sets': {_uuid(): None},
            'shared': False}


@gbp_attributes
def get_update_external_policy_attrs():
    return {'name': 'new_name'}


@gbp_attributes
def get_create_external_segment_default_attrs():
    return {'name': '', 'description': '',
            'external_routes': [],
            'ip_version': 4,
            'cidr': '172.16.0.0/12',
            'port_address_translation': False,
            'shared': False}


@gbp_attributes
def get_create_external_segment_attrs():
    return {'name': 'es1', 'tenant_id': _uuid(),
            'description': 'test ep',
            'external_routes': [{'destination': '0.0.0.0/0',
                                 'nexthop': '192.168.0.1'}],
            'cidr': '192.168.0.0/24',
            'ip_version': 4, 'port_address_translation': True,
            'shared': False}


@gbp_attributes
def get_update_external_segment_attrs():
    return {'name': 'new_name'}


@gbp_attributes
def get_create_nat_pool_default_attrs():
    return {'name': '', 'description': '',
            'external_segment_id': None, 'ip_version': 4,
            'ip_pool': '172.16.0.0/16',
            'shared': False}


@gbp_attributes
def get_create_nat_pool_attrs():
    return {'name': 'es1', 'tenant_id': _uuid(),
            'description': 'test ep',
            'ip_version': 4,
            'ip_pool': '172.16.0.0/16',
            'external_segment_id': _uuid(),
            'shared': False}


@gbp_attributes
def get_update_nat_pool_attrs():
    return {'name': 'new_name'}


def get_resource_plural(resource):
    if resource.endswith('y'):
        resource_plural = resource.replace('y', 'ies')
    else:
        resource_plural = resource + 's'

    return resource_plural
