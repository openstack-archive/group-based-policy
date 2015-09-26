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

from gbpservice.neutron.services.grouppolicy.common import exceptions as gpexc


class InvalidApicName(gpexc.GroupPolicyBadRequest):
    message = _("Resource has no valid APIC name.")

APIC_REFERENCE_PREFIX = 'apic:'


class ApicNameManager(object):

    gbp_to_apic = {'l3_policy': 'context',
                   'l2_policy': 'bridge_domain',
                   'policy_target_group': 'endpoint_group',
                   'policy_rule_set': 'contract'}

    def __init__(self, apic_manager):
        self.name_mapper = apic_manager.apic_mapper
        self.dn_manager = apic_manager.apic.dn_manager

    def __getattr__(self, item):
        if self.name_mapper.is_valid_name_type(item):
            def get_name_wrapper(context, obj_id, prefix=''):
                return self._get_name(item, context, obj_id, prefix=prefix)
            return get_name_wrapper

        raise AttributeError

    def tenant(self, obj):
        if self._is_apic_reference(obj):
            parts = self._try_all_types(obj)
            if parts:
                return parts[0]
        return self.name_mapper.tenant(None, obj['tenant_id'])

    def has_valid_name(self, obj):
        if self._is_apic_reference(obj):
            if not self._try_all_types(obj):
                raise InvalidApicName()

    def _try_all_types(self, obj):
        for possible in self.dn_manager.nice_to_rn:
            parts = getattr(self.dn_manager, 'decompose_%s' % possible)(
                self._extract_apic_reference(obj))
            if parts:
                return parts

    def _get_name(self, obj_type, context, obj, prefix=''):
        if self._is_apic_reference(obj) and obj_type in self.gbp_to_apic:
            map_type = self.gbp_to_apic[obj_type]
            parts = getattr(self.dn_manager, 'decompose_%s' % map_type)(
                self._extract_apic_reference(obj))
            result = parts[-1]
        else:
            result = getattr(self.name_mapper, obj_type)(context, obj['id'],
                                                         prefix=prefix)
        return result

    def _is_apic_reference(self, obj):
        return obj['name'].startswith(APIC_REFERENCE_PREFIX)

    def _extract_apic_reference(self, obj):
        return obj['name'][len(APIC_REFERENCE_PREFIX):]