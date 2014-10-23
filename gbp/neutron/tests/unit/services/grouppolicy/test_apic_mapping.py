# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import sys

import mock
from neutron.common import rpc as n_rpc
from neutron.tests.unit.ml2.drivers.cisco.apic import (
    test_cisco_apic_common as mocked)

sys.modules["apicapi"] = mock.Mock()

from gbp.neutron.services.grouppolicy import config
from gbp.neutron.services.grouppolicy.drivers.cisco.apic import apic_mapping
from gbp.neutron.tests.unit.services.grouppolicy import test_grouppolicy_plugin
from gbp.neutron.tests.unit.services.grouppolicy import test_resource_mapping

APIC_L2_POLICY = 'l2_policy'
APIC_L3_POLICY = 'l3_policy'
APIC_CONTRACT = 'contract'
APIC_ENDPOINT_GROUP = 'endpoint_group'
APIC_POLICY_RULE = 'policy_rule'


def echo(context, string):
    return string


class ApicMappingTestCase(
        test_grouppolicy_plugin.GroupPolicyPluginTestCase,
        mocked.ControllerMixin, mocked.ConfigMixin):

    def setUp(self):
        config.cfg.CONF.set_override('policy_drivers',
                                     ['implicit_policy', 'apic'],
                                     group='group_policy')
        n_rpc.create_connection = mock.Mock()
        apic_mapping.ApicMappingDriver.get_apic_manager = mock.Mock()
        super(ApicMappingTestCase, self).setUp(
            core_plugin=test_resource_mapping.CORE_PLUGIN)

        self.driver = apic_mapping.ApicMappingDriver.get_initialized_instance()
        apic_mapping.ApicMappingDriver.get_base_synchronizer = mock.Mock()
        self.driver.name_mapper = mock.Mock()
        self.driver.name_mapper.tenant = echo
        self.driver.name_mapper.l2_policy = echo
        self.driver.name_mapper.l3_policy = echo
        self.driver.name_mapper.contract = echo
        self.driver.name_mapper.policy_rule = echo
        self.driver.name_mapper.app_profile.return_value = mocked.APIC_AP
        self.driver.name_mapper.endpoint_group = echo
        self.driver.apic_manager = mock.Mock(name_mapper=mock.Mock())
        self.driver.apic_manager.apic.transaction = self.fake_transaction


class TestEndpointGroup(ApicMappingTestCase):

    def test_endpoint_group_created_on_apic(self):
        epg = self.create_endpoint_group(name="epg1")['endpoint_group']

        mgr = self.driver.apic_manager
        mgr.ensure_epg_created.assert_called_once_with(
            epg['tenant_id'], epg['id'], bd_name=epg['l2_policy_id'])

    def _test_epg_contract_created(self, provider=True):
        cntr = self.create_contract(name='c')['contract']

        if provider:
            epg = self.create_endpoint_group(
                provided_contracts={cntr['id']: 'scope'})['endpoint_group']
        else:
            epg = self.create_endpoint_group(
                consumed_contracts={cntr['id']: 'scope'})['endpoint_group']

        # Verify that the apic call is issued
        mgr = self.driver.apic_manager
        mgr.set_contract_for_epg.assert_called_with(
            epg['tenant_id'], epg['id'], cntr['id'], transaction='transaction',
            provider=provider)

    def _test_epg_contract_updated(self, provider=True):
        p_or_c = {True: 'provided_contracts', False: 'consumed_contracts'}
        cntr = self.create_contract(name='c1')['contract']
        new_cntr = self.create_contract(name='c2')['contract']

        if provider:
            epg = self.create_endpoint_group(
                provided_contracts={cntr['id']: 'scope'})
        else:
            epg = self.create_endpoint_group(
                consumed_contracts={cntr['id']: 'scope'})

        data = {'endpoint_group': {p_or_c[provider]:
                {new_cntr['id']: 'scope'}}}
        req = self.new_update_request('endpoint_groups', data,
                                      epg['endpoint_group']['id'], self.fmt)
        epg = self.deserialize(self.fmt, req.get_response(self.ext_api))
        epg = epg['endpoint_group']
        mgr = self.driver.apic_manager
        mgr.set_contract_for_epg.assert_called_with(
            epg['tenant_id'], epg['id'], new_cntr['id'],
            transaction='transaction', provider=provider)
        mgr.unset_contract_for_epg.assert_called_with(
            epg['tenant_id'], epg['id'], cntr['id'],
            transaction='transaction', provider=provider)

    def test_epg_contract_provider_created(self):
        self._test_epg_contract_created()

    def test_epg_contract_provider_updated(self):
        self._test_epg_contract_updated()

    def test_epg_contract_consumer_created(self):
        self._test_epg_contract_created(False)

    def test_epg_contract_consumer_updated(self):
        self._test_epg_contract_updated(False)

    def test_endpoint_group_deleted_on_apic(self):
        epg = self.create_endpoint_group(name="epg1")['endpoint_group']
        req = self.new_delete_request('endpoint_groups', epg['id'], self.fmt)
        req.get_response(self.ext_api)
        mgr = self.driver.apic_manager
        mgr.delete_epg_for_network.assert_called_once_with(
            epg['tenant_id'], epg['id'])


# TODO(ivar): test L2 Policy
class TestL2Policy(ApicMappingTestCase):
    pass


# TODO(ivar): test L3 Policy
class TestL3Policy(ApicMappingTestCase):
    pass


# TODO(ivar): test Contract
class TestContract(ApicMappingTestCase):
    pass
