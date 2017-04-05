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

import mock
from mock import call
import webob.exc

from neutron.db import api as db_api
from neutron_lib.db import model_base
from oslo_config import cfg
from vmware_nsx.common import config
from vmware_nsxlib.v3 import exceptions as nsxlib_exc

from gbpservice.neutron.services.grouppolicy.\
     drivers.vmware.nsx_policy import nsx_policy_mapping as driver
from gbpservice.neutron.tests.unit.services.grouppolicy import (
    test_resource_mapping as test_rmd)


TEST_PROJECT = 'test-project'

GET_RESPONSE_EMPTY = {}
GET_RESPONSE_DOMAIN_EXISTS = {'id': TEST_PROJECT}


class NsxPolicyMappingTestCase(test_rmd.ResourceMappingTestCase):

    def setUp(self):
        self.set_up_mocks()
        self.set_up_config()

        super(NsxPolicyMappingTestCase, self).setUp(
            policy_drivers=['implicit_policy', 'nsx_policy'])
        # REVISIT (annak): currently run with ML2 plugin
        # core_plugin='vmware_nsx.plugin.NsxV3Plugin'

        engine = db_api.get_engine()
        model_base.BASEV2.metadata.create_all(engine)

        self.driver = self._gbp_plugin.policy_driver_manager.policy_drivers[
               'nsx_policy'].obj
        self.nsx_policy = self.driver.nsx_policy
        self._tenant_id = TEST_PROJECT

    def tearDown(self):
        super(NsxPolicyMappingTestCase, self).tearDown()

    def set_up_config(self):
        cfg.CONF.register_opts(driver.policy_opts, driver.DRIVER_OPT_GROUP)
        cfg.CONF.register_opts(config.nsx_v3_opts, group="nsx_v3")
        cfg.CONF.set_override('nsx_policy_manager', '1.1.1.1',
                              driver.DRIVER_OPT_GROUP)
        cfg.CONF.set_override('nsx_api_managers', '1.1.1.1',
                              driver.NSX_V3_GROUP)

    def set_up_mocks(self):
        mock.patch("vmware_nsxlib.v3.client.NSX3Client").start()

    def _mock_domain_create(self):
        return mock.patch.object(self.nsx_policy.domain, 'create')

    def _mock_domain_delete(self):
        return mock.patch.object(self.nsx_policy.domain, 'delete')

    def _mock_service_create(self):
        return mock.patch.object(self.nsx_policy.service, 'create')

    def _mock_service_delete(self):
        return mock.patch.object(self.nsx_policy.service, 'delete')

    def _mock_profile_create(self):
        return mock.patch.object(self.nsx_policy.comm_profile, 'create')

    def _mock_profile_list(self, profile_ids):
        return mock.patch.object(self.nsx_policy.comm_profile, 'list',
                                 return_value=[{'id': p}
                                               for p in profile_ids])

    def _mock_group_create(self):
        return mock.patch.object(self.nsx_policy.group, 'create')

    def _mock_group_create_fails(self):
        return mock.patch.object(self.nsx_policy.group, 'create',
                                 side_effect=nsxlib_exc.ManagerError)

    def _mock_group_delete(self):
        return mock.patch.object(self.nsx_policy.group, 'delete')

    def _mock_map_update(self):
        return mock.patch.object(self.nsx_policy.comm_map, 'update')

    def _mock_map_delete(self):
        return mock.patch.object(self.nsx_policy.comm_map, 'delete')

    def _mock_map_update_fails(self):
        return mock.patch.object(self.nsx_policy.comm_map, 'update',
                                 side_effect=nsxlib_exc.ManagerError)

    def _mock_policy_create_fails(self):
        return mock.patch.object(self.policy_api, 'create',
                                 side_effect=nsxlib_exc.ManagerError)

    def _mock_policy_create_with_parent_fails(self):
        return mock.patch.object(self.policy_api, 'create_with_parent',
                                 side_effect=nsxlib_exc.ManagerError)

    def _mock_policy_delete(self):
        return mock.patch.object(self.policy_api, 'delete')


class TestPolicyClassifier(NsxPolicyMappingTestCase):

    def test_create(self):
        # Create non-first classifier within tenant
        # Should not trigger domain generation on backend
        with self._mock_service_create() as service_create_call:

            self.create_policy_classifier(name='test',
                                          protocol='TCP',
                                          port_range='80',
                                          direction='bi')

            # verify API call to create the service
            service_create_call.assert_called_with(
                name='test',
                description=mock.ANY,
                protocol='tcp',
                dest_ports=['80'],
                service_id=mock.ANY)

    def test_delete(self):
        with self._mock_service_create(),\
            self._mock_service_delete() as service_delete_call:

            classifier = self.create_policy_classifier(
                name='test',
                protocol='TCP',
                port_range='80',
                direction='bi')['policy_classifier']
            self.delete_policy_classifier(classifier['id'])

            service_delete_call.assert_called_with(classifier['id'])


class TestPolicyTargetGroup(NsxPolicyMappingTestCase):

    def _prepare_rule_set(self, name='test'):
        with self._mock_service_create(),\
             self._mock_profile_create():

            rule = self._create_simple_policy_rule()
            return self.create_policy_rule_set(
                    name=name, policy_rules=[rule['id']])['policy_rule_set']

    def assert_neutron_resources(self, net_count, subnet_count, port_count):
        networks = self._plugin.get_networks(self._context)
        self.assertEqual(net_count, len(networks))

        subnets = self._plugin.get_subnets(self._context)
        self.assertEqual(subnet_count, len(subnets))

        ports = self._plugin.get_ports(self._context)
        self.assertEqual(port_count, len(ports))

    def assert_neutron_rollback(self):
        self.assert_neutron_resources(0, 0, 0)

    def group_call(self, name, group_id):
        return call(domain_id=TEST_PROJECT,
                    name=name,
                    description=mock.ANY,
                    cond_val=group_id,
                    group_id=group_id)

    def ingress_map_call(self, prs_id, provider_ids, consumer_ids):
        return call(domain_id=TEST_PROJECT,
                    profile_id=driver.in_name(prs_id),
                    map_id=mock.ANY,
                    description=mock.ANY,
                    source_groups=consumer_ids,
                    dest_groups=provider_ids)

    def egress_map_call(self, prs_id, provider_ids, consumer_ids):
        return call(domain_id=TEST_PROJECT,
                    profile_id=driver.out_name(prs_id),
                    map_id=mock.ANY,
                    description=mock.ANY,
                    source_groups=provider_ids,
                    dest_groups=consumer_ids)

    def test_create_first_ptg_for_project(self):
        '''Create first ptg for tenant and verify domain creation'''

        with self._mock_domain_create() as domain_create,\
            self._mock_group_create() as group_create,\
            self._mock_map_update() as map_update:

            ptg = self.create_policy_target_group(
                name='test')['policy_target_group']

            domain_create.assert_called_with(domain_id=TEST_PROJECT,
                                             name=TEST_PROJECT)
            group_create.assert_has_calls([self.group_call('test', ptg['id'])])
            map_update.assert_not_called()

    def _test_ptg_pair_with_single_rule(self,
                                        direction_in=True,
                                        direction_out=True):
        '''Test consumer and producer group pair with single rule lifecycle.

        Verify backend group and rule creation calls.
        Verify spawned neutron resources.
        '''

        policy_rule_set = self._prepare_rule_set()
        profile_in = driver.in_name(policy_rule_set['id'])
        profile_out = driver.out_name(policy_rule_set['id'])
        profile_ids = []
        if direction_in:
            profile_ids.append(profile_in)
        if direction_out:
            profile_ids.append(profile_out)

        # Create group pair
        with self._mock_group_create() as group_create,\
            self._mock_profile_list(profile_ids),\
            self._mock_map_update() as map_create,\
            self._mock_domain_create():

            provider_ptg, consumer_ptg = self._create_provider_consumer_ptgs(
                    policy_rule_set['id'])

            # validate group creation on backend
            calls = [self.group_call('ptg1', provider_ptg),
                     self.group_call('ptg2', consumer_ptg)]
            group_create.assert_has_calls(calls)

            # validate communication map creation on backend
            calls = []
            if direction_in:
                calls.append(self.ingress_map_call(policy_rule_set['id'],
                                                   [provider_ptg],
                                                   [consumer_ptg]))
            if direction_out:
                calls.append(self.egress_map_call(policy_rule_set['id'],
                                                  [provider_ptg],
                                                  [consumer_ptg]))
            map_create.assert_has_calls(calls)

            # validate neutron resources
            self.assert_neutron_resources(2, 2, 2)

        # Delete producer
        with self._mock_map_delete() as map_delete,\
            self._mock_profile_list(profile_ids),\
            self._mock_group_delete() as group_delete,\
            self._mock_domain_delete() as domain_delete:

            self.delete_policy_target_group(provider_ptg)

            # verify communication map delete on backend
            calls = []
            if direction_in:
                calls.append(call(TEST_PROJECT,
                                  driver.in_name(policy_rule_set['id'])))
            if direction_out:
                calls.append(call(TEST_PROJECT,
                                  driver.out_name(policy_rule_set['id'])))

            map_delete.assert_has_calls(calls)

            # verify group delete call
            group_delete.assert_called_with(TEST_PROJECT, provider_ptg)

            # verify domain not deleted yet
            domain_delete.assert_not_called()

        # Delete consumer
        with self._mock_map_delete() as map_delete,\
            self._mock_profile_list(profile_ids),\
            self._mock_group_delete() as group_delete,\
            self._mock_domain_delete() as domain_delete:

            self.delete_policy_target_group(consumer_ptg)

            # no deletions on communication map are expected
            map_delete.assert_not_called()

            # verify group delete call
            group_delete.assert_called_with(TEST_PROJECT, consumer_ptg)

            # last group is deleted, domain should go as well
            domain_delete.assert_called_with(TEST_PROJECT)

    def test_create_ptg_pair_with_single_rule_in(self):
        self._test_ptg_pair_with_single_rule(True, False)

    def test_create_ptg_pair_with_single_rule_out(self):
        self._test_ptg_pair_with_single_rule(False, True)

    def test_create_ptg_pair_with_single_rule_bi(self):
        self._test_ptg_pair_with_single_rule(True, True)

    def test_create_fail_isolated(self):
        '''Verify integrity when backend fails on isolated group creation.

        Verify backend receives a group delete call.
        Verify spawned neutron resources are cleaned up.
        '''

        policy_rule_set = self._prepare_rule_set()

        with self._mock_domain_create(),\
            self._mock_group_create_fails(),\
            self._mock_group_delete() as group_delete,\
            self._mock_domain_delete() as domain_delete:

            self.assertRaises(webob.exc.HTTPClientError,
                              self._create_provider_consumer_ptgs,
                              policy_rule_set['id'])

            group_delete.assert_called_with(self._tenant_id,
                                            mock.ANY)

            # verify domain deletion since group failed to create
            domain_delete.assert_called_with(TEST_PROJECT)

            self.assert_neutron_rollback()

    def test_create_fail_connected(self):
        '''Verify integrity when backend fails on connectivity map creation

        This test creates a pair of groups. First group creation succeeds,
        while second fails on connectivity enforcement.
        Verify backend receives a group delete call for second group.
        Verify spawned neutron resources are cleaned up for second group.
        '''

        policy_rule_set = self._prepare_rule_set()
        profile_ids = [driver.in_name(policy_rule_set['id']),
                       driver.out_name(policy_rule_set['id'])]

        with self._mock_group_create(),\
            self._mock_profile_list(profile_ids),\
            self._mock_map_update_fails(),\
            self._mock_group_delete() as group_delete:

            self.assertRaises(webob.exc.HTTPClientError,
                              self._create_provider_consumer_ptgs,
                              policy_rule_set['id'])

            group_delete.assert_called_with(self._tenant_id, mock.ANY)

            self.assert_neutron_resources(1, 1, 1)

    def test_create_ptg_pair_multi_rule_set(self):
        '''Create ptg pair based on 3 rule sets

        First rule set is simulated to have only ingress connectivity,
        second - only egress connectivity, and third - both
        '''
        prs1 = self._prepare_rule_set()['id']
        prs2 = self._prepare_rule_set()['id']
        prs3 = self._prepare_rule_set()['id']

        profile_ids = [driver.in_name(prs1),
                       driver.out_name(prs2),
                       driver.in_name(prs3),
                       driver.out_name(prs3)]

        with self._mock_domain_create(),\
            self._mock_group_create() as group_create,\
            self._mock_profile_list(profile_ids),\
            self._mock_map_update() as map_update:

            rule_set_dict = {prs1: None, prs2: None, prs3: None}
            provider_ptg = self.create_policy_target_group(
                name='ptg1', provided_policy_rule_sets=rule_set_dict)
            provider_id = provider_ptg['policy_target_group']['id']
            consumer_ptg = self.create_policy_target_group(
                name='ptg2', consumed_policy_rule_sets=rule_set_dict)
            consumer_id = consumer_ptg['policy_target_group']['id']

            group_create.assert_has_calls(
                [self.group_call('ptg1', provider_id),
                 self.group_call('ptg2', consumer_id)])

            map_calls = [
                self.ingress_map_call(prs1, [provider_id], [consumer_id]),
                self.egress_map_call(prs2, [provider_id], [consumer_id]),
                self.ingress_map_call(prs3, [provider_id], [consumer_id]),
                self.egress_map_call(prs3, [provider_id], [consumer_id])]
            map_update.assert_has_calls(map_calls, any_order=True)

    def test_create_ptg_ring(self):
        ring_size = 3

        prs_ids = []
        for i in range(0, ring_size):
            prs_ids.append(self._prepare_rule_set()['id'])

        profile_ids = [driver.in_name(prs_id) for prs_id in prs_ids]

        with self._mock_domain_create(),\
            self._mock_profile_list(profile_ids),\
            self._mock_group_create() as group_create,\
            self._mock_map_update() as map_update:

            group_calls = []
            map_calls = []
            ptg_ids = []
            for i in range(0, ring_size):
                provided_rule_set_dict = {prs_ids[i]: None}
                next_i = (i + 1) % ring_size
                consumed_rule_set_dict = {prs_ids[next_i]: None}
                name = 'ptg_%d' % i
                ptg = self.create_policy_target_group(
                        name=name,
                        provided_policy_rule_sets=provided_rule_set_dict,
                        consumed_policy_rule_sets=consumed_rule_set_dict)

                ptg_id = ptg['policy_target_group']['id']
                ptg_ids.append(ptg_id)
                group_calls.append(self.group_call(name, ptg_id))

                if i > 0:
                    map_calls.append(self.ingress_map_call(
                        prs_ids[i],
                        [ptg_id],
                        [ptg_ids[i - 1]]))

            map_calls.append(self.ingress_map_call(prs_ids[0],
                                                   [ptg_ids[0]],
                                                   [ptg_id]))

            group_create.assert_has_calls(group_calls)
            map_update.assert_has_calls(map_calls)

            self.assert_neutron_resources(ring_size, ring_size, ring_size)

    def test_create_ptg_star(self):
        '''Star-like topology (single producer and N consumers) lifecycle'''

        star_size = 10
        policy_rule_set = self._prepare_rule_set()
        prs_id = policy_rule_set['id']
        profile_ids = [driver.in_name(prs_id)]

        # Create topology
        with self._mock_domain_create(),\
            self._mock_profile_list(profile_ids),\
            self._mock_group_create() as group_create,\
            self._mock_map_update() as map_update:

            policy_rule_set_dict = {prs_id: None}
            provider_ptg = self.create_policy_target_group(
                    name='producer',
                    provided_policy_rule_sets=policy_rule_set_dict)
            provider_id = provider_ptg['policy_target_group']['id']

            group_calls = [self.group_call('producer', provider_id)]
            map_calls = []

            consumer_ids = []
            for i in range(0, star_size):
                name = 'consumer_%d' % i
                consumer_ptg = self.create_policy_target_group(
                        name=name,
                        consumed_policy_rule_sets=policy_rule_set_dict)

                consumer_id = consumer_ptg['policy_target_group']['id']
                consumer_ids.append(consumer_id)

                group_calls.append(self.group_call(name, consumer_id))

                map_calls.append(self.ingress_map_call(
                    prs_id,
                    [provider_id],
                    consumer_ids[:]))

            group_create.assert_has_calls(group_calls)
            map_update.assert_has_calls(map_calls)

            star_size += 1
            self.assert_neutron_resources(star_size, star_size, star_size)

        # Delete one consumer group
        with self._mock_map_delete() as map_delete,\
            self._mock_map_update() as map_update,\
            self._mock_profile_list(profile_ids),\
            self._mock_group_delete() as group_delete:

            consumer_id = consumer_ids.pop(0)
            self.delete_policy_target_group(consumer_id)

            map_update.assert_has_calls(
                [self.ingress_map_call(prs_id,
                                      [provider_id],
                                      consumer_ids)])

            map_delete.assert_not_called()

            group_delete.assert_called_with(TEST_PROJECT, consumer_id)

            star_size -= 1
            self.assert_neutron_resources(star_size, star_size, star_size)

        # Delete provider group
        with self._mock_map_delete() as map_delete,\
            self._mock_map_update() as map_update,\
            self._mock_profile_list(profile_ids),\
            self._mock_group_delete() as group_delete:

            self.delete_policy_target_group(provider_id)

            map_update.assert_not_called()
            map_delete.assert_called_with(TEST_PROJECT, driver.in_name(prs_id))

            star_size -= 1
            group_delete.assert_called_with(TEST_PROJECT, provider_id)


class TestPolicyRuleSet(NsxPolicyMappingTestCase):

    def test_policy_rule_set_create_bidirectional(self):
        with self._mock_profile_create() as profile_create:

            rule = self._create_simple_policy_rule()
            rule_set = self.create_policy_rule_set(
                name='test', policy_rules=[rule['id']])['policy_rule_set']

            calls = [call(name=driver.in_name('test'),
                          description=mock.ANY,
                          profile_id=driver.in_name(rule_set['id']),
                          services=[rule['policy_classifier_id']]),
                     call(name=driver.out_name('test'),
                          description=mock.ANY,
                          profile_id=driver.out_name(rule_set['id']),
                          services=[rule['policy_classifier_id']])]

            profile_create.assert_has_calls(calls)
