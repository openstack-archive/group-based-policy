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

from oslo_config import cfg
from vmware_nsx.common import config
from vmware_nsxlib.v3 import exceptions as nsxlib_exc

from gbpservice.neutron.services.grouppolicy.drivers.vmware.nsx_policy import (
    nsx_policy_mapping as driver)
from gbpservice.neutron.tests.unit.services.grouppolicy import (
    test_resource_mapping as test_rmd)
import unittest2


TEST_PROJECT = 'test-project'
TEMPORARY_SKIP = 'skipping temporarily while adjusting to next backend version'


class NsxPolicyMappingTestCase(test_rmd.ResourceMappingTestCase):

    def setUp(self):
        self.set_up_mocks()
        self.set_up_config()

        super(NsxPolicyMappingTestCase, self).setUp(
            policy_drivers=['implicit_policy', 'nsx_policy'])
        # REVISIT (annak): currently run with ML2 plugin
        # core_plugin='vmware_nsx.plugin.NsxV3Plugin'

        self.driver = self._gbp_plugin.policy_driver_manager.policy_drivers[
               'nsx_policy'].obj
        self.nsx_policy = self.driver.nsx_policy
        self.nsx_port = self.driver.nsx_port
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
        mock.patch("vmware_nsxlib.v3.policy_resources"
                   ".NsxPolicyEnforcementPointApi").start()
        mock.patch("vmware_nsxlib.v3.cluster.ClusteredAPI"
                   "._init_endpoints").start()

    def _mock_domain_create(self):
        return mock.patch.object(self.nsx_policy.domain, 'create_or_overwrite')

    def _mock_domain_delete(self):
        return mock.patch.object(self.nsx_policy.domain, 'delete')

    def _mock_service_create(self):
        return mock.patch.object(self.nsx_policy.service,
                                 'create_or_overwrite')

    def _mock_icmp_service_create(self):
        return mock.patch.object(self.nsx_policy.icmp_service,
                                 'create_or_overwrite')

    def _mock_service_delete(self):
        return mock.patch.object(self.nsx_policy.service, 'delete')

    def _mock_icmp_service_delete(self):
        return mock.patch.object(self.nsx_policy.icmp_service, 'delete')

    def _mock_profile_create(self):
        return mock.patch.object(self.nsx_policy.comm_profile,
                                 'create_or_overwrite')

    def _mock_nth_profile_create_fails(self, n=2):
        self.call_count = 1

        def raise_on_nth_call(**kwargs):
            if self.call_count == n:
                raise nsxlib_exc.ManagerError
            else:
                self.call_count += 1
        return mock.patch.object(self.nsx_policy.comm_profile,
                                 'create_or_overwrite',
                                 side_effect=raise_on_nth_call)

    def _mock_profile_delete(self):
        return mock.patch.object(self.nsx_policy.comm_profile, 'delete')

    def _mock_profile_list(self, profile_ids):
        return mock.patch.object(self.nsx_policy.comm_profile, 'list',
                                 return_value=[{'id': p}
                                               for p in profile_ids])

    def _mock_group_create(self):
        return mock.patch.object(self.nsx_policy.group, 'create_or_overwrite')

    def _mock_group_create_fails(self):
        return mock.patch.object(self.nsx_policy.group, 'create_or_overwrite',
                                 side_effect=nsxlib_exc.ManagerError)

    def _mock_group_delete(self):
        return mock.patch.object(self.nsx_policy.group, 'delete')

    def _mock_map_create(self):
        return mock.patch.object(self.nsx_policy.comm_map,
                                 'create_or_overwrite')

    def _mock_map_delete(self):
        return mock.patch.object(self.nsx_policy.comm_map, 'delete')

    def _mock_map_create_fails(self):
        return mock.patch.object(self.nsx_policy.comm_map,
                                 'create_or_overwrite',
                                 side_effect=nsxlib_exc.ManagerError)

    def _mock_nth_map_create_fails(self, n=2):
        self.call_count = 1

        def raise_on_nth_call(**kwargs):
            if self.call_count == n:
                raise nsxlib_exc.ManagerError
            else:
                self.call_count += 1
        return mock.patch.object(self.nsx_policy.comm_map,
                                 'create_or_overwrite',
                                 side_effect=raise_on_nth_call)

    def _mock_policy_create_fails(self):
        return mock.patch.object(self.policy_api, 'create_or_overwrite',
                                 side_effect=nsxlib_exc.ManagerError)

    def _mock_policy_delete(self):
        return mock.patch.object(self.policy_api, 'delete')

    def _mock_nsx_db(self):
        def mirror_port_id(session, port_id):
            return None, port_id
        mock.patch('vmware_nsx.db.db.get_nsx_switch_and_port_id',
                   side_effect=mirror_port_id).start()

    def _mock_nsx_port_update(self):
        return mock.patch.object(self.nsx_port, 'update')


class TestPolicyClassifier(NsxPolicyMappingTestCase):

    @unittest2.skip(TEMPORARY_SKIP)
    def test_l4_lifecycle(self):
        with self._mock_service_create() as service_create_call, \
            self._mock_service_delete() as service_delete_call:

            # classifier create
            cl = self.create_policy_classifier(
                name='test',
                protocol='TCP',
                port_range='80',
                direction='bi')['policy_classifier']

            # verify API call to create the service
            service_create_call.assert_called_with(
                name=mock.ANY,
                description=mock.ANY,
                protocol='tcp',
                dest_ports=['80'],
                service_id=mock.ANY)

            service_create_call.reset_mock()

            # classifier update
            cl = self.update_policy_classifier(
                    cl['id'],
                    port_range='443',
                    direction='in')['policy_classifier']

            service_create_call.assert_called_with(
                name=mock.ANY,
                description=mock.ANY,
                protocol='tcp',
                dest_ports=['443'],
                service_id=mock.ANY)

            # classifier delete
            self.delete_policy_classifier(cl['id'])

            service_delete_call.assert_called_with(cl['id'])

    @unittest2.skip(TEMPORARY_SKIP)
    def test_create_port_range(self):
        with self._mock_service_create() as service_create_call:

            self.create_policy_classifier(name='test',
                                          protocol='UDP',
                                          port_range='777:888',
                                          direction='in')

            port_list = [str(p) for p in range(777, 889)]
            service_create_call.assert_called_with(
                name=mock.ANY,
                description=mock.ANY,
                protocol='udp',
                dest_ports=port_list,
                service_id=mock.ANY)

    @unittest2.skip(TEMPORARY_SKIP)
    def test_create_without_ports(self):
        with self._mock_service_create() as service_create_call:

            self.create_policy_classifier(name='test',
                                          protocol='TCP',
                                          direction='in')

            service_create_call.assert_called_with(
                name=mock.ANY,
                description=mock.ANY,
                protocol='tcp',
                dest_ports=[],
                service_id=mock.ANY)

    @unittest2.skip(TEMPORARY_SKIP)
    def test_icmp_lifecycle(self):
        with self._mock_icmp_service_create() as service_create_call, \
            self._mock_icmp_service_delete() as service_delete_call:

            cl = self.create_policy_classifier(
                name='test',
                protocol='icmp',
                direction='bi')['policy_classifier']

            # verify API call to create the service
            service_create_call.assert_called()

            self.delete_policy_classifier(cl['id'])

            service_delete_call.assert_called_with(cl['id'])

    @unittest2.skip(TEMPORARY_SKIP)
    def test_update_protocol_fails(self):
        with self._mock_icmp_service_create():

            cl = self.create_policy_classifier(
                name='test',
                protocol='icmp',
                direction='bi')['policy_classifier']

            self.assertRaises(webob.exc.HTTPClientError,
                              self.update_policy_classifier,
                              cl['id'],
                              protocol='tcp',
                              dest_ports=['80'])

    @unittest2.skip(TEMPORARY_SKIP)
    def test_icmpv6_protocol_fails(self):
        self.assertRaises(webob.exc.HTTPClientError,
                          self.create_policy_classifier,
                          name='test',
                          protocol='58',
                          direction='bi')


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
                    name=driver.generate_nsx_name(group_id, name),
                    description=mock.ANY,
                    cond_val=group_id,
                    group_id=group_id)

    def ingress_map_call(self, prs_id, provider_ids, consumer_ids):
        return call(domain_id=TEST_PROJECT,
                    profile_id=driver.append_in_dir(prs_id),
                    map_id=mock.ANY,
                    name=driver.append_in_dir(prs_id),
                    description=mock.ANY,
                    source_groups=consumer_ids,
                    dest_groups=provider_ids)

    def egress_map_call(self, prs_id, provider_ids, consumer_ids):
        return call(domain_id=TEST_PROJECT,
                    profile_id=driver.append_out_dir(prs_id),
                    map_id=mock.ANY,
                    name=driver.append_out_dir(prs_id),
                    description=mock.ANY,
                    source_groups=provider_ids,
                    dest_groups=consumer_ids)

    @unittest2.skip(TEMPORARY_SKIP)
    def test_create_first_ptg_for_project(self):
        '''Create first ptg for tenant and verify domain creation'''

        with self._mock_domain_create() as domain_create,\
            self._mock_group_create() as group_create,\
            self._mock_map_create() as map_create:

            ptg = self.create_policy_target_group(
                name='test')['policy_target_group']

            domain_create.assert_called_with(domain_id=TEST_PROJECT,
                                             name=mock.ANY,
                                             description=mock.ANY)
            group_create.assert_has_calls([self.group_call('test', ptg['id'])])
            map_create.assert_not_called()

    def _test_ptg_pair_with_single_rule(self,
                                        direction_in=True,
                                        direction_out=True):
        '''Test consumer and producer group pair with single rule lifecycle.

        Verify backend group and rule creation calls.
        Verify spawned neutron resources.
        '''

        policy_rule_set = self._prepare_rule_set()
        profile_in = driver.append_in_dir(policy_rule_set['id'])
        profile_out = driver.append_out_dir(policy_rule_set['id'])
        profile_ids = []
        if direction_in:
            profile_ids.append(profile_in)
        if direction_out:
            profile_ids.append(profile_out)

        # Create group pair
        with self._mock_group_create() as group_create,\
            self._mock_profile_list(profile_ids),\
            self._mock_map_create() as map_create,\
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
                calls.append(call(
                    TEST_PROJECT,
                    driver.append_in_dir(policy_rule_set['id'])))
            if direction_out:
                calls.append(call(
                    TEST_PROJECT,
                    driver.append_out_dir(policy_rule_set['id'])))

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

    @unittest2.skip(TEMPORARY_SKIP)
    def test_create_ptg_pair_with_single_rule_in(self):
        self._test_ptg_pair_with_single_rule(True, False)

    @unittest2.skip(TEMPORARY_SKIP)
    def test_create_ptg_pair_with_single_rule_out(self):
        self._test_ptg_pair_with_single_rule(False, True)

    @unittest2.skip(TEMPORARY_SKIP)
    def test_create_ptg_pair_with_single_rule_bi(self):
        self._test_ptg_pair_with_single_rule(True, True)

    @unittest2.skip(TEMPORARY_SKIP)
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

    @unittest2.skip(TEMPORARY_SKIP)
    def test_create_fail_connected(self):
        '''Verify integrity when backend fails on connectivity map creation

        This test creates a pair of groups. First group creation succeeds,
        while second fails on connectivity enforcement.
        Verify backend receives a group delete call for second group.
        Verify spawned neutron resources are cleaned up for second group.
        '''

        policy_rule_set = self._prepare_rule_set()
        profile_ids = [driver.append_in_dir(policy_rule_set['id']),
                       driver.append_out_dir(policy_rule_set['id'])]

        with self._mock_group_create(),\
            self._mock_profile_list(profile_ids),\
            self._mock_map_create_fails(),\
            self._mock_group_delete() as group_delete:

            self.assertRaises(webob.exc.HTTPClientError,
                              self._create_provider_consumer_ptgs,
                              policy_rule_set['id'])

            group_delete.assert_called_with(self._tenant_id, mock.ANY)

            self.assert_neutron_resources(1, 1, 1)

    @unittest2.skip(TEMPORARY_SKIP)
    def test_create_fail_multi_connected(self):
        '''Verify integrity when backend fails on connectivity map creation

        This test creates three groups a<-->b<==>c
        B is created last, and creation fails on its last connectivity
        enforcement.
        Verify all maps are deleted in cleanup.
        Verify spawned neutron resources are cleaned up for third group.
        '''

        prs1 = self._prepare_rule_set()['id']
        prs2 = self._prepare_rule_set()['id']
        prs3 = self._prepare_rule_set()['id']
        profile_ids = [driver.append_in_dir(prs1), driver.append_out_dir(prs1),
                       driver.append_in_dir(prs2), driver.append_out_dir(prs2),
                       driver.append_in_dir(prs3), driver.append_out_dir(prs3)]

        # Create a and c
        with self._mock_group_create(),\
            self._mock_profile_list(profile_ids),\
            self._mock_map_create():

            ab_dict = {prs1: None}
            bc_dict = {prs2: None, prs3: None}
            a = self.create_policy_target_group(
                name='a',
                provided_policy_rule_sets=ab_dict)['policy_target_group']['id']
            c = self.create_policy_target_group(
                name='c',
                consumed_policy_rule_sets=bc_dict)['policy_target_group']['id']

        with self._mock_group_create(),\
            self._mock_profile_list(profile_ids),\
            self._mock_nth_map_create_fails(n=6) as map_create,\
            self._mock_map_delete() as map_delete,\
            self._mock_group_delete() as group_delete:

            self.assertRaises(webob.exc.HTTPClientError,
                              self.create_policy_target_group,
                              name='c',
                              consumed_policy_rule_sets=ab_dict,
                              provided_policy_rule_sets=bc_dict)

            b = mock.ANY
            map_create_calls = [self.ingress_map_call(prs1, [a], [b]),
                                self.egress_map_call(prs1, [a], [b]),
                                self.ingress_map_call(prs2, [b], [c]),
                                self.egress_map_call(prs2, [b], [c]),
                                self.ingress_map_call(prs3, [b], [c]),
                                self.egress_map_call(prs3, [b], [c])]

            map_create.assert_has_calls(map_create_calls, any_order=True)

            map_delete_calls = [
                call(TEST_PROJECT, driver.append_in_dir(prs1)),
                call(TEST_PROJECT, driver.append_out_dir(prs1)),
                call(TEST_PROJECT, driver.append_in_dir(prs2)),
                call(TEST_PROJECT, driver.append_out_dir(prs2)),
                call(TEST_PROJECT, driver.append_in_dir(prs3))]

            map_delete.assert_has_calls(map_delete_calls, any_order=True)

            group_delete.assert_called_with(TEST_PROJECT, mock.ANY)

            self.assert_neutron_resources(2, 2, 2)

    @unittest2.skip(TEMPORARY_SKIP)
    def test_create_ptg_pair_multi_rule_set(self):
        '''Create ptg pair based on 3 rule sets

        First rule set is simulated to have only ingress connectivity,
        second - only egress connectivity, and third - both
        '''
        prs1 = self._prepare_rule_set()['id']
        prs2 = self._prepare_rule_set()['id']
        prs3 = self._prepare_rule_set()['id']

        profile_ids = [driver.append_in_dir(prs1),
                       driver.append_out_dir(prs2),
                       driver.append_in_dir(prs3),
                       driver.append_out_dir(prs3)]

        with self._mock_domain_create(),\
            self._mock_group_create() as group_create,\
            self._mock_profile_list(profile_ids),\
            self._mock_map_create() as map_create:

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
            map_create.assert_has_calls(map_calls, any_order=True)

    @unittest2.skip(TEMPORARY_SKIP)
    def test_create_ptg_ring(self):
        ring_size = 10

        prs_ids = []
        for i in range(0, ring_size):
            prs_ids.append(self._prepare_rule_set()['id'])

        profile_ids = [driver.append_in_dir(prs_id) for prs_id in prs_ids]

        # Create ring topology
        with self._mock_domain_create(),\
            self._mock_profile_list(profile_ids),\
            self._mock_group_create() as group_create,\
            self._mock_map_create() as map_create:

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
            map_create.assert_has_calls(map_calls, any_order=True)

            self.assert_neutron_resources(ring_size, ring_size, ring_size)

        # Delete single group and verify connectors are deleted
        with self._mock_map_delete() as map_delete,\
            self._mock_map_create() as map_create,\
            self._mock_profile_list(profile_ids),\
            self._mock_group_delete() as group_delete:

            ptg_id = ptg_ids[2]
            self.delete_policy_target_group(ptg_id)

            map_calls = [call(TEST_PROJECT, driver.append_in_dir(prs_ids[2])),
                         call(TEST_PROJECT, driver.append_in_dir(prs_ids[3]))]

            map_delete.assert_has_calls(map_calls)
            map_create.assert_not_called()
            group_delete.assert_called_with(TEST_PROJECT, ptg_id)

        # Remove connectors from single group
        with self._mock_map_delete() as map_delete,\
            self._mock_map_create() as map_create,\
            self._mock_profile_list(profile_ids),\
            self._mock_group_delete() as group_delete:

            ptg_id = ptg_ids[5]
            self.update_policy_target_group(
                ptg_id, provided_policy_rule_sets={})

            map_calls = [call(TEST_PROJECT, driver.append_in_dir(prs_ids[5]))]
            map_delete.assert_has_calls(map_calls)
            map_create.assert_not_called()
            group_delete.assert_not_called()

    @unittest2.skip(TEMPORARY_SKIP)
    def test_create_ptg_star(self):
        '''Star-like topology (single producer and N consumers) lifecycle'''

        star_size = 10
        policy_rule_set = self._prepare_rule_set()
        prs_id = policy_rule_set['id']
        profile_ids = [driver.append_in_dir(prs_id)]

        # Create topology
        with self._mock_domain_create(),\
            self._mock_profile_list(profile_ids),\
            self._mock_group_create() as group_create,\
            self._mock_map_create() as map_create:

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
            map_create.assert_has_calls(map_calls)

            star_size += 1
            self.assert_neutron_resources(star_size, star_size, star_size)

        # Delete one consumer group
        with self._mock_map_delete() as map_delete,\
            self._mock_map_create() as map_create,\
            self._mock_profile_list(profile_ids),\
            self._mock_group_delete() as group_delete:

            consumer_id = consumer_ids.pop(0)
            self.delete_policy_target_group(consumer_id)

            map_create.assert_has_calls(
                [self.ingress_map_call(prs_id,
                                      [provider_id],
                                      consumer_ids)])

            map_delete.assert_not_called()

            group_delete.assert_called_with(TEST_PROJECT, consumer_id)

            star_size -= 1
            self.assert_neutron_resources(star_size, star_size, star_size)

        # Delete provider group
        with self._mock_map_delete() as map_delete,\
            self._mock_map_create() as map_create,\
            self._mock_profile_list(profile_ids),\
            self._mock_group_delete() as group_delete:

            self.delete_policy_target_group(provider_id)

            map_create.assert_not_called()
            map_delete.assert_called_with(TEST_PROJECT,
                                          driver.append_in_dir(prs_id))

            star_size -= 1
            group_delete.assert_called_with(TEST_PROJECT, provider_id)


class TestPolicyRuleSet(NsxPolicyMappingTestCase):

    @unittest2.skip(TEMPORARY_SKIP)
    def test_bidirectional(self):
        ''' Create and delete bidirectional rule set'''

        with self._mock_profile_create() as profile_create,\
            self._mock_profile_delete() as profile_delete:

            rule = self._create_simple_policy_rule()
            rule_set = self.create_policy_rule_set(
                name='test', policy_rules=[rule['id']])['policy_rule_set']

            calls = [call(name=mock.ANY,
                          description=mock.ANY,
                          profile_id=driver.append_in_dir(rule_set['id']),
                          services=[rule['policy_classifier_id']]),
                     call(name=mock.ANY,
                          description=mock.ANY,
                          profile_id=driver.append_out_dir(rule_set['id']),
                          services=[rule['policy_classifier_id']])]

            profile_create.assert_has_calls(calls)

            self.delete_policy_rule_set(rule_set['id'])

            calls = [call(driver.append_in_dir(rule_set['id'])),
                     call(driver.append_out_dir(rule_set['id']))]
            profile_delete.assert_has_calls(calls)

    @unittest2.skip(TEMPORARY_SKIP)
    def test_empty(self):
        ''' Create and delete empty rule set and verify no backend calls'''
        rule = self._create_simple_policy_rule()
        rule_set = self.create_policy_rule_set(
            name='test', policy_rules=[rule['id']])['policy_rule_set']

        self.delete_policy_rule_set(rule_set['id'])

    @unittest2.skip(TEMPORARY_SKIP)
    def test_create_fails(self):
        ''' Create bidirectional rule set and fail second API call'''

        with self._mock_nth_profile_create_fails() as profile_create,\
            self._mock_profile_delete() as profile_delete:

            rule = self._create_simple_policy_rule()
            self.assertRaises(webob.exc.HTTPClientError,
                              self.create_policy_rule_set,
                              name='test',
                              policy_rules=[rule['id']])

            # Two create calls expected
            calls = [call(name=mock.ANY,
                          description=mock.ANY,
                          profile_id=mock.ANY,
                          services=[rule['policy_classifier_id']]),
                     call(name=mock.ANY,
                          description=mock.ANY,
                          profile_id=mock.ANY,
                          services=[rule['policy_classifier_id']])]

            profile_create.assert_has_calls(calls)

            # Rollback - two delete calls expected
            calls = [call(mock.ANY), call(mock.ANY)]
            profile_delete.assert_has_calls(calls)

    @unittest2.skip(TEMPORARY_SKIP)
    def _assert_profile_call(self, mock_calls,
                             name, profile_id, services):
        '''Asserts service list in any order'''

        services_set = set(services)
        for mock_call in mock_calls.call_args_list:
            if isinstance(mock_call, dict):
                if (mock_call.get('name') == name and
                    mock_call.get('profile_id') == profile_id and
                    set(mock_call.get('services')) == services_set):

                    return True

    @unittest2.skip(TEMPORARY_SKIP)
    def test_multi_set(self):
        '''Test lifecycle of set with 3 rules having different dirs'''

        # Create rule set with 3 rules
        with self._mock_profile_create() as profile_create:

            rule1 = self._create_simple_policy_rule('in', 'tcp', '7887')
            rule2 = self._create_simple_policy_rule('out', 'udp', '8778')
            rule3 = self._create_simple_policy_rule('bi', 'tcp', '5060')

            rule_set = self.create_policy_rule_set(
                name='test', policy_rules=[rule1['id'],
                                           rule2['id'],
                                           rule3['id']])['policy_rule_set']

            self.assertEqual(2, profile_create.call_count)
            profile_create._assert_profile_call(
                driver.append_in_dir('test'),
                driver.append_in_dir(rule_set['id']),
                [rule1['policy_classifier_id'], rule3['policy_classifier_id']])
            profile_create._assert_profile_call(
                driver.append_out_dir('test'),
                driver.append_out_dir(rule_set['id']),
                [rule2['policy_classifier_id'], rule3['policy_classifier_id']])

        # Replace rule3 with rule4
        with self._mock_profile_create() as profile_update:
            rule4 = self._create_simple_policy_rule('out', 'tcp', '555:777')

            rule_set1 = self.update_policy_rule_set(
                rule_set['id'], policy_rules=[rule1['id'],
                                              rule2['id'],
                                              rule4['id']])['policy_rule_set']

            self.assertEqual(rule_set['id'], rule_set1['id'])
            self.assertEqual(2, profile_create.call_count)
            profile_update._assert_profile_call(
                driver.append_in_dir('test'),
                driver.append_in_dir(rule_set['id']),
                [rule1['policy_classifier_id']])
            profile_update._assert_profile_call(
                driver.append_out_dir('test'),
                driver.append_out_dir(rule_set['id']),
                [rule2['policy_classifier_id'], rule4['policy_classifier_id']])

        # Delete rule1 from the rule set and verify ingress profile is
        # is deleted on backend
        with self._mock_profile_delete() as profile_delete:
            self.update_policy_rule_set(rule_set['id'],
                                        policy_rules=[rule2['id'],
                                                      rule4['id']])

            profile_delete.assert_called_once_with(
                driver.append_in_dir(rule_set['id']))

        # Delete the rule set and verify egress profile is deleted
        with self._mock_profile_delete() as profile_delete:
            self.delete_policy_rule_set(rule_set['id'])

            profile_delete.assert_called_once_with(
                driver.append_out_dir(rule_set['id']))


class TestPolicyTargetTag(NsxPolicyMappingTestCase):

    def _prepare_group(self, name='test'):
        with self._mock_group_create():
            return self.create_policy_target_group(
                name='test')['policy_target_group']

    @unittest2.skip(TEMPORARY_SKIP)
    def test_target_lifecycle(self):
        self._mock_nsx_db()

        ptg = self._prepare_group()

        # create policy target and verify port tag update
        with self._mock_nsx_port_update() as port_update:

            target = self.create_policy_target(
                policy_target_group_id=ptg['id'])['policy_target']

            # nsx mock function will map neutron port id to same value
            # for nsx port id
            port_update.assert_called_once_with(
                target['port_id'],
                None,
                tags_update=[{'scope': 'gbp',
                              'tag': ptg['id']}])

        # verify group membership change is not supported
        ptg1 = self._prepare_group()
        self.assertRaises(webob.exc.HTTPClientError,
                          self.update_policy_target,
                          target['id'],
                          policy_target_group_id=ptg1['id'])

        # policy target deletion should not affect backend policy-wise
        self.delete_policy_target(target['id'])


class TestL3Policy(NsxPolicyMappingTestCase):

    def test_ipv6_supported(self):
        self.assertRaises(webob.exc.HTTPClientError,
                          self.create_l3_policy,
                          ip_version=6,
                          ip_pool='1001::0/64')
