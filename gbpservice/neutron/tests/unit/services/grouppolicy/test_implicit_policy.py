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

from oslo.config import cfg
import webob.exc

from gbpservice.neutron.db import servicechain_db  # noqa
from gbpservice.neutron.services.servicechain.plugins.ncp import (  # noqa
    model)  # noqa
from gbpservice.neutron.tests.unit.services.grouppolicy import (
    test_grouppolicy_plugin as test_plugin)


class ImplicitPolicyTestCase(
        test_plugin.GroupPolicyPluginTestCase):

    def setUp(self):
        cfg.CONF.set_override('policy_drivers', ['implicit_policy'],
                              group='group_policy')
        super(ImplicitPolicyTestCase, self).setUp()


class TestImplicitL2Policy(ImplicitPolicyTestCase):

    def _test_implicit_lifecycle(self, shared=False):
        # Create policy_target group with implicit L2 policy.
        ptg1 = self.create_policy_target_group(shared=shared)
        self.assertEqual(shared, ptg1['policy_target_group']['shared'])
        ptg1_id = ptg1['policy_target_group']['id']
        l2p1_id = ptg1['policy_target_group']['l2_policy_id']
        self.assertIsNotNone(l2p1_id)
        req = self.new_show_request('policy_target_groups', ptg1_id,
                                    fmt=self.fmt)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        self.assertEqual(l2p1_id, res['policy_target_group']['l2_policy_id'])
        req = self.new_show_request('l2_policies', l2p1_id, fmt=self.fmt)
        l2p1 = self.deserialize(self.fmt, req.get_response(self.ext_api))
        self.assertEqual(ptg1['policy_target_group']['name'],
                         l2p1['l2_policy']['name'])
        self.assertEqual(shared, l2p1['l2_policy']['shared'])

        # Create 2nd policy_target group with different implicit L2 policy.
        ptg2 = self.create_policy_target_group()
        ptg2_id = ptg2['policy_target_group']['id']
        l2p2_id = ptg2['policy_target_group']['l2_policy_id']
        self.assertIsNotNone(l2p2_id)
        self.assertNotEqual(l2p1_id, l2p2_id)

        # Verify deleting 1st policy_target group does cleanup its L2
        # policy.
        req = self.new_delete_request('policy_target_groups', ptg1_id)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)
        req = self.new_show_request('l2_policies', l2p1_id, fmt=self.fmt)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPNotFound.code)

        # Verify deleting 2nd policy_target group does cleanup its L2
        # policy.
        req = self.new_delete_request('policy_target_groups', ptg2_id)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)
        req = self.new_show_request('l2_policies', l2p2_id, fmt=self.fmt)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPNotFound.code)

    def test_implicit_shared_lifecycle_negative(self):
        # Create PTG non shared
        self.create_policy_target_group()
        # This creates a non shared L3 policy that will be reused for any other
        # implicit PTG. Now create a shared PTG and verify that fails
        self.create_policy_target_group(
            shared=True, expected_res_status=webob.exc.HTTPBadRequest.code)

    def test_impicit_lifecycle(self):
        self._test_implicit_lifecycle()

    def test_implicit_lifecycle_shared(self):
        self._test_implicit_lifecycle(True)

    def test_explicit_lifecycle(self):
        # Create policy_target group with explicit L2 policy.
        l2p = self.create_l2_policy()
        l2p_id = l2p['l2_policy']['id']
        ptg = self.create_policy_target_group(l2_policy_id=l2p_id)
        ptg_id = ptg['policy_target_group']['id']
        self.assertEqual(l2p_id, ptg['policy_target_group']['l2_policy_id'])

        # Verify deleting policy_target group does not cleanup L2 policy.
        req = self.new_delete_request('policy_target_groups', ptg_id)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)
        req = self.new_show_request('l2_policies', l2p_id, fmt=self.fmt)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPOk.code)

    def test_delete_from_implicit(self):
        # Create policy_target group with explicit L2 policy.
        l2p1 = self.create_l2_policy()
        l2p1_id = l2p1['l2_policy']['id']
        ptg = self.create_policy_target_group(l2_policy_id=l2p1_id)
        ptg_id = ptg['policy_target_group']['id']
        self.assertEqual(l2p1_id, ptg['policy_target_group']['l2_policy_id'])

        # Delete PTG
        self.delete_policy_target_group(ptg_id, expected_res_status=204)

        # Verify old L2 policy was not cleaned up.
        req = self.new_show_request('l2_policies', l2p1_id, fmt=self.fmt)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPOk.code)


class TestImplicitL3Policy(ImplicitPolicyTestCase):

    def _test_implicit_lifecycle(self, shared=False):
        # Create L2 policy with implicit L3 policy.
        l2p1 = self.create_l2_policy(shared=shared)
        l2p1_id = l2p1['l2_policy']['id']
        l3p_id = l2p1['l2_policy']['l3_policy_id']
        self.assertIsNotNone(l3p_id)
        self.assertEqual(shared, l2p1['l2_policy']['shared'])
        req = self.new_show_request('l2_policies', l2p1_id, fmt=self.fmt)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        self.assertEqual(l3p_id, res['l2_policy']['l3_policy_id'])
        req = self.new_show_request('l3_policies', l3p_id, fmt=self.fmt)
        l3p = self.deserialize(self.fmt, req.get_response(self.ext_api))
        self.assertEqual('default', l3p['l3_policy']['name'])
        self.assertEqual(shared, l3p['l3_policy']['shared'])
        self.assertEqual(24, l3p['l3_policy']['subnet_prefix_length'])

        # Create 2nd L2 policy sharing implicit L3 policy.
        l2p2 = self.create_l2_policy()
        l2p2_id = l2p2['l2_policy']['id']
        self.assertEqual(l3p_id, l2p2['l2_policy']['l3_policy_id'])

        # Verify deleting 1st L2 policy does not cleanup L3 policy.
        req = self.new_delete_request('l2_policies', l2p1_id)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)
        req = self.new_show_request('l3_policies', l3p_id, fmt=self.fmt)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPOk.code)

        # Verify deleting last L2 policy does cleanup L3 policy.
        req = self.new_delete_request('l2_policies', l2p2_id)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)
        req = self.new_show_request('l3_policies', l3p_id, fmt=self.fmt)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPNotFound.code)

    def test_impicit_lifecycle(self):
        self._test_implicit_lifecycle()

    def test_implicit_lifecycle_shared(self):
        self._test_implicit_lifecycle(True)

    def test_explicit_lifecycle(self):
        # Create L2 policy with explicit L3 policy.
        l3p = self.create_l3_policy()
        l3p_id = l3p['l3_policy']['id']
        l2p = self.create_l2_policy(l3_policy_id=l3p_id)
        l2p_id = l2p['l2_policy']['id']
        self.assertEqual(l3p_id, l2p['l2_policy']['l3_policy_id'])

        # Verify deleting L2 policy does not cleanup L3 policy.
        req = self.new_delete_request('l2_policies', l2p_id)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)
        req = self.new_show_request('l3_policies', l3p_id, fmt=self.fmt)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPOk.code)

    def test_unowned_default_lifecycle(self):
        # Create L2 policy with unowned default L3 policy.
        l3p = self.create_l3_policy(name='default')
        l3p_id = l3p['l3_policy']['id']
        l2p = self.create_l2_policy()
        l2p_id = l2p['l2_policy']['id']
        self.assertEqual(l3p_id, l2p['l2_policy']['l3_policy_id'])

        # Verify deleting L2 policy does not cleanup L3 policy.
        req = self.new_delete_request('l2_policies', l2p_id)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)
        req = self.new_show_request('l3_policies', l3p_id, fmt=self.fmt)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPOk.code)

    def test_single_default_policy(self):
        # Verify only one default L3 policy can be created per tenant.
        l3p = self.create_l3_policy(name='default')
        self.assertEqual('default', l3p['l3_policy']['name'])
        res = self.create_l3_policy(name='default', expected_res_status=400)
        self.assertEqual('DefaultL3PolicyAlreadyExists',
                         res['NeutronError']['type'])

    def test_update_from_implicit(self):
        # Create L2 policy with implicit L3 policy.
        l2p = self.create_l2_policy()
        l2p_id = l2p['l2_policy']['id']
        l3p1_id = l2p['l2_policy']['l3_policy_id']
        req = self.new_show_request('l3_policies', l3p1_id, fmt=self.fmt)
        l3p1 = self.deserialize(self.fmt, req.get_response(self.ext_api))
        self.assertEqual('default', l3p1['l3_policy']['name'])

        # Update L2 policy to explicit L3 policy.
        l3p2 = self.create_l3_policy()
        l3p2_id = l3p2['l3_policy']['id']
        data = {'l2_policy': {'l3_policy_id': l3p2_id}}
        req = self.new_update_request('l2_policies', data, l2p_id)
        l2p = self.deserialize(self.fmt, req.get_response(self.ext_api))
        self.assertEqual(l3p2_id, l2p['l2_policy']['l3_policy_id'])

        # Verify old L3 policy was cleaned up
        req = self.new_show_request('l3_policies', l3p1_id, fmt=self.fmt)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPNotFound.code)

        # Verify deleting L2 policy does not cleanup new L3 policy.
        req = self.new_delete_request('l2_policies', l2p_id)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)
        req = self.new_show_request('l3_policies', l3p2_id, fmt=self.fmt)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPOk.code)

    def test_update_to_implicit(self):
        # Create L2 policy with explicit L3 policy.
        l3p1 = self.create_l3_policy()
        l3p1_id = l3p1['l3_policy']['id']
        l2p = self.create_l2_policy(l3_policy_id=l3p1_id)
        l2p_id = l2p['l2_policy']['id']
        self.assertEqual(l3p1_id, l2p['l2_policy']['l3_policy_id'])

        # Update L2 policy to implicit L3 policy.
        data = {'l2_policy': {'l3_policy_id': None}}
        req = self.new_update_request('l2_policies', data, l2p_id)
        l2p = self.deserialize(self.fmt, req.get_response(self.ext_api))
        l3p2_id = l2p['l2_policy']['l3_policy_id']
        self.assertNotEqual(l3p1_id, l3p2_id)
        self.assertIsNotNone(l3p2_id)
        req = self.new_show_request('l3_policies', l3p2_id, fmt=self.fmt)
        l3p2 = self.deserialize(self.fmt, req.get_response(self.ext_api))
        self.assertEqual('default', l3p2['l3_policy']['name'])

        # Verify old L3 policy was not cleaned up.
        req = self.new_show_request('l3_policies', l3p1_id, fmt=self.fmt)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPOk.code)

        # Verify deleting L2 policy does cleanup new L3 policy.
        req = self.new_delete_request('l2_policies', l2p_id)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)
        req = self.new_show_request('l3_policies', l3p2_id, fmt=self.fmt)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPNotFound.code)


class TestImplicitExternalSegment(ImplicitPolicyTestCase):

    def setUp(self):
        self._default_es_name = 'default'
        cfg.CONF.set_override(
            'default_external_segment_name', self._default_es_name,
            group='group_policy_implicit_policy')
        super(TestImplicitExternalSegment, self).setUp()

    def _create_default_es(self, **kwargs):
        return self.create_external_segment(name=self._default_es_name,
                                            **kwargs)

    def _test_implicit_lifecycle(self, shared=False):
        # Create default ES
        es = self._create_default_es(shared=shared)['external_segment']
        # Create non-default ES
        ndes = self.create_external_segment(
            name='non-default-name')['external_segment']

        # Create EP without ES set
        ep = self.create_external_policy()['external_policy']
        self.assertEqual(es['id'], ep['external_segments'][0])
        # Verify persisted
        req = self.new_show_request('external_policies', ep['id'],
                                    fmt=self.fmt)
        ep = self.deserialize(
            self.fmt, req.get_response(self.ext_api))['external_policy']
        self.assertEqual(es['id'], ep['external_segments'][0])

        # Verify update
        ep = self.update_external_policy(
            ep['id'], expected_res_status=200,
            external_segments=[ndes['id']])['external_policy']
        self.assertEqual(ndes['id'], ep['external_segments'][0])
        self.assertEqual(1, len(ep['external_segments']))

        # Create L3P without ES set
        l3p = self.create_l3_policy()['l3_policy']
        self.assertEqual(es['id'], l3p['external_segments'].keys()[0])
        # Verify persisted
        req = self.new_show_request('l3_policies', l3p['id'],
                                    fmt=self.fmt)
        l3p = self.deserialize(
            self.fmt, req.get_response(self.ext_api))['l3_policy']
        self.assertEqual(es['id'], l3p['external_segments'].keys()[0])

        # Verify update
        l3p = self.update_l3_policy(
            l3p['id'], expected_res_status=200,
            external_segments={ndes['id']: []})['l3_policy']
        self.assertEqual(ndes['id'], l3p['external_segments'].keys()[0])
        self.assertEqual(1, len(l3p['external_segments']))

        # Verify only one visible ES can exist
        res = self._create_default_es(expected_res_status=400)
        self.assertEqual('DefaultExternalSegmentAlreadyExists',
                         res['NeutronError']['type'])

    def test_impicit_lifecycle(self):
        self._test_implicit_lifecycle()

    def test_implicit_lifecycle_shared(self):
        self._test_implicit_lifecycle(True)

    def test_implicit_shared_visibility(self):
        es = self._create_default_es(shared=True,
                                     tenant_id='onetenant')['external_segment']
        ep = self.create_external_policy(
            tenant_id='anothertenant')['external_policy']
        self.assertEqual(es['id'], ep['external_segments'][0])
        self.assertEqual(1, len(ep['external_segments']))

        l3p = self.create_l3_policy(
            tenant_id='anothertenant')['l3_policy']
        self.assertEqual(es['id'], l3p['external_segments'].keys()[0])
        self.assertEqual(1, len(ep['external_segments']))

        res = self._create_default_es(expected_res_status=400,
                                      tenant_id='anothertenant')
        self.assertEqual('DefaultExternalSegmentAlreadyExists',
                         res['NeutronError']['type'])


class TestQuotasForGBPWithImplicitDriver(ImplicitPolicyTestCase):

    def setUp(self):
        cfg.CONF.set_override('quota_l3_policy', 1, group='QUOTAS')
        cfg.CONF.set_override('quota_l2_policy', 1, group='QUOTAS')
        cfg.CONF.set_override('quota_policy_target_group', 1, group='QUOTAS')
        cfg.CONF.set_override('quota_policy_target', 1, group='QUOTAS')
        super(TestQuotasForGBPWithImplicitDriver, self).setUp()

    def tearDown(self):
        cfg.CONF.set_override('quota_l3_policy', -1, group='QUOTAS')
        cfg.CONF.set_override('quota_l2_policy', -1, group='QUOTAS')
        cfg.CONF.set_override('quota_policy_target_group', -1, group='QUOTAS')
        cfg.CONF.set_override('quota_policy_target', -1, group='QUOTAS')
        super(TestQuotasForGBPWithImplicitDriver, self).tearDown()

    def test_quota_for_group_resources_implicit(self):
        # The following tests that implicitly created L2P and L3P
        # are counted as a part of the resource quota.
        ptg_id = self.create_policy_target_group()['policy_target_group']['id']
        self.create_policy_target(policy_target_group_id=ptg_id)
        self.assertRaises(webob.exc.HTTPClientError,
                          self.create_policy_target,
                          policy_target_group_id=ptg_id)
        self.assertRaises(webob.exc.HTTPClientError,
                          self.create_policy_target_group)
        self.assertRaises(webob.exc.HTTPClientError,
                          self.create_l3_policy)
        self.assertRaises(webob.exc.HTTPClientError,
                          self.create_l2_policy)

    def test_quota_for_implicit_l3p(self):
        # The following tests that implicit L3P creation fails
        # when resource quota is reached.
        cfg.CONF.set_override('quota_policy_target_group', 2, group='QUOTAS')
        cfg.CONF.set_override('quota_l2_policy', 2, group='QUOTAS')
        l3p = self.create_l3_policy(name='test')
        l3p_id = l3p['l3_policy']['id']
        l2p = self.create_l2_policy(name='test', l3_policy_id=l3p_id)
        l2p_id = l2p['l2_policy']['id']
        self.create_policy_target_group(
            l2_policy_id=l2p_id)['policy_target_group']['id']
        self.assertRaises(webob.exc.HTTPClientError,
                          self.create_policy_target_group)

    def test_quota_for_implicit_l2p(self):
        # The following tests that implicit L2P creation fails
        # when resource quota is reached.
        cfg.CONF.set_override('quota_policy_target_group', 2, group='QUOTAS')
        cfg.CONF.set_override('quota_l3_policy', 2, group='QUOTAS')
        l3p = self.create_l3_policy(name='test')
        l3p_id = l3p['l3_policy']['id']
        l2p = self.create_l2_policy(name='test', l3_policy_id=l3p_id)
        l2p_id = l2p['l2_policy']['id']
        self.create_policy_target_group(
            l2_policy_id=l2p_id)['policy_target_group']['id']
        self.assertRaises(webob.exc.HTTPClientError,
                          self.create_policy_target_group)
