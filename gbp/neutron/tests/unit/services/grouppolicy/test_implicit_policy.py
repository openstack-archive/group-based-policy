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

import webob.exc

from gbp.neutron.services.grouppolicy import config
from gbp.neutron.tests.unit.services.grouppolicy import test_grouppolicy_plugin


class ImplicitPolicyTestCase(
        test_grouppolicy_plugin.GroupPolicyPluginTestCase):

    def setUp(self):
        config.cfg.CONF.set_override('policy_drivers',
                                     ['implicit_policy'],
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

    def test_update_from_implicit(self):
        # Create policy_target group with implicit L2 policy.
        ptg = self.create_policy_target_group()
        ptg_id = ptg['policy_target_group']['id']
        l2p1_id = ptg['policy_target_group']['l2_policy_id']
        req = self.new_show_request('l2_policies', l2p1_id, fmt=self.fmt)
        l2p1 = self.deserialize(self.fmt, req.get_response(self.ext_api))
        self.assertEqual(ptg['policy_target_group']['name'],
                         l2p1['l2_policy']['name'])

        # Update policy_target group to explicit L2 policy.
        l2p2 = self.create_l2_policy()
        l2p2_id = l2p2['l2_policy']['id']
        data = {'policy_target_group': {'l2_policy_id': l2p2_id}}
        req = self.new_update_request('policy_target_groups', data, ptg_id)
        ptg = self.deserialize(self.fmt, req.get_response(self.ext_api))
        self.assertEqual(l2p2_id, ptg['policy_target_group']['l2_policy_id'])

        # Verify old L2 policy was cleaned up.
        req = self.new_show_request('l2_policies', l2p1_id, fmt=self.fmt)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPNotFound.code)

        # Verify deleting policy_target group does not cleanup new L2
        # policy.
        req = self.new_delete_request('policy_target_groups', ptg_id)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)
        req = self.new_show_request('l2_policies', l2p2_id, fmt=self.fmt)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPOk.code)

    def test_update_to_implicit(self):
        # Create policy_target group with explicit L2 policy.
        l2p1 = self.create_l2_policy()
        l2p1_id = l2p1['l2_policy']['id']
        ptg = self.create_policy_target_group(l2_policy_id=l2p1_id)
        ptg_id = ptg['policy_target_group']['id']
        self.assertEqual(l2p1_id, ptg['policy_target_group']['l2_policy_id'])

        # Update policy_target group to implicit L2 policy.
        data = {'policy_target_group': {'l2_policy_id': None}}
        req = self.new_update_request('policy_target_groups', data, ptg_id)
        ptg = self.deserialize(self.fmt, req.get_response(self.ext_api))
        l2p2_id = ptg['policy_target_group']['l2_policy_id']
        self.assertNotEqual(l2p1_id, l2p2_id)
        self.assertIsNotNone(l2p2_id)
        req = self.new_show_request('l2_policies', l2p2_id, fmt=self.fmt)
        l2p2 = self.deserialize(self.fmt, req.get_response(self.ext_api))
        self.assertEqual(ptg['policy_target_group']['name'],
                         l2p2['l2_policy']['name'])

        # Verify old L2 policy was not cleaned up.
        req = self.new_show_request('l2_policies', l2p1_id, fmt=self.fmt)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPOk.code)

        # Verify deleting policy_target group does cleanup new L2 policy.
        req = self.new_delete_request('policy_target_groups', ptg_id)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)
        req = self.new_show_request('l2_policies', l2p2_id, fmt=self.fmt)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPNotFound.code)


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
