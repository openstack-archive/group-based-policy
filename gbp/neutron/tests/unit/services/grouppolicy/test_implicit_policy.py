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

    def test_impicit_lifecycle(self):
        # Create endpoint group with implicit L2 policy.
        epg1 = self.create_endpoint_group()
        epg1_id = epg1['endpoint_group']['id']
        l2p1_id = epg1['endpoint_group']['l2_policy_id']
        self.assertIsNotNone(l2p1_id)
        req = self.new_show_request('endpoint_groups', epg1_id, fmt=self.fmt)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        self.assertEqual(l2p1_id, res['endpoint_group']['l2_policy_id'])
        req = self.new_show_request('l2_policies', l2p1_id, fmt=self.fmt)
        l2p1 = self.deserialize(self.fmt, req.get_response(self.ext_api))
        self.assertEqual(epg1['endpoint_group']['name'],
                         l2p1['l2_policy']['name'])

        # Create 2nd endpoint group with different implicit L2 policy.
        epg2 = self.create_endpoint_group()
        epg2_id = epg2['endpoint_group']['id']
        l2p2_id = epg2['endpoint_group']['l2_policy_id']
        self.assertIsNotNone(l2p2_id)
        self.assertNotEqual(l2p1_id, l2p2_id)

        # Verify deleting 1st endpoint group does cleanup its L2
        # policy.
        req = self.new_delete_request('endpoint_groups', epg1_id)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)
        req = self.new_show_request('l2_policies', l2p1_id, fmt=self.fmt)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPNotFound.code)

        # Verify deleting 2nd endpoint group does cleanup its L2
        # policy.
        req = self.new_delete_request('endpoint_groups', epg2_id)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)
        req = self.new_show_request('l2_policies', l2p2_id, fmt=self.fmt)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPNotFound.code)

    def test_explicit_lifecycle(self):
        # Create endpoint group with explicit L2 policy.
        l2p = self.create_l2_policy()
        l2p_id = l2p['l2_policy']['id']
        epg = self.create_endpoint_group(l2_policy_id=l2p_id)
        epg_id = epg['endpoint_group']['id']
        self.assertEqual(l2p_id, epg['endpoint_group']['l2_policy_id'])

        # Verify deleting endpoint group does not cleanup L2 policy.
        req = self.new_delete_request('endpoint_groups', epg_id)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)
        req = self.new_show_request('l2_policies', l2p_id, fmt=self.fmt)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPOk.code)

    def test_update_from_implicit(self):
        # Create endpoint group with implicit L2 policy.
        epg = self.create_endpoint_group()
        epg_id = epg['endpoint_group']['id']
        l2p1_id = epg['endpoint_group']['l2_policy_id']
        req = self.new_show_request('l2_policies', l2p1_id, fmt=self.fmt)
        l2p1 = self.deserialize(self.fmt, req.get_response(self.ext_api))
        self.assertEqual(epg['endpoint_group']['name'],
                         l2p1['l2_policy']['name'])

        # Update endpoint group to explicit L2 policy.
        l2p2 = self.create_l2_policy()
        l2p2_id = l2p2['l2_policy']['id']
        data = {'endpoint_group': {'l2_policy_id': l2p2_id}}
        req = self.new_update_request('endpoint_groups', data, epg_id)
        epg = self.deserialize(self.fmt, req.get_response(self.ext_api))
        self.assertEqual(l2p2_id, epg['endpoint_group']['l2_policy_id'])

        # Verify old L2 policy was cleaned up.
        req = self.new_show_request('l2_policies', l2p1_id, fmt=self.fmt)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPNotFound.code)

        # Verify deleting endpoint group does not cleanup new L2
        # policy.
        req = self.new_delete_request('endpoint_groups', epg_id)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)
        req = self.new_show_request('l2_policies', l2p2_id, fmt=self.fmt)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPOk.code)

    def test_update_to_implicit(self):
        # Create endpoint group with explicit L2 policy.
        l2p1 = self.create_l2_policy()
        l2p1_id = l2p1['l2_policy']['id']
        epg = self.create_endpoint_group(l2_policy_id=l2p1_id)
        epg_id = epg['endpoint_group']['id']
        self.assertEqual(l2p1_id, epg['endpoint_group']['l2_policy_id'])

        # Update endpoint group to implicit L2 policy.
        data = {'endpoint_group': {'l2_policy_id': None}}
        req = self.new_update_request('endpoint_groups', data, epg_id)
        epg = self.deserialize(self.fmt, req.get_response(self.ext_api))
        l2p2_id = epg['endpoint_group']['l2_policy_id']
        self.assertNotEqual(l2p1_id, l2p2_id)
        self.assertIsNotNone(l2p2_id)
        req = self.new_show_request('l2_policies', l2p2_id, fmt=self.fmt)
        l2p2 = self.deserialize(self.fmt, req.get_response(self.ext_api))
        self.assertEqual(epg['endpoint_group']['name'],
                         l2p2['l2_policy']['name'])

        # Verify old L2 policy was not cleaned up.
        req = self.new_show_request('l2_policies', l2p1_id, fmt=self.fmt)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPOk.code)

        # Verify deleting endpoint group does cleanup new L2 policy.
        req = self.new_delete_request('endpoint_groups', epg_id)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)
        req = self.new_show_request('l2_policies', l2p2_id, fmt=self.fmt)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPNotFound.code)


class TestImplicitL3Policy(ImplicitPolicyTestCase):

    def test_impicit_lifecycle(self):
        # Create L2 policy with implicit L3 policy.
        l2p1 = self.create_l2_policy()
        l2p1_id = l2p1['l2_policy']['id']
        l3p_id = l2p1['l2_policy']['l3_policy_id']
        self.assertIsNotNone(l3p_id)
        req = self.new_show_request('l2_policies', l2p1_id, fmt=self.fmt)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        self.assertEqual(l3p_id, res['l2_policy']['l3_policy_id'])
        req = self.new_show_request('l3_policies', l3p_id, fmt=self.fmt)
        l3p = self.deserialize(self.fmt, req.get_response(self.ext_api))
        self.assertEqual('default', l3p['l3_policy']['name'])

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
