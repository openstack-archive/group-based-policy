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

from neutron import context as n_ctx
from sqlalchemy.orm import exc as orm_exc

from gbpservice.neutron.db.grouppolicy.extensions import group_proxy_db
from gbpservice.neutron.tests.unit.services.grouppolicy import (
    test_extension_driver_api as test_ext_base)


class ExtensionDriverTestCaseMixin(object):

    def test_proxy_group_extension(self):
        l3p = self.create_l3_policy()['l3_policy']
        self.assertEqual('192.168.0.0/16', l3p['proxy_ip_pool'])
        self.assertEqual(28, l3p['proxy_subnet_prefix_length'])

        l2p = self.create_l2_policy(l3_policy_id=l3p['id'])['l2_policy']
        ptg = self.create_policy_target_group(
            l2_policy_id=l2p['id'])['policy_target_group']
        self.assertIsNone(ptg['proxy_group_id'])
        self.assertIsNone(ptg['proxied_group_id'])
        self.assertIsNone(ptg['proxy_type'])

        # Verify Default L3P pool mapping on show
        l3p = self.show_l3_policy(l3p['id'])['l3_policy']
        self.assertEqual('192.168.0.0/16', l3p['proxy_ip_pool'])
        self.assertEqual(28, l3p['proxy_subnet_prefix_length'])

        # No proxy
        ptg_proxy = self.create_policy_target_group()['policy_target_group']
        self.assertTrue(ptg_proxy['enforce_service_chains'])
        ptg_proxy = self.show_policy_target_group(
            ptg_proxy['id'])['policy_target_group']
        self.assertTrue(ptg_proxy['enforce_service_chains'])
        ptg_proxy = self.create_policy_target_group(
            enforce_service_chains=False,
            is_admin_context=True)['policy_target_group']
        self.assertFalse(ptg_proxy['enforce_service_chains'])
        ptg_proxy = self.show_policy_target_group(
            ptg_proxy['id'])['policy_target_group']
        self.assertFalse(ptg_proxy['enforce_service_chains'])

        ptg_proxy = self.create_policy_target_group(
            proxied_group_id=ptg['id'])['policy_target_group']
        self.assertIsNone(ptg_proxy['proxy_group_id'])
        self.assertEqual(ptg['id'], ptg_proxy['proxied_group_id'])
        self.assertEqual('l3', ptg_proxy['proxy_type'])
        self.assertFalse(ptg_proxy['enforce_service_chains'])

        # Verify relationship added
        ptg = self.show_policy_target_group(ptg['id'])['policy_target_group']
        self.assertEqual(ptg_proxy['id'], ptg['proxy_group_id'])
        self.assertIsNone(ptg['proxied_group_id'])

        pt = self.create_policy_target(
            policy_target_group_id=ptg_proxy['id'])['policy_target']
        self.assertFalse(pt['proxy_gateway'])
        self.assertFalse(pt['group_default_gateway'])
        pt = self.create_policy_target(
            policy_target_group_id=ptg_proxy['id'],
            proxy_gateway=True, group_default_gateway=True)['policy_target']
        self.assertTrue(pt['proxy_gateway'])
        self.assertTrue(pt['group_default_gateway'])
        pt = self.show_policy_target(pt['id'])['policy_target']
        self.assertTrue(pt['proxy_gateway'])
        self.assertTrue(pt['group_default_gateway'])

    def test_preexisting_pt(self):
        ptg = self.create_policy_target_group()['policy_target_group']
        pt = self.create_policy_target(
            policy_target_group_id=ptg['id'])['policy_target']
        self.assertTrue('proxy_gateway' in pt)
        self.assertTrue('group_default_gateway' in pt)

        # Forcefully delete the entry in the proxy table, and verify that it's
        # fixed by the subsequent GET
        admin_context = n_ctx.get_admin_context()
        mapping = admin_context.session.query(
            group_proxy_db.ProxyGatewayMapping).filter_by(
                policy_target_id=pt['id']).one()
        admin_context.session.delete(mapping)
        query = admin_context.session.query(
            group_proxy_db.ProxyGatewayMapping).filter_by(
                policy_target_id=pt['id'])
        self.assertRaises(orm_exc.NoResultFound, query.one)

        # Showing the object just ignores the extension
        pt = self.show_policy_target(pt['id'],
                                     expected_res_status=200)['policy_target']
        self.assertFalse('proxy_gateway' in pt)
        self.assertFalse('group_default_gateway' in pt)

        # Updating the object just ignores the extension
        pt = self.update_policy_target(
            pt['id'], name='somenewname',
            expected_res_status=200)['policy_target']
        self.assertEqual('somenewname', pt['name'])
        self.assertFalse('proxy_gateway' in pt)
        self.assertFalse('group_default_gateway' in pt)

    def test_proxy_group_multiple_proxies(self):
        # same PTG proxied multiple times will fail
        ptg = self.create_policy_target_group()['policy_target_group']
        self.create_policy_target_group(proxied_group_id=ptg['id'])
        # Second proxy will fail
        res = self.create_policy_target_group(proxied_group_id=ptg['id'],
                                              expected_res_status=400)
        self.assertEqual('InvalidProxiedGroup', res['NeutronError']['type'])

    def test_proxy_group_chain_proxy(self):
        # Verify no error is raised when chaining multiple proxy PTGs
        ptg0 = self.create_policy_target_group()['policy_target_group']
        ptg1 = self.create_policy_target_group(
            proxied_group_id=ptg0['id'],
            expected_res_status=201)['policy_target_group']
        self.create_policy_target_group(proxied_group_id=ptg1['id'],
                                        expected_res_status=201)

    def test_proxy_group_no_update(self):
        ptg0 = self.create_policy_target_group()['policy_target_group']
        ptg1 = self.create_policy_target_group()['policy_target_group']
        ptg_proxy = self.create_policy_target_group(
            proxied_group_id=ptg0['id'])['policy_target_group']
        self.update_policy_target_group(
            ptg_proxy['id'], proxied_group_id=ptg1['id'],
            expected_res_status=400)

    def test_different_proxy_type(self):
        ptg = self.create_policy_target_group()['policy_target_group']
        ptg_proxy = self.create_policy_target_group(
            proxied_group_id=ptg['id'], proxy_type='l2')['policy_target_group']
        self.assertEqual('l2', ptg_proxy['proxy_type'])

        ptg_proxy = self.show_policy_target_group(
            ptg_proxy['id'])['policy_target_group']
        self.assertEqual('l2', ptg_proxy['proxy_type'])

    def test_proxy_type_fails(self):
        ptg = self.create_policy_target_group()['policy_target_group']
        res = self.create_policy_target_group(proxy_type='l2',
                                              expected_res_status=400)
        self.assertEqual('ProxyTypeSetWithoutProxiedPTG',
                         res['NeutronError']['type'])

        self.create_policy_target_group(proxied_group_id=ptg['id'],
                                        proxy_type='notvalid',
                                        expected_res_status=400)

    def test_proxy_gateway_no_proxy(self):
        ptg = self.create_policy_target_group()['policy_target_group']
        res = self.create_policy_target(
            policy_target_group_id=ptg['id'], proxy_gateway=True,
            expected_res_status=400)
        self.assertEqual('InvalidProxyGatewayGroup',
                         res['NeutronError']['type'])

    def test_proxy_pool_invalid_prefix_length(self):
        l3p = self.create_l3_policy(proxy_subnet_prefix_length=29)['l3_policy']
        res = self.update_l3_policy(l3p['id'], proxy_subnet_prefix_length=32,
                                    expected_res_status=400)
        self.assertEqual('InvalidDefaultSubnetPrefixLength',
                         res['NeutronError']['type'])

        # Verify change didn't persist
        l3p = self.show_l3_policy(l3p['id'])['l3_policy']
        self.assertEqual(29, l3p['proxy_subnet_prefix_length'])

        # Verify it fails in creation
        res = self.create_l3_policy(
            proxy_subnet_prefix_length=32, expected_res_status=400)
        self.assertEqual('InvalidDefaultSubnetPrefixLength',
                         res['NeutronError']['type'])

    def test_proxy_pool_invalid_version(self):
        # proxy_ip_pool is of a different version
        res = self.create_l3_policy(ip_version=6, ip_pool='1::1/16',
                                    proxy_ip_pool='192.168.0.0/16',
                                    expected_res_status=400)
        self.assertEqual('InvalidIpPoolVersion', res['NeutronError']['type'])


class ExtensionDriverTestCase(test_ext_base.ExtensionDriverTestBase,
                              ExtensionDriverTestCaseMixin):
    _extension_drivers = ['proxy_group']
    _extension_path = None
