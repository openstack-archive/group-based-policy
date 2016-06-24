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

import mock
import uuid

from gbpservice.contrib.nfp.config_orchestrator.common import common
from gbpservice.contrib.nfp.config_orchestrator.handlers.config import (
    firewall as fw)
from gbpservice.contrib.nfp.config_orchestrator.handlers.config import (
    loadbalancer as lb)
from gbpservice.contrib.nfp.config_orchestrator.handlers.config import vpn
from gbpservice.contrib.nfp.config_orchestrator.handlers.notification import (
    handler as notif_handler)
from gbpservice.nfp.lib import transport

from neutron import context as ctx
from neutron.tests import base


class TestContext(object):

    def get_context(self):
        try:
            return ctx.Context('some_user', 'some_tenant')
        except Exception:
            return ctx.Context('some_user', 'some_tenant')


class Conf(object):

    class Test_RPC(object):

        def __init__(self):
            self.topic = 'xyz_topic'

    def __init__(self):
        self.host = 'dummy_host'
        self.backend = 'rpc'
        self.RPC = self.Test_RPC()


class RpcMethods(object):

    def cast(self, context, method, **kwargs):
        return

    def call(self, context, method, **kwargs):
        return {}


def call_network_function_info():
    data = {'network_function': {
        'id': str(uuid.uuid4()),
        'description': {}
    }}
    return data


class GeneralConfigStructure(object):

    def _check_general_structure(self, request_data, rsrc_name, resource=None):
        flag = 0
        if all(key in request_data for key in ["info", "config"]):
            header_data = request_data['info']
            if all(key in header_data for key in ["context", "service_type",
                                                  "service_vendor"]):
                if not self._check_resource_header_data(rsrc_name,
                                                        header_data["context"],
                                                        resource):
                    return False
                data = request_data['config']
                for ele in data:
                    if all(key in ele for key in ["resource",
                                                  "resource_data"]):
                        if self._check_resource_structure(rsrc_name,
                                                          ele['resource_data'],
                                                          resource):
                            flag = 1
                        else:
                            flag = 0
                    else:
                        flag = 0
        if flag == 1:
            return True
        return False

    def verify_firewall_structure(self, blob_data, resource=None):
        if all(k in blob_data for k in ["neutron_context", "host",
                                        "firewall"]):
            context = blob_data['neutron_context']
            try:
                if context['service_info']:
                    data = context['service_info']
                    if all(k in data for k in ["firewalls",
                                               "firewall_policies",
                                               "firewall_rules"]):
                        return True
            except AttributeError:
                return False
        return False

    def verify_firewall_header_data(self, data, resource=None):
        if all(k in data for k in ["neutron_context", "network_function_id",
                                   "fw_mac", "requester"]):
            if data['requester'] == 'nas_service':
                return True
            return False

    def verify_loadbalancer_header_data(self, data, resource=None):
        if all(k in data for k in ["neutron_context", "requester"]):
            if resource == "vip":
                if not all(k in data for k in ["network_function_id",
                                               "vip_id"]):
                    return False
            if data['requester'] == 'nas_service':
                return True
        return False

    def verify_vpn_header_data(self, data, resource=None):
        if all(k in data for k in ["neutron_context", "requester"]):
            if resource == "ipsec_site_connection":
                if not all(k in data for k in ["network_function_id",
                                               "ipsec_site_connection_id"]):
                    return False
            if data['requester'] == 'nas_service':
                return True
            return False

    def verify_loadbalancer_structure(self, blob_data, resource):
        if all(k in blob_data for k in ["neutron_context", resource]):
            context = blob_data["neutron_context"]
            try:
                if context['service_info']:
                    data = context['service_info']
                    if all(k in data for k in ["pools", "vips", "members",
                                               "health_monitors"]):
                        return True
            except AttributeError:
                return False
        return False

    def verify_vpn_structure(self, blob_data, resource):
        if all(k in blob_data for k in ["neutron_context", "resource",
                                        "rsrc_id", "reason"]):
            context = blob_data["neutron_context"]
            try:
                if context['service_info']:
                    data = context['service_info']
                    if resource.lower() == "vpn_service":
                        if all(k in data for k in ["vpnservices"]):
                            return True
                    elif resource.lower() == "ipsec_site_connection":
                        if all(k in data for k in ["vpnservices",
                                                   "ikepolicies",
                                                   "ipsecpolicies",
                                                   "ipsec_site_conns",
                                                   "subnets",
                                                   "routers"]):
                            return True
            except AttributeError:
                return False
        return False

    def _check_resource_structure(self, rsrc_name, data, resource=None):
        mod = self
        mod_method = getattr(mod, "verify_%s_structure" % rsrc_name)
        return mod_method(data, resource)

    def _check_resource_header_data(self, rsrc_name, data, resource):
        mod = self
        mod_method = getattr(mod, "verify_%s_header_data" % rsrc_name)
        return mod_method(data, resource)


class FirewallTestCase(base.BaseTestCase):

    def setUp(self):
        super(FirewallTestCase, self).setUp()
        self.conf = Conf()
        self.fw_handler = fw.FwAgent(self.conf, 'sc')
        self.context = TestContext().get_context()
        self.rpc_methods = RpcMethods()
        self.fw = self._firewall_data()
        self.host = 'host'
        import_path = ("neutron_fwaas.db.firewall.firewall_db."
                       "Firewall_db_mixin")
        self.import_fw_api = import_path + '.get_firewalls'
        self.import_fwp_api = import_path + '.get_firewall_policies'
        self.import_fwr_api = import_path + '.get_firewall_rules'
        self.import_lib = 'gbpservice.nfp.lib.transport'
        self._call = 'oslo_messaging.rpc.client._CallContext.call'

    def _firewall_data(self):
        return {'tenant_id': str(uuid.uuid4()),
                'description': str({'network_function_id': str(uuid.uuid4())}),
                'firewall_policy_id': str(uuid.uuid4())
                }

    def _cast_firewall(self, conf, context, body,
                       method_type, device_config=False,
                       network_function_event=False):
        g_cnfg = GeneralConfigStructure()
        self.assertTrue(g_cnfg._check_general_structure(body, 'firewall'))

    def _call_to_get_network_function_desc(self):
        data = call_network_function_info()
        data['network_function']['description'] = "\n" + str(
            {'provider_ptg_info': [str(uuid.uuid4())],
             'service_vendor': 'xyz'})
        return data['network_function']

    def test_create_firewall(self):
        import_send = self.import_lib + '.send_request_to_configurator'
        with mock.patch(self.import_fw_api) as gfw, mock.patch(
                self.import_fwp_api) as gfwp, mock.patch(
                self.import_fwr_api) as gfwr, mock.patch(
                self._call) as mock_call, mock.patch(
                import_send) as mock_send:
            gfw.return_value = []
            gfwp.return_value = []
            gfwr.return_value = []
            network_function_desc = self._call_to_get_network_function_desc()
            common.get_network_function_details = mock.MagicMock(
                return_value=network_function_desc)

            mock_call.side_effect = self._call_to_get_network_function_desc
            mock_send.side_effect = self._cast_firewall
            self.fw_handler.create_firewall(self.context, self.fw, self.host)

    def test_delete_firewall(self):
        import_send = self.import_lib + '.send_request_to_configurator'
        with mock.patch(self.import_fw_api) as gfw, mock.patch(
                self.import_fwp_api) as gfwp, mock.patch(
                self.import_fwr_api) as gfwr, mock.patch(
                self._call) as mock_call, mock.patch(
                import_send) as mock_send:
            gfw.return_value = []
            gfwp.return_value = []
            gfwr.return_value = []
            network_function_desc = self._call_to_get_network_function_desc()
            common.get_network_function_details = mock.MagicMock(
                return_value=network_function_desc)

            mock_call.side_effect = self._call_to_get_network_function_desc
            mock_send.side_effect = self._cast_firewall
            self.fw_handler.delete_firewall(self.context, self.fw, self.host)


class LoadBalanceTestCase(base.BaseTestCase):

    def setUp(self):
        super(LoadBalanceTestCase, self).setUp()
        self.conf = Conf()
        self.lb_handler = lb.LbAgent(self.conf, 'sc')
        self.context = TestContext().get_context()
        import_path = ("neutron_lbaas.db.loadbalancer.loadbalancer_db."
                       "LoadBalancerPluginDb")
        self.import_gp_api = import_path + '.get_pools'
        self.import_gv_api = import_path + '.get_vips'
        self.import_gm_api = import_path + '.get_members'
        self.import_ghm_api = import_path + '.get_health_monitors'
        self.import_lib = 'gbpservice.nfp.lib.transport'
        self._call = 'oslo_messaging.rpc.client._CallContext.call'
        self._get_pool = import_path + '.get_pool'

    def _cast_loadbalancer(self, conf, context, body,
                           method_type, device_config=False,
                           network_function_event=False):
        g_cnfg = GeneralConfigStructure()
        try:
            resource = body['config'][0]['resource']
            if resource == 'pool_health_monitor':
                resource = 'health_monitor'
            self.assertTrue(g_cnfg._check_general_structure(
                body, 'loadbalancer', resource))
        except Exception:
            self.assertTrue(False)

    def _call_to_get_network_function_desc(self):
        data = call_network_function_info()
        data['network_function']['description'] = ("\n" + str(
            {'service_vendor': 'xyz'}))
        return data['network_function']

    def _call_data(self, context, method, **kwargs):
        if method.lower() == "get_network_function_details":
            data = call_network_function_info()
            data['network_function']['description'] = "\n" + str(
                {'service_vendor': 'xyz'})
            return data['network_function']

        return []

    def _loadbalancer_data(self, resource):
        data = {'tenant_id': str(uuid.uuid4()),
                'id': str(uuid.uuid4())
                }
        if resource.lower() not in ['member', 'health_monitor']:
            desc = str({'network_function_id': str(uuid.uuid4())})
            data.update({'description': desc})
        if resource.lower() == 'vip':
            data.update({'pool_id': str(uuid.uuid4())})
        return data

    def _get_mocked_pool(self, context, pool_id):
        return {'id': pool_id,
                'description': str({'network_function_id': str(uuid.uuid4())})}

    def test_create_vip(self):
        import_send = self.import_lib + '.send_request_to_configurator'
        with mock.patch(self.import_gp_api) as gp, mock.patch(
                self.import_gv_api) as gv, mock.patch(
                self.import_gm_api) as gm, mock.patch(
                self.import_ghm_api) as ghm, mock.patch(
                self._call) as mock_call, mock.patch(
                import_send) as mock_send:
            gp.return_value = []
            gv.return_value = []
            gm.return_value = []
            ghm.return_value = []
            network_function_desc = self._call_to_get_network_function_desc()
            common.get_network_function_details = mock.MagicMock(
                return_value=network_function_desc)
            mock_call.side_effect = self._call_data
            mock_send.side_effect = self._cast_loadbalancer
            vip = self._loadbalancer_data('vip')
            self.lb_handler.create_vip(self.context, vip)

    def test_update_vip(self):
        import_send = self.import_lib + '.send_request_to_configurator'
        with mock.patch(self.import_gp_api) as gp, mock.patch(
                self.import_gv_api) as gv, mock.patch(
                self.import_gm_api) as gm, mock.patch(
                self.import_ghm_api) as ghm, mock.patch(
                self._call) as mock_call, mock.patch(
                import_send) as mock_send:
            gp.return_value = []
            gv.return_value = []
            gm.return_value = []
            ghm.return_value = []
            network_function_desc = self._call_to_get_network_function_desc()
            common.get_network_function_details = mock.MagicMock(
                return_value=network_function_desc)
            mock_call.side_effect = self._call_data
            mock_send.side_effect = self._cast_loadbalancer
            old_vip = self._loadbalancer_data('vip')
            vip = self._loadbalancer_data('vip')
            self.lb_handler.update_vip(self.context, old_vip, vip)

    def test_delete_vip(self):
        import_send = self.import_lib + '.send_request_to_configurator'
        with mock.patch(self.import_gp_api) as gp, mock.patch(
                self.import_gv_api) as gv, mock.patch(
                self.import_gm_api) as gm, mock.patch(
                self.import_ghm_api) as ghm, mock.patch(
                self._call) as mock_call, mock.patch(
                import_send) as mock_send:
            gp.return_value = []
            gv.return_value = []
            gm.return_value = []
            ghm.return_value = []
            network_function_desc = self._call_to_get_network_function_desc()
            common.get_network_function_details = mock.MagicMock(
                return_value=network_function_desc)
            mock_call.side_effect = self._call_data
            mock_send.side_effect = self._cast_loadbalancer
            vip = self._loadbalancer_data('vip')
            self.lb_handler.delete_vip(self.context, vip)

    def test_create_pool(self):
        import_send = self.import_lib + '.send_request_to_configurator'
        with mock.patch(self.import_gp_api) as gp, mock.patch(
                self.import_gv_api) as gv, mock.patch(
                self.import_gm_api) as gm, mock.patch(
                self.import_ghm_api) as ghm, mock.patch(
                self._call) as mock_call, mock.patch(
                import_send) as mock_send:
            gp.return_value = []
            gv.return_value = []
            gm.return_value = []
            ghm.return_value = []
            network_function_desc = self._call_to_get_network_function_desc()
            common.get_network_function_details = mock.MagicMock(
                return_value=network_function_desc)
            mock_call.side_effect = self._call_data
            mock_send.side_effect = self._cast_loadbalancer
            pool = self._loadbalancer_data('pool')
            driver_name = "dummy"
            self.lb_handler.create_pool(self.context, pool, driver_name)

    def test_update_pool(self):
        import_send = self.import_lib + '.send_request_to_configurator'
        with mock.patch(self.import_gp_api) as gp, mock.patch(
                self.import_gv_api) as gv, mock.patch(
                self.import_gm_api) as gm, mock.patch(
                self.import_ghm_api) as ghm, mock.patch(
                self._call) as mock_call, mock.patch(
                import_send) as mock_send:
            gp.return_value = []
            gv.return_value = []
            gm.return_value = []
            ghm.return_value = []
            network_function_desc = self._call_to_get_network_function_desc()
            common.get_network_function_details = mock.MagicMock(
                return_value=network_function_desc)
            mock_call.side_effect = self._call_data
            mock_send.side_effect = self._cast_loadbalancer
            old_pool = self._loadbalancer_data('pool')
            pool = self._loadbalancer_data('pool')
            self.lb_handler.update_pool(self.context, old_pool, pool)

    def test_delete_pool(self):
        import_send = self.import_lib + '.send_request_to_configurator'
        with mock.patch(self.import_gp_api) as gp, mock.patch(
                self.import_gv_api) as gv, mock.patch(
                self.import_gm_api) as gm, mock.patch(
                self.import_ghm_api) as ghm, mock.patch(
                self._call) as mock_call, mock.patch(
                import_send) as mock_send:
            gp.return_value = []
            gv.return_value = []
            gm.return_value = []
            ghm.return_value = []
            network_function_desc = self._call_to_get_network_function_desc()
            common.get_network_function_details = mock.MagicMock(
                return_value=network_function_desc)
            mock_call.side_effect = self._call_data
            mock_send.side_effect = self._cast_loadbalancer
            pool = self._loadbalancer_data('pool')
            self.lb_handler.delete_pool(self.context, pool)

    def test_create_member(self):
        import_send = self.import_lib + '.send_request_to_configurator'
        with mock.patch(self.import_gp_api) as gp, mock.patch(
                self.import_gv_api) as gv, mock.patch(
                self.import_gm_api) as gm, mock.patch(
                self.import_ghm_api) as ghm, mock.patch(
                self._call) as mock_call, mock.patch(
                self._get_pool) as mock_pool, mock.patch(
                import_send) as mock_send:
            gp.return_value = []
            gv.return_value = []
            gm.return_value = []
            ghm.return_value = []
            network_function_desc = self._call_to_get_network_function_desc()
            common.get_network_function_details = mock.MagicMock(
                return_value=network_function_desc)
            mock_call.side_effect = self._call_data
            mock_send.side_effect = self._cast_loadbalancer
            mock_pool.side_effect = self._get_mocked_pool
            member = self._loadbalancer_data('member')
            member.update({'pool_id': str(uuid.uuid4())})
            self.lb_handler.create_member(self.context, member)

    def test_update_member(self):
        import_send = self.import_lib + '.send_request_to_configurator'
        with mock.patch(self.import_gp_api) as gp, mock.patch(
                self.import_gv_api) as gv, mock.patch(
                self.import_gm_api) as gm, mock.patch(
                self.import_ghm_api) as ghm, mock.patch(
                self._call) as mock_call, mock.patch(
                self._get_pool) as mock_pool, mock.patch(
                import_send) as mock_send:
            gp.return_value = []
            gv.return_value = []
            gm.return_value = []
            ghm.return_value = []
            network_function_desc = self._call_to_get_network_function_desc()
            common.get_network_function_details = mock.MagicMock(
                return_value=network_function_desc)
            mock_call.side_effect = self._call_data
            mock_send.side_effect = self._cast_loadbalancer
            mock_pool.side_effect = self._get_mocked_pool
            old_member = self._loadbalancer_data('member')
            member = self._loadbalancer_data('member')
            pool_id = str(uuid.uuid4())
            old_member.update({'pool_id': pool_id})
            member.update({'pool_id': pool_id})
            self.lb_handler.update_member(self.context, old_member, member)

    def test_delete_member(self):
        import_send = self.import_lib + '.send_request_to_configurator'
        with mock.patch(self.import_gp_api) as gp, mock.patch(
                self.import_gv_api) as gv, mock.patch(
                self.import_gm_api) as gm, mock.patch(
                self.import_ghm_api) as ghm, mock.patch(
                self._call) as mock_call, mock.patch(
                self._get_pool) as mock_pool, mock.patch(
                import_send) as mock_send:
            gp.return_value = []
            gv.return_value = []
            gm.return_value = []
            ghm.return_value = []
            network_function_desc = self._call_to_get_network_function_desc()
            common.get_network_function_details = mock.MagicMock(
                return_value=network_function_desc)
            mock_call.side_effect = self._call_data
            mock_send.side_effect = self._cast_loadbalancer
            mock_pool.side_effect = self._get_mocked_pool
            member = self._loadbalancer_data('member')
            member.update({'pool_id': str(uuid.uuid4())})
            self.lb_handler.delete_member(self.context, member)

    def test_create_pool_health_monitor(self):
        import_send = self.import_lib + '.send_request_to_configurator'
        with mock.patch(self.import_gp_api) as gp, mock.patch(
                self.import_gv_api) as gv, mock.patch(
                self.import_gm_api) as gm, mock.patch(
                self.import_ghm_api) as ghm, mock.patch(
                self._call) as mock_call, mock.patch(
                self._get_pool) as mock_pool, mock.patch(
                import_send) as mock_send:
            gp.return_value = []
            gv.return_value = []
            gm.return_value = []
            ghm.return_value = []
            mock_call.side_effect = self._call_data
            mock_send.side_effect = self._cast_loadbalancer
            mock_pool.side_effect = self._get_mocked_pool
            network_function_desc = self._call_to_get_network_function_desc()
            common.get_network_function_details = mock.MagicMock(
                return_value=network_function_desc)
            hm = self._loadbalancer_data('health_monitor')
            pool_id = str(uuid.uuid4())
            self.lb_handler.create_pool_health_monitor(
                self.context, hm, pool_id)

    def test_update_pool_health_monitor(self):
        import_send = self.import_lib + '.send_request_to_configurator'
        with mock.patch(self.import_gp_api) as gp, mock.patch(
                self.import_gv_api) as gv, mock.patch(
                self.import_gm_api) as gm, mock.patch(
                self.import_ghm_api) as ghm, mock.patch(
                self._call) as mock_call, mock.patch(
                self._get_pool) as mock_pool, mock.patch(
                import_send) as mock_send:
            gp.return_value = []
            gv.return_value = []
            gm.return_value = []
            ghm.return_value = []
            network_function_desc = self._call_to_get_network_function_desc()
            common.get_network_function_details = mock.MagicMock(
                return_value=network_function_desc)
            mock_call.side_effect = self._call_data
            mock_send.side_effect = self._cast_loadbalancer
            mock_pool.side_effect = self._get_mocked_pool
            old_hm = self._loadbalancer_data('health_monitor')
            hm = self._loadbalancer_data('health_monitor')
            pool_id = str(uuid.uuid4())
            self.lb_handler.update_pool_health_monitor(
                self.context, old_hm, hm, pool_id)

    def test_delete_pool_health_monitor(self):
        import_send = self.import_lib + '.send_request_to_configurator'
        with mock.patch(self.import_gp_api) as gp, mock.patch(
                self.import_gv_api) as gv, mock.patch(
                self.import_gm_api) as gm, mock.patch(
                self.import_ghm_api) as ghm, mock.patch(
                self._call) as mock_call, mock.patch(
                self._get_pool) as mock_pool, mock.patch(
                import_send) as mock_send:
            gp.return_value = []
            gv.return_value = []
            gm.return_value = []
            ghm.return_value = []
            network_function_desc = self._call_to_get_network_function_desc()
            common.get_network_function_details = mock.MagicMock(
                return_value=network_function_desc)

            mock_call.side_effect = self._call_data
            mock_send.side_effect = self._cast_loadbalancer
            mock_pool.side_effect = self._get_mocked_pool
            hm = self._loadbalancer_data('health_monitor')
            pool_id = str(uuid.uuid4())
            self.lb_handler.delete_pool_health_monitor(
                self.context, hm, pool_id)


class VPNTestCase(base.BaseTestCase):

    def setUp(self):
        super(VPNTestCase, self).setUp()
        self.conf = Conf()
        self.vpn_handler = vpn.VpnAgent(self.conf, 'sc')
        self.context = TestContext().get_context()
        import_path = "neutron_vpnaas.db.vpn.vpn_db.VPNPluginDb"
        self.import_gvs_api = import_path + '.get_vpnservices'
        self.import_gikp_api = import_path + '.get_ikepolicies'
        self.import_gipsp_api = import_path + '.get_ipsecpolicies'
        self.import_gisc_api = import_path + '.get_ipsec_site_connections'
        self.import_lib = 'gbpservice.nfp.lib.transport'
        self._call = 'oslo_messaging.rpc.client._CallContext.call'

    def _cast_vpn(self, conf, context, body,
                  method_type, device_config=False,
                  network_function_event=False):
        g_cnfg = GeneralConfigStructure()
        try:
            resource = body['config'][0]['resource']
            self.assertTrue(g_cnfg._check_general_structure(
                body, 'vpn', resource))
        except Exception:
            self.assertTrue(False)

    def _call_data(self, context, method, **kwargs):
        if method.lower() == "get_network_function_details":
            data = call_network_function_info()
            data['network_function']['description'] = ("\n" + (
                "ipsec_site_connection_id=%s;service_vendor=xyz" % (
                    str(uuid.uuid4()))))
            return data['network_function']

        return []

    def _prepare_request_data(self, reason, rsrc_type):
        resource = {'tenant_id': str(uuid.uuid4()),
                    'id': str(uuid.uuid4()),
                    'description': (
                        "{'network_function_id':'%s'}" % (str(uuid.uuid4())))
                    }
        if rsrc_type.lower() == 'ipsec_site_connection':
            resource.update({'vpnservice_id': str(uuid.uuid4()),
                             'ikepolicy_id': str(uuid.uuid4()),
                             'ipsecpolicy_id': str(uuid.uuid4())})
        elif rsrc_type.lower() == 'vpn_service':
            resource.update({'subnet_id': str(uuid.uuid4()),
                             'router_id': str(uuid.uuid4())})
        return {'resource': resource,
                'rsrc_type': rsrc_type,
                'reason': reason,
                'rsrc_id': str(uuid.uuid4())
                }

    def _call_to_get_network_function_desc(self):
        data = call_network_function_info()
        data['network_function']['description'] = ("\n" + (
            "ipsec_site_connection_id=%s;service_vendor=xyz" % (
                str(uuid.uuid4()))))
        return data['network_function']

    def _get_networks(self):
        return []

    def _get_routers(self):
        return []

    def test_update_vpnservice_for_vpnservice(self):
        import_send = self.import_lib + '.send_request_to_configurator'
        with mock.patch(self.import_gvs_api) as gvs, mock.patch(
                self.import_gikp_api) as gikp, mock.patch(
                self.import_gipsp_api) as gipsp, mock.patch(
                self.import_gisc_api) as gisc, mock.patch(
                self._call) as mock_call, mock.patch(
                import_send) as mock_send:
            gvs.return_value = []
            gikp.return_value = []
            gipsp.return_value = []
            gisc.return_value = []

            network_function_desc = self._call_to_get_network_function_desc()
            common.get_network_function_details = mock.MagicMock(
                return_value=network_function_desc)

            mock_call.side_effect = self._call_data
            mock_send.side_effect = self._cast_vpn
            rsrc_type = 'vpn_service'
            reason = 'create'
            kwargs = self._prepare_request_data(reason, rsrc_type)
            self.vpn_handler.vpnservice_updated(self.context, **kwargs)

    def test_update_vpnservice_for_ipsec_site_connection(self):
        import_send = self.import_lib + '.send_request_to_configurator'
        with mock.patch(self.import_gvs_api) as gvs, mock.patch(
                self.import_gikp_api) as gikp, mock.patch(
                self.import_gipsp_api) as gipsp, mock.patch(
                self.import_gisc_api) as gisc, mock.patch(
                self._call) as mock_call, mock.patch(
                import_send) as mock_send:
            gvs.return_value = []
            gikp.return_value = []
            gipsp.return_value = []
            gisc.return_value = []

            network_function_desc = self._call_to_get_network_function_desc()
            common.get_network_function_details = mock.MagicMock(
                return_value=network_function_desc)

            networks = self._get_networks()
            routers = self._get_routers()
            common.get_networks = mock.MagicMock(return_value=networks)
            common.get_routers = mock.MagicMock(return_value=routers)

            mock_call.side_effect = self._call_data
            mock_send.side_effect = self._cast_vpn
            rsrc_type = 'ipsec_site_connection'
            reason = 'delete'
            kwargs = self._prepare_request_data(reason, rsrc_type)
            self.vpn_handler.vpnservice_updated(self.context, **kwargs)


class FirewallNotifierTestCase(base.BaseTestCase):

    class Controller(object):

        def new_event(self, **kwargs):
            return

        def post_event(self, event):
            return

    def setUp(self):
        super(FirewallNotifierTestCase, self).setUp()
        self.conf = Conf()
        self.n_handler = notif_handler.NaasNotificationHandler(
            self.conf, self.Controller())
        self.context = TestContext().get_context()

    def _get_rpc_client(self):
        class Context(object):
            def cast(self, context, method, host='', firewall_id='', body=''):
                return {}

        class RCPClient(object):
            def __init__(self):
                self.cctxt = Context()

        return RCPClient()

    def get_notification_data(self):
        return {'info': {'service_type': 'firewall',
                         'context': {'logging_context': {}}},
                'notification': [{'data': {'firewall_id': '123',
                                           'status': 'set_firewall_status',
                                           'notification_type':
                                                     'set_firewall_status',
                                           'host': 'localhost'}
                                  }]
                }

    def test_set_firewall_status(self):
        notification_data = self.get_notification_data()
        rpc_client = self._get_rpc_client()
        transport.RPCClient = mock.MagicMock(return_value=rpc_client)
        self.n_handler.handle_notification(self.context,
                                           notification_data)

    def test_set_firewall_deleted(self):
        notification_data = self.get_notification_data()
        notification_data['notification'][0]['data'][
                          'notification_type'] = 'firewall_deleted'
        rpc_client = self._get_rpc_client()
        transport.RPCClient = mock.MagicMock(return_value=rpc_client)
        self.n_handler.handle_notification(self.context,
                                           notification_data)


class LoadbalancerNotifierTestCase(base.BaseTestCase):

    class Controller(object):

        def new_event(self, **kwargs):
            return

        def post_event(self, event):
            return

    def setUp(self):
        super(LoadbalancerNotifierTestCase, self).setUp()
        self.conf = Conf()
        self.n_handler = notif_handler.NaasNotificationHandler(
            self.conf, self.Controller())
        self.context = TestContext().get_context()

    def _get_rpc_client(self):
        class Context(object):
            def cast(self, context, method, host='', pool_id='',
                     stats='', body=''):
                return {}

        class RCPClient(object):
            def __init__(self):
                self.cctxt = Context()

        return RCPClient()

    def get_notification_data(self):
        return {'info': {'service_type': 'loadbalancer',
                         'context': {'logging_context': {}}},
                'notification': [{'data': {'obj_type': 'lb',
                                           'obj_id': '123',
                                           'status': 'set_firewall_status',
                                           'notification_type':
                                                     'update_status',
                                           'host': 'localhost'}
                                  }]
                }

    def test_update_status(self):
        notification_data = self.get_notification_data()
        rpc_client = self._get_rpc_client()
        transport.RPCClient = mock.MagicMock(return_value=rpc_client)
        self.n_handler.handle_notification(self.context,
                                           notification_data)

    def test_update_pool_stats(self):
        notification_data = self.get_notification_data()
        notification_data['notification'][0]['data'][
                          'notification_type'] = 'update_pool_stats'
        rpc_client = self._get_rpc_client()
        transport.RPCClient = mock.MagicMock(return_value=rpc_client)
        self.n_handler.handle_notification(self.context,
                                           notification_data)


class VpnNotifierTestCase(base.BaseTestCase):

    class Controller(object):

        def new_event(self, **kwargs):
            return

        def post_event(self, event):
            return

    def setUp(self):
        super(VpnNotifierTestCase, self).setUp()
        self.conf = Conf()
        self.n_handler = notif_handler.NaasNotificationHandler(
            self.conf, self.Controller())
        self.context = TestContext().get_context()

    def _get_rpc_client(self):
        class Context(object):
            def cast(self, context, method, host='', status='', body=''):
                return {}

        class RCPClient(object):
            def __init__(self):
                self.cctxt = Context()

        return RCPClient()

    def get_notification_data(self):
        return {'info': {'service_type': 'vpn',
                         'context': {'logging_context': {}}},
                'notification': [{'data': {'firewall_id': '123',
                                           'status': 'set_firewall_status',
                                           'notification_type':
                                                     'update_status',
                                           'host': 'localhost'}
                                  }]
                }

    def test_update_status(self):
        notification_data = self.get_notification_data()
        rpc_client = self._get_rpc_client()
        transport.RPCClient = mock.MagicMock(return_value=rpc_client)
        self.n_handler.handle_notification(self.context,
                                           notification_data)
