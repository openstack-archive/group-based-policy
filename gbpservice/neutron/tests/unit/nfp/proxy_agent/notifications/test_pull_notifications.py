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

from gbpservice.nfp.proxy_agent.notifications import pull
import mock
from neutron import context as ctx
import unittest

from neutron.common import rpc as n_rpc
from oslo_config import cfg

pull_notification = pull.PullNotification


class TestContext(object):

    def get_context_dict(self):
        try:
            context = ctx.Context('some_user', 'some_tenant')
        except Exception:
            context = ctx.Context('some_user', 'some_tenant')
        return context.to_dict()

"""Common class for pull notification tests"""


class PullNotificationTestCase(unittest.TestCase):

    def _resp_base_structure(self):
        response_data = [
            {'receiver': None,
             'resource': None,
             'method': None,
             'kwargs': None
             },
        ]
        return response_data

    def setUp(self):
        n_rpc.init(cfg.CONF)
        self.p_notification = pull_notification('sc', 'conf')
        self.context = TestContext().get_context_dict()
        self.ev = ''
        self.import_lib = 'gbpservice.nfp.lib.transport'
        self.import_cast = 'oslo_messaging.rpc.client._CallContext.cast'

    def _cast(self, context, method, **kwargs):
        return

    def _resp_data_set_firewall(self, conf):
        response_data = self._resp_base_structure()
        response_data[0]['receiver'] = 'neutron'
        response_data[0]['resource'] = 'firewall'
        response_data[0]['method'] = 'set_firewall_status'
        response_data[0]['kwargs'] = {'context': self.context,
                                      'host': '',
                                      'status': '',
                                      'firewall_id': ''}
        return response_data

    def test_set_firewall_status_pull_notifications(self):
        import_get = self.import_lib + '.get_response_from_configurator'
        with mock.patch(import_get) as mock_get_resp, \
                mock.patch(self.import_cast) as mock_cast:
            mock_get_resp.side_effect = self._resp_data_set_firewall
            mock_cast.side_effect = self._cast
            self.p_notification.pull_notifications(self.ev)

    def _resp_data_firewall_delete(self, conf):
        response_data = self._resp_base_structure()
        response_data[0]['receiver'] = 'neutron'
        response_data[0]['resource'] = 'firewall'
        response_data[0]['method'] = 'firewall_deleted'
        response_data[0]['kwargs'] = {'context': self.context,
                                      'host': '',
                                      'firewall_id': ''}
        return response_data

    def test_firewall_deleted_pull_notifications(self):
        import_get = self.import_lib + '.get_response_from_configurator'
        with mock.patch(import_get) as mock_get, \
                mock.patch(self.import_cast) as mock_cast:
            mock_get.side_effect = self._resp_data_firewall_delete
            mock_cast.side_effect = self._cast
            self.p_notification.pull_notifications(self.ev)

    def _resp_data_update_status_vpn(self, conf):
        response_data = self._resp_base_structure()
        response_data[0]['receiver'] = 'neutron'
        response_data[0]['resource'] = 'vpn'
        response_data[0]['method'] = 'update_status'
        response_data[0]['kwargs'] = {'context': self.context,
                                      'status': ''}
        return response_data

    def test_update_status_vpn_pull_notifications(self):
        import_get = self.import_lib + '.get_response_from_configurator'
        with mock.patch(import_get) as mock_get, \
                mock.patch(self.import_cast) as mock_cast:
            mock_get.side_effect = self._resp_data_update_status_vpn
            mock_cast.side_effect = self._cast
            self.p_notification.pull_notifications(self.ev)

    def _resp_data_update_status_lb(self, conf):
        response_data = self._resp_base_structure()
        response_data[0]['receiver'] = 'neutron'
        response_data[0]['resource'] = 'loadbalancer'
        response_data[0]['method'] = 'update_status'
        response_data[0]['kwargs'] = {'context': self.context,
                                      'status': '',
                                      'obj_type': '',
                                      'obj_id': ''}
        return response_data

    def test_update_status_lb_pull_notifications(self):
        import_get = self.import_lib + '.get_response_from_configurator'
        with mock.patch(import_get) as mock_get, \
                mock.patch(self.import_cast) as mock_cast:
            mock_get.side_effect = self._resp_data_update_status_lb
            mock_cast.side_effect = self._cast
            self.p_notification.pull_notifications(self.ev)

    def _resp_data_update_pool_stats(self, conf):
        response_data = self._resp_base_structure()
        response_data[0]['receiver'] = 'neutron'
        response_data[0]['resource'] = 'loadbalancer'
        response_data[0]['method'] = 'update_pool_stats'
        response_data[0]['kwargs'] = {'context': self.context,
                                      'stats': '',
                                      'pool_id': '',
                                      'host': ''}
        return response_data

    def test_update_pool_stats_pull_notifications(self):
        import_get = self.import_lib + '.get_response_from_configurator'
        with mock.patch(import_get) as mock_get, \
                mock.patch(self.import_cast) as mock_cast:
            mock_get.side_effect = self._resp_data_update_pool_stats
            mock_cast.side_effect = self._cast
            self.p_notification.pull_notifications(self.ev)

    def _resp_data_pool_destroyed(self, conf):
        response_data = self._resp_base_structure()
        response_data[0]['receiver'] = 'neutron'
        response_data[0]['resource'] = 'loadbalancer'
        response_data[0]['method'] = 'pool_destroyed'
        response_data[0]['kwargs'] = {'context': self.context,
                                      'pool_id': ''}
        return response_data

    def test_pool_destroyed_pull_notifications(self):
        import_get = self.import_lib + '.get_response_from_configurator'
        with mock.patch(import_get) as mock_get, \
                mock.patch(self.import_cast) as mock_cast:
            mock_get.side_effect = self._resp_data_pool_destroyed
            mock_cast.side_effect = self._cast
            self.p_notification.pull_notifications(self.ev)

    def _resp_data_pool_deployed(self, conf):
        response_data = self._resp_base_structure()
        response_data[0]['receiver'] = 'neutron'
        response_data[0]['resource'] = 'loadbalancer'
        response_data[0]['method'] = 'pool_deployed'
        response_data[0]['kwargs'] = {'context': self.context,
                                      'pool_id': ''}
        return response_data

    def test_pool_deployed_pull_notifications(self):
        import_get = self.import_lib + '.get_response_from_configurator'
        with mock.patch(import_get) as mock_get, \
                mock.patch(self.import_cast) as mock_cast:
            mock_get.side_effect = self._resp_data_pool_deployed
            mock_cast.side_effect = self._cast
            self.p_notification.pull_notifications(self.ev)

    def _resp_data_device_orch(self, conf):
        response_data = self._resp_base_structure()
        response_data[0]['receiver'] = 'device_orchestrator'
        response_data[0]['resource'] = 'dummy'
        response_data[0]['method'] = 'network_function_device_notification'
        response_data[0]['kwargs'] = [{'context': self.context}]
        return response_data

    def test_device_orch_network_function_device_pull_notification(self):
        import_get = self.import_lib + '.get_response_from_configurator'
        with mock.patch(import_get) as mock_get, \
                mock.patch(self.import_cast) as mock_cast:
            mock_get.side_effect = self._resp_data_device_orch
            mock_cast.side_effect = self._cast
            self.p_notification.pull_notifications(self.ev)

    def _resp_data_service_orch(self, conf):
        response_data = self._resp_base_structure()
        response_data[0]['receiver'] = 'service_orchestrator'
        response_data[0]['resource'] = 'heat'
        response_data[0]['method'] = 'network_function_device_notification'
        response_data[0]['kwargs'] = [{'context': self.context}]
        return response_data

    def test_service_orch_network_function_device_pull_notification(self):
        import_get = self.import_lib + '.get_response_from_configurator'
        with mock.patch(import_get) as mock_get, \
                mock.patch(self.import_cast) as mock_cast:
            mock_get.side_effect = self._resp_data_service_orch
            mock_cast.side_effect = self._cast
            self.p_notification.pull_notifications(self.ev)
