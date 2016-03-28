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

    def setUp(self):
        n_rpc.init(cfg.CONF)
        self.p_notification = pull_notification('sc', 'conf')
        self.context = TestContext().get_context_dict()
        self.ev = ''
        self.import_lib = 'gbpservice.nfp.lib.transport'
        self.import_cast = 'oslo_messaging.rpc.client._CallContext.cast'

    def _resp_base_structure(self, requester):
        response_data = [{
            'info': {
                'context': {
                    'neutron_context': self.context,
                    'requester': requester}
            }}]
        return response_data

    def _cast(self, context, method, **kwargs):
        return

    def _resp_data_nso(self, conf):
        response_data = self._resp_base_structure('service_orch')
        return response_data

    def _resp_data_ndo(self, conf):
        response_data = self._resp_base_structure('device_orch')
        return response_data

    def _resp_data_nco(self, conf):
        response_data = self._resp_base_structure('nas_service')
        return response_data

    def test_nco_pull_notifications(self):
        import_get = self.import_lib + '.get_response_from_configurator'
        with mock.patch(import_get) as (
            mock_get), mock.patch(self.import_cast) as (
            mock_cast):
            mock_get.side_effect = self._resp_data_nco
            mock_cast.side_effect = self._cast
            self.p_notification.pull_notifications(self.ev)

    def test_nso_pull_notifications(self):
        import_get = self.import_lib + '.get_response_from_configurator'
        with mock.patch(import_get) as (
            mock_get), mock.patch(self.import_cast) as (
            mock_cast):
            mock_get.side_effect = self._resp_data_nso
            mock_cast.side_effect = self._cast
            self.p_notification.pull_notifications(self.ev)

    def test_ndo_pull_notifications(self):
        import_get = self.import_lib + '.get_response_from_configurator'
        with mock.patch(import_get) as (
            mock_get), mock.patch(self.import_cast) as (
            mock_cast):
            mock_get.side_effect = self._resp_data_ndo
            mock_cast.side_effect = self._cast
            self.p_notification.pull_notifications(self.ev)
