# Copyright 2014 Alcatel-Lucent USA Inc.
#
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
from neutron.tests.unit.plugins.ml2 import test_plugin
from oslo_config import cfg

from gbpservice.neutron.services.grouppolicy import config
from gbpservice.neutron.services.grouppolicy.drivers.nuage import (
    driver as nuage_driver)
from gbpservice.neutron.tests.unit.services.grouppolicy import (
    test_grouppolicy_plugin as test_gp_plugin)

FAKE_GBP_APP = 'ut_gbp_app'
FAKE_DEFAULT_ENT = 'default'
NUAGE_PLUGIN_PATH = 'neutron.plugins.nuage.plugin'
FAKE_SERVER = '1.1.1.1'
FAKE_SERVER_AUTH = 'user:pass'
FAKE_SERVER_SSL = False
FAKE_BASE_URI = '/base/'
FAKE_AUTH_RESOURCE = '/auth'
FAKE_ORGANIZATION = 'fake_org'


class FakeNuageGBPClient(object):

    def __init__(self, server, base_uri, serverssl,
                 serverauth, auth_resource, organization):
        pass

    def create_ptg_postcommit(self, context, application):
        pass

    def update_ptg_postcommit(self, context, gbp_policyruleset,
                              application):
        pass

    def delete_ptg_postcommit(self, context, application):
        pass

    def create_policyrule_postcommit(self, context, gbp_action,
                                     gbp_classifier, application):
        pass

    def delete_policyrule_postcommit(self, context, application):
        pass

    def create_policytarget(self, context, port, ptg, application):
        pass


class NuageGBPDriverTestCase(test_gp_plugin.GroupPolicyPluginTestCase):

    def setUp(self):
        config.cfg.CONF.set_override('policy_drivers',
                                     ['implicit_policy', 'resource_mapping',
                                      'nuage_gbp_driver'],
                                     group='group_policy')
        ml2_opts = {
            'mechanism_drivers': ['nuage_gbp'],
        }
        for opt, val in ml2_opts.items():
                cfg.CONF.set_override(opt, val, 'ml2')

        def mock_nuageclient_init(self):
            server = FAKE_SERVER
            serverauth = FAKE_SERVER_AUTH
            serverssl = FAKE_SERVER_SSL
            base_uri = FAKE_BASE_URI
            auth_resource = FAKE_AUTH_RESOURCE
            organization = FAKE_ORGANIZATION
            self.nuageclient = FakeNuageGBPClient(server,
                                                  base_uri,
                                                  serverssl,
                                                  serverauth,
                                                  auth_resource,
                                                  organization)
            self.nuage_app = FAKE_GBP_APP

        with mock.patch.object(nuage_driver.NuageGBPDriver,
                               'nuageclient_init', new=mock_nuageclient_init):
            super(NuageGBPDriverTestCase, self).setUp(
                core_plugin=test_plugin.PLUGIN_NAME)


class TestPolicyTargetGroup(NuageGBPDriverTestCase):
    pass


class TestPolicyRuleSet(NuageGBPDriverTestCase):
    pass


class TestPolicyRule(NuageGBPDriverTestCase):
    pass
