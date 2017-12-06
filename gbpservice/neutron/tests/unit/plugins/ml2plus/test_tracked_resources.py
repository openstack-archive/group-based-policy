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

import functools
import mock

from neutron.api import extensions
from neutron.tests.unit.plugins.ml2 import (
    test_tracked_resources as n_tracked)
from neutron.tests.unit.plugins.ml2 import test_plugin

import gbpservice.neutron.extensions

PLUGIN_NAME = 'ml2plus'


class Ml2PlusConfFixture(test_plugin.PluginConfFixture):

    def __init__(self, parent_setup=None):
        super(Ml2PlusConfFixture, self).__init__(PLUGIN_NAME, parent_setup)


class Ml2PlusTestTrackedResourcesEventHandler(
        n_tracked.TestTrackedResourcesEventHandler):

    def setUp(self):
        extensions.append_api_extensions_path(
            gbpservice.neutron.extensions.__path__)
        # Prevent noise from default security group operations
        super(Ml2PlusTestTrackedResourcesEventHandler, self).setUp()
        get_sec_group_port_patch = mock.patch(
            'neutron.db.securitygroups_db.SecurityGroupDbMixin.'
            '_get_security_groups_on_port')
        get_sec_group_port_patch.start()

    def setup_parent(self):
        """Perform parent setup with the common plugin configuration class."""
        service_plugins = {'l3_plugin_name': self.l3_plugin}
        service_plugins.update(self.get_additional_service_plugins())
        # Ensure that the parent setup can be called without arguments
        # by the common configuration setUp.
        parent_setup = functools.partial(
            super(test_plugin.Ml2PluginV2TestCase, self).setUp,
            plugin=PLUGIN_NAME,
            service_plugins=service_plugins,
        )
        self.useFixture(Ml2PlusConfFixture(parent_setup))
        self.port_create_status = 'DOWN'


class Ml2PlusTestTrackedResources(n_tracked.TestTrackedResources):

    def setUp(self):
        extensions.append_api_extensions_path(
            gbpservice.neutron.extensions.__path__)
        # Prevent noise from default security group operations
        super(Ml2PlusTestTrackedResources, self).setUp()
        get_sec_group_port_patch = mock.patch(
            'neutron.db.securitygroups_db.SecurityGroupDbMixin.'
            '_get_security_groups_on_port')
        get_sec_group_port_patch.start()

    def setup_parent(self):
        """Perform parent setup with the common plugin configuration class."""
        service_plugins = {'l3_plugin_name': self.l3_plugin}
        service_plugins.update(self.get_additional_service_plugins())
        # Ensure that the parent setup can be called without arguments
        # by the common configuration setUp.
        parent_setup = functools.partial(
            super(test_plugin.Ml2PluginV2TestCase, self).setUp,
            plugin=PLUGIN_NAME,
            service_plugins=service_plugins,
        )
        self.useFixture(Ml2PlusConfFixture(parent_setup))
        self.port_create_status = 'DOWN'
