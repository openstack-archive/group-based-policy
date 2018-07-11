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

from neutron_lib.plugins import constants as pconst
from neutron_lib.plugins import directory
from oslo_log import log as logging

from gbpservice.neutron.services.grouppolicy.common import exceptions as gp_exc
from gbpservice.neutron.services.grouppolicy import plugin as gbp_plugin


LOG = logging.getLogger(__name__)


class SharingMixin(object):

    """Implementation of the Service Chain Plugin sharing rules.

    """

    usage_graph = {'servicechain_spec': {'nodes':
                                         'servicechain_node'},
                   'servicechain_node': {'service_profile_id':
                                         'service_profile'},
                   'servicechain_instance': {},
                   'service_profile': {},
                   }

    @property
    def gbp_plugin(self):
        # REVISIT(rkukura): Need initialization method after all
        # plugins are loaded to grab and store plugin.
        gbp_plugin = directory.get_plugin(pconst.GROUP_POLICY)
        if not gbp_plugin:
            LOG.error("No group policy service plugin found.")
            raise gp_exc.GroupPolicyDeploymentError()
        return gbp_plugin

    def _validate_shared_create(self, context, obj, identity):
        return gbp_plugin.GroupPolicyPlugin._validate_shared_create(
            self, context, obj, identity)

    def _validate_shared_update(self, context, original, updated, identity):
        self._validate_shared_create(context, updated, identity)
        if updated.get('shared') != original.get('shared'):
            context = context.elevated()
            getattr(self, '_validate_%s_unshare' % identity)(context, updated)

    def _validate_servicechain_node_unshare(self, context, obj):
        # Verify not pointed by shared SCS
        gbp_plugin.GroupPolicyPlugin._check_shared_or_different_tenant(
            context, obj, self.get_servicechain_specs, 'id',
            obj['servicechain_specs'])

    def _validate_servicechain_spec_unshare(self, context, obj):
        # Verify not pointed by shared policy actions
        gbp_plugin.GroupPolicyPlugin._check_shared_or_different_tenant(
            context, obj, self.gbp_plugin.get_policy_actions, 'action_value',
            [obj['id']])

    def _validate_service_profile_unshare(self, context, obj):
        gbp_plugin.GroupPolicyPlugin._check_shared_or_different_tenant(
            context, obj, self.get_servicechain_nodes, 'service_profile_id')
