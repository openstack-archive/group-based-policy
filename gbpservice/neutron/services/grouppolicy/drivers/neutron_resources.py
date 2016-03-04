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

from oslo_log import helpers as log
from oslo_log import log as logging

from gbpservice.neutron.services.grouppolicy.common import exceptions as exc
from gbpservice.neutron.services.grouppolicy.drivers import (
    implicit_policy as ipd)
from gbpservice.neutron.services.grouppolicy.drivers import (
    resource_mapping as rmd)


LOG = logging.getLogger(__name__)


class CommonNeutronBase(ipd.ImplicitPolicyBase, rmd.OwnedResourcesOperations,
                        rmd.ImplicitResourceOperations):
    """Neutron Resources' Orchestration driver.

    This driver realizes GBP's network semantics by orchestrating
    the necessary Neutron resources.
    """

    @log.log_method_call
    def initialize(self):
        # REVISIT: Check if this is still required
        self._cached_agent_notifier = None
        super(CommonNeutronBase, self).initialize()

    @log.log_method_call
    def create_l2_policy_precommit(self, context):
        l2p_db = context._plugin._get_l2_policy(
            context._plugin_context, context.current['id'])
        if not context.current['l3_policy_id']:
            self._create_implicit_l3_policy(context, clean_session=False)
            l2p_db['l3_policy_id'] = context.current['l3_policy_id']
        if not context.current['network_id']:
            self._use_implicit_network(context, clean_session=False)
            l2p_db['network_id'] = context.current['network_id']

    @log.log_method_call
    def update_l2_policy_precommit(self, context):
        if (context.current['inject_default_route'] !=
            context.original['inject_default_route']):
            raise exc.UnsettingInjectDefaultRouteOfL2PolicyNotSupported()
        if (context.current['l3_policy_id'] !=
            context.original['l3_policy_id']):
            raise exc.L3PolicyUpdateOfL2PolicyNotSupported()

    @log.log_method_call
    def delete_l2_policy_precommit(self, context):
        l2p_db = context._plugin._get_l2_policy(
            context._plugin_context, context.current['id'])
        if l2p_db['network_id']:
            network_id = l2p_db['network_id']
            l2p_db.update({'network_id': None})
            self._cleanup_network(context._plugin_context, network_id,
                                  clean_session=False)
        if l2p_db['l3_policy_id']:
            l3p_id = l2p_db['l3_policy_id']
            l2p_db.update({'l3_policy_id': None})
            self._cleanup_l3_policy(context, l3p_id, clean_session=False)
