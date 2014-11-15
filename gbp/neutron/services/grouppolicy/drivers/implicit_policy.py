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

from oslo.config import cfg
import sqlalchemy as sa

from neutron.common import log
from neutron.db import model_base
from neutron.openstack.common import log as logging

from gbp.neutron.services.grouppolicy import group_policy_driver_api as api


LOG = logging.getLogger(__name__)

opts = [
    cfg.StrOpt('default_l3_policy_name',
               default='default',
               help=_("Name of each tenant's default L3 policy.")),
    cfg.IntOpt('default_ip_version',
               default=4,
               help=_("IP version (4 or 6) for implicitly created default L3 "
                      "policies.")),
    cfg.StrOpt('default_ip_pool',
               default='172.16.0.0/12',
               help=_("IP pool for implicitly created default L3 policies, "
                      "from which subnets are allocated for endpoint "
                      "groups.")),
    cfg.IntOpt('default_subnet_prefix_length',
               default=26,
               help=_("Subnet prefix length for implicitly created default L3 "
                      "polices, controlling size of subnets allocated for "
                      "endpoint groups.")),
]

cfg.CONF.register_opts(opts, "group_policy_implicit_policy")


class OwnedL2Policy(model_base.BASEV2):
    """An L2 Policy owned by the mapping driver."""

    __tablename__ = 'gpm_owned_l2_policies'
    l2_policy_id = sa.Column(sa.String(36),
                             sa.ForeignKey('gp_l2_policies.id',
                                           ondelete='CASCADE'),
                             nullable=False, primary_key=True)


class OwnedL3Policy(model_base.BASEV2):
    """An L3 Policy owned by the mapping driver."""

    __tablename__ = 'gpm_owned_l3_policies'
    l3_policy_id = sa.Column(sa.String(36),
                             sa.ForeignKey('gp_l3_policies.id',
                                           ondelete='CASCADE'),
                             nullable=False, primary_key=True)


class ImplicitPolicyDriver(api.PolicyDriver):
    """Implicit Policy driver for Group Policy plugin.

    This driver ensures that the l2_policy_id attribute of
    EndpointGroup references an L2Policy instance and that the
    l3_policy_id attribute of L2Policy references an L3Policy instance
    when the default value of None is specified.
    """

    @log.log
    def initialize(self):
        gpip = cfg.CONF.group_policy_implicit_policy
        self._default_l3p_name = gpip.default_l3_policy_name
        self._default_ip_version = gpip.default_ip_version
        self._default_ip_pool = gpip.default_ip_pool
        self._default_subnet_prefix_length = gpip.default_subnet_prefix_length

    @log.log
    def create_endpoint_group_postcommit(self, context):
        if not context.current['l2_policy_id']:
            self._use_implicit_l2_policy(context)

    @log.log
    def update_endpoint_group_postcommit(self, context):
        old_l2p_id = context.original['l2_policy_id']
        new_l2p_id = context.current['l2_policy_id']
        if old_l2p_id != new_l2p_id:
            self._cleanup_l2_policy(context, old_l2p_id)
            if not new_l2p_id:
                self._use_implicit_l2_policy(context)

    @log.log
    def delete_endpoint_group_postcommit(self, context):
        l2p_id = context.current['l2_policy_id']
        self._cleanup_l2_policy(context, l2p_id)

    @log.log
    def create_l2_policy_postcommit(self, context):
        if not context.current['l3_policy_id']:
            self._use_implicit_l3_policy(context)

    @log.log
    def update_l2_policy_postcommit(self, context):
        old_l3p_id = context.original['l3_policy_id']
        new_l3p_id = context.current['l3_policy_id']
        if old_l3p_id != new_l3p_id:
            self._cleanup_l3_policy(context, old_l3p_id)
            if not new_l3p_id:
                self._use_implicit_l3_policy(context)

    @log.log
    def delete_l2_policy_postcommit(self, context):
        l3p_id = context.current['l3_policy_id']
        self._cleanup_l3_policy(context, l3p_id)

    def _use_implicit_l2_policy(self, context):
        attrs = {'l2_policy':
                 {'tenant_id': context.current['tenant_id'],
                  'name': context.current['name'],
                  'description': _("Implicitly created L2 policy"),
                  'l3_policy_id': None,
                  'shared': context.current.get('shared', False),
                  'network_id': None}}
        l2p = context._plugin.create_l2_policy(context._plugin_context, attrs)
        l2p_id = l2p['id']
        self._mark_l2_policy_owned(context._plugin_context.session, l2p_id)
        context.current['l2_policy_id'] = l2p_id
        context._plugin.update_endpoint_group(
            context._plugin_context, context.current['id'],
            {'endpoint_group': {'l2_policy_id': l2p_id}})

    def _cleanup_l2_policy(self, context, l2p_id):
        if self._l2_policy_is_owned(context._plugin_context.session, l2p_id):
            context._plugin.delete_l2_policy(context._plugin_context, l2p_id)

    def _use_implicit_l3_policy(self, context):
        filter = {'tenant_id': [context.current['tenant_id']],
                  'name': [self._default_l3p_name]}
        l3ps = context._plugin.get_l3_policies(context._plugin_context, filter)
        l3p = l3ps and l3ps[0]
        if not l3p:
            # REVISIT(rkukura): Concurrency could result in multiple
            # default L3Ps for the same tenant. A DB table mapping
            # tenant_id to default l3_policy_id may be needed to
            # ensure a single default L3 policy is used per tenant.
            attrs = {'l3_policy':
                     {'tenant_id': context.current['tenant_id'],
                      'name': self._default_l3p_name,
                      'description': _("Implicitly created L3 policy"),
                      'ip_version': self._default_ip_version,
                      'ip_pool': self._default_ip_pool,
                      'shared': context.current.get('shared', False),
                      'subnet_prefix_length':
                      self._default_subnet_prefix_length}}
            l3p = context._plugin.create_l3_policy(context._plugin_context,
                                                   attrs)
            self._mark_l3_policy_owned(context._plugin_context.session,
                                       l3p['id'])
        context.current['l3_policy_id'] = l3p['id']
        context._plugin.update_l2_policy(
            context._plugin_context, context.current['id'],
            {'l2_policy': {'l3_policy_id': l3p['id']}})

    def _cleanup_l3_policy(self, context, l3p_id):
        if self._l3_policy_is_owned(context._plugin_context.session, l3p_id):
            context._plugin.delete_l3_policy(context._plugin_context, l3p_id,
                                             check_unused=True)

    def _mark_l2_policy_owned(self, session, l2p_id):
        with session.begin(subtransactions=True):
            owned = OwnedL2Policy(l2_policy_id=l2p_id)
            session.add(owned)

    def _l2_policy_is_owned(self, session, l2p_id):
        with session.begin(subtransactions=True):
            return (session.query(OwnedL2Policy).
                    filter_by(l2_policy_id=l2p_id).
                    first() is not None)

    def _mark_l3_policy_owned(self, session, l3p_id):
        with session.begin(subtransactions=True):
            owned = OwnedL3Policy(l3_policy_id=l3p_id)
            session.add(owned)

    def _l3_policy_is_owned(self, session, l3p_id):
        with session.begin(subtransactions=True):
            return (session.query(OwnedL3Policy).
                    filter_by(l3_policy_id=l3p_id).
                    first() is not None)
