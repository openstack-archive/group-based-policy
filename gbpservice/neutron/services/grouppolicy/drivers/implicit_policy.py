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

from gbpservice.neutron.services.grouppolicy import (
    group_policy_driver_api as api)
from gbpservice.neutron.services.grouppolicy.common import exceptions as exc


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
               default='10.0.0.0/8',
               help=_("IP pool for implicitly created default L3 policies, "
                      "from which subnets are allocated for policy target "
                      "groups.")),
    cfg.IntOpt('default_subnet_prefix_length',
               default=26,
               help=_("Subnet prefix length for implicitly created default L3 "
                      "polices, controlling size of subnets allocated for "
                      "policy target groups.")),

    cfg.StrOpt('default_external_segment_name',
               default='default',
               help=_("Name of default External Segment. This will be used "
                      "whenever a new EP/L3P is created without a referenced "
                      "External Segment. Set to None if a completely "
                      "explicit workflow is preferred.")),
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
    PolicyTargetGroup references an L2Policy instance and that the
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

        self._default_es_name = gpip.default_external_segment_name

    @log.log
    def create_policy_target_group_postcommit(self, context):
        if not context.current['l2_policy_id']:
            self._use_implicit_l2_policy(context)

    @log.log
    def update_policy_target_group_postcommit(self, context):
        old_l2p_id = context.original['l2_policy_id']
        new_l2p_id = context.current['l2_policy_id']
        if old_l2p_id != new_l2p_id:
            self._cleanup_l2_policy(context, old_l2p_id)
            if not new_l2p_id:
                self._use_implicit_l2_policy(context)

    @log.log
    def delete_policy_target_group_postcommit(self, context):
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

    @log.log
    def create_external_segment_precommit(self, context):
        # REVISIT(ivar): find a better way to retrieve the default ES
        if self._default_es_name == context.current['name']:
            filters = {'name': [self._default_es_name]}
            ess = context._plugin.get_external_segments(
                context._plugin_context, filters)
            if [x for x in ess if x['id'] != context.current['id']]:
                raise exc.DefaultExternalSegmentAlreadyExists(
                    es_name=self._default_es_name)

    @log.log
    def create_external_policy_postcommit(self, context):
        if not context.current['external_segments']:
            self._use_implicit_external_segment(context)

    @log.log
    def update_external_policy_postcommit(self, context):
        old_es_ids = set(context.original['external_segments'])
        new_es_ids = set(context.current['external_segments'])
        added = new_es_ids - old_es_ids
        if not added:
            self._use_implicit_external_segment(context)

    @log.log
    def create_l3_policy_postcommit(self, context):
        if not context.current['external_segments']:
            self._use_implicit_external_segment(context)

    @log.log
    def update_l3_policy_postcommit(self, context):
        old_es_ids = set(context.original['external_segments'].keys())
        new_es_ids = set(context.current['external_segments'].keys())
        added = new_es_ids - old_es_ids
        if not added:
            self._use_implicit_external_segment(context)

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
        context.set_l2_policy_id(l2p_id)

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
        context.set_l3_policy_id(l3p['id'])

    def _use_implicit_external_segment(self, context):
        if not self._default_es_name:
            return

        filter = {'name': [self._default_es_name]}
        ess = context._plugin.get_external_segments(context._plugin_context,
                                                    filter)
        # Multiple default ES may exist, this can happen when a per-tenant
        # default ES gets his shared attribute flipped. Always prefer the
        # specific tenant's ES if any.
        for es in ess:
            if es['tenant_id'] == context.current['tenant_id']:
                default = es
                break
        else:
            default = ess and ess[0]
        if default:
            # Set default ES
            context.set_external_segment(default['id'])

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
