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

from neutron._i18n import _LI
from neutron._i18n import _LW
from neutron.db import model_base
from oslo_config import cfg
from oslo_log import helpers as log
from oslo_log import log as logging
from oslo_utils import excutils
import sqlalchemy as sa

from gbpservice.network.neutronv2 import local_api
from gbpservice.neutron.extensions import driver_proxy_group as pg_ext
from gbpservice.neutron.extensions import group_policy as gbp_ext
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
               default=24,
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


class ImplicitPolicyBase(api.PolicyDriver, local_api.LocalAPI):

    @log.log_method_call
    def initialize(self):
        gpip = cfg.CONF.group_policy_implicit_policy
        gpconf = cfg.CONF.group_policy
        gpproxy = cfg.CONF.group_policy_proxy_group
        self._proxy_group_enabled = (pg_ext.PROXY_GROUP in
                                     gpconf.extension_drivers)
        self._default_l3p_name = gpip.default_l3_policy_name
        self._default_ip_version = gpip.default_ip_version
        self._default_ip_pool = gpip.default_ip_pool
        self._default_subnet_prefix_length = gpip.default_subnet_prefix_length
        self._default_proxy_ip_pool = gpproxy.default_proxy_ip_pool
        self._default_proxy_subnet_prefix_length = (
            gpproxy.default_proxy_subnet_prefix_length)
        self._default_es_name = gpip.default_external_segment_name

    def _create_implicit_l3_policy(self, context, clean_session=True):
        tenant_id = context.current['tenant_id']
        filter = {'tenant_id': [tenant_id],
                  'name': [self._default_l3p_name]}
        l3ps = self._get_l3_policies(context._plugin_context, filter,
                                     clean_session)
        l3p = l3ps and l3ps[0]
        if not l3p:
            attrs = {'tenant_id': tenant_id,
                     'name': self._default_l3p_name,
                     'description': _("Implicitly created L3 policy"),
                     'ip_version': self._default_ip_version,
                     'ip_pool': self._default_ip_pool,
                     'shared': context.current.get('shared', False),
                     'subnet_prefix_length':
                     self._default_subnet_prefix_length}
            if self._proxy_group_enabled:
                attrs['proxy_ip_pool'] = (
                    self._default_proxy_ip_pool)
                attrs['proxy_subnet_prefix_length'] = (
                    self._default_proxy_subnet_prefix_length)
            try:
                l3p = self._create_l3_policy(context._plugin_context, attrs,
                                             clean_session)
                self._mark_l3_policy_owned(context._plugin_context.session,
                                           l3p['id'])
            except exc.DefaultL3PolicyAlreadyExists:
                with excutils.save_and_reraise_exception(
                        reraise=False) as ctxt:
                    LOG.debug("Possible concurrent creation of default L3 "
                              "policy for tenant %s", tenant_id)
                    l3ps = self._get_l3_policies(context._plugin_context,
                                                 filter, clean_session)
                    l3p = l3ps and l3ps[0]
                    if not l3p:
                        LOG.warning(_LW(
                            "Caught DefaultL3PolicyAlreadyExists, "
                            "but default L3 policy not concurrently "
                            "created for tenant %s"), tenant_id)
                        ctxt.reraise = True
            except exc.OverlappingIPPoolsInSameTenantNotAllowed:
                with excutils.save_and_reraise_exception():
                    LOG.info(_LI("Caught "
                                 "OverlappingIPPoolsinSameTenantNotAllowed "
                                 "during creation of default L3 policy for "
                                 "tenant %s"), tenant_id)
        context.current['l3_policy_id'] = l3p['id']

    def _use_implicit_l3_policy(self, context):
        self._create_implicit_l3_policy(context)
        context.set_l3_policy_id(context.current['l3_policy_id'])

    def _create_implicit_l2_policy(self, context, clean_session=True):
        attrs = {'tenant_id': context.current['tenant_id'],
                 'name': context.current['name'],
                 'description': _("Implicitly created L2 policy"),
                 'l3_policy_id': None,
                 'shared': context.current.get('shared', False),
                 'network_id': None}
        if context.current.get('proxied_group_id'):
            # The L3P has to be the same as the proxied group
            group = context._plugin.get_policy_target_group(
                context._plugin_context, context.current['proxied_group_id'])
            l2p = context._plugin.get_l2_policy(
                context._plugin_context, group['l2_policy_id'])
            attrs['l3_policy_id'] = l2p['l3_policy_id']

        l2p = self._create_l2_policy(context._plugin_context, attrs,
                                     clean_session)
        context.current['l2_policy_id'] = l2p['id']
        self._mark_l2_policy_owned(context._plugin_context.session, l2p['id'])

    def _use_implicit_l2_policy(self, context):
        self._create_implicit_l2_policy(context)
        context.set_l2_policy_id(context.current['l2_policy_id'])

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

    def _cleanup_l3_policy(self, context, l3p_id, clean_session=True):
        if self._l3_policy_is_owned(context._plugin_context.session, l3p_id):
            # REVISIT(rkukura): Add check_unused parameter to
            # local_api._delete_l3_policy()?
            context._plugin.delete_l3_policy(context._plugin_context, l3p_id,
                                             check_unused=True)

    def _cleanup_l2_policy(self, context, l2p_id, clean_session=True):
        if self._l2_policy_is_owned(context._plugin_context.session, l2p_id):
            try:
                self._delete_l2_policy(context._plugin_context, l2p_id,
                                       clean_session)
            except gbp_ext.L2PolicyInUse:
                LOG.info(_LI(
                    "Cannot delete implicit L2 Policy %s because it's "
                    "in use."), l2p_id)


class ImplicitPolicyDriver(ImplicitPolicyBase):
    """Implicit Policy driver for Group Policy plugin.

    This driver ensures that the l2_policy_id attribute of
    PolicyTargetGroup references an L2Policy instance and that the
    l3_policy_id attribute of L2Policy references an L3Policy instance
    when the default value of None is specified.
    """

    @log.log_method_call
    def initialize(self):
        super(ImplicitPolicyDriver, self).initialize()

    @log.log_method_call
    def create_policy_target_group_postcommit(self, context):
        if not context.current['l2_policy_id']:
            self._use_implicit_l2_policy(context)

    @log.log_method_call
    def update_policy_target_group_postcommit(self, context):
        old_l2p_id = context.original['l2_policy_id']
        new_l2p_id = context.current['l2_policy_id']
        if old_l2p_id != new_l2p_id:
            self._cleanup_l2_policy(context, old_l2p_id)
            if not new_l2p_id:
                self._use_implicit_l2_policy(context)

    @log.log_method_call
    def delete_policy_target_group_postcommit(self, context):
        l2p_id = context.current['l2_policy_id']
        self._cleanup_l2_policy(context, l2p_id)

    @log.log_method_call
    def create_l2_policy_postcommit(self, context):
        if not context.current['l3_policy_id']:
            self._use_implicit_l3_policy(context)

    @log.log_method_call
    def update_l2_policy_postcommit(self, context):
        old_l3p_id = context.original['l3_policy_id']
        new_l3p_id = context.current['l3_policy_id']
        if old_l3p_id != new_l3p_id:
            self._cleanup_l3_policy(context, old_l3p_id)
            if not new_l3p_id:
                self._use_implicit_l3_policy(context)

    @log.log_method_call
    def delete_l2_policy_postcommit(self, context):
        l3p_id = context.current['l3_policy_id']
        self._cleanup_l3_policy(context, l3p_id)

    @log.log_method_call
    def create_external_segment_precommit(self, context):
        # REVISIT(ivar): find a better way to retrieve the default ES
        if self._default_es_name == context.current['name']:
            filters = {'name': [self._default_es_name]}
            ess = context._plugin.get_external_segments(
                context._plugin_context, filters)
            if [x for x in ess if x['id'] != context.current['id']]:
                raise exc.DefaultExternalSegmentAlreadyExists(
                    es_name=self._default_es_name)

    @log.log_method_call
    def create_external_policy_postcommit(self, context):
        if not context.current['external_segments']:
            self._use_implicit_external_segment(context)

    @log.log_method_call
    def update_external_policy_postcommit(self, context):
        pass

    @log.log_method_call
    def create_l3_policy_precommit(self, context):
        if self._default_l3p_name == context.current['name']:
            LOG.debug("Creating default L3 policy: %s", context.current)
            tenant_id = context.current['tenant_id']
            filter = {'tenant_id': [tenant_id],
                      'name': [self._default_l3p_name]}
            l3ps = context._plugin.get_l3_policies(context._plugin_context,
                                                   filter)
            if [x for x in l3ps if x['id'] != context.current['id']]:
                LOG.debug("Rejecting default L3 policy: %s", context.current)
                raise exc.DefaultL3PolicyAlreadyExists(
                    l3p_name=self._default_l3p_name)

    @log.log_method_call
    def create_l3_policy_postcommit(self, context):
        if not context.current['external_segments']:
            self._use_implicit_external_segment(context)

    @log.log_method_call
    def update_l3_policy_postcommit(self, context):
        pass

    def _use_implicit_external_segment(self, context):
        if not self._default_es_name:
            return

        filter = {'name': [self._default_es_name]}
        ess = self._get_external_segments(context._plugin_context, filter)
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
