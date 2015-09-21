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

import netaddr

from neutron.api.v2 import attributes as nattr
from neutron.common import log
from neutron import context as n_ctx
from neutron.extensions import portbindings
from neutron import manager as n_manager
from neutron.plugins.common import constants as pconst
from oslo_log import log as logging
from oslo_utils import excutils

from gbpservice.neutron.db.grouppolicy import group_policy_db as gpdb
from gbpservice.neutron.db.grouppolicy import group_policy_mapping_db
from gbpservice.neutron.extensions import group_policy as gpex
from gbpservice.neutron.services.grouppolicy import (
    extension_manager as ext_manager)
from gbpservice.neutron.services.grouppolicy import (
    group_policy_context as p_context)
from gbpservice.neutron.services.grouppolicy import (
    policy_driver_manager as manager)
from gbpservice.neutron.services.grouppolicy.common import constants as gp_cts
from gbpservice.neutron.services.grouppolicy.common import exceptions as gp_exc
from gbpservice.neutron.services.servicechain.plugins.ncp import (
    model as ncp_model)


LOG = logging.getLogger(__name__)


class GroupPolicyPlugin(group_policy_mapping_db.GroupPolicyMappingDbPlugin):

    """Implementation of the Group Policy Model Plugin.

    This class manages the workflow of Group Policy request/response.
    Most DB related works are implemented in class
    db_group_policy_mapping.GroupPolicyMappingDbMixin.
    """
    _supported_extension_aliases = ["group-policy", "group-policy-mapping"]

    @property
    def supported_extension_aliases(self):
        if not hasattr(self, '_aliases'):
            aliases = self._supported_extension_aliases[:]
            aliases += self.extension_manager.extension_aliases()
            self._aliases = aliases
        return self._aliases

    @property
    def servicechain_plugin(self):
        # REVISIT(rkukura): Need initialization method after all
        # plugins are loaded to grab and store plugin.
        plugins = n_manager.NeutronManager.get_service_plugins()
        servicechain_plugin = plugins.get(pconst.SERVICECHAIN)
        if not servicechain_plugin:
            LOG.error(_("No Servicechain service plugin found."))
            raise gp_exc.GroupPolicyDeploymentError()
        return servicechain_plugin

    # Shared attribute validation rules:
    # - A shared resource cannot use/link a non-shared resource
    # - A shared resource cannot be reverted to non-shared if used/linked by
    # other shared resources, or by any resource owned by any other tenant

    # In the usage graph, specify which resource has to be checked to validate
    # sharing policy conformity:
    # usage_graph = {<to_check>: {<attribute>: <type>}, ...}
    # <attribute> is the field on the <to_check> dictionary that can be used
    # to retrieve the UUID/s of the specific object <type>

    usage_graph = {'l3_policy': {'external_segments':
                                 'external_segment'},
                   'l2_policy': {'l3_policy_id': 'l3_policy'},
                   'policy_target_group': {
                       'network_service_policy_id': 'network_service_policy',
                       'l2_policy_id': 'l2_policy',
                       'provided_policy_rule_sets': 'policy_rule_set',
                       'consumed_policy_rule_sets': 'policy_rule_set'},
                   'network_service_policy': {},
                   'policy_rule': {
                       'policy_classifier_id': 'policy_classifier',
                       'policy_actions': 'policy_action'},
                   'policy_action': {},
                   'policy_classifier': {},
                   'policy_rule_set': {
                       'parent_id': 'policy_rule_set',
                       'policy_rules': 'policy_rule'},
                   'external_segment': {},
                   'external_policy': {
                       'external_segments': 'external_segment',
                       'provided_policy_rule_sets': 'policy_rule_set',
                       'consumed_policy_rule_sets': 'policy_rule_set'},
                   'nat_pool': {'external_segment_id':
                                'external_segment'},
                   'policy_target': {'policy_target_group_id':
                                     'policy_target_group'}
                   }
    _plurals = None

    @property
    def plurals(self):
        if not self._plurals:
            self._plurals = dict((nattr.PLURALS[k], k) for k in nattr.PLURALS)
        return self._plurals

    @staticmethod
    def _validate_shared_create(self, context, obj, identity):
        # REVISIT(ivar): only validate new references
        links = self.usage_graph.get(identity, {})
        for attr in links:
            ids = obj[attr]
            if ids:
                if isinstance(ids, basestring):
                    ids = [ids]
                ref_type = links[attr]
                linked_objects = getattr(
                    self, 'get_%s' % self.plurals[ref_type])(
                        context, filters={'id': ids})
                link_ids = set()
                for linked in linked_objects:
                    link_ids.add(linked['id'])
                    GroupPolicyPlugin._verify_sharing_consistency(
                        obj, linked, identity, ref_type)
                # Check for missing references
                missing = set(ids) - link_ids
                if missing:
                    raise gpex.GbpResourceNotFound(identity=ref_type,
                                                   id=str(missing))

    @staticmethod
    def _validate_shared_update(self, context, original, updated, identity):
        # Need admin context to check sharing constraints

        # Even though the shared attribute may not be changed, the objects
        # it is referring to might. For this reson we run the reference
        # validation every time a shared resource is updated
        # TODO(ivar): run only when relevant updates happen
        self._validate_shared_create(self, context, updated, identity)
        if updated.get('shared') != original.get('shared'):
            context = context.elevated()
            getattr(self, '_validate_%s_unshare' % identity)(context, updated)

    @staticmethod
    def _check_shared_or_different_tenant(context, obj, method, attr,
                                          value=None):
        tenant_id = obj['tenant_id']
        refs = method(context, filters={attr: value or [obj['id']]})
        for ref in refs:
            if ref.get('shared') or tenant_id != ref['tenant_id']:
                raise gp_exc.InvalidSharedAttributeUpdate(id=obj['id'],
                                                          rid=ref['id'])

    def _validate_l3_policy_unshare(self, context, obj):
        self._check_shared_or_different_tenant(
            context, obj, self.get_l2_policies, 'l3_policy_id')

    def _validate_l2_policy_unshare(self, context, obj):
        self._check_shared_or_different_tenant(
            context, obj, self.get_policy_target_groups, 'l2_policy_id')

    def _validate_policy_target_group_unshare(self, context, obj):
        self._check_shared_or_different_tenant(
            context, obj, self.get_policy_targets, 'policy_target_group_id')

    def _validate_network_service_policy_unshare(self, context, obj):
        self._check_shared_or_different_tenant(
            context, obj, self.get_policy_target_groups,
            'network_service_policy_id')

    def _validate_policy_rule_set_unshare(self, context, obj):
        self._check_shared_or_different_tenant(
            context, obj, self.get_policy_target_groups, 'id',
            obj['providing_policy_target_groups'] +
            obj['consuming_policy_target_groups'])
        self._check_shared_or_different_tenant(
            context, obj, self.get_external_policies, 'id',
            obj['providing_external_policies'] +
            obj['consuming_external_policies'])

    def _validate_policy_classifier_unshare(self, context, obj):
        self._check_shared_or_different_tenant(
            context, obj, self.get_policy_rules, 'policy_classifier_id')

    def _validate_policy_rule_unshare(self, context, obj):
        c_ids = self._get_policy_rule_policy_rule_sets(context, obj['id'])
        self._check_shared_or_different_tenant(
            context, obj, self.get_policy_rule_sets, 'id', c_ids)

    def _validate_policy_action_unshare(self, context, obj):
        r_ids = self._get_policy_action_rules(context, obj['id'])
        self._check_shared_or_different_tenant(
            context, obj, self.get_policy_rules, 'id', r_ids)

    def _validate_external_segment_unshare(self, context, obj):
        self._check_shared_or_different_tenant(
            context, obj, self.get_l3_policies, 'id', obj['l3_policies'])
        self._check_shared_or_different_tenant(
            context, obj, self.get_external_policies, 'id',
            obj['external_policies'])
        self._check_shared_or_different_tenant(
            context, obj, self.get_nat_pools, 'external_segment_id')

    def _validate_external_policy_unshare(self, context, obj):
        pass

    def _validate_nat_pool_unshare(self, context, obj):
        pass

    def _validate_routes(self, context, current, original=None):
        if original:
            added = (set((x['destination'], x['nexthop']) for x in
                         current['external_routes']) -
                     set((x['destination'], x['nexthop']) for x in
                         original['external_routes']))
        else:
            added = set((x['destination'], x['nexthop']) for x in
                        current['external_routes'])
        if added:
            # Verify new ones don't overlap with the existing L3P
            added_dest = set(x[0] for x in added)
            # Remove default routes
            added_dest.discard('0.0.0.0/0')
            added_dest.discard('::/0')
            added_ipset = netaddr.IPSet(added_dest)
            if current['l3_policies']:
                l3ps = self.get_l3_policies(
                    context, filters={'id': current['l3_policies']})
                for l3p in l3ps:
                    if netaddr.IPSet([l3p['ip_pool']]) & added_ipset:
                        raise gp_exc.ExternalRouteOverlapsWithL3PIpPool(
                            destination=added_dest, l3p_id=l3p['id'],
                            es_id=current['id'])
            # Verify NH in ES pool
            added_nexthop = netaddr.IPSet(x[1] for x in added if x[1])
            es_subnet = netaddr.IPSet([current['cidr']])
            if added_nexthop & es_subnet != added_nexthop:
                raise gp_exc.ExternalRouteNextHopNotInExternalSegment(
                    cidr=current['cidr'])

    def _validate_l3p_es(self, context, current, original=None):
        if original:
            added = (set(current['external_segments'].keys()) -
                     set(original['external_segments'].keys()))
        else:
            added = set(current['external_segments'].keys())
        if added:
            es_list = self.get_external_segments(context,
                                                 filters={'id': added})
            l3p_ipset = netaddr.IPSet([current['ip_pool']])
            for es in es_list:
                # Verify no route overlap
                dest_set = set(x['destination'] for x in
                               es['external_routes'])
                dest_set.discard('0.0.0.0/0')
                dest_set.discard('::/0')
                if l3p_ipset & netaddr.IPSet(dest_set):
                    raise gp_exc.ExternalRouteOverlapsWithL3PIpPool(
                        destination=dest_set, l3p_id=current['id'],
                        es_id=es['id'])
                # Verify segment CIDR doesn't overlap with L3P's
                if l3p_ipset & netaddr.IPSet([es['cidr']]):
                    raise gp_exc.ExternalSegmentSubnetOverlapsWithL3PIpPool(
                        subnet=es['cidr'], l3p_id=current['id'],
                        es_id=current['id'])
                # Verify allocated address correctly in subnet
                for addr in current['external_segments'][es['id']]:
                    if addr != gpdb.ADDRESS_NOT_SPECIFIED:
                        if addr not in netaddr.IPNetwork(es['cidr']):
                            raise gp_exc.InvalidL3PExternalIPAddress(
                                ip=addr, es_id=es['id'], l3p_id=current['id'],
                                es_cidr=es['cidr'])

    def _validate_action_value(self, context, action):
        if action.get('action_type') == gp_cts.GP_ACTION_REDIRECT:
            if action.get('action_value'):
                # Verify sc spec existence and visibility
                spec = self.servicechain_plugin.get_servicechain_spec(
                    context, action['action_value'])
                GroupPolicyPlugin._verify_sharing_consistency(
                    action, spec, 'polocy_action', 'servicechain_spec')

    @staticmethod
    def _verify_sharing_consistency(primary, reference, primary_type,
                                    reference_type):
        if not reference.get('shared'):
            if primary.get('shared'):
                raise gp_exc.SharedResourceReferenceError(
                    res_type=primary_type, res_id=primary['id'],
                    ref_type=reference_type, ref_id=reference['id'])
            if primary.get('tenant_id') != reference.get('tenant_id'):
                raise gp_exc.InvalidCrossTenantReference(
                    res_type=primary_type, res_id=primary['id'],
                    ref_type=reference_type, ref_id=reference['id'])

    def __init__(self):
        self.extension_manager = ext_manager.ExtensionManager()
        self.policy_driver_manager = manager.PolicyDriverManager()
        super(GroupPolicyPlugin, self).__init__()
        self.extension_manager.initialize()
        self.policy_driver_manager.initialize()

    def _notify_sc_plugin_pt_added(self, context, policy_target):
        if self.servicechain_plugin:
            self.servicechain_plugin.update_chains_pt_added(context,
                                                            policy_target)

    def _notify_sc_plugin_pt_removed(self, context, policy_target):
        if self.servicechain_plugin:
            self.servicechain_plugin.update_chains_pt_removed(context,
                                                              policy_target)

    @log.log
    def create_policy_target(self, context, policy_target, notify_sc=True):
        session = context.session
        with session.begin(subtransactions=True):
            result = super(GroupPolicyPlugin,
                           self).create_policy_target(context, policy_target)
            self.extension_manager.process_create_policy_target(
                session, policy_target, result)
            self._validate_shared_create(
                self, context, result, 'policy_target')
            policy_context = p_context.PolicyTargetContext(self, context,
                                                           result)
            self.policy_driver_manager.create_policy_target_precommit(
                policy_context)

        try:
            self.policy_driver_manager.create_policy_target_postcommit(
                policy_context)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.error(_("create_policy_target_postcommit "
                            "failed, deleting policy_target %s"),
                          result['id'])
                self.delete_policy_target(context, result['id'])

        # REVISIT(ivar): For now just raise the exception if something goes
        # wrong. This will eventually be managed in an asynchronous way.
        if notify_sc:
            self._notify_sc_plugin_pt_added(context, result)

        return result

    @log.log
    def update_policy_target(self, context, policy_target_id, policy_target):
        session = context.session
        with session.begin(subtransactions=True):
            original_policy_target = self.get_policy_target(context,
                                                            policy_target_id)
            updated_policy_target = super(
                GroupPolicyPlugin, self).update_policy_target(
                    context, policy_target_id, policy_target)
            self.extension_manager.process_update_policy_target(
                session, policy_target, updated_policy_target)
            self._validate_shared_update(self, context, original_policy_target,
                                         updated_policy_target,
                                         'policy_target')
            policy_context = p_context.PolicyTargetContext(
                self, context, updated_policy_target,
                original_policy_target=original_policy_target)
            self.policy_driver_manager.update_policy_target_precommit(
                policy_context)

        self.policy_driver_manager.update_policy_target_postcommit(
            policy_context)
        return updated_policy_target

    @log.log
    def delete_policy_target(self, context, policy_target_id,
                             notify_sc=True):
        session = context.session
        with session.begin(subtransactions=True):
            policy_target = self.get_policy_target(context, policy_target_id)
            policy_context = p_context.PolicyTargetContext(
                self, context, policy_target)
            self.policy_driver_manager.delete_policy_target_precommit(
                policy_context)
            super(GroupPolicyPlugin, self).delete_policy_target(
                context, policy_target_id)

        if notify_sc:
            # REVISIT(ivar): For now just raise the exception if something goes
            # wrong. This will eventually be managed in an asynchronous way.
            self._notify_sc_plugin_pt_removed(
                context, policy_target)

        try:
            self.policy_driver_manager.delete_policy_target_postcommit(
                policy_context)
        except Exception:
            LOG.exception(_("delete_policy_target_postcommit failed "
                            "for policy_target %s"),
                          policy_target_id)

    def get_policy_target(self, context, policy_target_id, fields=None):
        session = context.session
        with session.begin(subtransactions=True):
            result = super(GroupPolicyPlugin, self).get_policy_target(
                context, policy_target_id, None)
            self.extension_manager.extend_policy_target_dict(session, result)
        return self._fields(result, fields)

    def get_policy_targets(self, context, filters=None, fields=None,
                           sorts=None, limit=None, marker=None,
                           page_reverse=False):
        session = context.session
        with session.begin(subtransactions=True):
            results = super(GroupPolicyPlugin, self).get_policy_targets(
                context, filters, None, sorts, limit, marker, page_reverse)
            for result in results:
                self.extension_manager.extend_policy_target_dict(
                    session, result)
        return [self._fields(result, fields) for result in results]

    @log.log
    def create_policy_target_group(self, context, policy_target_group):
        session = context.session
        with session.begin(subtransactions=True):
            result = super(GroupPolicyPlugin,
                           self).create_policy_target_group(
                               context, policy_target_group)
            self.extension_manager.process_create_policy_target_group(
                session, policy_target_group, result)
            self._validate_shared_create(self, context, result,
                                         'policy_target_group')
            policy_context = p_context.PolicyTargetGroupContext(
                self, context, result)
            self.policy_driver_manager.create_policy_target_group_precommit(
                policy_context)

        try:
            self.policy_driver_manager.create_policy_target_group_postcommit(
                policy_context)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.error(_("create_policy_target_group_postcommit "
                            "failed, deleting policy_target_group %s"),
                          result['id'])
                self.delete_policy_target_group(context, result['id'])

        return result

    @log.log
    def update_policy_target_group(self, context, policy_target_group_id,
                                   policy_target_group):
        session = context.session
        with session.begin(subtransactions=True):
            original_policy_target_group = self.get_policy_target_group(
                    context, policy_target_group_id)
            updated_policy_target_group = super(
                GroupPolicyPlugin, self).update_policy_target_group(
                    context, policy_target_group_id, policy_target_group)
            self.extension_manager.process_update_policy_target_group(
                session, policy_target_group, updated_policy_target_group)
            self._validate_shared_update(
                self, context, original_policy_target_group,
                updated_policy_target_group, 'policy_target_group')
            policy_context = p_context.PolicyTargetGroupContext(
                self, context, updated_policy_target_group,
                original_policy_target_group=original_policy_target_group)
            self.policy_driver_manager.update_policy_target_group_precommit(
                policy_context)

        self.policy_driver_manager.update_policy_target_group_postcommit(
            policy_context)

        return updated_policy_target_group

    @log.log
    def delete_policy_target_group(self, context, policy_target_group_id):
        session = context.session
        with session.begin(subtransactions=True):
            policy_target_group = self.get_policy_target_group(
                context, policy_target_group_id)
            pt_ids = policy_target_group['policy_targets']
            for pt in self.get_policy_targets(context, {'id': pt_ids}):
                if pt['port_id'] and self._is_port_bound(pt['port_id']) or (
                        self._is_service_target(context, pt['id'])):
                    raise gp_exc.PolicyTargetGroupInUse(
                        policy_target_group=policy_target_group_id)
            policy_context = p_context.PolicyTargetGroupContext(
                self, context, policy_target_group)
            self.policy_driver_manager.delete_policy_target_group_precommit(
                policy_context)

        # Disassociate all the PRSs first, this will trigger service chains
        # deletion.
        self.update_policy_target_group(
            context, policy_target_group_id,
            {'policy_target_group': {'provided_policy_rule_sets': {},
                                     'consumed_policy_rule_sets': {}}})

        with session.begin(subtransactions=True):
            for pt_id in pt_ids:
                # We will allow PTG deletion if all PTs are unused.
                # We could have cleaned these opportunistically in
                # the previous loop, but we will keep it simple,
                # such that either all unused PTs are deleted
                # or nothing is.
                self.delete_policy_target(context, pt_id)
            super(GroupPolicyPlugin, self).delete_policy_target_group(
                context, policy_target_group_id)

        try:
            self.policy_driver_manager.delete_policy_target_group_postcommit(
                policy_context)
        except Exception:
            LOG.exception(_("delete_policy_target_group_postcommit failed "
                            "for policy_target_group %s"),
                          policy_target_group_id)

    def get_policy_target_group(self, context, policy_target_group_id,
                                fields=None):
        session = context.session
        with session.begin(subtransactions=True):
            result = super(GroupPolicyPlugin, self).get_policy_target_group(
                context, policy_target_group_id, None)
            self.extension_manager.extend_policy_target_group_dict(session,
                                                                   result)
        return self._fields(result, fields)

    def get_policy_target_groups(self, context, filters=None, fields=None,
                                 sorts=None, limit=None, marker=None,
                                 page_reverse=False):
        session = context.session
        with session.begin(subtransactions=True):
            results = super(GroupPolicyPlugin, self).get_policy_target_groups(
                context, filters, None, sorts, limit, marker, page_reverse)
            for result in results:
                self.extension_manager.extend_policy_target_group_dict(
                    session, result)
        return [self._fields(result, fields) for result in results]

    @log.log
    def create_l2_policy(self, context, l2_policy):
        session = context.session
        with session.begin(subtransactions=True):
            result = super(GroupPolicyPlugin,
                           self).create_l2_policy(context, l2_policy)
            self.extension_manager.process_create_l2_policy(
                session, l2_policy, result)
            self._validate_shared_create(self, context, result, 'l2_policy')
            policy_context = p_context.L2PolicyContext(self, context, result)
            self.policy_driver_manager.create_l2_policy_precommit(
                policy_context)

        try:
            self.policy_driver_manager.create_l2_policy_postcommit(
                policy_context)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.error(_("create_l2_policy_postcommit "
                            "failed, deleting l2_policy %s"), result['id'])
                self.delete_l2_policy(context, result['id'])

        return result

    @log.log
    def update_l2_policy(self, context, l2_policy_id, l2_policy):
        session = context.session
        with session.begin(subtransactions=True):
            original_l2_policy = self.get_l2_policy(context, l2_policy_id)
            updated_l2_policy = super(GroupPolicyPlugin,
                                      self).update_l2_policy(
                                          context, l2_policy_id, l2_policy)
            self.extension_manager.process_update_l2_policy(
                session, l2_policy, updated_l2_policy)
            self._validate_shared_update(self, context, original_l2_policy,
                                         updated_l2_policy, 'l2_policy')
            policy_context = p_context.L2PolicyContext(
                self, context, updated_l2_policy,
                original_l2_policy=original_l2_policy)
            self.policy_driver_manager.update_l2_policy_precommit(
                policy_context)

        self.policy_driver_manager.update_l2_policy_postcommit(
            policy_context)
        return updated_l2_policy

    @log.log
    def delete_l2_policy(self, context, l2_policy_id):
        session = context.session
        with session.begin(subtransactions=True):
            l2_policy = self.get_l2_policy(context, l2_policy_id)
            policy_context = p_context.L2PolicyContext(self, context,
                                                       l2_policy)
            self.policy_driver_manager.delete_l2_policy_precommit(
                policy_context)
            super(GroupPolicyPlugin, self).delete_l2_policy(context,
                                                            l2_policy_id)

        try:
            self.policy_driver_manager.delete_l2_policy_postcommit(
                policy_context)
        except Exception:
            LOG.exception(_("delete_l2_policy_postcommit failed "
                            "for l2_policy %s"),
                          l2_policy_id)

    def get_l2_policy(self, context, l2_policy_id, fields=None):
        session = context.session
        with session.begin(subtransactions=True):
            result = super(GroupPolicyPlugin, self).get_l2_policy(
                context, l2_policy_id, None)
            self.extension_manager.extend_l2_policy_dict(session, result)
        return self._fields(result, fields)

    def get_l2_policies(self, context, filters=None, fields=None,
                        sorts=None, limit=None, marker=None,
                        page_reverse=False):
        session = context.session
        with session.begin(subtransactions=True):
            results = super(GroupPolicyPlugin, self).get_l2_policies(
                context, filters, None, sorts, limit, marker, page_reverse)
            for result in results:
                self.extension_manager.extend_l2_policy_dict(
                    session, result)
        return [self._fields(result, fields) for result in results]

    @log.log
    def create_network_service_policy(self, context, network_service_policy):
        session = context.session
        with session.begin(subtransactions=True):
            result = super(GroupPolicyPlugin,
                           self).create_network_service_policy(
                               context, network_service_policy)
            self.extension_manager.process_create_network_service_policy(
                session, network_service_policy, result)
            self._validate_shared_create(self, context, result,
                                         'network_service_policy')
            policy_context = p_context.NetworkServicePolicyContext(
                self, context, result)
            pdm = self.policy_driver_manager
            pdm.create_network_service_policy_precommit(
                policy_context)

        try:
            pdm.create_network_service_policy_postcommit(
                policy_context)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.error(_("create_network_service_policy_postcommit "
                            "failed, deleting network_service_policy %s"),
                          result['id'])
                self.delete_network_service_policy(context, result['id'])

        return result

    @log.log
    def update_network_service_policy(self, context, network_service_policy_id,
                                      network_service_policy):
        session = context.session
        with session.begin(subtransactions=True):
            original_network_service_policy = super(
                GroupPolicyPlugin, self).get_network_service_policy(
                    context, network_service_policy_id)
            updated_network_service_policy = super(
                GroupPolicyPlugin, self).update_network_service_policy(
                    context, network_service_policy_id, network_service_policy)
            self.extension_manager.process_update_network_service_policy(
                session, network_service_policy,
                updated_network_service_policy)
            self._validate_shared_update(
                self, context, original_network_service_policy,
                updated_network_service_policy, 'network_service_policy')
            policy_context = p_context.NetworkServicePolicyContext(
                self, context, updated_network_service_policy,
                original_network_service_policy=
                original_network_service_policy)
            self.policy_driver_manager.update_network_service_policy_precommit(
                policy_context)

        self.policy_driver_manager.update_network_service_policy_postcommit(
            policy_context)
        return updated_network_service_policy

    @log.log
    def delete_network_service_policy(
        self, context, network_service_policy_id):
        session = context.session
        with session.begin(subtransactions=True):
            network_service_policy = self.get_network_service_policy(
                context, network_service_policy_id)
            policy_context = p_context.NetworkServicePolicyContext(
                self, context, network_service_policy)
            self.policy_driver_manager.delete_network_service_policy_precommit(
                policy_context)
            super(GroupPolicyPlugin, self).delete_network_service_policy(
                context, network_service_policy_id)

        try:
            pdm = self.policy_driver_manager
            pdm.delete_network_service_policy_postcommit(policy_context)
        except Exception:
            LOG.exception(_("delete_network_service_policy_postcommit failed "
                            "for network_service_policy %s"),
                          network_service_policy_id)

    def get_network_service_policy(self, context, network_service_policy_id,
                                   fields=None):
        session = context.session
        with session.begin(subtransactions=True):
            result = super(GroupPolicyPlugin, self).get_network_service_policy(
                context, network_service_policy_id, None)
            self.extension_manager.extend_network_service_policy_dict(session,
                                                                      result)
        return self._fields(result, fields)

    def get_network_service_policies(self, context, filters=None, fields=None,
                                     sorts=None, limit=None, marker=None,
                                     page_reverse=False):
        session = context.session
        with session.begin(subtransactions=True):
            results = super(GroupPolicyPlugin,
                            self).get_network_service_policies(
                context, filters, None, sorts, limit, marker, page_reverse)
            for result in results:
                self.extension_manager.extend_network_service_policy_dict(
                    session, result)
        return [self._fields(result, fields) for result in results]

    @log.log
    def create_l3_policy(self, context, l3_policy):
        session = context.session
        with session.begin(subtransactions=True):
            result = super(GroupPolicyPlugin,
                           self).create_l3_policy(context, l3_policy)
            self.extension_manager.process_create_l3_policy(
                session, l3_policy, result)
            self._validate_shared_create(self, context, result, 'l3_policy')
            self._validate_l3p_es(context, result)
            policy_context = p_context.L3PolicyContext(self, context,
                                                       result)
            self.policy_driver_manager.create_l3_policy_precommit(
                policy_context)

        try:
            self.policy_driver_manager.create_l3_policy_postcommit(
                policy_context)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.error(_("create_l3_policy_postcommit "
                            "failed, deleting l3_policy %s"), result['id'])
                self.delete_l3_policy(context, result['id'])

        return result

    @log.log
    def update_l3_policy(self, context, l3_policy_id, l3_policy):
        session = context.session
        with session.begin(subtransactions=True):
            original_l3_policy = self.get_l3_policy(context, l3_policy_id)
            updated_l3_policy = super(
                GroupPolicyPlugin, self).update_l3_policy(
                    context, l3_policy_id, l3_policy)
            self.extension_manager.process_update_l3_policy(
                session, l3_policy, updated_l3_policy)
            self._validate_shared_update(self, context, original_l3_policy,
                                         updated_l3_policy, 'l3_policy')
            self._validate_l3p_es(context, updated_l3_policy,
                                  original_l3_policy)
            policy_context = p_context.L3PolicyContext(
                self, context, updated_l3_policy,
                original_l3_policy=original_l3_policy)
            self.policy_driver_manager.update_l3_policy_precommit(
                policy_context)

        self.policy_driver_manager.update_l3_policy_postcommit(
            policy_context)
        return updated_l3_policy

    @log.log
    def delete_l3_policy(self, context, l3_policy_id, check_unused=False):
        session = context.session
        with session.begin(subtransactions=True):
            if (check_unused and
                (session.query(group_policy_mapping_db.L2PolicyMapping).
                 filter_by(l3_policy_id=l3_policy_id).count())):
                return False
            l3_policy = self.get_l3_policy(context, l3_policy_id)
            policy_context = p_context.L3PolicyContext(self, context,
                                                       l3_policy)
            self.policy_driver_manager.delete_l3_policy_precommit(
                policy_context)
            super(GroupPolicyPlugin, self).delete_l3_policy(context,
                                                            l3_policy_id)

        try:
            self.policy_driver_manager.delete_l3_policy_postcommit(
                policy_context)
        except Exception:
            LOG.exception(_("delete_l3_policy_postcommit failed "
                            "for l3_policy %s"),
                          l3_policy_id)
        return True

    def get_l3_policy(self, context, l3_policy_id, fields=None):
        session = context.session
        with session.begin(subtransactions=True):
            result = super(GroupPolicyPlugin, self).get_l3_policy(
                context, l3_policy_id, None)
            self.extension_manager.extend_l3_policy_dict(session, result)
        return self._fields(result, fields)

    def get_l3_policies(self, context, filters=None, fields=None,
                        sorts=None, limit=None, marker=None,
                        page_reverse=False):
        session = context.session
        with session.begin(subtransactions=True):
            results = super(GroupPolicyPlugin, self).get_l3_policies(
                context, filters, None, sorts, limit, marker, page_reverse)
            for result in results:
                self.extension_manager.extend_l3_policy_dict(
                    session, result)
        return [self._fields(result, fields) for result in results]

    @log.log
    def create_policy_classifier(self, context, policy_classifier):
        session = context.session
        with session.begin(subtransactions=True):
            result = super(
                GroupPolicyPlugin, self).create_policy_classifier(
                    context, policy_classifier)
            self.extension_manager.process_create_policy_classifier(
                session, policy_classifier, result)
            self._validate_shared_create(
                self, context, result, 'policy_classifier')
            policy_context = p_context.PolicyClassifierContext(self, context,
                                                               result)
            self.policy_driver_manager.create_policy_classifier_precommit(
                policy_context)

        try:
            self.policy_driver_manager.create_policy_classifier_postcommit(
                policy_context)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.error(_(
                    "policy_driver_manager.create_policy_classifier_postcommit"
                    " failed, deleting policy_classifier %s"), result['id'])
                self.delete_policy_classifier(context, result['id'])

        return result

    @log.log
    def update_policy_classifier(self, context, id, policy_classifier):
        session = context.session
        with session.begin(subtransactions=True):
            original_policy_classifier = super(
                GroupPolicyPlugin, self).get_policy_classifier(context, id)
            updated_policy_classifier = super(
                GroupPolicyPlugin, self).update_policy_classifier(
                    context, id, policy_classifier)
            self.extension_manager.process_update_policy_classifier(
                session, policy_classifier, updated_policy_classifier)
            self._validate_shared_update(
                self, context, original_policy_classifier,
                updated_policy_classifier, 'policy_classifier')
            policy_context = p_context.PolicyClassifierContext(
                self, context, updated_policy_classifier,
                original_policy_classifier=original_policy_classifier)
            self.policy_driver_manager.update_policy_classifier_precommit(
                policy_context)

        self.policy_driver_manager.update_policy_classifier_postcommit(
            policy_context)
        return updated_policy_classifier

    @log.log
    def delete_policy_classifier(self, context, id):
        session = context.session
        with session.begin(subtransactions=True):
            policy_classifier = self.get_policy_classifier(context, id)
            policy_context = p_context.PolicyClassifierContext(
                self, context, policy_classifier)
            self.policy_driver_manager.delete_policy_classifier_precommit(
                policy_context)
            super(GroupPolicyPlugin, self).delete_policy_classifier(
                context, id)

        try:
            self.policy_driver_manager.delete_policy_classifier_postcommit(
                policy_context)
        except Exception:
            LOG.exception(_("delete_policy_classifier_postcommit failed "
                            "for policy_classifier %s"),
                          id)

    def get_policy_classifier(self, context, policy_classifier_id,
                              fields=None):
        session = context.session
        with session.begin(subtransactions=True):
            result = super(GroupPolicyPlugin, self).get_policy_classifier(
                context, policy_classifier_id, None)
            self.extension_manager.extend_policy_classifier_dict(session,
                                                                 result)
        return self._fields(result, fields)

    def get_policy_classifiers(self, context, filters=None, fields=None,
                               sorts=None, limit=None, marker=None,
                               page_reverse=False):
        session = context.session
        with session.begin(subtransactions=True):
            results = super(GroupPolicyPlugin, self).get_policy_classifiers(
                context, filters, None, sorts, limit, marker, page_reverse)
            for result in results:
                self.extension_manager.extend_policy_classifier_dict(
                    session, result)
        return [self._fields(result, fields) for result in results]

    @log.log
    def create_policy_action(self, context, policy_action):
        session = context.session
        with session.begin(subtransactions=True):
            result = super(GroupPolicyPlugin,
                           self).create_policy_action(context, policy_action)
            self.extension_manager.process_create_policy_action(
                session, policy_action, result)
            self._validate_shared_create(self, context, result,
                                         'policy_action')
            self._validate_action_value(context, result)
            policy_context = p_context.PolicyActionContext(self, context,
                                                           result)
            self.policy_driver_manager.create_policy_action_precommit(
                policy_context)

        try:
            self.policy_driver_manager.create_policy_action_postcommit(
                policy_context)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.error(_(
                    "policy_driver_manager.create_policy_action_postcommit "
                    "failed, deleting policy_action %s"), result['id'])
                self.delete_policy_action(context, result['id'])

        return result

    @log.log
    def update_policy_action(self, context, id, policy_action):
        session = context.session
        with session.begin(subtransactions=True):
            original_policy_action = super(
                GroupPolicyPlugin, self).get_policy_action(context, id)
            updated_policy_action = super(
                GroupPolicyPlugin, self).update_policy_action(context, id,
                                                              policy_action)
            self.extension_manager.process_update_policy_action(
                session, policy_action, updated_policy_action)
            self._validate_shared_update(self, context, original_policy_action,
                                         updated_policy_action,
                                         'policy_action')
            self._validate_action_value(context, updated_policy_action)
            policy_context = p_context.PolicyActionContext(
                self, context, updated_policy_action,
                original_policy_action=original_policy_action)
            self.policy_driver_manager.update_policy_action_precommit(
                policy_context)

        self.policy_driver_manager.update_policy_action_postcommit(
            policy_context)
        return updated_policy_action

    @log.log
    def delete_policy_action(self, context, id):
        session = context.session
        with session.begin(subtransactions=True):
            policy_action = self.get_policy_action(context, id)
            policy_context = p_context.PolicyActionContext(self, context,
                                                           policy_action)
            self.policy_driver_manager.delete_policy_action_precommit(
                policy_context)
            super(GroupPolicyPlugin, self).delete_policy_action(context, id)

        try:
            self.policy_driver_manager.delete_policy_action_postcommit(
                policy_context)
        except Exception:
            LOG.exception(_("delete_policy_action_postcommit failed "
                            "for policy_action %s"),
                          id)

    def get_policy_action(self, context, policy_action_id, fields=None):
        session = context.session
        with session.begin(subtransactions=True):
            result = super(GroupPolicyPlugin, self).get_policy_action(
                context, policy_action_id, None)
            self.extension_manager.extend_policy_action_dict(session, result)
        return self._fields(result, fields)

    def get_policy_actions(self, context, filters=None, fields=None,
                           sorts=None, limit=None, marker=None,
                           page_reverse=False):
        session = context.session
        with session.begin(subtransactions=True):
            results = super(GroupPolicyPlugin, self).get_policy_actions(
                context, filters, None, sorts, limit, marker, page_reverse)
            for result in results:
                self.extension_manager.extend_policy_action_dict(
                    session, result)
        return [self._fields(result, fields) for result in results]

    @log.log
    def create_policy_rule(self, context, policy_rule):
        session = context.session
        with session.begin(subtransactions=True):
            result = super(
                GroupPolicyPlugin, self).create_policy_rule(
                    context, policy_rule)
            self.extension_manager.process_create_policy_rule(
                session, policy_rule, result)
            self._validate_shared_create(self, context, result, 'policy_rule')
            policy_context = p_context.PolicyRuleContext(self, context,
                                                         result)
            self.policy_driver_manager.create_policy_rule_precommit(
                policy_context)

        try:
            self.policy_driver_manager.create_policy_rule_postcommit(
                policy_context)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.error(_(
                    "policy_driver_manager.create_policy_rule_postcommit"
                    " failed, deleting policy_rule %s"), result['id'])
                self.delete_policy_rule(context, result['id'])

        return result

    @log.log
    def update_policy_rule(self, context, id, policy_rule):
        session = context.session
        with session.begin(subtransactions=True):
            original_policy_rule = super(
                GroupPolicyPlugin, self).get_policy_rule(context, id)
            updated_policy_rule = super(
                GroupPolicyPlugin, self).update_policy_rule(
                    context, id, policy_rule)
            self.extension_manager.process_update_policy_rule(
                session, policy_rule, updated_policy_rule)
            self._validate_shared_update(self, context, original_policy_rule,
                                         updated_policy_rule, 'policy_rule')
            policy_context = p_context.PolicyRuleContext(
                self, context, updated_policy_rule,
                original_policy_rule=original_policy_rule)
            self.policy_driver_manager.update_policy_rule_precommit(
                policy_context)

        self.policy_driver_manager.update_policy_rule_postcommit(
            policy_context)
        return updated_policy_rule

    @log.log
    def delete_policy_rule(self, context, id):
        session = context.session
        with session.begin(subtransactions=True):
            policy_rule = self.get_policy_rule(context, id)
            policy_context = p_context.PolicyRuleContext(self, context,
                                                         policy_rule)
            self.policy_driver_manager.delete_policy_rule_precommit(
                policy_context)
            super(GroupPolicyPlugin, self).delete_policy_rule(
                context, id)

        try:
            self.policy_driver_manager.delete_policy_rule_postcommit(
                policy_context)
        except Exception:
            LOG.exception(_("delete_policy_rule_postcommit failed "
                            "for policy_rule %s"),
                          id)

    def get_policy_rule(self, context, policy_rule_id, fields=None):
        session = context.session
        with session.begin(subtransactions=True):
            result = super(GroupPolicyPlugin, self).get_policy_rule(
                context, policy_rule_id, None)
            self.extension_manager.extend_policy_rule_dict(session, result)
        return self._fields(result, fields)

    def get_policy_rules(self, context, filters=None, fields=None,
                         sorts=None, limit=None, marker=None,
                         page_reverse=False):
        session = context.session
        with session.begin(subtransactions=True):
            results = super(GroupPolicyPlugin, self).get_policy_rules(
                context, filters, None, sorts, limit, marker, page_reverse)
            for result in results:
                self.extension_manager.extend_policy_rule_dict(
                    session, result)
        return [self._fields(result, fields) for result in results]

    @log.log
    def create_policy_rule_set(self, context, policy_rule_set):
        session = context.session
        with session.begin(subtransactions=True):
            result = super(GroupPolicyPlugin,
                           self).create_policy_rule_set(
                               context, policy_rule_set)
            self.extension_manager.process_create_policy_rule_set(
                session, policy_rule_set, result)
            self._validate_shared_create(
                self, context, result, 'policy_rule_set')
            policy_context = p_context.PolicyRuleSetContext(
                self, context, result)
            self.policy_driver_manager.create_policy_rule_set_precommit(
                policy_context)

        try:
            self.policy_driver_manager.create_policy_rule_set_postcommit(
                policy_context)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.error(_(
                    "policy_driver_manager.create_policy_rule_set_postcommit "
                    "failed, deleting policy_rule_set %s"), result['id'])
                self.delete_policy_rule_set(context, result['id'])

        return result

    @log.log
    def update_policy_rule_set(self, context, id, policy_rule_set):
        session = context.session
        with session.begin(subtransactions=True):
            original_policy_rule_set = super(
                GroupPolicyPlugin, self).get_policy_rule_set(context, id)
            updated_policy_rule_set = super(
                GroupPolicyPlugin, self).update_policy_rule_set(
                    context, id, policy_rule_set)
            self.extension_manager.process_update_policy_rule_set(
                session, policy_rule_set, updated_policy_rule_set)
            self._validate_shared_update(
                self, context, original_policy_rule_set,
                updated_policy_rule_set, 'policy_rule_set')
            policy_context = p_context.PolicyRuleSetContext(
                self, context, updated_policy_rule_set,
                original_policy_rule_set=original_policy_rule_set)
            self.policy_driver_manager.update_policy_rule_set_precommit(
                policy_context)

        self.policy_driver_manager.update_policy_rule_set_postcommit(
            policy_context)
        return updated_policy_rule_set

    @log.log
    def delete_policy_rule_set(self, context, id):
        session = context.session
        with session.begin(subtransactions=True):
            policy_rule_set = self.get_policy_rule_set(context, id)
            policy_context = p_context.PolicyRuleSetContext(
                self, context, policy_rule_set)
            self.policy_driver_manager.delete_policy_rule_set_precommit(
                policy_context)
            super(GroupPolicyPlugin, self).delete_policy_rule_set(context, id)

        try:
            self.policy_driver_manager.delete_policy_rule_set_postcommit(
                policy_context)
        except Exception:
            LOG.exception(_("delete_policy_rule_set_postcommit failed "
                            "for policy_rule_set %s"),
                          id)

    def get_policy_rule_set(self, context, policy_rule_set_id, fields=None):
        session = context.session
        with session.begin(subtransactions=True):
            result = super(GroupPolicyPlugin, self).get_policy_rule_set(
                context, policy_rule_set_id, None)
            self.extension_manager.extend_policy_rule_set_dict(session, result)
        return self._fields(result, fields)

    def get_policy_rule_sets(self, context, filters=None, fields=None,
                             sorts=None, limit=None, marker=None,
                             page_reverse=False):
        session = context.session
        with session.begin(subtransactions=True):
            results = super(GroupPolicyPlugin, self).get_policy_rule_sets(
                context, filters, None, sorts, limit, marker, page_reverse)
            for result in results:
                self.extension_manager.extend_policy_rule_set_dict(
                    session, result)
        return [self._fields(result, fields) for result in results]

    @log.log
    def create_external_segment(self, context, external_segment):
        session = context.session
        with session.begin(subtransactions=True):
            result = super(GroupPolicyPlugin,
                           self).create_external_segment(context,
                                                         external_segment)
            self.extension_manager.process_create_external_segment(
                session, external_segment, result)
            self._validate_shared_create(self, context, result,
                                         'external_segment')
            policy_context = p_context.ExternalSegmentContext(
                self, context, result)
            (self.policy_driver_manager.
             create_external_segment_precommit(policy_context))
            # Validate the routes after the drivers had the chance to fill
            # the cidr field.
            self._validate_routes(context, result)

        try:
            (self.policy_driver_manager.
             create_external_segment_postcommit(policy_context))
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.error(_("create_external_segment_postcommit "
                            "failed, deleting external_segment "
                            "%s"), result['id'])
                self.delete_external_segment(context, result['id'])

        return result

    @log.log
    def update_external_segment(self, context, external_segment_id,
                                external_segment):
        session = context.session
        with session.begin(subtransactions=True):
            original_external_segment = super(
                GroupPolicyPlugin, self).get_external_segment(
                    context, external_segment_id)
            updated_external_segment = super(
                GroupPolicyPlugin, self).update_external_segment(
                    context, external_segment_id,
                    external_segment)
            self.extension_manager.process_update_external_segment(
                session, external_segment, updated_external_segment)
            self._validate_shared_update(
                self, context, original_external_segment,
                updated_external_segment, 'external_segment')
            self._validate_routes(context, updated_external_segment,
                                  original_external_segment)
            # TODO(ivar): Validate Routes' GW in es subnet
            policy_context = p_context.ExternalSegmentContext(
                self, context, updated_external_segment,
                original_external_segment)
            (self.policy_driver_manager.
             update_external_segment_precommit(policy_context))

        self.policy_driver_manager.update_external_segment_postcommit(
            policy_context)
        return updated_external_segment

    @log.log
    def delete_external_segment(self, context, external_segment_id):
        session = context.session
        with session.begin(subtransactions=True):
            es = self.get_external_segment(context, external_segment_id)
            if es['l3_policies'] or es['nat_pools'] or es['external_policies']:
                raise gpex.ExternalSegmentInUse(es_id=es['id'])
            policy_context = p_context.ExternalSegmentContext(
                self, context, es)
            (self.policy_driver_manager.
             delete_external_segment_precommit(policy_context))
            super(GroupPolicyPlugin, self).delete_external_segment(
                context, external_segment_id)

        try:
            (self.policy_driver_manager.
             delete_external_segment_postcommit(policy_context))
        except Exception:
            LOG.exception(_("delete_external_segment_postcommit failed "
                            "for external_segment %s"),
                          external_segment_id)
        return True

    def get_external_segment(self, context, external_segment_id, fields=None):
        session = context.session
        with session.begin(subtransactions=True):
            result = super(GroupPolicyPlugin, self).get_external_segment(
                context, external_segment_id, None)
            self.extension_manager.extend_external_segment_dict(session,
                                                                result)
        return self._fields(result, fields)

    def get_external_segments(self, context, filters=None, fields=None,
                              sorts=None, limit=None, marker=None,
                              page_reverse=False):
        session = context.session
        with session.begin(subtransactions=True):
            results = super(GroupPolicyPlugin, self).get_external_segments(
                context, filters, None, sorts, limit, marker, page_reverse)
            for result in results:
                self.extension_manager.extend_external_segment_dict(
                    session, result)
        return [self._fields(result, fields) for result in results]

    @log.log
    def create_external_policy(self, context, external_policy):
        session = context.session
        with session.begin(subtransactions=True):
            result = super(GroupPolicyPlugin,
                           self).create_external_policy(
                               context, external_policy)
            self.extension_manager.process_create_external_policy(
                session, external_policy, result)
            self._validate_shared_create(self, context, result,
                                         'external_policy')
            policy_context = p_context.ExternalPolicyContext(
                self, context, result)
            (self.policy_driver_manager.
             create_external_policy_precommit(policy_context))

        try:
            (self.policy_driver_manager.
             create_external_policy_postcommit(policy_context))
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.error(_("create_external_policy_postcommit "
                            "failed, deleting external_policy "
                            "%s"), result['id'])
                self.delete_external_policy(context, result['id'])

        return result

    @log.log
    def update_external_policy(self, context, external_policy_id,
                               external_policy):
        session = context.session
        with session.begin(subtransactions=True):
            original_external_policy = super(
                GroupPolicyPlugin, self).get_external_policy(
                    context, external_policy_id)
            updated_external_policy = super(
                GroupPolicyPlugin, self).update_external_policy(
                    context, external_policy_id,
                    external_policy)
            self.extension_manager.process_update_external_policy(
                session, external_policy, updated_external_policy)
            self._validate_shared_update(
                self, context, original_external_policy,
                updated_external_policy, 'external_policy')
            policy_context = p_context.ExternalPolicyContext(
                self, context, updated_external_policy,
                original_external_policy)
            (self.policy_driver_manager.
             update_external_policy_precommit(policy_context))

        self.policy_driver_manager.update_external_policy_postcommit(
            policy_context)
        return updated_external_policy

    @log.log
    def delete_external_policy(self, context, external_policy_id,
                               check_unused=False):
        session = context.session
        with session.begin(subtransactions=True):
            es = self.get_external_policy(context, external_policy_id)
            policy_context = p_context.ExternalPolicyContext(
                self, context, es)
            (self.policy_driver_manager.
             delete_external_policy_precommit(policy_context))
            super(GroupPolicyPlugin, self).delete_external_policy(
                context, external_policy_id)

        try:
            self.policy_driver_manager.delete_external_policy_postcommit(
                policy_context)
        except Exception:
            LOG.exception(_("delete_external_policy_postcommit failed "
                            "for external_policy %s"),
                          external_policy_id)

    def get_external_policy(self, context, external_policy_id, fields=None):
        session = context.session
        with session.begin(subtransactions=True):
            result = super(GroupPolicyPlugin, self).get_external_policy(
                context, external_policy_id, None)
            self.extension_manager.extend_external_policy_dict(session,
                                                               result)
        return self._fields(result, fields)

    def get_external_policies(self, context, filters=None, fields=None,
                              sorts=None, limit=None, marker=None,
                              page_reverse=False):
        session = context.session
        with session.begin(subtransactions=True):
            results = super(GroupPolicyPlugin, self).get_external_policies(
                context, filters, None, sorts, limit, marker, page_reverse)
            for result in results:
                self.extension_manager.extend_external_policy_dict(
                    session, result)
        return [self._fields(result, fields) for result in results]

    @log.log
    def create_nat_pool(self, context, nat_pool):
        session = context.session
        with session.begin(subtransactions=True):
            result = super(GroupPolicyPlugin, self).create_nat_pool(
                context, nat_pool)
            self.extension_manager.process_create_nat_pool(session, nat_pool,
                                                           result)
            self._validate_shared_create(self, context, result, 'nat_pool')
            policy_context = p_context.NatPoolContext(self, context, result)
            (self.policy_driver_manager.
             create_nat_pool_precommit(policy_context))

        try:
            (self.policy_driver_manager.
             create_nat_pool_postcommit(policy_context))
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.error(_("create_nat_pool_postcommit failed, deleting "
                            "nat_pool %s"), result['id'])
                self.delete_nat_pool(context, result['id'])

        return result

    @log.log
    def update_nat_pool(self, context, nat_pool_id, nat_pool):
        session = context.session
        with session.begin(subtransactions=True):
            original_nat_pool = super(
                GroupPolicyPlugin, self).get_nat_pool(context, nat_pool_id)
            updated_nat_pool = super(
                GroupPolicyPlugin, self).update_nat_pool(context, nat_pool_id,
                                                         nat_pool)
            self.extension_manager.process_update_nat_pool(
                session, nat_pool, updated_nat_pool)
            self._validate_shared_update(self, context, original_nat_pool,
                                         updated_nat_pool, 'nat_pool')
            policy_context = p_context.NatPoolContext(
                self, context, updated_nat_pool, original_nat_pool)
            (self.policy_driver_manager.
             update_nat_pool_precommit(policy_context))

        self.policy_driver_manager.update_nat_pool_postcommit(policy_context)
        return updated_nat_pool

    @log.log
    def delete_nat_pool(self, context, nat_pool_id, check_unused=False):
        session = context.session
        with session.begin(subtransactions=True):
            es = self.get_nat_pool(context, nat_pool_id)
            policy_context = p_context.NatPoolContext(self, context, es)
            (self.policy_driver_manager.delete_nat_pool_precommit(
                policy_context))
            super(GroupPolicyPlugin, self).delete_nat_pool(context,
                                                           nat_pool_id)

        try:
            self.policy_driver_manager.delete_nat_pool_postcommit(
                policy_context)
        except Exception:
            LOG.exception(_("delete_nat_pool_postcommit failed "
                            "for nat_pool %s"),
                          nat_pool_id)

    def get_nat_pool(self, context, nat_pool_id, fields=None):
        session = context.session
        with session.begin(subtransactions=True):
            result = super(GroupPolicyPlugin, self).get_nat_pool(
                context, nat_pool_id, None)
            self.extension_manager.extend_nat_pool_dict(session, result)
        return self._fields(result, fields)

    def get_nat_pools(self, context, filters=None, fields=None,
                      sorts=None, limit=None, marker=None,
                      page_reverse=False):
        session = context.session
        with session.begin(subtransactions=True):
            results = super(GroupPolicyPlugin, self).get_nat_pools(
                context, filters, None, sorts, limit, marker, page_reverse)
            for result in results:
                self.extension_manager.extend_nat_pool_dict(
                    session, result)
        return [self._fields(result, fields) for result in results]

    def _is_port_bound(self, port_id):
        # REVISIT(ivar): This operation shouldn't be done within a DB lock
        # once we refactor the server.
        not_bound = [portbindings.VIF_TYPE_UNBOUND,
                     portbindings.VIF_TYPE_BINDING_FAILED]
        context = n_ctx.get_admin_context()
        port = n_manager.NeutronManager.get_plugin().get_port(context, port_id)
        return (port.get('binding:vif_type') not in not_bound) and port.get(
            'binding:host_id') and (port['device_owner'] or port['device_id'])

    def _is_service_target(self, context, pt_id):
        return bool(ncp_model.get_service_targets_count(
            context.session, pt_id))
