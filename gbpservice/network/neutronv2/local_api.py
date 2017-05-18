# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from neutron.callbacks import registry
from neutron.extensions import address_scope
from neutron.extensions import l3
from neutron.extensions import securitygroup as ext_sg
from neutron import manager
from neutron.notifiers import nova
from neutron.plugins.common import constants as pconst
from neutron import quota
from neutron_lib import exceptions as n_exc
from oslo_log import log as logging
from oslo_utils import excutils

from gbpservice._i18n import _LE
from gbpservice._i18n import _LW
from gbpservice.neutron.extensions import group_policy as gp_ext
from gbpservice.neutron.extensions import servicechain as sc_ext
from gbpservice.neutron.services.grouppolicy.common import exceptions as exc

LOG = logging.getLogger(__name__)


def get_outer_transaction(transaction):
    if not transaction:
        return
    if not transaction._parent:
        return transaction
    else:
        return get_outer_transaction(transaction._parent)


# Note: QUEUE_OUT_OF_PROCESS_NOTIFICATIONS can be set to
# True only by drivers which use the ml2plus neutron plugin
QUEUE_OUT_OF_PROCESS_NOTIFICATIONS = False
NOVA_NOTIFIER_METHOD = 'send_network_change'
DHCP_NOTIFIER_METHOD = 'notify'
NOTIFIER_REF = 'notifier_object_reference'
NOTIFIER_METHOD = 'notifier_method_name'
NOTIFICATION_ARGS = 'notification_args'
REGISTRY_RESOURCE = 'registry_resource'
REGISTRY_EVENT = 'registry_event'
REGISTRY_TRIGGER = 'registry_trigger'
# Add known agent RPC notifiers here. These notifiers will be invoked
# in a delayed manner after the outermost transaction that initiated
# the notification has completed.
# These module names/prefixes are mutually exclusive from the
# notifiers/notifications that are handled in process.
OUT_OF_PROCESS_NOTIFICATIONS = ['neutron.api.rpc.agentnotifiers',
                                'neutron.notifiers.nova', 'opflexagent.rpc']


def _enqueue(session, transaction_key, entry):
    if transaction_key not in session.notification_queue:
        session.notification_queue[transaction_key] = [entry]
    else:
        session.notification_queue[transaction_key].append(entry)


def _queue_notification(session, transaction_key, notifier_obj,
                        notifier_method, args):
    entry = {NOTIFIER_REF: notifier_obj, NOTIFIER_METHOD: notifier_method,
             NOTIFICATION_ARGS: args}
    _enqueue(session, transaction_key, entry)


def _queue_registry_notification(session, transaction_key, resource,
                                 event, trigger, **kwargs):
    entry = {REGISTRY_RESOURCE: resource, REGISTRY_EVENT: event,
             REGISTRY_TRIGGER: trigger, NOTIFICATION_ARGS: kwargs}
    _enqueue(session, transaction_key, entry)


def send_or_queue_notification(session, transaction_key, notifier_obj,
                               notifier_method, args):
    rname = ''
    if notifier_method == NOVA_NOTIFIER_METHOD:
        # parse argument like "create_subnetpool"
        rname = args[0].split('_', 1)[1]
        event_name = 'after_' + args[0].split('_')[0]
        registry_method = getattr(notifier_obj,
                                  '_send_nova_notification')
    elif notifier_method == DHCP_NOTIFIER_METHOD:
        # parse argument like "subnetpool.create.end"
        rname = args[2].split('.')[0]
        event_name = 'after_' + args[2].split('.')[1]
        registry_method = getattr(notifier_obj,
                                  '_native_event_send_dhcp_notification')
    if rname:
        cbacks = registry._get_callback_manager()._callbacks.get(rname, None)
        if cbacks and event_name in cbacks.keys():
            for entry in cbacks.values():
                method = entry.values()[0]
                if registry_method == method:
                    # This notification is already being sent by Neutron
                    # soe we will avoid sending a duplicate notification
                    return

    if not transaction_key or 'subnet.delete.end' in args or (
        not QUEUE_OUT_OF_PROCESS_NOTIFICATIONS):
        # We make an exception for the dhcp agent notification
        # for port and subnet delete since the implementation
        # for sending that notification checks for the existence
        # of the associated network, which is not present in certain
        # cases if the delete notification is queued and sent after
        # the network delete.
        getattr(notifier_obj, notifier_method)(*args)
        return

    _queue_notification(session, transaction_key, notifier_obj,
                        notifier_method, args)


def _get_callbacks_for_resource_event(resource, event):
    return list(registry._get_callback_manager()._callbacks[
        resource].get(event, {}).items())


def _get_in_process_callbacks(callbacks):
    return [i for i in callbacks if not [
        j for j in OUT_OF_PROCESS_NOTIFICATIONS if i[0].startswith(j)]]


def _registry_notify(resource, event, trigger, **kwargs):
    # This invokes neutron's original (unpatched) registry notification
    # method.
    registry._get_callback_manager().notify(
        resource, event, trigger, **kwargs)


def send_or_queue_registry_notification(
    session, transaction_key, resource, event, trigger, **kwargs):
    if not QUEUE_OUT_OF_PROCESS_NOTIFICATIONS:
        # Queueing is not enabled, so no more processing required,
        # relay notification to Neutron's callback registry
        _registry_notify(resource, event, trigger, **kwargs)
        return

    # Both, in-process and agent, notifieres may be registered for the
    # same event, so we might need to send and queue
    send, queue = False, False
    callbacks = _get_callbacks_for_resource_event(resource, event)
    if resource in ['port', 'router_interface', 'subnet'] and (
        event in ['after_update', 'after_delete', 'precommit_delete']):
        # We make an exception for the dhcp agent notification
        # for port and subnet since the implementation for
        # sending that notification checks for the existence of the
        # associated network, which is not present in certain
        # cases if the notification is queued and sent after the network
        # delete.
        # All notifiers (in-process as well as agent) will be
        # invoked in this case, no queueing of the notification
        # is required.
        send = True
    if not send:
        # Build a list of all in-process registered callbacks
        # for this resource
        in_process_callbacks = _get_in_process_callbacks(callbacks)
        send = True if in_process_callbacks else False
        callbacks = in_process_callbacks if send else callbacks
        # If there are notifiers registered which are not in-process,
        # we need to queue up this notification
        queue = (in_process_callbacks != callbacks)

    if not session or not transaction_key or send:
        if callbacks:
            # Note: For the following to work, the _notify_loop()
            # function implemented in neutron.callbacks.manager
            # needs to be patched to handle the callbacks argument
            # like its being done in:
            # gbpservice/neutron/plugins/ml2plus/patch_neutron.py
            kwargs['callbacks'] = callbacks
            _registry_notify(resource, event, trigger, **kwargs)

    if queue and session:
        _queue_registry_notification(session, transaction_key, resource,
                                     event, trigger, **kwargs)


def post_notifications_from_queue(session, transaction_key):
    queue = session.notification_queue[transaction_key]
    for entry in queue:
        if REGISTRY_RESOURCE in entry:
            callbacks = _get_callbacks_for_resource_event(
                entry[REGISTRY_RESOURCE], entry[REGISTRY_EVENT])
            in_process_callbacks = _get_in_process_callbacks(callbacks)
            # Only process out-of-process notifications
            callbacks = list(set(callbacks) - set(in_process_callbacks))
            if callbacks:
                entry[NOTIFICATION_ARGS]['callbacks'] = callbacks
                _registry_notify(
                    entry[REGISTRY_RESOURCE], entry[REGISTRY_EVENT],
                    entry[REGISTRY_TRIGGER], **entry[NOTIFICATION_ARGS])
        else:
            getattr(entry[NOTIFIER_REF],
                    entry[NOTIFIER_METHOD])(*entry[NOTIFICATION_ARGS])
    del session.notification_queue[transaction_key]


def discard_notifications_after_rollback(session):
    session.notification_queue.pop(session.transaction, None)


class LocalAPI(object):
    """API for interacting with the neutron Plugins directly."""

    @property
    def _nova_notifier(self):
        return nova.Notifier()

    @property
    def _core_plugin(self):
        # REVISIT(rkukura): Need initialization method after all
        # plugins are loaded to grab and store plugin.
        return manager.NeutronManager.get_plugin()

    @property
    def _l3_plugin(self):
        # REVISIT(rkukura): Need initialization method after all
        # plugins are loaded to grab and store plugin.
        plugins = manager.NeutronManager.get_service_plugins()
        l3_plugin = plugins.get(pconst.L3_ROUTER_NAT)
        if not l3_plugin:
            LOG.error(_LE("No L3 router service plugin found."))
            raise exc.GroupPolicyDeploymentError()
        return l3_plugin

    @property
    def _group_policy_plugin(self):
        # REVISIT(rkukura): Need initialization method after all
        # plugins are loaded to grab and store plugin.
        plugins = manager.NeutronManager.get_service_plugins()
        group_policy_plugin = plugins.get(pconst.GROUP_POLICY)
        if not group_policy_plugin:
            LOG.error(_LE("No GroupPolicy service plugin found."))
            raise exc.GroupPolicyDeploymentError()
        return group_policy_plugin

    @property
    def _servicechain_plugin(self):
        # REVISIT(rkukura): Need initialization method after all
        # plugins are loaded to grab and store plugin.
        plugins = manager.NeutronManager.get_service_plugins()
        servicechain_plugin = plugins.get(pconst.SERVICECHAIN)
        if not servicechain_plugin:
            LOG.error(_LE("No Servicechain service plugin found."))
            raise exc.GroupPolicyDeploymentError()
        return servicechain_plugin

    def _create_resource(self, plugin, context, resource, attrs,
                         do_notify=True):
        # REVISIT(rkukura): Do create.start notification?
        # REVISIT(rkukura): Check authorization?
        reservation = None
        if plugin in [self._group_policy_plugin, self._servicechain_plugin]:
            reservation = quota.QUOTAS.make_reservation(
                context, context.tenant_id, {resource: 1}, plugin)
        action = 'create_' + resource
        obj_creator = getattr(plugin, action)
        try:
            obj = obj_creator(context, {resource: attrs})
        except Exception:
            # In case of failure the plugin will always raise an
            # exception. Cancel the reservation
            with excutils.save_and_reraise_exception():
                if reservation:
                    quota.QUOTAS.cancel_reservation(
                        context, reservation.reservation_id)
        if reservation:
            quota.QUOTAS.commit_reservation(
                context, reservation.reservation_id)
            # At this point the implicit resource creation is successfull,
            # so we should be calling:
            # resource_registry.set_resources_dirty(context)
            # to appropriately notify the quota engine. However, the above
            # call begins a new transaction and we want to avoid that.
            # Moreover, it can be safely assumed that any implicit resource
            # creation via this local_api is always in response to an
            # explicit resource creation request, and hence the above
            # method will be invoked in the API layer.
        return obj

    def _update_resource(self, plugin, context, resource, resource_id, attrs,
                         do_notify=True):
        # REVISIT(rkukura): Check authorization?
        action = 'update_' + resource
        obj_updater = getattr(plugin, action)
        obj = obj_updater(context, resource_id, {resource: attrs})
        return obj

    def _delete_resource(self, plugin, context, resource, resource_id,
                         do_notify=True):
        # REVISIT(rkukura): Check authorization?
        action = 'delete_' + resource
        obj_deleter = getattr(plugin, action)
        obj_deleter(context, resource_id)

    def _get_resource(self, plugin, context, resource, resource_id):
        obj_getter = getattr(plugin, 'get_' + resource)
        obj = obj_getter(context, resource_id)
        return obj

    def _get_resources(self, plugin, context, resource_plural, filters=None):
        obj_getter = getattr(plugin, 'get_' + resource_plural)
        obj = obj_getter(context, filters)
        return obj

    # The following methods perform the necessary subset of
    # functionality from neutron.api.v2.base.Controller.
    #
    # REVISIT(rkukura): Can we just use the WSGI Controller?  Using
    # neutronclient is also a possibility, but presents significant
    # issues to unit testing as well as overhead and failure modes.

    def _get_port(self, plugin_context, port_id):
        return self._get_resource(self._core_plugin, plugin_context, 'port',
                                  port_id)

    def _get_ports(self, plugin_context, filters=None):
        filters = filters or {}
        return self._get_resources(self._core_plugin, plugin_context, 'ports',
                                   filters)

    def _create_port(self, plugin_context, attrs):
        return self._create_resource(self._core_plugin, plugin_context, 'port',
                                     attrs)

    def _update_port(self, plugin_context, port_id, attrs):
        return self._update_resource(self._core_plugin, plugin_context, 'port',
                                     port_id, attrs)

    def _delete_port(self, plugin_context, port_id):
        try:
            self._delete_resource(self._core_plugin,
                                  plugin_context, 'port', port_id)
        except n_exc.PortNotFound:
            LOG.warning(_LW('Port %s already deleted'), port_id)

    def _get_subnet(self, plugin_context, subnet_id):
        return self._get_resource(self._core_plugin, plugin_context, 'subnet',
                                  subnet_id)

    def _get_subnets(self, plugin_context, filters=None):
        filters = filters or {}
        return self._get_resources(self._core_plugin, plugin_context,
                                   'subnets', filters)

    def _create_subnet(self, plugin_context, attrs):
        return self._create_resource(self._core_plugin, plugin_context,
                                     'subnet', attrs)

    def _update_subnet(self, plugin_context, subnet_id, attrs):
        return self._update_resource(self._core_plugin, plugin_context,
                                     'subnet', subnet_id, attrs)

    def _delete_subnet(self, plugin_context, subnet_id):
        try:
            self._delete_resource(self._core_plugin, plugin_context, 'subnet',
                                  subnet_id)
        except n_exc.SubnetNotFound:
            LOG.warning(_LW('Subnet %s already deleted'), subnet_id)

    def _get_network(self, plugin_context, network_id):
        return self._get_resource(self._core_plugin, plugin_context, 'network',
                                  network_id)

    def _get_networks(self, plugin_context, filters=None):
        filters = filters or {}
        return self._get_resources(
            self._core_plugin, plugin_context, 'networks', filters)

    def _create_network(self, plugin_context, attrs):
        return self._create_resource(self._core_plugin, plugin_context,
                                     'network', attrs, True)

    def _update_network(self, plugin_context, network_id, attrs):
        return self._update_resource(self._core_plugin, plugin_context,
                                     'network', network_id, attrs)

    def _delete_network(self, plugin_context, network_id):
        try:
            self._delete_resource(self._core_plugin, plugin_context,
                                  'network', network_id)
        except n_exc.NetworkNotFound:
            LOG.warning(_LW('Network %s already deleted'), network_id)

    def _get_router(self, plugin_context, router_id):
        return self._get_resource(self._l3_plugin, plugin_context, 'router',
                                  router_id)

    def _get_routers(self, plugin_context, filters=None):
        filters = filters or {}
        return self._get_resources(self._l3_plugin, plugin_context, 'routers',
                                   filters)

    def _create_router(self, plugin_context, attrs):
        return self._create_resource(self._l3_plugin, plugin_context, 'router',
                                     attrs)

    def _update_router(self, plugin_context, router_id, attrs):
        return self._update_resource(self._l3_plugin, plugin_context, 'router',
                                     router_id, attrs)

    def _add_router_interface(self, plugin_context, router_id, interface_info):
        self._l3_plugin.add_router_interface(plugin_context,
                                             router_id, interface_info)

    def _remove_router_interface(self, plugin_context, router_id,
                                 interface_info):
        # To detach Router interface either port ID or Subnet ID is mandatory
        try:
            self._l3_plugin.remove_router_interface(plugin_context, router_id,
                                                    interface_info)
        except l3.RouterInterfaceNotFoundForSubnet:
            LOG.warning(_LW('Router interface already deleted for subnet %s'),
                        interface_info)
            return

    def _add_router_gw_interface(self, plugin_context, router_id, gw_info):
        return self._l3_plugin.update_router(
            plugin_context, router_id,
            {'router': {'external_gateway_info': gw_info}})

    def _remove_router_gw_interface(self, plugin_context, router_id,
                                    interface_info):
        self._l3_plugin.update_router(
            plugin_context, router_id,
            {'router': {'external_gateway_info': None}})

    def _delete_router(self, plugin_context, router_id):
        try:
            self._delete_resource(self._l3_plugin, plugin_context, 'router',
                                  router_id)
        except l3.RouterNotFound:
            LOG.warning(_LW('Router %s already deleted'), router_id)

    def _get_sg(self, plugin_context, sg_id):
        return self._get_resource(
            self._core_plugin, plugin_context, 'security_group', sg_id)

    def _get_sgs(self, plugin_context, filters=None):
        filters = filters or {}
        return self._get_resources(
            self._core_plugin, plugin_context, 'security_groups', filters)

    def _create_sg(self, plugin_context, attrs):
        return self._create_resource(self._core_plugin, plugin_context,
                                     'security_group', attrs)

    def _update_sg(self, plugin_context, sg_id, attrs):
        return self._update_resource(self._core_plugin, plugin_context,
                                     'security_group', sg_id, attrs)

    def _delete_sg(self, plugin_context, sg_id):
        try:
            self._delete_resource(self._core_plugin, plugin_context,
                                  'security_group', sg_id)
        except ext_sg.SecurityGroupNotFound:
            LOG.warning(_LW('Security Group %s already deleted'), sg_id)

    def _get_sg_rule(self, plugin_context, sg_rule_id):
        return self._get_resource(
            self._core_plugin, plugin_context, 'security_group_rule',
            sg_rule_id)

    def _get_sg_rules(self, plugin_context, filters=None):
        filters = filters or {}
        return self._get_resources(
            self._core_plugin, plugin_context, 'security_group_rules', filters)

    def _create_sg_rule(self, plugin_context, attrs):
        try:
            return self._create_resource(self._core_plugin, plugin_context,
                                         'security_group_rule', attrs)
        except ext_sg.SecurityGroupRuleExists as ex:
            LOG.warning(_LW('Security Group already exists %s'), ex.message)
            return

    def _update_sg_rule(self, plugin_context, sg_rule_id, attrs):
        return self._update_resource(self._core_plugin, plugin_context,
                                     'security_group_rule', sg_rule_id,
                                     attrs)

    def _delete_sg_rule(self, plugin_context, sg_rule_id):
        try:
            self._delete_resource(self._core_plugin, plugin_context,
                                  'security_group_rule', sg_rule_id)
        except ext_sg.SecurityGroupRuleNotFound:
            LOG.warning(_LW('Security Group Rule %s already deleted'),
                        sg_rule_id)

    def _get_fip(self, plugin_context, fip_id):
        return self._get_resource(
            self._l3_plugin, plugin_context, 'floatingip', fip_id)

    def _get_fips(self, plugin_context, filters=None):
        filters = filters or {}
        return self._get_resources(
            self._l3_plugin, plugin_context, 'floatingips', filters)

    def _create_fip(self, plugin_context, attrs):
        return self._create_resource(self._l3_plugin, plugin_context,
                                     'floatingip', attrs)

    def _update_fip(self, plugin_context, fip_id, attrs):
        return self._update_resource(self._l3_plugin, plugin_context,
                                     'floatingip', fip_id, attrs)

    def _delete_fip(self, plugin_context, fip_id):
        try:
            self._delete_resource(self._l3_plugin, plugin_context,
                                  'floatingip', fip_id)
        except l3.FloatingIPNotFound:
            LOG.warning(_LW('Floating IP %s Already deleted'), fip_id)

    def _get_address_scope(self, plugin_context, address_scope_id):
        return self._get_resource(self._core_plugin, plugin_context,
                                  'address_scope', address_scope_id)

    def _get_address_scopes(self, plugin_context, filters=None):
        filters = filters or {}
        return self._get_resources(self._core_plugin, plugin_context,
                                   'address_scopes', filters)

    def _create_address_scope(self, plugin_context, attrs):
        return self._create_resource(self._core_plugin, plugin_context,
                                     'address_scope', attrs)

    def _update_address_scope(self, plugin_context, address_scope_id, attrs):
        return self._update_resource(self._core_plugin, plugin_context,
                                     'address_scope', address_scope_id, attrs)

    def _delete_address_scope(self, plugin_context, address_scope_id):
        try:
            self._delete_resource(self._core_plugin, plugin_context,
                                  'address_scope', address_scope_id)
        except address_scope.AddressScopeNotFound:
            LOG.warning(_LW('Address Scope %s already deleted'),
                        address_scope_id)

    def _get_subnetpool(self, plugin_context, subnetpool_id):
        return self._get_resource(self._core_plugin, plugin_context,
                                  'subnetpool', subnetpool_id)

    def _get_subnetpools(self, plugin_context, filters=None):
        filters = filters or {}
        return self._get_resources(self._core_plugin, plugin_context,
                                   'subnetpools', filters)

    def _create_subnetpool(self, plugin_context, attrs):
        return self._create_resource(self._core_plugin, plugin_context,
                                     'subnetpool', attrs)

    def _update_subnetpool(self, plugin_context, subnetpool_id, attrs):
        return self._update_resource(self._core_plugin, plugin_context,
                                     'subnetpool', subnetpool_id, attrs)

    def _delete_subnetpool(self, plugin_context, subnetpool_id):
        try:
            self._delete_resource(self._core_plugin, plugin_context,
                                  'subnetpool', subnetpool_id)
        except n_exc.SubnetpoolNotFound:
            LOG.warning(_LW('Subnetpool %s already deleted'), subnetpool_id)

    def _get_l2_policy(self, plugin_context, l2p_id):
        return self._get_resource(self._group_policy_plugin, plugin_context,
                                  'l2_policy', l2p_id)

    def _get_l2_policies(self, plugin_context, filters=None):
        filters = filters or {}
        return self._get_resources(self._group_policy_plugin, plugin_context,
                                   'l2_policies', filters)

    def _create_l2_policy(self, plugin_context, attrs):
        return self._create_resource(self._group_policy_plugin, plugin_context,
                                     'l2_policy', attrs, False)

    def _update_l2_policy(self, plugin_context, l2p_id, attrs):
        return self._update_resource(self._group_policy_plugin, plugin_context,
                                     'l2_policy', l2p_id, attrs, False)

    def _delete_l2_policy(self, plugin_context, l2p_id):
        try:
            self._delete_resource(self._group_policy_plugin,
                                  plugin_context, 'l2_policy', l2p_id, False)
        except gp_ext.L2PolicyNotFound:
            LOG.warning(_LW('L2 Policy %s already deleted'), l2p_id)

    def _get_l3_policy(self, plugin_context, l3p_id):
        return self._get_resource(self._group_policy_plugin, plugin_context,
                                  'l3_policy', l3p_id)

    def _get_l3_policies(self, plugin_context, filters=None):
        filters = filters or {}
        return self._get_resources(self._group_policy_plugin, plugin_context,
                                   'l3_policies', filters)

    def _create_l3_policy(self, plugin_context, attrs):
        return self._create_resource(self._group_policy_plugin, plugin_context,
                                     'l3_policy', attrs, False)

    def _update_l3_policy(self, plugin_context, l3p_id, attrs):
        return self._update_resource(self._group_policy_plugin, plugin_context,
                                     'l3_policy', l3p_id, attrs, False)

    def _delete_l3_policy(self, plugin_context, l3p_id):
        try:
            self._delete_resource(self._group_policy_plugin,
                                  plugin_context, 'l3_policy', l3p_id, False)
        except gp_ext.L3PolicyNotFound:
            LOG.warning(_LW('L3 Policy %s already deleted'), l3p_id)

    def _get_external_segment(self, plugin_context, es_id):
        return self._get_resource(self._group_policy_plugin, plugin_context,
                                  'external_segment', es_id)

    def _get_external_segments(self, plugin_context, filters=None):
        filters = filters or {}
        return self._get_resources(self._group_policy_plugin, plugin_context,
                                   'external_segments', filters)

    def _create_external_segment(self, plugin_context, attrs):
        return self._create_resource(self._group_policy_plugin, plugin_context,
                                     'external_segment', attrs, False)

    def _update_external_segment(self, plugin_context, es_id, attrs):
        return self._update_resource(self._group_policy_plugin, plugin_context,
                                     'external_segment', es_id, attrs, False)

    def _delete_external_segment(self, plugin_context, es_id):
        try:
            self._delete_resource(self._group_policy_plugin, plugin_context,
                                  'external_segment', es_id, False)
        except gp_ext.ExternalSegmentNotFound:
            LOG.warning(_LW('External Segment %s already deleted'), es_id)

    def _get_external_policy(self, plugin_context, ep_id):
        return self._get_resource(self._group_policy_plugin, plugin_context,
                                  'external_policy', ep_id)

    def _get_external_policies(self, plugin_context, filters=None):
        filters = filters or {}
        return self._get_resources(self._group_policy_plugin, plugin_context,
                                   'external_policies', filters)

    def _create_external_policy(self, plugin_context, attrs):
        return self._create_resource(self._group_policy_plugin, plugin_context,
                                     'external_policy', attrs, False)

    def _update_external_policy(self, plugin_context, ep_id, attrs):
        return self._update_resource(self._group_policy_plugin, plugin_context,
                                     'external_policy', ep_id, attrs, False)

    def _delete_external_policy(self, plugin_context, ep_id):
        try:
            self._delete_resource(self._group_policy_plugin, plugin_context,
                                  'external_policy', ep_id, False)
        except gp_ext.ExternalPolicyNotFound:
            LOG.warning(_LW('External Policy %s already deleted'), ep_id)

    def _get_policy_rule_set(self, plugin_context, prs_id):
        return self._get_resource(self._group_policy_plugin, plugin_context,
                                  'policy_rule_set', prs_id)

    def _get_policy_rule_sets(self, plugin_context, filters=None):
        filters = filters or {}
        return self._get_resources(self._group_policy_plugin, plugin_context,
                                   'policy_rule_sets', filters)

    def _create_policy_rule_set(self, plugin_context, attrs):
        return self._create_resource(self._group_policy_plugin, plugin_context,
                                     'policy_rule_set', attrs, False)

    def _update_policy_rule_set(self, plugin_context, prs_id, attrs):
        return self._update_resource(self._group_policy_plugin, plugin_context,
                                     'policy_rule_set', prs_id, attrs, False)

    def _delete_policy_rule_set(self, plugin_context, prs_id):
        try:
            self._delete_resource(self._group_policy_plugin, plugin_context,
                                  'policy_rule_set', prs_id, False)
        except gp_ext.PolicyRuleSetNotFound:
            LOG.warning(_LW('Policy Rule Set %s already deleted'), prs_id)

    def _get_servicechain_instance(self, plugin_context, sci_id):
        return self._get_resource(self._servicechain_plugin, plugin_context,
                                  'servicechain_instance', sci_id)

    def _get_servicechain_instances(self, plugin_context, filters=None):
        filters = filters or {}
        return self._get_resources(self._servicechain_plugin, plugin_context,
                                   'servicechain_instances', filters)

    def _create_servicechain_instance(self, plugin_context, attrs):
        return self._create_resource(self._servicechain_plugin, plugin_context,
                                     'servicechain_instance', attrs, False)

    def _update_servicechain_instance(self, plugin_context, sci_id, attrs):
        return self._update_resource(self._servicechain_plugin, plugin_context,
                                     'servicechain_instance', sci_id, attrs,
                                     False)

    def _delete_servicechain_instance(self, plugin_context, sci_id):
        try:
            self._delete_resource(self._servicechain_plugin, plugin_context,
                                  'servicechain_instance', sci_id, False)
        except sc_ext.ServiceChainInstanceNotFound:
            LOG.warning(_LW("servicechain %s already deleted"), sci_id)

    def _get_servicechain_spec(self, plugin_context, scs_id):
        return self._get_resource(self._servicechain_plugin, plugin_context,
                                  'servicechain_spec', scs_id)

    def _get_servicechain_specs(self, plugin_context, filters=None):
        filters = filters or {}
        return self._get_resources(self._servicechain_plugin, plugin_context,
                                   'servicechain_specs', filters)

    def _create_servicechain_spec(self, plugin_context, attrs):
        return self._create_resource(self._servicechain_plugin, plugin_context,
                                     'servicechain_spec', attrs, False)

    def _update_servicechain_spec(self, plugin_context, scs_id, attrs):
        return self._update_resource(self._servicechain_plugin, plugin_context,
                                     'servicechain_spec', scs_id, attrs, False)

    def _delete_servicechain_spec(self, plugin_context, scs_id):
        try:
            self._delete_resource(self._servicechain_plugin, plugin_context,
                                  'servicechain_spec', scs_id)
        except sc_ext.ServiceChainSpecNotFound:
            LOG.warning(_LW("servicechain spec %s already deleted"), scs_id)

    def _get_policy_target(self, plugin_context, pt_id):
        return self._get_resource(self._group_policy_plugin, plugin_context,
                                  'policy_target', pt_id)

    def _get_policy_targets(self, plugin_context, filters=None):
        filters = filters or {}
        return self._get_resources(self._group_policy_plugin, plugin_context,
                                   'policy_targets', filters)

    def _create_policy_target(self, plugin_context, attrs):
        return self._create_resource(self._group_policy_plugin, plugin_context,
                                     'policy_target', attrs, False)

    def _update_policy_target(self, plugin_context, pt_id, attrs):
        return self._update_resource(self._group_policy_plugin, plugin_context,
                                     'policy_target', pt_id, attrs, False)

    def _delete_policy_target(self, plugin_context, pt_id):
        try:
            self._delete_resource(self._group_policy_plugin, plugin_context,
                                  'policy_target', pt_id, False)
        except gp_ext.PolicyTargetNotFound:
            LOG.warning(_LW('Policy Rule Set %s already deleted'), pt_id)

    def _get_policy_target_group(self, plugin_context, ptg_id):
        return self._get_resource(self._group_policy_plugin, plugin_context,
                                  'policy_target_group', ptg_id)

    def _get_policy_target_groups(self, plugin_context, filters=None):
        filters = filters or {}
        return self._get_resources(self._group_policy_plugin, plugin_context,
                                   'policy_target_groups', filters)

    def _create_policy_target_group(self, plugin_context, attrs):
        return self._create_resource(self._group_policy_plugin, plugin_context,
                                     'policy_target_group', attrs, False)

    def _update_policy_target_group(self, plugin_context, ptg_id, attrs):
        return self._update_resource(self._group_policy_plugin, plugin_context,
                                     'policy_target_group', ptg_id, attrs,
                                     False)

    def _delete_policy_target_group(self, plugin_context, ptg_id):
        try:
            self._delete_resource(self._group_policy_plugin, plugin_context,
                                  'policy_target_group', ptg_id)
        except sc_ext.ServiceChainSpecNotFound:
            LOG.warning(_LW("Policy Target Group %s already deleted"), ptg_id)
