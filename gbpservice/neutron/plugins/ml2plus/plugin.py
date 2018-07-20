# Copyright (c) 2016 Cisco Systems Inc.
# All Rights Reserved.
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

# The following is imported at the beginning to ensure
# that the patches are applied before any of the
# modules save a reference to the functions being patched
from gbpservice.neutron import extensions as gbp_extensions
from gbpservice.neutron.extensions import patch  # noqa
from gbpservice.neutron.plugins.ml2plus import patch_neutron  # noqa

from neutron.common import constants as n_const
from neutron.db import _resource_extend as resource_extend
from neutron.db import _utils as db_utils
from neutron.db import api as db_api
from neutron.db.models import securitygroup as securitygroups_db
from neutron.db import models_v2
from neutron.db import provisioning_blocks
from neutron.extensions import address_scope as as_ext
from neutron.plugins.ml2.common import exceptions as ml2_exc
from neutron.plugins.ml2 import managers as ml2_managers
from neutron.plugins.ml2 import plugin as ml2_plugin
from neutron.quota import resource_registry
from neutron_lib.api.definitions import address_scope as as_def
from neutron_lib.api.definitions import network as net_def
from neutron_lib.api.definitions import port as port_def
from neutron_lib.api.definitions import subnet as subnet_def
from neutron_lib.api.definitions import subnetpool as subnetpool_def
from neutron_lib.api import validators
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib.plugins import directory
from oslo_log import log
from oslo_utils import excutils

from gbpservice.neutron.db import implicitsubnetpool_db
from gbpservice.neutron.plugins.ml2plus import driver_api as api_plus
from gbpservice.neutron.plugins.ml2plus import driver_context
from gbpservice.neutron.plugins.ml2plus import managers

LOG = log.getLogger(__name__)


@resource_extend.has_resource_extenders
class Ml2PlusPlugin(ml2_plugin.Ml2Plugin,
                    implicitsubnetpool_db.ImplicitSubnetpoolMixin):

    """Extend the ML2 core plugin with missing functionality.

    The standard ML2 core plugin in Neutron is missing a few features
    needed for optimal APIC AIM support. This class adds those
    features, while maintaining compatibility with all standard ML2
    drivers and configuration. The only change necessary to use
    ML2Plus is to register the ml2plus entry point instead of the ml2
    entry port as Neutron's core_plugin. Drivers that need these
    features inherit from the extended MechanismDriver and
    ExtensionDriver abstract base classes.
    """

    __native_bulk_support = True
    __native_pagination_support = True
    __native_sorting_support = True
    ml2_plugin.Ml2Plugin._supported_extension_aliases += [
        "implicit-subnetpools"]

    # Override and bypass immediate base class's __init__ in order to
    # instantate extended manager class(es).
    @resource_registry.tracked_resources(
        network=models_v2.Network,
        port=models_v2.Port,
        subnet=models_v2.Subnet,
        subnetpool=models_v2.SubnetPool,
        security_group=securitygroups_db.SecurityGroup,
        security_group_rule=securitygroups_db.SecurityGroupRule)
    def __init__(self):
        LOG.info("Ml2Plus initializing")
        registry._get_callback_manager()._notify_loop = (
            patch_neutron._notify_loop)
        # First load drivers, then initialize DB, then initialize drivers
        self.type_manager = ml2_managers.TypeManager()
        self.extension_manager = managers.ExtensionManager()
        self.mechanism_manager = managers.MechanismManager()
        super(ml2_plugin.Ml2Plugin, self).__init__()
        self.type_manager.initialize()
        self.extension_manager.initialize()
        self.mechanism_manager.initialize()
        registry.subscribe(self._port_provisioned, resources.PORT,
                           provisioning_blocks.PROVISIONING_COMPLETE)
        registry.subscribe(self._handle_segment_change, resources.SEGMENT,
                           events.PRECOMMIT_CREATE)
        registry.subscribe(self._handle_segment_change, resources.SEGMENT,
                           events.PRECOMMIT_DELETE)
        registry.subscribe(self._handle_segment_change, resources.SEGMENT,
                           events.AFTER_CREATE)
        registry.subscribe(self._handle_segment_change, resources.SEGMENT,
                           events.AFTER_DELETE)

        # REVISIT(kent): All the postcommit calls for SG and SG rules are not
        # currently implemented as they are not needed at this moment.
        registry.subscribe(self._handle_security_group_change,
                           resources.SECURITY_GROUP, events.PRECOMMIT_CREATE)
        registry.subscribe(self._handle_security_group_change,
                           resources.SECURITY_GROUP, events.PRECOMMIT_DELETE)
        registry.subscribe(self._handle_security_group_change,
                           resources.SECURITY_GROUP, events.PRECOMMIT_UPDATE)

        # There is no update event to the security_group_rule
        registry.subscribe(self._handle_security_group_rule_change,
                           resources.SECURITY_GROUP_RULE,
                           events.PRECOMMIT_CREATE)
        registry.subscribe(self._handle_security_group_rule_change,
                           resources.SECURITY_GROUP_RULE,
                           events.PRECOMMIT_DELETE)
        try:
            registry.subscribe(self._subnet_delete_precommit_handler,
                    resources.SUBNET, events.PRECOMMIT_DELETE)
            registry.subscribe(self._subnet_delete_after_delete_handler,
                    resources.SUBNET, events.AFTER_DELETE)
        except AttributeError:
            LOG.info("Detected older version of Neutron, ML2Plus plugin "
                     "is not subscribed to subnet_precommit_delete and "
                     "subnet_after_delete events")
        self._setup_dhcp()
        self._start_rpc_notifiers()
        self.add_agent_status_check_worker(self.agent_health_check)
        self._verify_service_plugins_requirements()
        LOG.info("Modular L2 Plugin (extended) initialization complete")

    def _handle_security_group_change(self, resource, event, trigger,
                                      **kwargs):
        context = kwargs.get('context')
        security_group = kwargs.get('security_group')
        # There is a neutron bug that sometimes it will create a SG with
        # tenant_id field empty. We will not process it further when that
        # happens then.
        if not security_group['tenant_id']:
            return
        original_security_group = kwargs.get('original_security_group')
        mech_context = driver_context.SecurityGroupContext(
            self, context, security_group, original_security_group)
        if event == events.PRECOMMIT_CREATE:
            self._ensure_tenant(context, security_group)
            self.mechanism_manager.create_security_group_precommit(
                mech_context)
            return
        if event == events.PRECOMMIT_DELETE:
            self.mechanism_manager.delete_security_group_precommit(
                mech_context)
            return
        if event == events.PRECOMMIT_UPDATE:
            self.mechanism_manager.update_security_group_precommit(
                mech_context)

    def _handle_security_group_rule_change(self, resource, event, trigger,
                                           **kwargs):
        context = kwargs.get('context')
        if event == events.PRECOMMIT_CREATE:
            sg_rule = kwargs.get('security_group_rule')
            mech_context = driver_context.SecurityGroupRuleContext(
                self, context, sg_rule)
            self.mechanism_manager.create_security_group_rule_precommit(
                mech_context)
            return
        if event == events.PRECOMMIT_DELETE:
            sg_rule = {'id': kwargs.get('security_group_rule_id'),
                       'security_group_id': kwargs.get('security_group_id'),
                       'tenant_id': context.tenant}
            mech_context = driver_context.SecurityGroupRuleContext(
                self, context, sg_rule)
            self.mechanism_manager.delete_security_group_rule_precommit(
                mech_context)

    @staticmethod
    @resource_extend.extends([net_def.COLLECTION_NAME])
    def _ml2_md_extend_network_dict(result, netdb):
        plugin = directory.get_plugin()
        session = patch_neutron.get_current_session()
        # REVISIT: Check if transaction begin is still
        # required here, and if so, if reader pattern
        # can be used instead (will require getting the
        # current context)
        with session.begin(subtransactions=True):
            plugin.extension_manager.extend_network_dict(
                    session, netdb, result)

    @staticmethod
    @resource_extend.extends([net_def.COLLECTION_NAME + '_BULK'])
    def _ml2_md_extend_network_dict_bulk(results, _):
        plugin = directory.get_plugin()
        session = patch_neutron.get_current_session()
        with session.begin(subtransactions=True):
            plugin.extension_manager.extend_network_dict_bulk(session, results)

    @staticmethod
    @resource_extend.extends([port_def.COLLECTION_NAME])
    def _ml2_md_extend_port_dict(result, portdb):
        plugin = directory.get_plugin()
        session = patch_neutron.get_current_session()
        # REVISIT: Check if transaction begin is still
        # required here, and if so, if reader pattern
        # can be used instead (will require getting the
        # current context)
        with session.begin(subtransactions=True):
            plugin.extension_manager.extend_port_dict(
                    session, portdb, result)

    @staticmethod
    @resource_extend.extends([port_def.COLLECTION_NAME + '_BULK'])
    def _ml2_md_extend_port_dict_bulk(results, _):
        plugin = directory.get_plugin()
        session = patch_neutron.get_current_session()
        with session.begin(subtransactions=True):
            plugin.extension_manager.extend_port_dict_bulk(session, results)

    @staticmethod
    @resource_extend.extends([subnet_def.COLLECTION_NAME])
    def _ml2_md_extend_subnet_dict(result, subnetdb):
        plugin = directory.get_plugin()
        session = patch_neutron.get_current_session()
        # REVISIT: Check if transaction begin is still
        # required here, and if so, if reader pattern
        # can be used instead (will require getting the
        # current context)
        with session.begin(subtransactions=True):
            plugin.extension_manager.extend_subnet_dict(
                    session, subnetdb, result)

    @staticmethod
    @resource_extend.extends([subnet_def.COLLECTION_NAME + '_BULK'])
    def _ml2_md_extend_subnet_dict_bulk(results, _):
        plugin = directory.get_plugin()
        session = patch_neutron.get_current_session()
        with session.begin(subtransactions=True):
            plugin.extension_manager.extend_subnet_dict_bulk(session, results)

    @staticmethod
    @resource_extend.extends([subnetpool_def.COLLECTION_NAME])
    def _ml2_md_extend_subnetpool_dict(result, subnetpooldb):
        plugin = directory.get_plugin()
        session = patch_neutron.get_current_session()
        # REVISIT: Check if transaction begin is still
        # required here, and if so, if reader pattern
        # can be used instead (will require getting the
        # current context)
        with session.begin(subtransactions=True):
            plugin.extension_manager.extend_subnetpool_dict(
                    session, subnetpooldb, result)

    @staticmethod
    @resource_extend.extends([subnetpool_def.COLLECTION_NAME + '_BULK'])
    def _ml2_md_extend_subnetpool_dict_bulk(results, _):
        plugin = directory.get_plugin()
        session = patch_neutron.get_current_session()
        with session.begin(subtransactions=True):
            plugin.extension_manager.extend_subnetpool_dict_bulk(session,
                                                                 results)

    @staticmethod
    @resource_extend.extends([as_def.COLLECTION_NAME])
    def _ml2_md_extend_address_scope_dict(result, address_scope):
        plugin = directory.get_plugin()
        session = patch_neutron.get_current_session()
        # REVISIT: Check if transaction begin is still
        # required here, and if so, if reader pattern
        # can be used instead (will require getting the
        # current context)
        with session.begin(subtransactions=True):
            plugin.extension_manager.extend_address_scope_dict(
                    session, address_scope, result)

    @staticmethod
    @resource_extend.extends([as_def.COLLECTION_NAME + '_BULK'])
    def _ml2_md_extend_address_scope_dict_bulk(results, _):
        plugin = directory.get_plugin()
        session = patch_neutron.get_current_session()
        with session.begin(subtransactions=True):
            plugin.extension_manager.extend_address_scope_dict_bulk(session,
                                                                    results)

    # Base version does not call _apply_dict_extend_functions()
    def _make_address_scope_dict(self, address_scope, fields=None):
        res = {'id': address_scope['id'],
               'name': address_scope['name'],
               'tenant_id': address_scope['tenant_id'],
               'shared': address_scope['shared'],
               'ip_version': address_scope['ip_version']}
        self._apply_dict_extend_functions(as_ext.ADDRESS_SCOPES, res,
                                          address_scope)
        return self._fields(res, fields)

    @gbp_extensions.disable_transaction_guard
    @db_api.retry_if_session_inactive()
    def create_network(self, context, network):
        self._ensure_tenant(context, network[net_def.RESOURCE_NAME])
        return super(Ml2PlusPlugin, self).create_network(context, network)

    # We are overriding _create_network_db here to get
    # around a bug that was introduced in the following commit:
    # https://github.com/openstack/neutron/commit/
    # 2b7c6b2e987466973d983902eded6aff7f764830#
    # diff-2e958ca8f1a6e9987e28a7d0f95bc3d1L776
    # which moves the call to extending the dict before the call to
    # pre_commit. We need to extend_dict function to pick up the changes
    # from the pre_commit operations as well.
    def _create_network_db(self, context, network):
        with db_api.context_manager.writer.using(context):
            result, mech_context = super(
                    Ml2PlusPlugin, self)._create_network_db(
                            context, network)
            net_db = (context.session.query(models_v2.Network).
                      filter_by(id=result['id']).one())
            resource_extend.apply_funcs('networks', result, net_db)
            return result, mech_context

    @gbp_extensions.disable_transaction_guard
    @db_api.retry_if_session_inactive()
    def update_network(self, context, id, network):
        return super(Ml2PlusPlugin, self).update_network(context, id, network)

    @gbp_extensions.disable_transaction_guard
    @db_api.retry_if_session_inactive()
    def delete_network(self, context, id):
        return super(Ml2PlusPlugin, self).delete_network(context, id)

    @gbp_extensions.disable_transaction_guard
    @db_api.retry_if_session_inactive()
    def create_network_bulk(self, context, networks):
        self._ensure_tenant_bulk(context, networks[net_def.COLLECTION_NAME],
                net_def.RESOURCE_NAME)
        return super(Ml2PlusPlugin, self).create_network_bulk(context,
                                                              networks)

    @gbp_extensions.disable_transaction_guard
    @db_api.retry_if_session_inactive()
    def create_subnet(self, context, subnet):
        self._ensure_tenant(context, subnet[subnet_def.RESOURCE_NAME])
        return super(Ml2PlusPlugin, self).create_subnet(context, subnet)

    @gbp_extensions.disable_transaction_guard
    @db_api.retry_if_session_inactive()
    def update_subnet(self, context, id, subnet):
        return super(Ml2PlusPlugin, self).update_subnet(context, id, subnet)

    @gbp_extensions.disable_transaction_guard
    @db_api.retry_if_session_inactive()
    def delete_subnet(self, context, id):
        return super(Ml2PlusPlugin, self).delete_subnet(context, id)

    @gbp_extensions.disable_transaction_guard
    @db_api.retry_if_session_inactive()
    def create_subnet_bulk(self, context, subnets):
        self._ensure_tenant_bulk(context, subnets[subnet_def.COLLECTION_NAME],
                                 subnet_def.RESOURCE_NAME)
        return super(Ml2PlusPlugin, self).create_subnet_bulk(context,
                                                             subnets)

    @gbp_extensions.disable_transaction_guard
    @db_api.retry_if_session_inactive()
    def create_port(self, context, port):
        self._ensure_tenant(context, port[port_def.RESOURCE_NAME])
        return super(Ml2PlusPlugin, self).create_port(context, port)

    @gbp_extensions.disable_transaction_guard
    @db_api.retry_if_session_inactive()
    def create_port_bulk(self, context, ports):
        self._ensure_tenant_bulk(context, ports[port_def.COLLECTION_NAME],
                                 port_def.RESOURCE_NAME)
        return super(Ml2PlusPlugin, self).create_port_bulk(context,
                                                           ports)

    @gbp_extensions.disable_transaction_guard
    @db_api.retry_if_session_inactive()
    def update_port(self, context, id, port):
        return super(Ml2PlusPlugin, self).update_port(context, id, port)

    @gbp_extensions.disable_transaction_guard
    @db_api.retry_if_session_inactive()
    def delete_port(self, context, id, l3_port_check=True):
        return super(Ml2PlusPlugin, self).delete_port(
            context, id, l3_port_check=l3_port_check)

    @gbp_extensions.disable_transaction_guard
    @db_api.retry_if_session_inactive(context_var_name='plugin_context')
    def get_bound_port_context(self, plugin_context, port_id, host=None,
                               cached_networks=None):
        return super(Ml2PlusPlugin, self).get_bound_port_context(
            plugin_context, port_id, host=host,
            cached_networks=cached_networks)

    @gbp_extensions.disable_transaction_guard
    @db_api.retry_if_session_inactive()
    def update_port_status(self, context, port_id, status, host=None,
                           network=None):
        return super(Ml2PlusPlugin, self).update_port_status(
            context, port_id, status, host=host, network=network)

    @gbp_extensions.disable_transaction_guard
    @db_api.retry_if_session_inactive()
    def port_bound_to_host(self, context, port_id, host):
        return super(Ml2PlusPlugin, self).port_bound_to_host(
            context, port_id, host)

    @gbp_extensions.disable_transaction_guard
    @db_api.retry_if_session_inactive()
    def get_ports_from_devices(self, context, devices):
        return super(Ml2PlusPlugin, self).get_ports_from_devices(
            context, devices)

    @gbp_extensions.disable_transaction_guard
    @db_api.retry_if_session_inactive()
    def create_subnetpool(self, context, subnetpool):
        self._ensure_tenant(context, subnetpool[subnetpool_def.RESOURCE_NAME])
        with db_api.context_manager.writer.using(context):
            result = super(Ml2PlusPlugin, self).create_subnetpool(context,
                                                                  subnetpool)
            self._update_implicit_subnetpool(context, subnetpool, result)
            self.extension_manager.process_create_subnetpool(
                context, subnetpool[subnetpool_def.RESOURCE_NAME], result)
            mech_context = driver_context.SubnetPoolContext(
                self, context, result)
            self.mechanism_manager.create_subnetpool_precommit(mech_context)
        try:
            self.mechanism_manager.create_subnetpool_postcommit(mech_context)
        except ml2_exc.MechanismDriverError:
            with excutils.save_and_reraise_exception():
                LOG.error("mechanism_manager.create_subnetpool_postcommit "
                          "failed, deleting subnetpool '%s'",
                          result['id'])
                self.delete_subnetpool(context, result['id'])
        return result

    # REVISIT(rkukura): Is create_subnetpool_bulk() needed?

    @gbp_extensions.disable_transaction_guard
    @db_api.retry_if_session_inactive()
    def update_subnetpool(self, context, id, subnetpool):
        with db_api.context_manager.writer.using(context):
            original_subnetpool = super(Ml2PlusPlugin, self).get_subnetpool(
                context, id)
            updated_subnetpool = super(Ml2PlusPlugin, self).update_subnetpool(
                context, id, subnetpool)
            self._update_implicit_subnetpool(context, subnetpool,
                                             updated_subnetpool)
            self.extension_manager.process_update_subnetpool(
                context, subnetpool[subnetpool_def.RESOURCE_NAME],
                updated_subnetpool)
            mech_context = driver_context.SubnetPoolContext(
                self, context, updated_subnetpool,
                original_subnetpool=original_subnetpool)
            self.mechanism_manager.update_subnetpool_precommit(mech_context)
        self.mechanism_manager.update_subnetpool_postcommit(mech_context)
        return updated_subnetpool

    @gbp_extensions.disable_transaction_guard
    def delete_subnetpool(self, context, id):
        with db_api.context_manager.writer.using(context):
            subnetpool = super(Ml2PlusPlugin, self).get_subnetpool(context, id)
            mech_context = driver_context.SubnetPoolContext(
                self, context, subnetpool)
            self.mechanism_manager.delete_subnetpool_precommit(mech_context)
            super(Ml2PlusPlugin, self).delete_subnetpool(context, id)
        self.mechanism_manager.delete_subnetpool_postcommit(mech_context)

    def _update_implicit_subnetpool(self, context, request, result):
        if validators.is_attr_set(request['subnetpool'].get('is_implicit')):
            result['is_implicit'] = request['subnetpool']['is_implicit']
            result['is_implicit'] = (
                self.update_implicit_subnetpool(context, result))

    @gbp_extensions.disable_transaction_guard
    def create_address_scope(self, context, address_scope):
        self._ensure_tenant(context, address_scope[as_ext.ADDRESS_SCOPE])
        with db_api.context_manager.writer.using(context):
            result = super(Ml2PlusPlugin, self).create_address_scope(
                context, address_scope)
            self.extension_manager.process_create_address_scope(
                context, address_scope[as_ext.ADDRESS_SCOPE], result)
            mech_context = driver_context.AddressScopeContext(
                self, context, result)
            self.mechanism_manager.create_address_scope_precommit(
                mech_context)
        try:
            self.mechanism_manager.create_address_scope_postcommit(
                mech_context)
        except ml2_exc.MechanismDriverError:
            with excutils.save_and_reraise_exception():
                LOG.error("mechanism_manager.create_address_scope_"
                          "postcommit failed, deleting address_scope"
                          " '%s'",
                          result['id'])
                self.delete_address_scope(context, result['id'])
        return result

    # REVISIT(rkukura): Is create_address_scope_bulk() needed?

    @gbp_extensions.disable_transaction_guard
    def update_address_scope(self, context, id, address_scope):
        with db_api.context_manager.writer.using(context):
            original_address_scope = super(Ml2PlusPlugin,
                                           self).get_address_scope(context, id)
            updated_address_scope = super(Ml2PlusPlugin,
                                          self).update_address_scope(
                                              context, id, address_scope)
            self.extension_manager.process_update_address_scope(
                context, address_scope[as_ext.ADDRESS_SCOPE],
                updated_address_scope)
            mech_context = driver_context.AddressScopeContext(
                self, context, updated_address_scope,
                original_address_scope=original_address_scope)
            self.mechanism_manager.update_address_scope_precommit(mech_context)
        self.mechanism_manager.update_address_scope_postcommit(mech_context)
        return updated_address_scope

    @gbp_extensions.disable_transaction_guard
    def delete_address_scope(self, context, id):
        with db_api.context_manager.writer.using(context):
            address_scope = super(Ml2PlusPlugin, self).get_address_scope(
                context, id)
            mech_context = driver_context.AddressScopeContext(
                self, context, address_scope)
            self.mechanism_manager.delete_address_scope_precommit(mech_context)
            super(Ml2PlusPlugin, self).delete_address_scope(context, id)
        self.mechanism_manager.delete_address_scope_postcommit(mech_context)

    def _ensure_tenant(self, context, resource):
        tenant_id = resource['tenant_id']
        self.mechanism_manager.ensure_tenant(context, tenant_id)

    def _ensure_tenant_bulk(self, context, resources, singular):
        tenant_ids = [resource[singular]['tenant_id']
                      for resource in resources]
        for tenant_id in set(tenant_ids):
            self.mechanism_manager.ensure_tenant(context, tenant_id)

    def _get_subnetpool_id(self, context, subnet):
        # Check for regular subnetpool ID first, then Tenant's implicit,
        # then global implicit.
        ip_version = subnet['ip_version']
        return (
            super(Ml2PlusPlugin, self)._get_subnetpool_id(context, subnet) or
            self.get_implicit_subnetpool_id(context,
                                            tenant=subnet['tenant_id'],
                                            ip_version=ip_version) or
            self.get_implicit_subnetpool_id(context, tenant=None,
                                            ip_version=ip_version))

    # REVISIT(ivar): patching bulk gets for extension performance

    def _make_networks_dict(self, networks, context):
        nets = []
        for network in networks:
            if network.mtu is None:
                # TODO(ivar): also refactor this to run for bulk networks
                network.mtu = self._get_network_mtu(network, validate=False)
            res = {'id': network['id'],
                   'name': network['name'],
                   'tenant_id': network['tenant_id'],
                   'admin_state_up': network['admin_state_up'],
                   'mtu': network.get('mtu', n_const.DEFAULT_NETWORK_MTU),
                   'status': network['status'],
                   'subnets': [subnet['id']
                               for subnet in network['subnets']]}
            res['shared'] = self._is_network_shared(context,
                                                    network.rbac_entries)
            nets.append((res, network))

        # Bulk extend first
        resource_extend.apply_funcs(net_def.COLLECTION_NAME + '_BULK', nets,
                                    None)

        result = []
        for res, network in nets:
            res[api_plus.BULK_EXTENDED] = True
            resource_extend.apply_funcs(net_def.COLLECTION_NAME, res, network)
            res.pop(api_plus.BULK_EXTENDED, None)
            result.append(db_utils.resource_fields(res, []))
        return result

    @db_api.retry_if_session_inactive()
    def get_networks(self, context, filters=None, fields=None,
                     sorts=None, limit=None, marker=None, page_reverse=False):
        with db_api.context_manager.writer.using(context):
            nets_db = super(Ml2PlusPlugin, self)._get_networks(
                context, filters, None, sorts, limit, marker, page_reverse)

            net_data = self._make_networks_dict(nets_db, context)

            self.type_manager.extend_networks_dict_provider(context, net_data)
            nets = self._filter_nets_provider(context, net_data, filters)
        return [db_utils.resource_fields(net, fields) for net in nets]
