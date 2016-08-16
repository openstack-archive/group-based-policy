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

from neutron._i18n import _LE
from neutron._i18n import _LI
from neutron.api.v2 import attributes
from neutron.db import db_base_plugin_v2
from neutron.db import models_v2
from neutron.db import securitygroups_db
from neutron.extensions import address_scope as as_ext
from neutron.plugins.ml2.common import exceptions as ml2_exc
from neutron.plugins.ml2 import managers as ml2_managers
from neutron.plugins.ml2 import plugin as ml2_plugin
from neutron.quota import resource_registry
from oslo_log import log
from oslo_utils import excutils
from sqlalchemy import inspect

from gbpservice.neutron.plugins.ml2plus import driver_context
from gbpservice.neutron.plugins.ml2plus import managers
from gbpservice.neutron.plugins.ml2plus import patch_neutron  # noqa

LOG = log.getLogger(__name__)


class Ml2PlusPlugin(ml2_plugin.Ml2Plugin):

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
        LOG.info(_LI("Ml2Plus initializing"))
        # First load drivers, then initialize DB, then initialize drivers
        self.type_manager = ml2_managers.TypeManager()
        self.extension_manager = managers.ExtensionManager()
        self.mechanism_manager = managers.MechanismManager()
        super(ml2_plugin.Ml2Plugin, self).__init__()
        self.type_manager.initialize()
        self.extension_manager.initialize()
        self.mechanism_manager.initialize()
        self._setup_dhcp()
        self._start_rpc_notifiers()
        self.add_agent_status_check(self.agent_health_check)
        self._verify_service_plugins_requirements()
        LOG.info(_LI("Modular L2 Plugin (extended) initialization complete"))

    db_base_plugin_v2.NeutronDbPluginV2.register_dict_extend_funcs(
               attributes.SUBNETPOOLS, ['_ml2_md_extend_subnetpool_dict'])

    db_base_plugin_v2.NeutronDbPluginV2.register_dict_extend_funcs(
               as_ext.ADDRESS_SCOPES, ['_ml2_md_extend_address_scope_dict'])

    def _ml2_md_extend_network_dict(self, result, netdb):
        session = inspect(netdb).session
        with session.begin(subtransactions=True):
            self.extension_manager.extend_network_dict(session, netdb, result)

    def _ml2_md_extend_port_dict(self, result, portdb):
        session = inspect(portdb).session
        with session.begin(subtransactions=True):
            self.extension_manager.extend_port_dict(session, portdb, result)

    def _ml2_md_extend_subnet_dict(self, result, subnetdb):
        session = inspect(subnetdb).session
        with session.begin(subtransactions=True):
            self.extension_manager.extend_subnet_dict(
                session, subnetdb, result)

    def _ml2_md_extend_subnetpool_dict(self, result, subnetpooldb):
        session = inspect(subnetpooldb).session
        with session.begin(subtransactions=True):
            self.extension_manager.extend_subnetpool_dict(
                session, subnetpooldb, result)

    def _ml2_md_extend_address_scope_dict(self, result, address_scopedb):
        session = inspect(address_scopedb).session
        with session.begin(subtransactions=True):
            self.extension_manager.extend_address_scope_dict(
                session, address_scopedb, result)

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

    def create_network(self, context, network):
        self._ensure_tenant(context, network[attributes.NETWORK])
        return super(Ml2PlusPlugin, self).create_network(context, network)

    def create_network_bulk(self, context, networks):
        self._ensure_tenant_bulk(context, networks[attributes.NETWORKS],
                                 attributes.NETWORK)
        return super(Ml2PlusPlugin, self).create_network_bulk(context,
                                                              networks)

    def create_subnet(self, context, subnet):
        self._ensure_tenant(context, subnet[attributes.SUBNET])
        return super(Ml2PlusPlugin, self).create_subnet(context, subnet)

    def create_subnet_bulk(self, context, subnets):
        self._ensure_tenant_bulk(context, subnets[attributes.SUBNETS],
                                 attributes.SUBNET)
        return super(Ml2PlusPlugin, self).create_subnet_bulk(context,
                                                             subnets)

    def create_port(self, context, port):
        self._ensure_tenant(context, port[attributes.PORT])
        return super(Ml2PlusPlugin, self).create_port(context, port)

    def create_port_bulk(self, context, ports):
        self._ensure_tenant_bulk(context, ports[attributes.PORTS],
                                 attributes.PORT)
        return super(Ml2PlusPlugin, self).create_port_bulk(context,
                                                           ports)

    def create_subnetpool(self, context, subnetpool):
        self._ensure_tenant(context, subnetpool[attributes.SUBNETPOOL])
        session = context.session
        with session.begin(subtransactions=True):
            result = super(Ml2PlusPlugin, self).create_subnetpool(context,
                                                                  subnetpool)
            self.extension_manager.process_create_subnetpool(
                context, subnetpool[attributes.SUBNETPOOL], result)
            mech_context = driver_context.SubnetPoolContext(
                self, context, result)
            self.mechanism_manager.create_subnetpool_precommit(mech_context)
        try:
            self.mechanism_manager.create_subnetpool_postcommit(mech_context)
        except ml2_exc.MechanismDriverError:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("mechanism_manager.create_subnetpool_postcommit "
                              "failed, deleting subnetpool '%s'"),
                          result['id'])
                self.delete_subnetpool(context, result['id'])
        return result

    # REVISIT(rkukura): Is create_subnetpool_bulk() needed?

    def update_subnetpool(self, context, id, subnetpool):
        session = context.session
        with session.begin(subtransactions=True):
            original_subnetpool = super(Ml2PlusPlugin, self).get_subnetpool(
                context, id)
            updated_subnetpool = super(Ml2PlusPlugin, self).update_subnetpool(
                context, id, subnetpool)
            self.extension_manager.process_update_subnetpool(
                context, subnetpool[attributes.SUBNETPOOL],
                updated_subnetpool)
            mech_context = driver_context.SubnetPoolContext(
                self, context, updated_subnetpool,
                original_subnetpool=original_subnetpool)
            self.mechanism_manager.update_subnetpool_precommit(mech_context)
        self.mechanism_manager.update_subnetpool_postcommit(mech_context)
        return updated_subnetpool

    def delete_subnetpool(self, context, id):
        session = context.session
        with session.begin(subtransactions=True):
            subnetpool = super(Ml2PlusPlugin, self).get_subnetpool(context, id)
            super(Ml2PlusPlugin, self).delete_subnetpool(context, id)
            mech_context = driver_context.SubnetPoolContext(
                self, context, subnetpool)
            self.mechanism_manager.delete_subnetpool_precommit(mech_context)
        self.mechanism_manager.delete_subnetpool_postcommit(mech_context)

    def create_address_scope(self, context, address_scope):
        self._ensure_tenant(context, address_scope[as_ext.ADDRESS_SCOPE])
        session = context.session
        with session.begin(subtransactions=True):
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
                LOG.error(_LE("mechanism_manager.create_address_scope_"
                              "postcommit failed, deleting address_scope"
                              " '%s'"),
                          result['id'])
                self.delete_address_scope(context, result['id'])
        return result

    # REVISIT(rkukura): Is create_address_scope_bulk() needed?

    def update_address_scope(self, context, id, address_scope):
        session = context.session
        with session.begin(subtransactions=True):
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

    def delete_address_scope(self, context, id):
        session = context.session
        with session.begin(subtransactions=True):
            address_scope = super(Ml2PlusPlugin, self).get_address_scope(
                context, id)
            super(Ml2PlusPlugin, self).delete_address_scope(context, id)
            mech_context = driver_context.AddressScopeContext(
                self, context, address_scope)
            self.mechanism_manager.delete_address_scope_precommit(mech_context)
        self.mechanism_manager.delete_address_scope_postcommit(mech_context)

    def _ensure_tenant(self, context, resource):
        tenant_id = resource['tenant_id']
        self.mechanism_manager.ensure_tenant(context, tenant_id)

    def _ensure_tenant_bulk(self, context, resources, singular):
        tenant_ids = [resource[singular]['tenant_id']
                      for resource in resources]
        for tenant_id in set(tenant_ids):
            self.mechanism_manager.ensure_tenant(context, tenant_id)
