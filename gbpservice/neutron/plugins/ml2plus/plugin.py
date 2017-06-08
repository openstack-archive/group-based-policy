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
from neutron.db import api as db_api
from neutron.db import db_base_plugin_v2
from neutron.db import models_v2
from neutron.db import securitygroups_db
from neutron.extensions import address_scope as as_ext
from neutron.plugins.ml2.common import exceptions as ml2_exc
from neutron.plugins.ml2 import managers as ml2_managers
from neutron.plugins.ml2 import plugin as ml2_plugin
from neutron.quota import resource_registry
from oslo_config import cfg
from oslo_log import log
from oslo_utils import excutils
from pecan import util as p_util
import six
from sqlalchemy import inspect

from gbpservice.neutron.db import implicitsubnetpool_db
from gbpservice.neutron.plugins.ml2plus import driver_context
from gbpservice.neutron.plugins.ml2plus import managers
from gbpservice.neutron.plugins.ml2plus import patch_neutron  # noqa

LOG = log.getLogger(__name__)


opts = [
    cfg.BoolOpt('refresh_network_db_obj',
                default=False,
                help=_("Refresh the network DB object to correctly "
                       "reflect the most recent state of all its "
                       "attributes. This refresh will be performed "
                       "in the _ml2_md_extend_network_dict method "
                       "inside the ml2plus plugin. The refresh option "
                       "may have a significant performace impact "
                       "and should be avoided. Hence this configuration "
                       "is set to False by default.")),
    cfg.BoolOpt('refresh_port_db_obj',
                default=False,
                help=_("Refresh the port DB object to correctly "
                       "reflect the most recent state of all its "
                       "attributes. This refresh will be performed "
                       "in the _ml2_md_extend_port_dict method "
                       "inside the ml2plus plugin. The refresh option "
                       "may have a significant performace impact "
                       "and should be avoided. Hence this configuration "
                       "is set to False by default.")),
    cfg.BoolOpt('refresh_subnet_db_obj',
                default=False,
                help=_("Refresh the subnet DB object to correctly "
                       "reflect the most recent state of all its "
                       "attributes. This refresh will be performed "
                       "in the _ml2_md_extend_subnet_dict method "
                       "inside the ml2plus plugin. The refresh option "
                       "may have a significant performace impact "
                       "and should be avoided. Hence this configuration "
                       "is set to False by default.")),
    cfg.BoolOpt('refresh_subnetpool_db_obj',
                default=False,
                help=_("Refresh the subnetpool DB object to correctly "
                       "reflect the most recent state of all its "
                       "attributes. This refresh will be performed "
                       "in the _ml2_md_extend_subnetpool_dict method "
                       "inside the ml2plus plugin. The refresh option "
                       "may have a significant performace impact "
                       "and should be avoided. Hence this configuration "
                       "is set to False by default.")),
    cfg.BoolOpt('refresh_address_scope_db_obj',
                default=False,
                help=_("Refresh the address_scope DB object to correctly "
                       "reflect the most recent state of all its "
                       "attributes. This refresh will be performed "
                       "in the _ml2_md_extend_address_scope_dict method "
                       "inside the ml2plus plugin. The refresh option "
                       "may have a significant performace impact "
                       "and should be avoided. Hence this configuration "
                       "is set to False by default.")),
]

cfg.CONF.register_opts(opts, "ml2plus")


# Copied from newton version of neutron/db/api.py.
def retry_if_session_inactive(context_var_name='context'):
    """Retries only if the session in the context is inactive.

    Calls a retry_db_errors wrapped version of the function if the context's
    session passed in is inactive, otherwise it just calls the function
    directly. This is useful to avoid retrying things inside of a transaction
    which is ineffective for DB races/errors.

    This should be used in all cases where retries are desired and the method
    accepts a context.
    """
    def decorator(f):
        try:
            # NOTE(kevinbenton): we use pecan's util function here because it
            # deals with the horrors of finding args of already decorated
            # functions
            ctx_arg_index = p_util.getargspec(f).args.index(context_var_name)
        except ValueError:
            raise RuntimeError(_LE("Could not find position of var %s")
                               % context_var_name)
        f_with_retry = db_api.retry_db_errors(f)

        @six.wraps(f)
        def wrapped(*args, **kwargs):
            # only use retry wrapper if we aren't nested in an active
            # transaction
            if context_var_name in kwargs:
                context = kwargs[context_var_name]
            else:
                context = args[ctx_arg_index]
            method = f if context.session.is_active else f_with_retry
            return method(*args, **kwargs)
        return wrapped
    return decorator


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
        self.refresh_network_db_obj = cfg.CONF.ml2plus.refresh_network_db_obj
        self.refresh_port_db_obj = cfg.CONF.ml2plus.refresh_port_db_obj
        self.refresh_subnet_db_obj = cfg.CONF.ml2plus.refresh_subnet_db_obj
        self.refresh_subnetpool_db_obj = (
            cfg.CONF.ml2plus.refresh_subnetpool_db_obj)
        self.refresh_address_scope_db_obj = (
            cfg.CONF.ml2plus.refresh_address_scope_db_obj)
        LOG.info(_LI("Modular L2 Plugin (extended) initialization complete"))

    db_base_plugin_v2.NeutronDbPluginV2.register_dict_extend_funcs(
               attributes.SUBNETPOOLS, ['_ml2_md_extend_subnetpool_dict'])

    db_base_plugin_v2.NeutronDbPluginV2.register_dict_extend_funcs(
               as_ext.ADDRESS_SCOPES, ['_ml2_md_extend_address_scope_dict'])

    def _ml2_md_extend_network_dict(self, result, netdb):
        session = inspect(netdb).session
        with session.begin(subtransactions=True):
            if self.refresh_network_db_obj:
                # In deployment it has been observed that the subnet
                # backref is sometimes stale inside the driver's
                # extend_network_dict. The call to refresh below
                # ensures the backrefs and other attributes are
                # not stale.
                session.refresh(netdb)
            self.extension_manager.extend_network_dict(session, netdb, result)

    def _ml2_md_extend_port_dict(self, result, portdb):
        session = inspect(portdb).session
        with session.begin(subtransactions=True):
            if self.refresh_port_db_obj:
                session.refresh(portdb)
            self.extension_manager.extend_port_dict(session, portdb, result)

    def _ml2_md_extend_subnet_dict(self, result, subnetdb):
        session = inspect(subnetdb).session
        with session.begin(subtransactions=True):
            if self.refresh_subnet_db_obj:
                session.refresh(subnetdb)
            self.extension_manager.extend_subnet_dict(
                session, subnetdb, result)

    def _ml2_md_extend_subnetpool_dict(self, result, subnetpooldb):
        session = inspect(subnetpooldb).session
        with session.begin(subtransactions=True):
            if self.refresh_subnetpool_db_obj:
                session.refresh(subnetpooldb)
            self.extension_manager.extend_subnetpool_dict(
                session, subnetpooldb, result)

    def _ml2_md_extend_address_scope_dict(self, result, address_scopedb):
        session = inspect(address_scopedb).session
        with session.begin(subtransactions=True):
            if self.refresh_address_scope_db_obj:
                session.refresh(address_scopedb)
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

    @retry_if_session_inactive()
    def create_network(self, context, network):
        self._ensure_tenant(context, network[attributes.NETWORK])
        return super(Ml2PlusPlugin, self).create_network(context, network)

    @retry_if_session_inactive()
    def update_network(self, context, id, network):
        return super(Ml2PlusPlugin, self).update_network(context, id, network)

    @retry_if_session_inactive()
    def get_network(self, context, id, fields=None):
        return super(Ml2PlusPlugin, self).get_network(context, id, fields)

    @retry_if_session_inactive()
    def get_networks(self, context, filters=None, fields=None,
                     sorts=None, limit=None, marker=None, page_reverse=False):
        return super(Ml2PlusPlugin, self).get_networks(
            context, filters, fields, sorts, limit, marker, page_reverse)

    @retry_if_session_inactive()
    def delete_network(self, context, id):
        return super(Ml2PlusPlugin, self).delete_network(context, id)

    @retry_if_session_inactive()
    def create_network_bulk(self, context, networks):
        self._ensure_tenant_bulk(context, networks[attributes.NETWORKS],
                                 attributes.NETWORK)
        return super(Ml2PlusPlugin, self).create_network_bulk(context,
                                                              networks)

    @retry_if_session_inactive()
    def create_subnet(self, context, subnet):
        self._ensure_tenant(context, subnet[attributes.SUBNET])
        return super(Ml2PlusPlugin, self).create_subnet(context, subnet)

    @retry_if_session_inactive()
    def update_subnet(self, context, id, subnet):
        return super(Ml2PlusPlugin, self).update_subnet(context, id, subnet)

    @retry_if_session_inactive()
    def get_subnet(self, context, id, fields=None):
        return super(Ml2PlusPlugin, self).get_subnet(context, id, fields)

    @retry_if_session_inactive()
    def get_subnets(self, context, filters=None, fields=None,
                    sorts=None, limit=None, marker=None, page_reverse=False):
        return super(Ml2PlusPlugin, self).get_subnets(
            context, filters, fields, sorts, limit, marker, page_reverse)

    @retry_if_session_inactive()
    def delete_subnet(self, context, id):
        return super(Ml2PlusPlugin, self).delete_subnet(context, id)

    @retry_if_session_inactive()
    def create_subnet_bulk(self, context, subnets):
        self._ensure_tenant_bulk(context, subnets[attributes.SUBNETS],
                                 attributes.SUBNET)
        return super(Ml2PlusPlugin, self).create_subnet_bulk(context,
                                                             subnets)

    @retry_if_session_inactive()
    def create_port(self, context, port):
        self._ensure_tenant(context, port[attributes.PORT])
        return super(Ml2PlusPlugin, self).create_port(context, port)

    @retry_if_session_inactive()
    def create_port_bulk(self, context, ports):
        self._ensure_tenant_bulk(context, ports[attributes.PORTS],
                                 attributes.PORT)
        return super(Ml2PlusPlugin, self).create_port_bulk(context,
                                                           ports)

    @retry_if_session_inactive()
    def update_port(self, context, id, port):
        return super(Ml2PlusPlugin, self).update_port(context, id, port)

    @retry_if_session_inactive()
    def delete_port(self, context, id, l3_port_check=True):
        return super(Ml2PlusPlugin, self).delete_port(
            context, id, l3_port_check=l3_port_check)

    @retry_if_session_inactive(context_var_name='plugin_context')
    def get_bound_port_context(self, plugin_context, port_id, host=None,
                               cached_networks=None):
        return super(Ml2PlusPlugin, self).get_bound_port_context(
            plugin_context, port_id, host, cached_networks)

    @retry_if_session_inactive()
    def update_port_status(self, context, port_id, status, host=None,
                           network=None):
        return super(Ml2PlusPlugin, self).update_port_status(
            context, port_id, status, host, network)

    @retry_if_session_inactive()
    def port_bound_to_host(self, context, port_id, host):
        return super(Ml2PlusPlugin, self).port_bound_to_host(
            context, port_id, host)

    @retry_if_session_inactive()
    def get_ports_from_devices(self, context, devices):
        return super(Ml2PlusPlugin, self).get_ports_from_devices(
            context, devices)

    @retry_if_session_inactive()
    def create_subnetpool(self, context, subnetpool):
        self._ensure_tenant(context, subnetpool[attributes.SUBNETPOOL])
        session = context.session
        with session.begin(subtransactions=True):
            result = super(Ml2PlusPlugin, self).create_subnetpool(context,
                                                                  subnetpool)
            self._update_implicit_subnetpool(context, subnetpool, result)
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

    @retry_if_session_inactive()
    def update_subnetpool(self, context, id, subnetpool):
        session = context.session
        with session.begin(subtransactions=True):
            original_subnetpool = super(Ml2PlusPlugin, self).get_subnetpool(
                context, id)
            updated_subnetpool = super(Ml2PlusPlugin, self).update_subnetpool(
                context, id, subnetpool)
            self._update_implicit_subnetpool(context, subnetpool,
                                             updated_subnetpool)
            self.extension_manager.process_update_subnetpool(
                context, subnetpool[attributes.SUBNETPOOL],
                updated_subnetpool)
            mech_context = driver_context.SubnetPoolContext(
                self, context, updated_subnetpool,
                original_subnetpool=original_subnetpool)
            self.mechanism_manager.update_subnetpool_precommit(mech_context)
        self.mechanism_manager.update_subnetpool_postcommit(mech_context)
        return updated_subnetpool

    @retry_if_session_inactive()
    def get_subnetpool(self, context, id, fields=None):
        return super(Ml2PlusPlugin, self).get_subnetpool(context, id, fields)

    @retry_if_session_inactive()
    def get_subnetpools(self, context, filters=None, fields=None,
                        sorts=None, limit=None, marker=None,
                        page_reverse=False):
        return super(Ml2PlusPlugin, self).get_subnetpools(
            context, filters, fields, sorts, limit, marker, page_reverse)

    @retry_if_session_inactive()
    def delete_subnetpool(self, context, id):
        session = context.session
        with session.begin(subtransactions=True):
            subnetpool = super(Ml2PlusPlugin, self).get_subnetpool(context, id)
            mech_context = driver_context.SubnetPoolContext(
                self, context, subnetpool)
            self.mechanism_manager.delete_subnetpool_precommit(mech_context)
            super(Ml2PlusPlugin, self).delete_subnetpool(context, id)
        self.mechanism_manager.delete_subnetpool_postcommit(mech_context)

    def _update_implicit_subnetpool(self, context, request, result):
        if attributes.is_attr_set(request['subnetpool'].get('is_implicit')):
            result['is_implicit'] = request['subnetpool']['is_implicit']
            result['is_implicit'] = (
                self.update_implicit_subnetpool(context, result))

    @retry_if_session_inactive()
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

    @retry_if_session_inactive()
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

    @retry_if_session_inactive()
    def get_address_scope(self, context, id, fields=None):
        return super(Ml2PlusPlugin, self).get_address_scope(
            context, id, fields)

    @retry_if_session_inactive()
    def get_address_scopes(self, context, filters=None, fields=None,
                           sorts=None, limit=None, marker=None,
                           page_reverse=False):
        return super(Ml2PlusPlugin, self).get_address_scopes(
            context, filters, fields, sorts, limit, marker, page_reverse)

    @retry_if_session_inactive()
    def delete_address_scope(self, context, id):
        session = context.session
        with session.begin(subtransactions=True):
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
