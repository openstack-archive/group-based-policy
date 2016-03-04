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

from neutron._i18n import _LI
from neutron.api.v2 import attributes
from neutron.db import models_v2
from neutron.db import securitygroups_db
from neutron.plugins.ml2 import managers as ml2_managers
from neutron.plugins.ml2 import plugin as ml2_plugin
from neutron.quota import resource_registry
from oslo_log import log
from sqlalchemy import inspect

from gbpservice.neutron.plugins.ml2plus import managers

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
        self.extension_manager = ml2_managers.ExtensionManager()
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

    # TODO(rkukura): Override address_scope, subnet_pool, and any
    # other needed resources to ensure tenant and invoke mechanism and
    # extension drivers.

    def _ensure_tenant(self, context, resource):
        tenant_id = resource['tenant_id']
        self.mechanism_manager.ensure_tenant(context, tenant_id)

    def _ensure_tenant_bulk(self, context, resources, singular):
        tenant_ids = [resource[singular]['tenant_id']
                      for resource in resources]
        for tenant_id in set(tenant_ids):
            self.mechanism_manager.ensure_tenant(context, tenant_id)
