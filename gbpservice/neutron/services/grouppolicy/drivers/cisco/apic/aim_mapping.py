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

from aim.api import resource as aim_resource
from aim import context as aim_context
from neutron._i18n import _LE
from neutron._i18n import _LI
from neutron.agent.linux import dhcp
from neutron.common import constants as n_constants
from neutron import manager
from oslo_concurrency import lockutils
from oslo_log import helpers as log
from oslo_log import log as logging

from gbpservice.neutron.extensions import group_policy as gpolicy
from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim.extensions import (
    cisco_apic)
from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import model
from gbpservice.neutron.services.grouppolicy.common import (
    constants as gp_const)
from gbpservice.neutron.services.grouppolicy.common import exceptions as gpexc
from gbpservice.neutron.services.grouppolicy.drivers import (
    neutron_resources as nrd)
from gbpservice.neutron.services.grouppolicy.drivers.cisco.apic import (
    aim_mapping_rpc as aim_rpc)
from gbpservice.neutron.services.grouppolicy.drivers.cisco.apic import (
    apic_mapping_lib as alib)
from gbpservice.neutron.services.grouppolicy import plugin as gbp_plugin


LOG = logging.getLogger(__name__)
FORWARD = 'Forward'
REVERSE = 'Reverse'
FILTER_DIRECTIONS = {FORWARD: False, REVERSE: True}
FORWARD_FILTER_ENTRIES = 'Forward-FilterEntries'
REVERSE_FILTER_ENTRIES = 'Reverse-FilterEntries'

# Definitions duplicated from apicapi lib
APIC_OWNED = 'apic_owned_'
PROMISCUOUS_TYPES = [n_constants.DEVICE_OWNER_DHCP,
                     n_constants.DEVICE_OWNER_LOADBALANCER]
# TODO(ivar): define a proper promiscuous API
PROMISCUOUS_SUFFIX = 'promiscuous'


class ExplicitSubnetAssociationNotSupported(gpexc.GroupPolicyBadRequest):
    message = _("Explicit subnet association not supported by APIC driver.")


class AIMMappingDriver(nrd.CommonNeutronBase, aim_rpc.AIMMappingRPCMixin):
    """AIM Mapping Orchestration driver.

    This driver maps GBP resources to the ACI-Integration-Module (AIM).
    """

    @log.log_method_call
    def initialize(self):
        LOG.info(_LI("APIC AIM Policy Driver initializing"))
        self.db = model.DbModel()
        super(AIMMappingDriver, self).initialize()
        self._apic_aim_mech_driver = None
        self.setup_opflex_rpc_listeners()

    @property
    def aim_mech_driver(self):
        if not self._apic_aim_mech_driver:
            ml2plus_plugin = manager.NeutronManager.get_plugin()
            self._apic_aim_mech_driver = (
                ml2plus_plugin.mechanism_manager.mech_drivers['apic_aim'].obj)
        return self._apic_aim_mech_driver

    @property
    def aim(self):
        return self.aim_mech_driver.aim

    @property
    def name_mapper(self):
        return self.aim_mech_driver.name_mapper

    @log.log_method_call
    def ensure_tenant(self, plugin_context, tenant_id):
        self.aim_mech_driver.ensure_tenant(plugin_context, tenant_id)

    @log.log_method_call
    def create_policy_target_group_precommit(self, context):
        if context.current['subnets']:
            raise ExplicitSubnetAssociationNotSupported()

        ptg_db = context._plugin._get_policy_target_group(
            context._plugin_context, context.current['id'])

        session = context._plugin_context.session

        if not context.current['l2_policy_id']:
            self._create_implicit_l2_policy(context, clean_session=False)
            ptg_db['l2_policy_id'] = l2p_id = context.current['l2_policy_id']
        else:
            l2p_id = context.current['l2_policy_id']

        l2p_db = context._plugin._get_l2_policy(
            context._plugin_context, l2p_id)

        net = self._get_network(
            context._plugin_context, l2p_db['network_id'],
            clean_session=False)

        self._use_implicit_subnet(context)

        aim_ctx = aim_context.AimContext(session)

        bd_name = str(self.name_mapper.network(
            session, net['id'], net['name']))
        bd_tenant_name = str(self._aim_tenant_name(
            session, context.current['tenant_id']))

        epg = self._aim_endpoint_group(session, context.current, bd_name,
                                       bd_tenant_name)
        self.aim.create(aim_ctx, epg)

    @log.log_method_call
    def update_policy_target_group_precommit(self, context):
        # TODO(Sumit): Implement
        pass

    @log.log_method_call
    def delete_policy_target_group_precommit(self, context):
        plugin_context = context._plugin_context
        ptg_db = context._plugin._get_policy_target_group(
            context._plugin_context, context.current['id'])
        session = context._plugin_context.session

        aim_ctx = aim_context.AimContext(session)
        epg = self._aim_endpoint_group(session, context.current)
        self.aim.delete(aim_ctx, epg)
        self.name_mapper.delete_apic_name(session, context.current['id'])

        subnet_ids = [assoc['subnet_id'] for assoc in ptg_db['subnets']]

        context._plugin._remove_subnets_from_policy_target_group(
            context._plugin_context, ptg_db['id'])
        if subnet_ids:
            for subnet_id in subnet_ids:
                if not context._plugin._get_ptgs_for_subnet(
                    context._plugin_context, subnet_id):
                    self._cleanup_subnet(plugin_context, subnet_id,
                                         clean_session=False)

        if ptg_db['l2_policy_id']:
            l2p_id = ptg_db['l2_policy_id']
            ptg_db.update({'l2_policy_id': None})
            l2p_db = context._plugin._get_l2_policy(
                context._plugin_context, l2p_id)
            if not l2p_db['policy_target_groups']:
                self._cleanup_l2_policy(context, l2p_id, clean_session=False)

    @log.log_method_call
    def extend_policy_target_group_dict(self, session, result):
        epg = self._get_aim_endpoint_group(session, result)
        if epg:
            result[cisco_apic.DIST_NAMES] = {cisco_apic.EPG: epg.dn}

    @log.log_method_call
    def get_policy_target_group_status(self, context):
        session = context._plugin_context.session
        epg = self._get_aim_endpoint_group(session, context.current)
        context.current['status'] = self._map_aim_status(session, epg)

    @log.log_method_call
    def create_policy_target_precommit(self, context):
        if not context.current['port_id']:
            ptg = self._db_plugin(
                context._plugin).get_policy_target_group(
                    context._plugin_context,
                    context.current['policy_target_group_id'])
            subnets = self._get_subnets(
                context._plugin_context, {'id': ptg['subnets']},
                clean_session=False)

            self._use_implicit_port(context, subnets=subnets,
                                    clean_session=False)

    @log.log_method_call
    def update_policy_target_precommit(self, context):
        # TODO(Sumit): Implement
        pass

    @log.log_method_call
    def delete_policy_target_precommit(self, context):
        pt_db = context._plugin._get_policy_target(
            context._plugin_context, context.current['id'])
        if pt_db['port_id']:
            self._cleanup_port(context._plugin_context, pt_db['port_id'])

    @log.log_method_call
    def delete_l3_policy_precommit(self, context):
        # TODO(Sumit): Implement
        pass

    @log.log_method_call
    def create_policy_rule_precommit(self, context):
        entries = alib.get_filter_entries_for_policy_rule(context)
        if entries['forward_rules']:
            session = context._plugin_context.session
            aim_ctx = aim_context.AimContext(session)
            aim_filter = self._aim_filter(session, context.current)
            self.aim.create(aim_ctx, aim_filter)
            self._create_aim_filter_entries(session, aim_ctx, aim_filter,
                                            entries['forward_rules'])
            if entries['reverse_rules']:
                # Also create reverse rule
                aim_filter = self._aim_filter(session, context.current,
                                              reverse_prefix=True)
                self.aim.create(aim_ctx, aim_filter)
                self._create_aim_filter_entries(session, aim_ctx, aim_filter,
                                                entries['reverse_rules'])

    @log.log_method_call
    def update_policy_rule_precommit(self, context):
        self.delete_policy_rule_precommit(context)
        self.create_policy_rule_precommit(context)

    @log.log_method_call
    def delete_policy_rule_precommit(self, context):
        session = context._plugin_context.session
        aim_ctx = aim_context.AimContext(session)
        aim_filter = self._aim_filter(session, context.current)
        aim_filter_entries = self.aim.find(
            aim_ctx, aim_resource.FilterEntry,
            tenant_name=aim_filter.tenant_name,
            filter_name=aim_filter.name)
        for entry in aim_filter_entries:
            self.aim.delete(aim_ctx, entry)
        self.aim.delete(aim_ctx, aim_filter)
        aim_reverse_filter = self._aim_filter(
            session, context.current, reverse_prefix=True)
        if aim_reverse_filter:
            aim_reverse_filter_entries = self.aim.find(
                aim_ctx, aim_resource.FilterEntry,
                tenant_name=aim_reverse_filter.tenant_name,
                filter_name=aim_reverse_filter.name)
            for entry in aim_reverse_filter_entries:
                self.aim.delete(aim_ctx, entry)
            self.aim.delete(aim_ctx, aim_reverse_filter)
        self.name_mapper.delete_apic_name(session, context.current['id'])

    @log.log_method_call
    def extend_policy_rule_dict(self, session, result):
        result[cisco_apic.DIST_NAMES] = {}
        aim_filter_entries = self._get_aim_filter_entries(session, result)
        for k, v in aim_filter_entries.iteritems():
            dn_list = []
            for entry in v:
                dn_list.append(entry.dn)
            if k == FORWARD:
                result[cisco_apic.DIST_NAMES].update(
                    {FORWARD_FILTER_ENTRIES: dn_list})
            else:
                result[cisco_apic.DIST_NAMES].update(
                    {REVERSE_FILTER_ENTRIES: dn_list})

    @log.log_method_call
    def get_policy_rule_status(self, context):
        session = context._plugin_context.session
        aim_filters = self._get_aim_filters(session, context.current)
        aim_filter_entries = self._get_aim_filter_entries(session,
                                                          context.current)
        context.current['status'] = self._merge_aim_status(
            session, aim_filters.values() + aim_filter_entries.values())

    def _aim_tenant_name(self, session, tenant_id):
        # TODO(ivar): manage shared objects
        tenant_name = self.name_mapper.tenant(session, tenant_id)
        LOG.debug("Mapped tenant_id %(id)s to %(apic_name)s",
                  {'id': tenant_id, 'apic_name': tenant_name})
        return tenant_name

    def _aim_endpoint_group(self, session, ptg, bd_name=None,
                            bd_tenant_name=None):
        # This returns a new AIM EPG resource
        tenant_id = ptg['tenant_id']
        tenant_name = self._aim_tenant_name(session, tenant_id)
        id = ptg['id']
        name = ptg['name']
        epg_name = self.name_mapper.policy_target_group(session, id, name)
        LOG.debug("Mapped ptg_id %(id)s with name %(name)s to %(apic_name)s",
                  {'id': id, 'name': name, 'apic_name': epg_name})
        kwargs = {'tenant_name': str(tenant_name),
                  'name': str(epg_name),
                  'app_profile_name': self.aim_mech_driver.ap_name}
        if bd_name:
            kwargs['bd_name'] = bd_name
        if bd_tenant_name:
            kwargs['bd_tenant_name'] = bd_tenant_name

        epg = aim_resource.EndpointGroup(**kwargs)
        return epg

    def _get_aim_endpoint_group(self, session, ptg):
        # This gets an EPG from the AIM DB
        epg = self._aim_endpoint_group(session, ptg)
        aim_ctx = aim_context.AimContext(session)
        epg_fetched = self.aim.get(aim_ctx, epg)
        if not epg_fetched:
            LOG.debug("No EPG found in AIM DB")
        else:
            LOG.debug("Got epg: %s", epg_fetched.__dict__)
        return epg_fetched

    def _aim_filter(self, session, pr, reverse_prefix=False):
        # This returns a new AIM Filter resource
        tenant_id = pr['tenant_id']
        tenant_name = self._aim_tenant_name(session, tenant_id)
        id = pr['id']
        name = pr['name']
        if reverse_prefix:
            filter_name = self.name_mapper.policy_rule(
                session, id, resource_name=name, prefix=alib.REVERSE_PREFIX)
        else:
            filter_name = self.name_mapper.policy_rule(session, id,
                                                       resource_name=name)
        LOG.debug("Mapped policy_rule_id %(id)s with name %(name)s to",
                  "%(apic_name)s",
                  {'id': id, 'name': name, 'apic_name': filter_name})
        kwargs = {'tenant_name': str(tenant_name),
                  'name': str(filter_name)}

        aim_filter = aim_resource.Filter(**kwargs)
        return aim_filter

    def _aim_filter_entry(self, session, aim_filter, filter_entry_name,
                          filter_entry_attrs):
        # This returns a new AIM FilterEntry resource
        tenant_name = aim_filter.tenant_name
        filter_name = aim_filter.name
        kwargs = {'tenant_name': tenant_name,
                  'filter_name': filter_name,
                  'name': filter_entry_name}
        kwargs.update(filter_entry_attrs)

        aim_filter_entry = aim_resource.FilterEntry(**kwargs)
        return aim_filter_entry

    def _create_aim_filter_entries(self, session, aim_ctx, aim_filter,
                                   filter_entries):
        for k, v in filter_entries.iteritems():
            aim_filter_entry = self._aim_filter_entry(
                session, aim_filter, k, v)
            self.aim.create(aim_ctx, aim_filter_entry)

    def _get_aim_filters(self, session, policy_rule):
        # This gets the Forward and Reverse Filters from the AIM DB
        aim_ctx = aim_context.AimContext(session)
        filters = {}
        for k, v in FILTER_DIRECTIONS.iteritems():
            aim_filter = self._aim_filter(session, policy_rule, v)
            aim_filter_fetched = self.aim.get(aim_ctx, aim_filter)
            if not aim_filter_fetched:
                LOG.debug("No %s Filter found in AIM DB", k)
            else:
                LOG.debug("Got %s Filter: %s",
                          (aim_filter_fetched.__dict__, k))
            filters[k] = aim_filter_fetched
        return filters

    def _get_aim_filter_entries(self, session, policy_rule):
        # This gets the Forward and Reverse FilterEntries from the AIM DB
        aim_ctx = aim_context.AimContext(session)
        filters = self._get_aim_filters(session, policy_rule)
        filters_entries = {}
        for k, v in filters.iteritems():
            aim_filter_entries = self.aim.find(
                aim_ctx, aim_resource.FilterEntry,
                tenant_name=v.tenant_name, filter_name=v.name)
            if not aim_filter_entries:
                LOG.debug("No %s FilterEntry found in AIM DB", k)
            else:
                LOG.debug("Got %s FilterEntry: %s",
                          (aim_filter_entries, k))
            filters_entries[k] = aim_filter_entries
        return filters_entries

    def _get_aim_default_endpoint_group(self, session, network):
        epg_name = self.name_mapper.network(session, network['id'],
                                            network['name'])
        tenant_name = self.name_mapper.tenant(session, network['tenant_id'])
        aim_ctx = aim_context.AimContext(session)
        epg = aim_resource.EndpointGroup(
            tenant_name=tenant_name,
            app_profile_name=self.aim_mech_driver.ap_name, name=epg_name)
        return self.aim.get(aim_ctx, epg)

    def _aim_bridge_domain(self, session, tenant_id, network_id, network_name):
        # This returns a new AIM BD resource
        tenant_name = self._aim_tenant_name(session, tenant_id)
        bd_name = self.name_mapper.network(session, network_id, network_name)
        LOG.info(_LI("Mapped network_id %(id)s with name %(name)s to "
                     "%(apic_name)s"),
                 {'id': network_id, 'name': network_name,
                  'apic_name': bd_name})

        bd = aim_resource.BridgeDomain(tenant_name=str(tenant_name),
                                       name=str(bd_name))
        return bd

    def _get_l2p_subnets(self, context, l2p_id, clean_session=False):
        plugin_context = context._plugin_context
        l2p = context._plugin.get_l2_policy(plugin_context, l2p_id)
        # REVISIT: The following should be a get_subnets call via local API
        return self._core_plugin.get_subnets_by_network(
            plugin_context, l2p['network_id'])

    def _sync_ptg_subnets(self, context, l2p):
        l2p_subnets = [x['id'] for x in
                       self._get_l2p_subnets(context, l2p['id'])]
        ptgs = context._plugin._get_policy_target_groups(
            context._plugin_context.elevated(), {'l2_policy_id': [l2p['id']]})
        for sub in l2p_subnets:
            # Add to PTG
            for ptg in ptgs:
                if sub not in ptg['subnets']:
                    try:
                        (context._plugin.
                         _add_subnet_to_policy_target_group(
                             context._plugin_context.elevated(),
                             ptg['id'], sub))
                    except gpolicy.PolicyTargetGroupNotFound as e:
                        LOG.warning(e)

    def _use_implicit_subnet(self, context, force_add=False,
                             clean_session=False):
        """Implicit subnet for AIM.

        The first PTG in a L2P will allocate a new subnet from the L3P.
        Any subsequent PTG in the same L2P will use the same subnet.
        Additional subnets will be allocated as and when the currently used
        subnet runs out of IP addresses.
        """
        l2p_id = context.current['l2_policy_id']
        with lockutils.lock(l2p_id, external=True):
            subs = self._get_l2p_subnets(context, l2p_id)
            subs = set([x['id'] for x in subs])
            added = []
            if not subs or force_add:
                l2p = context._plugin.get_l2_policy(
                    context._plugin_context, l2p_id)
                name = APIC_OWNED + l2p['name']
                added = super(
                    AIMMappingDriver, self)._use_implicit_subnet(
                        context, subnet_specifics={'name': name},
                        is_proxy=False, clean_session=clean_session)
            context.add_subnets(subs - set(context.current['subnets']))
            for subnet in added:
                self._sync_ptg_subnets(context, l2p)

    def _map_aim_status(self, session, aim_resource_obj):
        # Note that this implementation assumes that this driver
        # is the only policy driver configured, and no merging
        # with any previous status is required.
        aim_ctx = aim_context.AimContext(session)
        aim_status = self.aim.get_status(aim_ctx, aim_resource_obj)
        if not aim_status:
            # REVIST(Sumit)
            return gp_const.STATUS_BUILD
        if aim_status.is_error():
            return gp_const.STATUS_ERROR
        elif aim_status.is_build():
            return gp_const.STATUS_BUILD
        else:
            return gp_const.STATUS_ACTIVE

    def _merge_aim_status(self, session, aim_resource_obj_list):
        # Note that this implementation assumes that this driver
        # is the only policy driver configured, and no merging
        # with any previous status is required.
        # When merging states of multiple AIM objects, the status
        # priority is ERROR > BUILD > ACTIVE.
        merged_status = gp_const.STATUS_ACTIVE
        for aim_obj in aim_resource_obj_list:
            status = self._map_aim_status(session, aim_obj)
            if status != gp_const.STATUS_ACTIVE:
                merged_status = status
            if merged_status == gp_const.STATUS_ERROR:
                break
        return merged_status

    def _db_plugin(self, plugin_obj):
            return super(gbp_plugin.GroupPolicyPlugin, plugin_obj)

    def _is_port_promiscuous(self, plugin_context, port):
        pt = self._port_id_to_pt(plugin_context, port['id'])
        if (pt and pt.get('cluster_id') and
                pt.get('cluster_id') != pt['id']):
            master = self._get_policy_target(plugin_context, pt['cluster_id'])
            if master.get('group_default_gateway'):
                return True
        return (port['device_owner'] in PROMISCUOUS_TYPES or
                port['name'].endswith(PROMISCUOUS_SUFFIX)) or (
                    pt and pt.get('group_default_gateway'))

    def _is_dhcp_optimized(self, plugin_context, port):
        return self.aim_mech_driver.enable_dhcp_opt

    def _is_metadata_optimized(self, plugin_context, port):
        return self.aim_mech_driver.enable_metadata_opt

    def _get_port_epg(self, plugin_context, port):
        ptg, pt = self._port_id_to_ptg(plugin_context, port['id'])
        if ptg:
            return self._get_aim_endpoint_group(plugin_context.session, ptg)
        else:
            # Return default EPG based on network
            network = self._get_network(plugin_context, port['network_id'])
            epg = self._get_aim_default_endpoint_group(plugin_context.session,
                                                       network)
            if not epg:
                # Something is wrong, default EPG doesn't exist.
                # TODO(ivar): should rise an exception
                LOG.error(_LE("Default EPG doesn't exist for "
                              "port %s"), port['id'])
            return epg

    def _get_subnet_details(self, plugin_context, port, details):
        # L2P might not exist for a pure Neutron port
        l2p = self._network_id_to_l2p(plugin_context, port['network_id'])
        # TODO(ivar): support shadow network
        #if not l2p and self._ptg_needs_shadow_network(context, ptg):
        #    l2p = self._get_l2_policy(context._plugin_context,
        #                              ptg['l2_policy_id'])

        subnets = self._get_subnets(
            plugin_context,
            filters={'id': [ip['subnet_id'] for ip in port['fixed_ips']]})
        for subnet in subnets:
            dhcp_ips = set()
            for port in self._get_ports(
                    plugin_context,
                    filters={
                        'network_id': [subnet['network_id']],
                        'device_owner': [n_constants.DEVICE_OWNER_DHCP]}):
                dhcp_ips |= set([x['ip_address'] for x in port['fixed_ips']
                                 if x['subnet_id'] == subnet['id']])
            dhcp_ips = list(dhcp_ips)
            if not subnet['dns_nameservers']:
                # Use DHCP namespace port IP
                subnet['dns_nameservers'] = dhcp_ips
            # Set Default & Metadata routes if needed
            default_route = metadata_route = {}
            if subnet['ip_version'] == 4:
                for route in subnet['host_routes']:
                    if route['destination'] == '0.0.0.0/0':
                        default_route = route
                    if route['destination'] == dhcp.METADATA_DEFAULT_CIDR:
                        metadata_route = route
                if not l2p or not l2p['inject_default_route']:
                    # In this case we do not want to send the default route
                    # and the metadata route. We also do not want to send
                    # the gateway_ip for the subnet.
                    if default_route:
                        subnet['host_routes'].remove(default_route)
                    if metadata_route:
                        subnet['host_routes'].remove(metadata_route)
                    del subnet['gateway_ip']
                else:
                    # Set missing routes
                    if not default_route:
                        subnet['host_routes'].append(
                            {'destination': '0.0.0.0/0',
                             'nexthop': subnet['gateway_ip']})
                    if not metadata_route and dhcp_ips and (
                        not self.enable_metadata_opt):
                        subnet['host_routes'].append(
                            {'destination': dhcp.METADATA_DEFAULT_CIDR,
                             'nexthop': dhcp_ips[0]})
            subnet['dhcp_server_ips'] = dhcp_ips
        return subnets

    def _get_aap_details(self, plugin_context, port, details):
        pt = self._port_id_to_pt(plugin_context, port['id'])
        aaps = port['allowed_address_pairs']
        if pt:
            # Set the correct address ownership for this port
            owned_addresses = self._get_owned_addresses(
                plugin_context, pt['port_id'])
            for allowed in aaps:
                if allowed['ip_address'] in owned_addresses:
                    # Signal the agent that this particular address is active
                    # on its port
                    allowed['active'] = True
        return aaps

    def _get_port_address_scope(self, plugin_context, port):
        for ip in port['fixed_ips']:
            subnet = self._get_subnet(plugin_context, ip['subnet_id'])
            subnetpool = self._get_subnetpools(
                plugin_context, filters={'id': [subnet['subnetpool_id']]})
            if subnetpool:
                address_scope = self._get_address_scopes(
                    plugin_context,
                    filters={'id': [subnetpool[0]['address_scope_id']]})
                if address_scope:
                    return address_scope[0]

    def _get_port_address_scope_cached(self, plugin_context, port, cache):
        if not cache.get('gbp_map_address_scope'):
            cache['gbp_map_address_scope'] = (
                self._get_port_address_scope(plugin_context, port))
        return cache['gbp_map_address_scope']

    # REVISIT(ivar): how the below info is retrieved depends on how the L3P
    # mapping is implemented. In theory, we should still be able to keeps
    # these methods unchanges as Neutron's Address Scopes and Address Pools
    # will be all we need to retrieve AIM's VRF
    def _get_vrf_id(self, plugin_context, port, details):
        # retrieve the Address Scope from the Neutron port
        address_scope = self._get_port_address_scope_cached(
            plugin_context, port, details['_cache'])
        # TODO(ivar): what should we return if Address Scope doesn't exist?
        return address_scope['id'] if address_scope else None

    def _get_port_vrf(self, plugin_context, port, details):
        address_scope = self._get_port_address_scope_cached(
            plugin_context, port, details['_cache'])
        if address_scope:
            vrf_name = self.name_mapper.address_scope(
                plugin_context.session, address_scope['id'],
                address_scope['name'])
            tenant_name = self.name_mapper.tenant(
                plugin_context.session, address_scope['tenant_id'])
            aim_ctx = aim_context.AimContext(plugin_context.session)
            epg = aim_resource.VRF(tenant_name=tenant_name, name=vrf_name)
            return self.aim.get(aim_ctx, epg)

    def _get_vrf_subnets(self, plugin_context, port, details):
        subnets = []
        address_scope = self._get_port_address_scope_cached(
            plugin_context, port, details['_cache'])
        if address_scope:
            # Get all the subnetpools associated with this Address Scope
            subnetpools = self._get_subnetpools(
                plugin_context,
                filters={'address_scope_id': [address_scope['id']]})
            for pool in subnetpools:
                subnets.extend(pool['prefixes'])
        return subnets
