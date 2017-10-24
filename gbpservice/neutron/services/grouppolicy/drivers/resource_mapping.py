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
import operator

from keystoneclient import exceptions as k_exceptions
from keystoneclient.v2_0 import client as k_client
from neutron.common import exceptions as neutron_exc
from neutron.db import api as db_api
from neutron.db import models_v2
from neutron.extensions import l3 as ext_l3
from neutron.extensions import securitygroup as ext_sg
from neutron_lib.api.definitions import port as port_def
from neutron_lib import constants as n_const
from neutron_lib import context as n_context
from neutron_lib.db import model_base
from neutron_lib import exceptions as n_exc
from neutron_lib.plugins import directory
from oslo_config import cfg
from oslo_db import exception as oslo_db_excp
from oslo_log import helpers as log
from oslo_log import log as logging
from oslo_utils import excutils
import sqlalchemy as sa
from sqlalchemy.orm import exc as sa_exc

from gbpservice.common import utils
from gbpservice.network.neutronv2 import local_api
from gbpservice.neutron.db.grouppolicy import group_policy_db as gpdb
from gbpservice.neutron.db.grouppolicy import group_policy_mapping_db as gpmdb
from gbpservice.neutron.extensions import driver_proxy_group as proxy_ext
from gbpservice.neutron.extensions import group_policy as gp_ext
from gbpservice.neutron.services.grouppolicy import (
    group_policy_driver_api as api)
from gbpservice.neutron.services.grouppolicy.common import constants as gconst
from gbpservice.neutron.services.grouppolicy.common import exceptions as exc
from gbpservice.neutron.services.grouppolicy.common import utils as gbp_utils
from gbpservice.neutron.services.grouppolicy.drivers import nsp_manager


LOG = logging.getLogger(__name__)
DEFAULT_SG_PREFIX = 'gbp_%s'
SCI_CONSUMER_NOT_AVAILABLE = 'N/A'

opts = [
    cfg.ListOpt('dns_nameservers',
                default=[],
                help=_("List of DNS nameservers to be configured for the "
                       "PTG subnets")),
    cfg.StrOpt('default_ipv6_ra_mode',
               default=None,
               help=_("default IPv6 Router Advertisement mode for subnets "
                      "created implicitly for L3 policies. Valid values are "
                      "'slaac', 'dhcpv6-stateful', and 'dhcpv6-stateless'")),
    cfg.StrOpt('default_ipv6_address_mode',
               default=None,
               help=_("default IPv6 address assignment mode for subnets "
                      "created implicitly for L3 policies. Valid values are "
                      "'slaac', 'dhcpv6-stateful', and 'dhcpv6-stateless'")),
    cfg.BoolOpt('use_subnetpools',
               default=True,
               help=_("make use of neutron subnet pools and address scopes "
                      "as L3 policy resource")),
]

cfg.CONF.register_opts(opts, "resource_mapping")

# something to shorten the config family name
MAPPING_CFG = cfg.CONF.resource_mapping


class OwnedPort(model_base.BASEV2):
    """A Port owned by the resource_mapping driver."""

    __tablename__ = 'gpm_owned_ports'
    port_id = sa.Column(sa.String(36),
                        sa.ForeignKey('ports.id', ondelete='CASCADE'),
                        nullable=False, primary_key=True)


class OwnedSubnet(model_base.BASEV2):
    """A Subnet owned by the resource_mapping driver."""

    __tablename__ = 'gpm_owned_subnets'
    subnet_id = sa.Column(sa.String(36),
                          sa.ForeignKey('subnets.id', ondelete='CASCADE'),
                          nullable=False, primary_key=True)


class OwnedNetwork(model_base.BASEV2):
    """A Network owned by the resource_mapping driver."""

    __tablename__ = 'gpm_owned_networks'
    network_id = sa.Column(sa.String(36),
                           sa.ForeignKey('networks.id', ondelete='CASCADE'),
                           nullable=False, primary_key=True)


class OwnedAddressScope(model_base.BASEV2):
    """An Address Scope owned by the resource_mapping driver."""

    __tablename__ = 'gpm_owned_address_scopes'
    address_scope_id = sa.Column(sa.String(36),
                                 sa.ForeignKey('address_scopes.id',
                                               ondelete='CASCADE'),
                                 nullable=False, primary_key=True)


class OwnedSubnetpool(model_base.BASEV2):
    """A Subnetpool owned by the resource_mapping driver."""

    __tablename__ = 'gpm_owned_subnetpools'
    subnetpool_id = sa.Column(sa.String(36),
                              sa.ForeignKey('subnetpools.id',
                                            ondelete='CASCADE'),
                              nullable=False, primary_key=True)


class OwnedRouter(model_base.BASEV2):
    """A Router owned by the resource_mapping driver."""

    __tablename__ = 'gpm_owned_routers'
    router_id = sa.Column(sa.String(36),
                          sa.ForeignKey('routers.id', ondelete='CASCADE'),
                          nullable=False, primary_key=True)


class PolicyRuleSetSGsMapping(model_base.BASEV2):
    """PolicyRuleSet to SGs mapping DB."""

    __tablename__ = 'gpm_policy_rule_set_sg_mapping'
    policy_rule_set_id = sa.Column(sa.String(36),
                                   sa.ForeignKey('gp_policy_rule_sets.id',
                                                 ondelete='CASCADE'),
                                   nullable=False, primary_key=True)
    provided_sg_id = sa.Column(sa.String(36),
                               sa.ForeignKey('securitygroups.id'))
    consumed_sg_id = sa.Column(sa.String(36),
                               sa.ForeignKey('securitygroups.id'))


# This exception should never escape the driver.
class CidrInUse(exc.GroupPolicyInternalError):
    message = _("CIDR %(cidr)s in-use within L3 policy %(l3p_id)s")


class OwnedResourcesOperations(object):

    # TODO(Sumit): All the following operations can be condensed into
    # a single _mark_resource_owned() and _resource_is_owned() method,
    # by creating a resource to DB class name mapping.

    def _mark_port_owned(self, session, port_id):
        with session.begin(subtransactions=True):
            owned = OwnedPort(port_id=port_id)
            session.add(owned)

    def _port_is_owned(self, session, port_id):
        with session.begin(subtransactions=True):
            return (session.query(OwnedPort).
                    filter_by(port_id=port_id).
                    first() is not None)

    def _mark_subnet_owned(self, session, subnet_id):
        with session.begin(subtransactions=True):
            owned = OwnedSubnet(subnet_id=subnet_id)
            session.add(owned)

    def _subnet_is_owned(self, session, subnet_id):
        with session.begin(subtransactions=True):
            return (session.query(OwnedSubnet).
                    filter_by(subnet_id=subnet_id).
                    first() is not None)

    def _mark_network_owned(self, session, network_id):
        with session.begin(subtransactions=True):
            owned = OwnedNetwork(network_id=network_id)
            session.add(owned)

    def _network_is_owned(self, session, network_id):
        with session.begin(subtransactions=True):
            return (session.query(OwnedNetwork).
                    filter_by(network_id=network_id).
                    first() is not None)

    def _mark_router_owned(self, session, router_id):
        with session.begin(subtransactions=True):
            owned = OwnedRouter(router_id=router_id)
            session.add(owned)

    def _router_is_owned(self, session, router_id):
        with session.begin(subtransactions=True):
            return (session.query(OwnedRouter).
                    filter_by(router_id=router_id).
                    first() is not None)

    def _mark_address_scope_owned(self, session, address_scope_id):
        with session.begin(subtransactions=True):
            owned = OwnedAddressScope(address_scope_id=address_scope_id)
            session.add(owned)

    def _address_scope_is_owned(self, session, address_scope_id):
        with session.begin(subtransactions=True):
            return (session.query(OwnedAddressScope).
                    filter_by(address_scope_id=address_scope_id).
                    first() is not None)

    def _mark_subnetpool_owned(self, session, subnetpool_id):
        with session.begin(subtransactions=True):
            owned = OwnedSubnetpool(subnetpool_id=subnetpool_id)
            session.add(owned)

    def _subnetpool_is_owned(self, session, subnetpool_id):
        with session.begin(subtransactions=True):
            return (session.query(OwnedSubnetpool).
                    filter_by(subnetpool_id=subnetpool_id).
                    first() is not None)


class ImplicitResourceOperations(local_api.LocalAPI,
                                 nsp_manager.NetworkServicePolicyMappingMixin):

    L3P_ADDRESS_SCOPE_KEYS = {4: 'address_scope_v4_id',
                             6: 'address_scope_v6_id'}
    L3P_SUBNETPOOLS_KEYS = {4: 'subnetpools_v4',
                            6: 'subnetpools_v6'}

    def _sg_rule(self, plugin_context, tenant_id, sg_id, direction,
                 protocol=None, port_range=None, cidr=None,
                 ethertype=n_const.IPv4, unset=False):
        if port_range:
            port_min, port_max = (gpdb.GroupPolicyDbPlugin.
                                  _get_min_max_ports_from_range(port_range))
        else:
            port_min, port_max = None, None

        attrs = {'tenant_id': tenant_id,
                 'security_group_id': sg_id,
                 'direction': direction,
                 'ethertype': ethertype,
                 'protocol': protocol,
                 'port_range_min': port_min,
                 'port_range_max': port_max,
                 'remote_ip_prefix': cidr,
                 'remote_group_id': None}
        filters = {}
        for key in attrs:
            value = attrs[key]
            if value:
                filters[key] = [value]
        rule = self._get_sg_rules(plugin_context, filters)
        if unset:
            if rule:
                self._delete_sg_rule(plugin_context, rule[0]['id'])
        else:
            if not rule:
                # There was a bug in Neutron until stable/mitaka
                # which prevented duplicate SG rules being added.
                # Since that is fixed in stable/newton overlapping
                # SG rules can be added within the same tenant. We
                # actually dont want to add overlapping rules,
                # hence we check before adding.
                return self._create_sg_rule(plugin_context, attrs)
            else:
                return rule[0]

    def _create_gbp_sg(self, plugin_context, tenant_id, name, **kwargs):
        # This method sets up the attributes of security group
        attrs = {'tenant_id': tenant_id,
                 'name': name,
                 'description': '',
                 'security_group_rules': ''}
        attrs.update(kwargs)
        sg = self._create_sg(plugin_context, attrs)
        # Cleanup default rules
        for rule in self._get_sg_rules(plugin_context,
                                       filters={'security_group_id':
                                                [sg['id']]}):
            self._delete_sg_rule(plugin_context, rule['id'])
        return sg

    def _create_implicit_address_scope(self, context, **kwargs):
        attrs = {'tenant_id': context.current['tenant_id'],
                 'name': context.current['name'], 'ip_version':
                 context.current['ip_version'],
                 'shared': context.current.get('shared', False)}
        attrs.update(**kwargs)
        address_scope = self._create_address_scope(
            context._plugin_context, attrs)
        as_id = address_scope['id']
        self._mark_address_scope_owned(context._plugin_context.session, as_id)
        return address_scope

    def _use_implicit_address_scope(self, context, ip_version=4, **kwargs):
        address_scope = self._create_implicit_address_scope(
            context, name='l3p_' + context.current['name'] +
            '_' + str(ip_version), ip_version=ip_version, **kwargs)
        context.set_address_scope_id(address_scope['id'], ip_version)
        return address_scope

    def _cleanup_address_scope(self, plugin_context, address_scope_id):
        if self._address_scope_is_owned(plugin_context.session,
                                        address_scope_id):
            subpools = self._get_subnetpools(plugin_context,
                                             filters={'address_scope_id':
                                                      [address_scope_id]})
            if subpools:
                LOG.warning("Cannot delete implicitly created "
                            "address_scope %(id)s since it has "
                            "associated subnetpools: %(pools)s",
                            {'id': address_scope_id, 'pools': subpools})
            else:
                self._delete_address_scope(plugin_context, address_scope_id)

    def _create_implicit_subnetpool(self, context, **kwargs):
        attrs = {'tenant_id': context.current['tenant_id'],
                 'name': context.current['name'], 'ip_version':
                 context.current['ip_version'],
                 'default_prefixlen': context.current['subnet_prefix_length'],
                 'prefixes': gbp_utils.convert_ip_pool_string_to_list(
                     context.current['ip_pool']),
                 'shared': context.current.get('shared', False),
                 # Per current understanding, is_default is used for
                 # auto_allocation and is a per-tenant setting.
                 'is_default': False}
        attrs.update(**kwargs)
        subnetpool = self._create_subnetpool(
            context._plugin_context, attrs)
        sp_id = subnetpool['id']
        self._mark_subnetpool_owned(context._plugin_context.session, sp_id)
        return subnetpool

    def _use_implicit_subnetpool(self, context, address_scope_id,
                                 ip_version=4, **kwargs):
        subnetpool = self._create_implicit_subnetpool(
            context, name='l3p_' + context.current['name'],
            address_scope_id=address_scope_id, ip_version=ip_version, **kwargs)
        context.add_subnetpool(subnetpool_id=subnetpool['id'],
                               ip_version=ip_version)

    def _cleanup_subnetpool(self, plugin_context, subnetpool_id):
        if self._subnetpool_is_owned(plugin_context.session,
                                     subnetpool_id):
            subnets = self._get_subnets(plugin_context,
                                        filters={'subnetpool_id':
                                                 [subnetpool_id]})
            if subnets:
                LOG.warning("Cannot delete implicitly created "
                            "subnetpool %(id)s since it has "
                            "associated subnets: %(subnets)s",
                            {'id': subnetpool_id, 'subnets': subnets})
            else:
                self._delete_subnetpool(plugin_context, subnetpool_id)

    def _create_implicit_network(self, context, **kwargs):
        attrs = {'tenant_id': context.current['tenant_id'],
                 'name': context.current['name'], 'admin_state_up': True,
                 'shared': context.current.get('shared', False)}
        attrs.update(**kwargs)
        network = self._create_network(context._plugin_context, attrs)
        network_id = network['id']
        self._mark_network_owned(context._plugin_context.session, network_id)
        return network

    def _use_implicit_network(self, context, address_scope_v4=None,
                              address_scope_v6=None):
        network = self._create_implicit_network(
            context, name='l2p_' + context.current['name'],
            ipv4_address_scope=address_scope_v4,
            ipv6_address_scope=address_scope_v6)
        context.set_network_id(network['id'])

    def _cleanup_network(self, plugin_context, network_id):
        if self._network_is_owned(plugin_context.session, network_id):
            self._delete_network(plugin_context, network_id)

    def _generate_subnets_from_cidrs(self, context, l2p, l3p, cidrs,
                                     subnet_specifics):
        for usable_cidr in cidrs:
            try:
                attrs = {'tenant_id': context.current['tenant_id'],
                         'name': 'ptg_' + context.current['name'],
                         'network_id': l2p['network_id'],
                         'ip_version': l3p['ip_version'],
                         'cidr': usable_cidr,
                         'enable_dhcp': True,
                         'gateway_ip': n_const.ATTR_NOT_SPECIFIED,
                         'allocation_pools': n_const.ATTR_NOT_SPECIFIED,
                         'dns_nameservers': (
                             MAPPING_CFG.dns_nameservers or
                             n_const.ATTR_NOT_SPECIFIED),
                         'host_routes': n_const.ATTR_NOT_SPECIFIED}
                attrs.update(subnet_specifics)
                subnet = self._create_subnet(
                    context._plugin_context, attrs)
                yield subnet
            except n_exc.BadRequest:
                # This is expected (CIDR overlap within network) until
                # we have a proper subnet allocation algorithm. We
                # ignore the exception and repeat with the next CIDR.
                pass

    def _get_ptg_cidrs(self, context, ptgs, ptg_dicts=None):
        cidrs = []
        if ptg_dicts:
            ptgs = ptg_dicts
        else:
            ptgs = context._plugin.get_policy_target_groups(
                context._plugin_context.elevated(), filters={'id': ptgs})
        subnets = []
        for ptg in ptgs:
            subnets.extend(ptg['subnets'])

        if subnets:
            cidrs = [x['cidr'] for x in self._get_subnets(
                context._plugin_context.elevated(), {'id': subnets})]
        return cidrs

    def _get_subnet(self, context, subnet_id):
        context.session.expire_all()
        return super(ImplicitResourceOperations, self)._get_subnet(
            context, subnet_id)

    def _get_l3p_allocated_subnets(self, context, l3p_id):
        ptgs = context._plugin._get_l3p_ptgs(
            context._plugin_context.elevated(), l3p_id)
        return self._get_ptg_cidrs(context, None, ptg_dicts=ptgs)

    def _validate_and_add_subnet(self, context, subnet, l3p_id):
        subnet_id = subnet['id']
        session = context._plugin_context.session
        with session.begin(subtransactions=True):
            LOG.debug("starting validate_and_add_subnet transaction for "
                      "subnet %s", subnet_id)
            ptgs = context._plugin._get_l3p_ptgs(
                context._plugin_context.elevated(), l3p_id)
            allocated = netaddr.IPSet(
                iterable=self._get_ptg_cidrs(context, None,
                                             ptg_dicts=ptgs))
            cidr = subnet['cidr']
            if cidr in allocated:
                LOG.debug("CIDR %s in-use for L3P %s, allocated: %s",
                          cidr, l3p_id, allocated)
                raise CidrInUse(cidr=cidr, l3p_id=l3p_id)
            context.add_subnet(subnet_id)
            LOG.debug("ending validate_and_add_subnet transaction for "
                      "subnet %s", subnet_id)

    def _use_l2_proxy_implicit_subnets(self, context,
                                       subnet_specifics, l2p, l3p):
        LOG.debug("allocate subnets for L2 Proxy %s",
                  context.current['id'])
        proxied = context._plugin.get_policy_target_group(
            context._plugin_context, context.current['proxied_group_id'])
        subnets = self._get_subnets(context._plugin_context,
                                    {'id': proxied['subnets']})
        # Use the same subnets as the Proxied PTG
        generator = self._generate_subnets_from_cidrs(
            context, l2p, l3p, [x['cidr'] for x in subnets],
            subnet_specifics)
        # Unroll the generator
        subnets = [x for x in generator]
        subnet_ids = [x['id'] for x in subnets]
        for subnet_id in subnet_ids:
            self._mark_subnet_owned(
                context._plugin_context.session, subnet_id)
            context.add_subnet(subnet_id)
        return subnets

    def _use_normal_implicit_subnet(self, context, is_proxy, prefix_len,
                                    subnet_specifics, l2p, l3p):
        LOG.debug("allocate subnets for L3 Proxy or normal PTG %s",
                  context.current['id'])

        # REVISIT(rkukura): The folowing is a temporary allocation
        # algorithm that should be replaced with use of a neutron
        # subnet pool.
        pool = netaddr.IPSet(gbp_utils.convert_ip_pool_string_to_list(
            l3p['proxy_ip_pool']) if is_proxy else
            gbp_utils.convert_ip_pool_string_to_list(l3p['ip_pool']))
        prefixlen = prefix_len or (
            l3p['proxy_subnet_prefix_length'] if is_proxy
            else l3p['subnet_prefix_length'])
        l3p_id = l3p['id']
        allocated = netaddr.IPSet(
            iterable=self._get_l3p_allocated_subnets(
                context, l3p_id))
        available = pool - allocated
        available.compact()

        for cidr in sorted(available.iter_cidrs(),
                           key=operator.attrgetter('prefixlen'),
                           reverse=True):
            if prefixlen < cidr.prefixlen:
                # Close the loop, no remaining subnet is big enough
                # for this allocation
                break
            generator = self._generate_subnets_from_cidrs(
                context, l2p, l3p, cidr.subnet(prefixlen),
                subnet_specifics)
            for subnet in generator:
                LOG.debug("Trying subnet %s for PTG %s", subnet,
                          context.current['id'])
                subnet_id = subnet['id']
                try:
                    self._mark_subnet_owned(context._plugin_context.session,
                                            subnet_id)
                    self._validate_and_add_subnet(context, subnet, l3p_id)
                    LOG.debug("Using subnet %s for PTG %s", subnet,
                              context.current['id'])
                    return [subnet]
                except CidrInUse:
                    # This exception is expected when a concurrent
                    # request has beat this one to calling
                    # _validate_and_add_subnet() using the same
                    # available CIDR. We delete the subnet and try the
                    # next available CIDR.
                    self._delete_subnet(context._plugin_context,
                                        subnet['id'])
                except n_exc.InvalidInput:
                    # This exception is not expected. We catch this
                    # here so that it isn't caught below and handled
                    # as if the CIDR is already in use.
                    self._delete_subnet(context._plugin_context,
                                        subnet['id'])
                    raise exc.GroupPolicyInternalError()

        raise exc.NoSubnetAvailable()

    def _use_implicit_subnet(self, context, is_proxy=False, prefix_len=None,
                             subnet_specifics=None):
        subnet_specifics = subnet_specifics or {}
        l2p_id = context.current['l2_policy_id']
        l2p = context._plugin.get_l2_policy(context._plugin_context, l2p_id)
        l3p_id = l2p['l3_policy_id']
        l3p = context._plugin.get_l3_policy(context._plugin_context, l3p_id)
        if (is_proxy and
                context.current['proxy_type'] == proxy_ext.PROXY_TYPE_L2):
            # In case of L2 proxy
            return self._use_l2_proxy_implicit_subnets(
                context, subnet_specifics, l2p, l3p)
        else:
            # In case of non proxy PTG or L3 Proxy
            return self._use_normal_implicit_subnet(
                context, is_proxy, prefix_len, subnet_specifics, l2p, l3p)

    def _use_implicit_subnet_from_subnetpool(
        self, context, subnet_specifics=None):
        # If a subnet needs to be created with a prefix_length other than
        # the subnet_prefix_length set for the l3_policy, a 'prefixlen' can be
        # passed explicitly in the subnet_specifics dict.
        # If a subnet with a specific CIDR needs to be created, the 'cidr' can
        # be passed explicitly in the subnet_specifics dict.
        # Note that either 'prefixlen' or 'cidr' can be requested, not both.
        # If a 'subnetpool_id' other than the one considered default is to be
        # used, it can be passed explicitly in the subnet_specifics dict.
        subnet_specifics = subnet_specifics or {}
        l2p_id = context.current['l2_policy_id']
        l2p = context._plugin.get_l2_policy(context._plugin_context, l2p_id)
        l3p_id = l2p['l3_policy_id']
        l3p_db = context._plugin.get_l3_policy(context._plugin_context, l3p_id)
        # Only allocate from subnetpools that belong to this tenant
        subnets = []
        for ip_version in (4, 6):
            # continue if no address scope defined for this ip version
            if not l3p_db[self.L3P_ADDRESS_SCOPE_KEYS[ip_version]]:
                continue

            filters = {'tenant_id': [context.current['tenant_id']],
                       'id': l3p_db[self.L3P_SUBNETPOOLS_KEYS[ip_version]]}
            # All relevant subnetpools owned by this tenant
            candidate_subpools = self._get_subnetpools(
                context._plugin_context, filters) or []
            del filters['tenant_id']
            filters['shared'] = [True]
            # All relevant shared subnetpools
            shared_subpools = self._get_subnetpools(
                context._plugin_context, filters) or []
            # Union of the above two lists of subnetpools
            candidate_subpools = {x['id']: x for x in candidate_subpools +
                                  shared_subpools}.values()
            subnet = None
            for pool in candidate_subpools:
                try:
                    attrs = {'tenant_id': context.current['tenant_id'],
                             'name': 'ptg_' + context.current['name'],
                             'network_id': l2p['network_id'],
                             'ip_version': ip_version,
                             'subnetpool_id': pool['id'],
                             'cidr': n_const.ATTR_NOT_SPECIFIED,
                             'prefixlen': n_const.ATTR_NOT_SPECIFIED,
                             'enable_dhcp': True,
                             'gateway_ip': n_const.ATTR_NOT_SPECIFIED,
                             'allocation_pools': n_const.ATTR_NOT_SPECIFIED,
                             'dns_nameservers': (
                                 MAPPING_CFG.dns_nameservers or
                                 n_const.ATTR_NOT_SPECIFIED),
                             'host_routes': n_const.ATTR_NOT_SPECIFIED}
                    if ip_version == 6:
                        if 'ipv6_ra_mode' not in subnet_specifics:
                            subnet_specifics['ipv6_ra_mode'] = (
                                MAPPING_CFG.default_ipv6_ra_mode or
                                n_const.ATTR_NOT_SPECIFIED)
                        if 'ipv6_address_mode' not in subnet_specifics:
                            subnet_specifics['ipv6_address_mode'] = (
                                MAPPING_CFG.default_ipv6_address_mode or
                                n_const.ATTR_NOT_SPECIFIED)
                    attrs.update(subnet_specifics)
                    subnet = self._create_subnet(context._plugin_context,
                                                 attrs)
                    self._mark_subnet_owned(context._plugin_context.session,
                                            subnet['id'])
                    LOG.debug("Allocated subnet %(sub)s from subnetpool: "
                              "%(sp)s.", {'sub': subnet['id'],
                                          'sp': pool['id']})
                    subnets.append(subnet)
                    break
                except Exception as e:
                    if isinstance(e, oslo_db_excp.RetryRequest):
                        raise e
                    LOG.info("Allocating subnet from subnetpool %(sp)s "
                             "failed. Allocation will be attempted "
                             "from any other configured "
                             "subnetpool(s). Exception: %(excp)s",
                             {'sp': pool['id'], 'excp': type(e)})
                    last = e
                    continue

        if subnets:
            return subnets
        else:
            # In the case of multiple subnetpools configured, the failure
            # condition for subnet allocation on earlier subnetpools might
            # be different from that on the last one, however it might still
            # be more helpful to propagate this last exception instead of
            # a generic exception.
            raise last

    def _cleanup_subnet(self, plugin_context, subnet_id, router_id=None):
        interface_info = {'subnet_id': subnet_id}
        if router_id:
            try:
                self._remove_router_interface(plugin_context, router_id,
                                              interface_info)
            except ext_l3.RouterInterfaceNotFoundForSubnet:
                LOG.debug("Ignoring RouterInterfaceNotFoundForSubnet cleaning "
                          "up subnet: %s", subnet_id)
        if self._subnet_is_owned(plugin_context.session, subnet_id):
            self._delete_subnet(plugin_context, subnet_id)

    def _get_default_security_group(self, plugin_context, ptg_id,
                                    tenant_id):
        port_name = DEFAULT_SG_PREFIX % ptg_id
        filters = {'name': [port_name], 'tenant_id': [tenant_id]}
        default_group = self._get_sgs(plugin_context, filters)
        return default_group[0]['id'] if default_group else None

    def _use_implicit_port(self, context, subnets=None):
        ptg_id = context.current['policy_target_group_id']
        ptg = context._plugin.get_policy_target_group(
            context._plugin_context, ptg_id)
        l2p_id = ptg['l2_policy_id']
        l2p = context._plugin.get_l2_policy(context._plugin_context, l2p_id)
        sg_id = self._get_default_security_group(
            context._plugin_context, ptg_id, context.current['tenant_id'])
        last = exc.NoSubnetAvailable()
        subnets = subnets or self._get_subnets(context._plugin_context,
                                               {'id': ptg['subnets']})
        v4_subnets = [subnet for subnet in subnets
                      if subnet['ip_version'] == 4]
        v6_subnets = [subnet for subnet in subnets
                      if subnet['ip_version'] == 6]
        for subnet in subnets:
            def subnet_family_generator(family_subnets):
                def inner():
                    for subnet in family_subnets:
                        yield subnet
                return inner
            # For dual-stack, try to create with this subnet and
            # a subnet from the other address family. Try this for
            # each address family
            if not (v4_subnets and v6_subnets):
                # for single stack, we need the empty list to
                # guarantee a single iteration
                subnet_generator = subnet_family_generator([''])
            elif subnet['ip_version'] == 4:
                subnet_generator = subnet_family_generator(v6_subnets)
            else:
                subnet_generator = subnet_family_generator(v4_subnets)
            for alt_subnet in subnet_generator():
                fixed_ips = [{'subnet_id': subnet['id']}]
                if alt_subnet:
                    fixed_ips.append({'subnet_id': alt_subnet['id']})
                try:
                    attrs = {'tenant_id': context.current['tenant_id'],
                             'name': 'pt_' + context.current['name'],
                             'network_id': l2p['network_id'],
                             'mac_address': n_const.ATTR_NOT_SPECIFIED,
                             'fixed_ips': fixed_ips,
                             'device_id': '',
                             'device_owner': '',
                             'security_groups': [sg_id] if sg_id else None,
                             'admin_state_up': True}
                    if context.current.get('group_default_gateway'):
                        attrs['fixed_ips'][0]['ip_address'] = subnet[
                            'gateway_ip']
                    attrs.update(context.current.get('port_attributes', {}))
                    port = self._create_port(context._plugin_context, attrs)
                    port_id = port['id']
                    self._mark_port_owned(context._plugin_context.session,
                                          port_id)
                    context.set_port_id(port_id)
                    return
                except n_exc.IpAddressGenerationFailure as ex:
                    LOG.warning("No more address available in subnet %s",
                                subnet['id'])
                    last = ex
        raise last

    def _cleanup_port(self, plugin_context, port_id):
        if self._port_is_owned(plugin_context.session, port_id):
            try:
                self._delete_port(plugin_context, port_id)
            except n_exc.PortNotFound:
                LOG.warning("Port %s is missing", port_id)

    def _reject_invalid_router_access(self, context):
        # Validate if the explicit router(s) belong to the tenant.
        # Are routers shared across tenants ??
        # How to check if admin and if admin can access all routers ??
        for router_id in context.current['routers']:
            router = None
            try:
                router = self._get_router(context._plugin_context, router_id)
            except n_exc.NotFound:
                raise exc.InvalidRouterAccess(
                    msg="Can't access other tenants router",
                    router_id=router_id,
                    tenant_id=context.current['tenant_id'])

            if router:
                tenant_id_of_explicit_router = router['tenant_id']
                curr_tenant_id = context.current['tenant_id']
                if tenant_id_of_explicit_router != curr_tenant_id:
                    raise exc.InvalidRouterAccess(
                        msg="Can't access other tenants router",
                        router_id=router_id,
                        tenant_id=context.current['tenant_id'])

    def _use_implicit_router(self, context, router_name=None):
        attrs = {'tenant_id': context.current['tenant_id'],
                 'name': router_name or ('l3p_' + context.current['name']),
                 'external_gateway_info': None,
                 'admin_state_up': True}
        router = self._create_router(context._plugin_context, attrs)
        router_id = router['id']
        self._mark_router_owned(context._plugin_context.session, router_id)
        context.add_router(router_id)
        return router_id

    def _cleanup_router(self, plugin_context, router_id):
        if self._router_is_owned(plugin_context.session, router_id):
            self._delete_router(plugin_context, router_id)

    def _plug_router_to_subnet(self, plugin_context, subnet_id, router_id):
        interface_info = {'subnet_id': subnet_id}
        if router_id:
            try:
                self._add_router_interface(plugin_context, router_id,
                                           interface_info)
            except n_exc.BadRequest as e:
                LOG.exception("Adding subnet to router failed, exception:"
                              "%s", e)
                raise exc.GroupPolicyInternalError()

    def _add_router_interface_for_subnet(self, context, router_id, subnet_id):
        self._plug_router_to_subnet(
            context._plugin_context, subnet_id, router_id)

    def _get_l3p_for_l2policy(self, context, l2p_id):
        l2p = context._plugin.get_l2_policy(context._plugin_context, l2p_id)
        l3p_id = l2p['l3_policy_id']
        l3p = context._plugin.get_l3_policy(context._plugin_context, l3p_id)
        return l3p

    def _create_router_gw_for_external_segment(self, plugin_context, es,
                                               es_dict, router_id):
        subnet = self._get_subnet(plugin_context.elevated(), es['subnet_id'])
        external_fixed_ips = [
            {'subnet_id': es['subnet_id'], 'ip_address': x}
            if x else {'subnet_id': es['subnet_id']}
            for x in es_dict[es['id']]
        ] if es_dict[es['id']] else [{'subnet_id': es['subnet_id']}]
        interface_info = {
            'network_id': subnet['network_id'],
            'enable_snat': es['port_address_translation'],
            'external_fixed_ips': external_fixed_ips}
        router = self._add_router_gw_interface(
            plugin_context, router_id, interface_info)
        return router

    def _reject_non_shared_net_on_shared_l2p(self, context):
        if context.current.get('shared') and context.current['network_id']:
            net = self._get_network(
                context._plugin_context, context.current['network_id'])
            if not net.get('shared'):
                raise exc.NonSharedNetworkOnSharedL2PolicyNotSupported()

    def _reject_invalid_network_access(self, context):
        # Validate if the explicit network belongs to the tenant.
        # Are networks shared across tenants ??
        # How to check if admin and if admin can access all networks ??
        if context.current['network_id']:
            network_id = context.current['network_id']
            plugin_context = context._plugin_context
            network = None
            try:
                network = self._get_network(plugin_context, network_id)
            except n_exc.NetworkNotFound:
                raise exc.InvalidNetworkAccess(
                    msg="Can't access other tenants networks",
                    network_id=context.current['network_id'],
                    tenant_id=context.current['tenant_id'])

            if network:
                tenant_id_of_explicit_net = network['tenant_id']
                if tenant_id_of_explicit_net != context.current['tenant_id']:
                    raise exc.InvalidNetworkAccess(
                        msg="Can't access other tenants networks",
                        network_id=context.current['network_id'],
                        tenant_id=context.current['tenant_id'])

    def _add_nat_pool_to_segment(self, context):
        external_segment = context._plugin.get_external_segment(
            context._plugin_context, context.current['external_segment_id'])
        if not external_segment['subnet_id']:
            raise exc.ESSubnetRequiredForNatPool()
        ext_sub = self._get_subnet(context._plugin_context,
                                   external_segment['subnet_id'])
        # Verify there's no overlap. This will also be verified by Neutron at
        # subnet creation, but we try to fail as soon as possible to return
        # a nicer error to the user (concurrency may still need to fallback on
        # Neutron's validation).
        ext_subs = self._get_subnets(context._plugin_context,
                                     {'network_id': [ext_sub['network_id']]})
        peer_pools = context._plugin.get_nat_pools(
                context._plugin_context.elevated(),
                {'id': external_segment['nat_pools']})
        peer_set = netaddr.IPSet(
            [x['ip_pool'] for x in peer_pools if
             x['id'] != context.current['id']])
        curr_ip_set = netaddr.IPSet([context.current['ip_pool']])
        if peer_set & curr_ip_set:
            # Raise for overlapping CIDRs
            raise exc.OverlappingNATPoolInES(
                es_id=external_segment['id'], np_id=context.current['id'])
        # A perfect subnet overlap is allowed as long as the subnet can be
        # assigned to the pool.
        match = [x for x in ext_subs if x['cidr'] ==
                 context.current['ip_pool']]
        if match:
            # There's no owning peer given the overlapping check above.
            # Use this subnet on the current Nat pool
            context._plugin._set_db_np_subnet(
                context._plugin_context, context.current, match[0]['id'])
        elif netaddr.IPSet([x['cidr'] for x in ext_subs]) & curr_ip_set:
            # Partial overlapp not allowed
            raise exc.OverlappingSubnetForNATPoolInES(
                net_id=ext_sub['network_id'], np_id=context.current['id'])
        # At this point, either a subnet was assigned to the NAT Pool, or a new
        # one needs to be created by the postcommit operation.

    def _use_implicit_nat_pool_subnet(self, context):
        es = context._plugin.get_external_segment(
            context._plugin_context, context.current['external_segment_id'])
        ext_sub = self._get_subnet(context._plugin_context, es['subnet_id'])
        attrs = {'tenant_id': context.current['tenant_id'],
                 'name': 'ptg_' + context.current['name'],
                 'network_id': ext_sub['network_id'],
                 'ip_version': context.current['ip_version'],
                 'cidr': context.current['ip_pool'],
                 'enable_dhcp': False,
                 'gateway_ip': n_const.ATTR_NOT_SPECIFIED,
                 'allocation_pools': n_const.ATTR_NOT_SPECIFIED,
                 'dns_nameservers': n_const.ATTR_NOT_SPECIFIED,
                 'host_routes': n_const.ATTR_NOT_SPECIFIED}
        subnet = self._create_subnet(context._plugin_context, attrs)
        context._plugin._set_db_np_subnet(
            context._plugin_context, context.current, subnet['id'])
        self._mark_subnet_owned(context._plugin_context.session, subnet['id'])
        return subnet

    def _process_ext_segment_update_for_nat_pool(self, context):
        nsps_using_nat_pool = self._get_nsps_using_nat_pool(context)
        if (context.original['external_segment_id'] !=
                context.current['external_segment_id']):
            if nsps_using_nat_pool:
                raise exc.NatPoolinUseByNSP()
            # Clean the current subnet_id. The subnet itself will be
            # cleaned by the postcommit operation
            context._plugin._set_db_np_subnet(
                context._plugin_context, context.current, None)
            self._add_nat_pool_to_segment(context)

    def _add_implicit_subnet_for_nat_pool_update(self, context):
        # For backward compatibility, do the following only if the external
        # segment changed
        if (context.original['external_segment_id'] !=
                context.current['external_segment_id']):
            if context.original['subnet_id']:
                if self._subnet_is_owned(context._plugin_context.session,
                                         context.original['subnet_id']):
                    self._delete_subnet(context._plugin_context,
                                        context.original['subnet_id'])
            if (context.current['external_segment_id'] and not
                    context.current['subnet_id']):
                self._use_implicit_nat_pool_subnet(context)

    def _add_implicit_subnet_for_nat_pool_create(self, context):
        if (context.current['external_segment_id'] and not
                context.current['subnet_id']):
            self._use_implicit_nat_pool_subnet(context)

    def _get_nsps_using_nat_pool(self, context):
        external_segment = context._plugin.get_external_segment(
            context._plugin_context, context.current['external_segment_id'])
        l3_policies = external_segment['l3_policies']
        l3_policies = context._plugin.get_l3_policies(
                    context._plugin_context, filters={'id': l3_policies})
        l2_policies = []
        for x in l3_policies:
            l2_policies.extend(x['l2_policies'])
        l2_policies = context._plugin.get_l2_policies(
                    context._plugin_context, filters={'id': l2_policies})
        ptgs = []
        for l2_policy in l2_policies:
            ptgs.extend(l2_policy['policy_target_groups'])
        ptgs = context._plugin.get_policy_target_groups(
                    context._plugin_context, filters={'id': ptgs})
        nsps = [x['network_service_policy_id'] for x in ptgs
                if x['network_service_policy_id']]
        nsps = context._plugin.get_network_service_policies(
            context._plugin_context, filters={'id': nsps})
        nsps_using_nat_pool = []
        for nsp in nsps:
            nsp_params = nsp.get("network_service_params")
            for nsp_param in nsp_params:
                if nsp_param['value'] == "nat_pool":
                    nsps_using_nat_pool.append(nsp)
                    break
        return nsps_using_nat_pool

    def _check_nat_pool_subnet_in_use(self, plugin_context, nat_pool):
        if not self._subnet_is_owned(plugin_context.session,
                                     nat_pool['subnet_id']):
            return
        # check if there are any ports with an address in nat-pool subnet
        ports = self._get_ports(plugin_context.elevated(),
            filters={'fixed_ips': {'subnet_id': [nat_pool['subnet_id']]}})
        if ports:
            raise exc.NatPoolInUseByPort()

    def _nat_pool_in_use(self, context):
        nsps_using_nat_pool = self._get_nsps_using_nat_pool(context)
        if nsps_using_nat_pool:
            raise exc.NatPoolinUseByNSP()
        self._check_nat_pool_subnet_in_use(context._plugin_context,
                                           context.current)

    def _delete_subnet_on_nat_pool_delete(self, context):
        if context.current['subnet_id']:
            if self._subnet_is_owned(context._plugin_context.session,
                                     context.current['subnet_id']):
                self._delete_subnet(context._plugin_context,
                                    context.current['subnet_id'])

    def _validate_nsp_parameters(self, context):
        nsp = context.current
        nsp_params = nsp.get("network_service_params")

        supported_static_nsp_pars = {
            gconst.GP_NETWORK_SVC_PARAM_TYPE_IP_SINGLE: [
                gconst.GP_NETWORK_SVC_PARAM_VALUE_SELF_SUBNET,
                gconst.GP_NETWORK_SVC_PARAM_VALUE_NAT_POOL],
            gconst.GP_NETWORK_SVC_PARAM_TYPE_IP_POOL: [
                gconst.GP_NETWORK_SVC_PARAM_VALUE_NAT_POOL]}

        # for params without a static value - later evaluation needed:
        supported_flexible_nsp_params = (
            gconst.GP_NETWORK_SVC_PARAM_TYPE_QOS_BURST,
            gconst.GP_NETWORK_SVC_PARAM_TYPE_QOS_MAX)

        # validate unique param types:
        types_inside = set((d['type'] for d in nsp_params))
        if len(types_inside) != len(nsp_params):
            raise exc.InvalidNetworkServiceParameters()

        for params in nsp_params:
            type_ = params.get("type")
            value_ = params.get("value")
            if (type_ not in supported_flexible_nsp_params):
                if (type_ not in supported_static_nsp_pars or
                    value_ not in supported_static_nsp_pars[type_]):
                    raise exc.InvalidNetworkServiceParameters()
            else:
                try:
                    if int(value_) < 0:
                        raise exc.InvalidNetworkServiceParameters()
                except ValueError:
                    raise exc.InvalidNetworkServiceParameters()

    def _validate_in_use_by_nsp(self, context):
        # We do not allow ES update for L3p when it is used by NSP
        # At present we do not support multiple ES, so adding a new ES is
        # not an issue here
        if (context.original['external_segments'] !=
            context.current['external_segments'] and
            context.original['external_segments']):
            l2_policies = context.current['l2_policies']
            l2_policies = context._plugin.get_l2_policies(
                    context._plugin_context, filters={'id': l2_policies})
            ptgs = []
            for l2p in l2_policies:
                ptgs.extend(l2p['policy_target_groups'])
            ptgs = context._plugin.get_policy_target_groups(
                    context._plugin_context, filters={'id': ptgs})
            nsps = [x['network_service_policy_id'] for x in ptgs
                    if x['network_service_policy_id']]
            if nsps:
                nsps = context._plugin.get_network_service_policies(
                    context._plugin_context, filters={'id': nsps})
                for nsp in nsps:
                    nsp_params = nsp.get("network_service_params")
                    for nsp_param in nsp_params:
                        if nsp_param['value'] == "nat_pool":
                            raise exc.L3PEsinUseByNSP()

    def _associate_fip_to_pt(self, context):
        ptg_id = context.current['policy_target_group_id']
        ptg = context._plugin.get_policy_target_group(
            context._plugin_context, ptg_id)
        network_service_policy_id = ptg.get(
            "network_service_policy_id")
        if not network_service_policy_id:
            return

        nsp = context._plugin.get_network_service_policy(
            context._plugin_context, network_service_policy_id)
        nsp_params = nsp.get("network_service_params")
        for nsp_parameter in nsp_params:
            if (nsp_parameter["type"] == "ip_pool" and
                nsp_parameter["value"] == "nat_pool"):
                fip_ids = self._allocate_floating_ips(
                    context, ptg['l2_policy_id'], context.current['port_id'])
                self._set_pt_floating_ips_mapping(
                    context._plugin_context,
                    context.current['id'],
                    fip_ids)
                return

    def _retrieve_es_with_nat_pools(self, context, l2_policy_id):
        es_list_with_nat_pools = []
        l2p = context._plugin.get_l2_policy(
                    context._plugin_context, l2_policy_id)
        l3p = context._plugin.get_l3_policy(context._plugin_context,
                                            l2p['l3_policy_id'])
        external_segments = l3p.get('external_segments').keys()
        if not external_segments:
            return es_list_with_nat_pools
        external_segments = context._plugin.get_external_segments(
            context._plugin_context,
            filters={'id': external_segments})
        for es in external_segments:
            if es['nat_pools']:
                es_list_with_nat_pools.append(es)
        return es_list_with_nat_pools

    def _gen_nat_pool_in_ext_seg(self, context, tenant_id, es):
        nat_pools = context._plugin.get_nat_pools(
            context._plugin_context.elevated(), {'id': es['nat_pools']})
        no_subnet_pools = []
        for nat_pool in nat_pools:
            # For backward compatibility
            if not nat_pool['subnet_id']:
                no_subnet_pools.append(nat_pool)
            else:
                yield nat_pool
        for nat_pool in no_subnet_pools:
            # Use old allocation method
            yield nat_pool

    def _allocate_floating_ips(self, context, l2_policy_id, fixed_port=None,
                               external_segments=None):
        if not external_segments:
            external_segments = self._retrieve_es_with_nat_pools(
                                            context, l2_policy_id)
        fip_ids = []
        if not external_segments:
            LOG.error("Network Service Policy to allocate Floating IP "
                      "could not be applied because l3policy does "
                      "not have an attached external segment")
            return fip_ids
        tenant_id = context.current['tenant_id']

        # Retrieve Router ID
        l2p = context._plugin.get_l2_policy(context._plugin_context,
                                            l2_policy_id)
        l3p = context._plugin.get_l3_policy(context._plugin_context,
                                            l2p['l3_policy_id'])
        if l3p.get('routers'):
            routers = self._get_routers(context._plugin_context,
                                        filters={'id': l3p['routers']})
        else:
            routers = []
        for es in external_segments:
            ext_sub = self._get_subnet(context._plugin_context,
                                       es['subnet_id'])
            ext_net_id = ext_sub['network_id']
            fip_id = None
            # For each L3P for an ES, we need to find the router
            # that's connected to the external segment, so we can
            # use that router ID in the floating IP allocated by
            # a NAT pool on that ES.
            rid = None
            for router in routers:
                if not router['external_gateway_info']:
                    continue
                net = router['external_gateway_info'].get('network_id')
                if net == ext_net_id:
                    rid = router['id']
                    break

            for nat_pool in self._gen_nat_pool_in_ext_seg(
                context, tenant_id, es):
                try:
                    fip_id = self._create_floatingip(
                        context._plugin_context, tenant_id, ext_net_id,
                        fixed_port, subnet_id=nat_pool['subnet_id'],
                        router_id=rid)
                    # FIP allocated, no need to try further allocation
                    break
                except n_exc.IpAddressGenerationFailure as ex:
                    LOG.warning("Floating allocation failed: %s",
                                ex.message)
            if fip_id:
                fip_ids.append(fip_id)
        return fip_ids

    def _create_floatingip(self, plugin_context, tenant_id, ext_net_id,
                           internal_port_id=None, floating_ip_address=None,
                           subnet_id=None, router_id=None):
        attrs = {'tenant_id': tenant_id,
                 'floating_network_id': ext_net_id}
        if subnet_id:
            attrs.update({"subnet_id": subnet_id})
        if router_id:
            attrs['router_id'] = router_id
        if internal_port_id:
            attrs.update({"port_id": internal_port_id})
        if floating_ip_address:
            attrs.update({"floating_ip_address": floating_ip_address})
        fip = self._create_fip(plugin_context, attrs)
        return fip['id']

    def _cleanup_network_service_policy(self, context, ptg,
                                        ipaddress=None, fip_maps=None):
        if not ipaddress:
            ipaddress = self._get_ptg_policy_ipaddress_mapping(
                context._plugin_context, ptg['id'])
        if ipaddress and ptg['subnets']:
            # TODO(rkukura): Loop on subnets?
            self._restore_ip_to_allocation_pool(
                context, ptg['subnets'][0], ipaddress.ipaddress)
        self._delete_policy_ipaddress_mapping(
            context._plugin_context, ptg['id'])
        if not fip_maps:
            fip_maps = self._get_ptg_policy_fip_mapping(
                context._plugin_context, ptg['id'])
        for fip_map in fip_maps:
            self._delete_fip(context._plugin_context, fip_map.floatingip_id)
        self._delete_ptg_policy_fip_mapping(
            context._plugin_context, ptg['id'])

        for pt in ptg['policy_targets']:
            pt_fip_maps = self._get_pt_floating_ip_mapping(
                    context._plugin_context, pt)
            for pt_fip_map in pt_fip_maps:
                self._delete_fip(context._plugin_context,
                                 pt_fip_map.floatingip_id)
            self._delete_pt_floating_ip_mapping(
                context._plugin_context, pt)

    def _handle_nsp_update_on_ptg(self, context):
        old_nsp = context.original.get("network_service_policy_id")
        new_nsp = context.current.get("network_service_policy_id")
        if old_nsp != new_nsp:
            if old_nsp:
                self._cleanup_network_service_policy(
                                        context,
                                        context.original)
            if new_nsp:
                self._handle_network_service_policy(context)

    def _validate_nat_pool_for_nsp(self, context):
        network_service_policy_id = context.current.get(
            "network_service_policy_id")
        if not network_service_policy_id:
            return

        nsp = context._plugin.get_network_service_policy(
            context._plugin_context, network_service_policy_id)
        nsp_params = nsp.get("network_service_params")
        for nsp_parameter in nsp_params:
            external_segments = []
            if ((nsp_parameter["type"] == "ip_single" or
                 nsp_parameter["type"] == "ip_pool") and
                nsp_parameter["value"] == "nat_pool"):
                if context.current['l2_policy_id']:
                    l2p = context._plugin.get_l2_policy(
                        context._plugin_context,
                        context.current['l2_policy_id'])
                    l3p = context._plugin.get_l3_policy(
                        context._plugin_context, l2p['l3_policy_id'])
                    external_segments = l3p.get('external_segments').keys()
                    if external_segments:
                        external_segments = (
                            context._plugin.get_external_segments(
                                context._plugin_context,
                                filters={'id': external_segments}))
                else:
                    gpip = cfg.CONF.group_policy_implicit_policy
                    filter = {'tenant_id': [context.current['tenant_id']],
                              'name': [gpip.default_l3_policy_name]}
                    l3ps = context._plugin.get_l3_policies(
                                    context._plugin_context, filter)
                    if l3ps:
                        external_segments = l3ps[0].get(
                                                'external_segments').keys()
                        if external_segments:
                            external_segments = (
                                context._plugin.get_external_segments(
                                    context._plugin_context,
                                    filters={'id': external_segments}))
                    else:
                        external_segments = (
                            context._plugin.get_external_segments(
                                context._plugin_context,
                                filters={'name': [
                                        gpip.default_external_segment_name]}))
                if not external_segments:
                    LOG.error(
                        "Network Service Policy to allocate Floating "
                        "IP could not be associated because l3policy "
                        "does not have an attached external segment")
                    raise exc.NSPRequiresES()
                for es in external_segments:
                    if not es['nat_pools']:
                        raise exc.NSPRequiresNatPool()

    def _handle_network_service_policy(self, context):
        network_service_policy_id = context.current.get(
            "network_service_policy_id")
        if not network_service_policy_id:
            return
        nsp = context._plugin.get_network_service_policy(
            context._plugin_context, network_service_policy_id)
        nsp_params = nsp.get("network_service_params")

        for nsp_parameter in nsp_params:
            if (nsp_parameter["type"] == "ip_single" and
                nsp_parameter["value"] == "self_subnet"):
                # TODO(Magesh):Handle concurrency issues
                free_ip = self._get_last_free_ip(context._plugin_context,
                                                 context.current['subnets'])
                if not free_ip:
                    LOG.error("Reserving IP Addresses failed for Network "
                              "Service Policy. No more IP Addresses on "
                              "subnet")
                    return
                # TODO(Magesh):Fetch subnet from PTG to which NSP is attached
                self._remove_ip_from_allocation_pool(
                    context, context.current['subnets'][0], free_ip)
                self._set_policy_ipaddress_mapping(
                    context._plugin_context,
                    network_service_policy_id,
                    context.current['id'],
                    free_ip)
            elif (nsp_parameter["type"] == "ip_single" and
                  nsp_parameter["value"] == "nat_pool"):
                # REVISIT(Magesh): We are logging an error when FIP allocation
                # fails. Should we fail PT create instead ?
                fip_ids = self._allocate_floating_ips(
                    context, context.current['l2_policy_id'])
                for fip_id in fip_ids:
                    self._set_ptg_policy_fip_mapping(
                        context._plugin_context,
                        network_service_policy_id,
                        context.current['id'],
                        fip_id)
            elif (nsp_parameter["type"] == "ip_pool" and
                  nsp_parameter["value"] == "nat_pool"):
                policy_targets = context.current['policy_targets']
                policy_targets = context._plugin.get_policy_targets(
                    context._plugin_context, filters={'id': policy_targets})
                es_list = self._retrieve_es_with_nat_pools(
                        context, context.current['l2_policy_id'])
                pt_fip_map = {}
                for policy_target in policy_targets:
                    fip_ids = self._allocate_floating_ips(
                        context,
                        context.current['l2_policy_id'],
                        fixed_port=policy_target['port_id'],
                        external_segments=es_list)
                    if fip_ids:
                        pt_fip_map[policy_target['id']] = fip_ids
                if pt_fip_map:
                    self._set_pts_floating_ips_mapping(
                        context._plugin_context, pt_fip_map)

    def _restore_ip_to_allocation_pool(self, context, subnet_id, ip_address):
        # TODO(Magesh):Pass subnets and loop on subnets. Better to add logic
        # to Merge the pools together after Fragmentation
        subnet = self._get_subnet(context._plugin_context, subnet_id)
        allocation_pools = subnet['allocation_pools']
        for allocation_pool in allocation_pools:
            pool_end_ip = allocation_pool.get('end')
            if ip_address == str(netaddr.IPAddress(pool_end_ip) + 1):
                new_last_ip = ip_address
                allocation_pool['end'] = new_last_ip
                del subnet['gateway_ip']
                subnet = self._update_subnet(context._plugin_context,
                                             subnet['id'], subnet)
                return

        # TODO(Magesh):Have to test this logic. Add proper unit tests
        subnet['allocation_pools'].append({"start": ip_address,
                                          "end": ip_address})
        del subnet['gateway_ip']
        subnet = self._update_subnet(context._plugin_context,
                                     subnet['id'], subnet)

    def _remove_ip_from_allocation_pool(self, context, subnet_id, ip_address):
        # TODO(Magesh):Pass subnets and loop on subnets
        subnet = self._get_subnet(context._plugin_context, subnet_id)
        allocation_pools = subnet['allocation_pools']
        for allocation_pool in reversed(allocation_pools):
            if ip_address == allocation_pool.get('end'):
                new_last_ip = str(netaddr.IPAddress(ip_address) - 1)
                allocation_pool['end'] = new_last_ip
                del subnet['gateway_ip']
                self._update_subnet(context._plugin_context,
                                    subnet['id'], subnet)
                break

    def _get_last_free_ip(self, context, subnets):
        # Hope lock_mode update is not needed
        # REVISIT: Temp workaround, always assumes last IP in subnet is
        # available
        range_qry = context.session.query(models_v2.IPAllocationPool)
        for subnet_id in subnets:
            ip_range = range_qry.filter_by(subnet_id=subnet_id).first()
            if not ip_range:
                continue
            ip_address = ip_range['last_ip']
            return ip_address

    def _get_in_use_subnetpools_for_l3p(self, context):
        return [x.subnetpool_id for x in
                context._plugin_context.session.query(models_v2.Subnet).join(
                    gpmdb.PTGToSubnetAssociation,
                    gpmdb.PTGToSubnetAssociation.subnet_id ==
                    models_v2.Subnet.id
                ).join(gpmdb.PolicyTargetGroupMapping,
                       gpmdb.PTGToSubnetAssociation.policy_target_group_id ==
                       gpmdb.PolicyTargetGroupMapping.id).join(
                           gpmdb.L2PolicyMapping).join(
                               gpmdb.L3PolicyMapping).filter(
                                   gpmdb.L2PolicyMapping.l3_policy_id ==
                                   context.current['id']).all()]

    def _check_subnetpools_for_same_scope(self, context, subnetpools,
                                          ascp, prefixes=None):
        sp_ascp = None
        for sp_id in subnetpools:
            sp = self._get_subnetpool(
                # admin context to retrieve subnetpools from
                # other tenants
                context._plugin_context.elevated(), sp_id)
            if not sp['address_scope_id']:
                raise exc.NoAddressScopeForSubnetpool()
            if not sp_ascp:
                if ascp:
                    # This is the case where the address_scope
                    # was explicitly set for the l3p  and we need to
                    # check if it conflicts with the address_scope of
                    # the first subnetpool
                    if sp['address_scope_id'] != ascp:
                        raise exc.InconsistentAddressScopeSubnetpool()
                else:
                    # No address_scope was explicitly set for the l3p,
                    # so set it to that of the first subnetpool
                    ascp = sp['address_scope_id']
                sp_ascp = sp['address_scope_id']
            elif sp_ascp != sp['address_scope_id']:
                # all subnetpools do not have the same address_scope
                raise exc.InconsistentAddressScopeSubnetpool()
            # aggregate subnetpool prefixes
            sp_prefixlist = [prefix for prefix in sp['prefixes']]
            if prefixes:
                stripped = [prefix.strip() for prefix in prefixes.split(',')]
                prefixes = ', '.join(stripped + sp_prefixlist)
            else:
                prefixes = ', '.join(sp_prefixlist)
        return ascp, prefixes

    def _configure_l3p_for_multiple_subnetpools(self, context,
                                                l3p_db, ip_version=4,
                                                address_scope_id=None):
        l3p_req = context.current
        ascp_id_key = 'address_scope_v4_id' if ip_version == 4 else (
            'address_scope_v6_id')
        subpool_ids_key = 'subnetpools_v4' if ip_version == 4 else (
            'subnetpools_v6')
        # admin context to retrieve subnetpools from a different tenant
        address_scope_id, prefixes = self._check_subnetpools_for_same_scope(
            context, l3p_req[subpool_ids_key], address_scope_id,
            prefixes=l3p_db['ip_pool'])
        l3p_db[ascp_id_key] = address_scope_id
        l3p_db['ip_pool'] = prefixes
        if l3p_req['subnet_prefix_length']:
            l3p_db['subnet_prefix_length'] = l3p_req['subnet_prefix_length']

    def _create_l3p_subnetpools(self, context):
        l3p_req = context.current
        l3p_db = context._plugin._get_l3_policy(
            context._plugin_context, l3p_req['id'])
        # The ip_version tells us what should be supported
        ip_version = l3p_req['ip_version']
        l3p_db['ip_version'] = ip_version
        # First determine the address scope for the address
        # families specified in ip_version. We look first at
        # explicitly passed address scopes, then the address
        # scopes of the subnetpools, then the address scopes
        # of default defined subnetpool (via that extension),
        # or just create one if none are present
        ip_dict = {}
        ascp = None
        # for pools that need to be created, we
        # want to use subnet_prefix_length as the
        # default for v4 subnets, and /64 for v6
        # subnets. If a subnet_prefix_length wasn't
        # provided, we use the implict default
        if ip_version == 4 or ip_version == 46:
            ip_dict[4] = {'default_prefixlen':
                          l3p_req['subnet_prefix_length'] or 24}
        if ip_version == 6 or ip_version == 46:
            ip_dict[6] = {'default_prefixlen': 64}

        for family in ip_dict.keys():
            explicit_scope = l3p_req[self.L3P_ADDRESS_SCOPE_KEYS[family]]
            explicit_pools = l3p_req[self.L3P_SUBNETPOOLS_KEYS[family]]
            default_pool = self._core_plugin.get_default_subnetpool(
                context._plugin_context.elevated(), ip_version=family)
            ip_pool = gbp_utils.convert_ip_pool_string_to_list(
                l3p_req['ip_pool'])
            family_prefixes = [prefix for prefix in ip_pool
                               if netaddr.IPNetwork(prefix).version == family]
            if explicit_scope:
                ascp = explicit_scope
            elif explicit_pools:
                ascp, _ = self._check_subnetpools_for_same_scope(context,
                    explicit_pools, None)
                l3p_db[self.L3P_ADDRESS_SCOPE_KEYS[family]] = ascp
            elif family_prefixes:
                ascp = self._use_implicit_address_scope(
                    context, ip_version=family)['id']

            elif default_pool and default_pool.get('address_scope_id'):
                ascp = default_pool['address_scope_id']
            else:
                raise exc.NoValidAddressScope()

            if explicit_scope or explicit_pools:
                # In the case of explicitly provided address_scope or
                # subnetpools, set shared flag of L3P to the address_scope
                ascp_db = self._get_address_scope(
                    context._plugin_context, ascp)
                l3p_db['shared'] = ascp_db['shared']
                context.current['shared'] = l3p_db['shared']

            if not explicit_pools and family_prefixes:
                self._use_implicit_subnetpool(context,
                    address_scope_id=ascp,
                    ip_version=family, prefixes=family_prefixes,
                    default_prefixlen=ip_dict[family]['default_prefixlen'])
            elif not explicit_pools and default_pool:
                l3p_req[self.L3P_SUBNETPOOLS_KEYS[family]] = [
                    default_pool['id']]
                context._plugin._add_subnetpools_to_l3_policy(
                    context._plugin_context, l3p_db, [default_pool['id']],
                    ip_version=family)

            # TODO(Sumit): check that l3p['ip_pool'] does not overlap with an
            # existing subnetpool associated with the explicit address_scope
            self._configure_l3p_for_multiple_subnetpools(context,
                l3p_db, ip_version=family,
                address_scope_id=ascp)

    def _update_l3p_subnetpools(self, context):
        l3p_orig = context.original
        l3p_curr = context.current
        for family in (4, 6):
            subnetpools_key = self.L3P_SUBNETPOOLS_KEYS[family]
            address_scope_key = self.L3P_ADDRESS_SCOPE_KEYS[family]
            if (l3p_curr[subnetpools_key] and (
                l3p_curr[subnetpools_key] != l3p_orig[subnetpools_key])):
                l3p_db = context._plugin._get_l3_policy(
                    context._plugin_context, l3p_curr['id'])
                self._configure_l3p_for_multiple_subnetpools(context,
                    l3p_db, ip_version=family,
                    address_scope_id=l3p_db[address_scope_key])
                removed = list(set(l3p_orig[subnetpools_key]) -
                               set(l3p_curr[subnetpools_key]))
                for sp_id in removed:
                    if sp_id in self._get_in_use_subnetpools_for_l3p(context):
                        raise exc.IncorrectSubnetpoolUpdate(
                            subnetpool_id=sp_id, l3p_id=l3p_curr['id'])
                    # If an implicitly created subnetpool is being
                    # disassocaited we try to delete it
                    self._cleanup_subnetpool(context._plugin_context, sp_id)

    def _delete_l3p_subnetpools(self, context):

        subpools = []
        for sp_key in self.L3P_SUBNETPOOLS_KEYS.values():
            subpools += context.current[sp_key]
        for sp_id in subpools:
            self._cleanup_subnetpool(context._plugin_context, sp_id)

        for ascp_key in self.L3P_ADDRESS_SCOPE_KEYS.values():
            if context.current[ascp_key]:
                self._cleanup_address_scope(context._plugin_context,
                                            context.current[ascp_key])


class ResourceMappingDriver(api.PolicyDriver, ImplicitResourceOperations,
                            OwnedResourcesOperations):
    """Resource Mapping driver for Group Policy plugin.

    This driver implements group policy semantics by mapping group
    policy resources to various other neutron resources.
    """

    @log.log_method_call
    def initialize(self):
        self._cached_agent_notifier = None
        self._resource_owner_tenant_id = None

    @property
    def gbp_plugin(self):
        if not self._gbp_plugin:
            self._gbp_plugin = directory.get_plugin("GROUP_POLICY")
        return self._gbp_plugin

    def _reject_shared(self, object, type):
        if object.get('shared'):
            raise exc.InvalidSharedResource(type=type,
                                            driver='resource_mapping')

    def _reject_cross_tenant_ptg_l2p(self, context):
        if context.current['l2_policy_id']:
            l2p = context._plugin.get_l2_policy(
                context._plugin_context, context.current['l2_policy_id'])
            if l2p['tenant_id'] != context.current['tenant_id']:
                raise (
                    exc.
                    CrossTenantPolicyTargetGroupL2PolicyNotSupported())

    def _reject_cross_tenant_l2p_l3p(self, context):
        if context.current['tenant_id'] == self.resource_owner_tenant_id:
            # Relax cross tenancy condition when current tenant id is admin.
            # Relaxing when l2policy tenant id is of admin, to address the
            # case for proxy group where l2policy belongs to admin tenant
            # but l3policy belongs to user tenant.
            return
        # Can't create non shared L2p on a shared L3p
        if context.current['l3_policy_id']:
            l3p = context._plugin.get_l3_policy(
                context._plugin_context,
                context.current['l3_policy_id'])
            if l3p['tenant_id'] != context.current['tenant_id']:
                raise exc.CrossTenantL2PolicyL3PolicyNotSupported()

    def _associate_qosp_to_pt(self, context):
        ptg_id = context.current['policy_target_group_id']
        ptg = context._plugin.get_policy_target_group(
            context._plugin_context, ptg_id)
        network_service_policy_id = ptg.get(
            "network_service_policy_id")
        if not network_service_policy_id:
            return

        nsp = context._plugin.get_network_service_policy(
            context._plugin_context, network_service_policy_id)
        nsp_params = nsp.get("network_service_params")
        # Check if at least a QoS NSP p. is defined (a QoS policy was created)
        for nsp_parameter in nsp_params:
            if nsp_parameter["type"] in (
                    gconst.GP_NETWORK_SVC_PARAM_TYPE_QOS_MAX,
                    gconst.GP_NETWORK_SVC_PARAM_TYPE_QOS_BURST):

                # get QoS Policy associated to NSP
                mapping = self._get_nsp_qos_mapping(
                    context._plugin_context,
                    network_service_policy_id)

                # apply QoS policy to PT's Neutron port
                port_id = context.current['port_id']
                port = {port_def.RESOURCE_NAME:
                        {'qos_policy_id': mapping['qos_policy_id']}}
                self._core_plugin.update_port(context._plugin_context,
                                              port_id, port)
                break

    def _disassociate_qosp_from_pt(self, context, pt_id):
        try:
            policy_target = context._plugin.get_policy_target(
                context._plugin_context, pt_id)
        except gp_ext.PolicyTargetNotFound:
            LOG.warning("Attempted to fetch deleted Service Target (QoS)")
        else:
            port_id = policy_target['port_id']
            port = {port_def.RESOURCE_NAME: {'qos_policy_id': None}}
            self._core_plugin.update_port(context._plugin_context,
                                          port_id, port)

    def _cleanup_network_service_policy(self, context, ptg,
                                        ipaddress=None, fip_maps=None):
        super(ResourceMappingDriver, self)._cleanup_network_service_policy(
            context, ptg, ipaddress, fip_maps)
        for pt in ptg['policy_targets']:
            self._disassociate_qosp_from_pt(context, pt)

    def _handle_network_service_policy(self, context):
        network_service_policy_id = context.current.get(
            "network_service_policy_id")
        if not network_service_policy_id:
            return
        super(ResourceMappingDriver, self)._handle_network_service_policy(
            context)
        nsp = context._plugin.get_network_service_policy(
            context._plugin_context, network_service_policy_id)
        nsp_params = nsp.get("network_service_params")

        for nsp_parameter in nsp_params:
            if nsp_parameter["type"] in (
                    gconst.GP_NETWORK_SVC_PARAM_TYPE_QOS_MAX,
                    gconst.GP_NETWORK_SVC_PARAM_TYPE_QOS_BURST):

                # get PTs/ports
                policy_targets = context.current['policy_targets']
                policy_targets = context._plugin.get_policy_targets(
                    context._plugin_context, filters={'id': policy_targets})
                # get QoS Policy associated to NSP
                mapping = self._get_nsp_qos_mapping(
                    context._plugin_context,
                    nsp['id'])
                # apply QoS policy to each PT's Neutron port
                for pt in policy_targets:
                    port_id = pt['port_id']
                    port = {port_def.RESOURCE_NAME:
                            {'qos_policy_id': mapping['qos_policy_id']}}
                    self._core_plugin.update_port(context._plugin_context,
                                                  port_id, port)

    @property
    def resource_owner_tenant_id(self):
        if not self._resource_owner_tenant_id:
            self._resource_owner_tenant_id = (
                self._get_resource_owner_tenant_id())
        return self._resource_owner_tenant_id

    def _get_resource_owner_tenant_id(self):
        # Returns service tenant id, which specified in neutron conf
        try:
            user, pwd, tenant, auth_url = utils.get_keystone_creds()
            keystoneclient = k_client.Client(username=user, password=pwd,
                                             auth_url=auth_url)
            tenant = keystoneclient.tenants.find(name=tenant)
            return tenant.id
        except k_exceptions.NotFound:
            with excutils.save_and_reraise_exception(reraise=True):
                LOG.error('No tenant with name %s exists.', tenant)
        except k_exceptions.NoUniqueMatch:
            with excutils.save_and_reraise_exception(reraise=True):
                LOG.error('Multiple tenants matches found for %s', tenant)
        except k_exceptions.AuthorizationFailure:
            LOG.error("User: %(user)s dont have permissions",
                     {'user': user})
        except k_exceptions.Unauthorized:
            LOG.error("Wrong credentials provided: user: %(user)s, "
                      "password: %(pwd)s, tenant: %(tenant)s",
                     {'user': user, 'pwd': pwd, 'tenant': tenant})

    @log.log_method_call
    def create_policy_target_precommit(self, context):
        self._check_create_policy_target(context)

    def _check_create_policy_target(self, context, verify_port_subnet=True):
        self._validate_cluster_id(context)
        if not context.current['policy_target_group_id']:
            raise exc.PolicyTargetRequiresPolicyTargetGroup()
        if context.current['port_id'] and verify_port_subnet:
            # Validate if explicit port's subnet
            # is same as the subnet of PTG.
            self._validate_pt_port_subnets(context)
        group_id = context.current['policy_target_group_id']
        if context.current.get('proxy_gateway'):
            pts = context._plugin.get_policy_targets(
                context._plugin_context, {'policy_target_group_id': group_id,
                                          'proxy_gateway': True})
            pts = [x['id'] for x in pts if x['id'] != context.current['id']]
            if pts:
                exc.OnlyOneProxyGatewayAllowed(group_id=group_id)
        if context.current.get('group_default_gateway'):
            pts = context._plugin.get_policy_targets(
                context._plugin_context, {'policy_target_group_id': group_id,
                                          'group_default_gateway': True})
            pts = [x['id'] for x in pts if x['id'] != context.current['id']]
            if pts:
                exc.OnlyOneGroupDefaultGatewayAllowed(group_id=group_id)

    @log.log_method_call
    def create_policy_target_postcommit(self, context):
        if not context.current['port_id']:
            self._use_implicit_port(context)
        self._update_cluster_membership(
            context, new_cluster_id=context.current['cluster_id'])
        self._assoc_ptg_sg_to_pt(context, context.current['id'],
                                 context.current['policy_target_group_id'])
        self._associate_fip_to_pt(context)
        self._associate_qosp_to_pt(context)
        if context.current.get('proxy_gateway'):
            self._set_proxy_gateway_routes(context, context.current)

    @log.log_method_call
    def update_policy_target_precommit(self, context):
        self._validate_cluster_id(context)
        if (context.current['policy_target_group_id'] !=
            context.original['policy_target_group_id']):
            raise exc.PolicyTargetGroupUpdateOfPolicyTargetNotSupported()

    @log.log_method_call
    def update_policy_target_postcommit(self, context):
        if context.current['cluster_id'] != context.original['cluster_id']:
            self._update_cluster_membership(
                context, new_cluster_id=context.current['cluster_id'],
                old_cluster_id=context.original['cluster_id'])
        if not context.current.get('port_id') and context.current.get(
                'proxy_gateway'):
            self._unset_proxy_gateway_routes(context, context.original)

    @log.log_method_call
    def delete_policy_target_precommit(self, context):
        self._validate_pt_in_use_by_cluster(context)
        context.fips = self._get_pt_floating_ip_mapping(
                    context._plugin_context,
                    context.current['id'])

    @log.log_method_call
    def delete_policy_target_postcommit(self, context):
        sg_list = self._generate_list_of_sg_from_ptg(
            context, context.current['policy_target_group_id'])
        self._disassoc_sgs_from_port(context._plugin_context,
                                     context.current['port_id'], sg_list)
        port_id = context.current['port_id']
        for fip in context.fips:
            self._delete_fip(context._plugin_context,
                             fip.floatingip_id)
        if context.current.get('proxy_gateway'):
            self._unset_proxy_gateway_routes(context, context.current)
        self._cleanup_port(context._plugin_context, port_id)

    @log.log_method_call
    def create_policy_target_group_precommit(self, context):
        self._reject_cross_tenant_ptg_l2p(context)
        self._validate_ptg_subnets(context)
        self._validate_nat_pool_for_nsp(context)
        self._validate_proxy_ptg(context)

    @log.log_method_call
    def create_policy_target_group_postcommit(self, context):
        # REVISIT(ivar) this validates the PTG L2P after the IPD creates it
        # (which happens in the postcommit phase)
        self._validate_proxy_ptg(context)

        # connect router to subnets of the PTG
        l2p_id = context.current['l2_policy_id']
        l2p = context._plugin.get_l2_policy(context._plugin_context,
                                            l2p_id)
        l3p_id = l2p['l3_policy_id']
        l3p = context._plugin.get_l3_policy(context._plugin_context,
                                            l3p_id)

        if not context.current['subnets']:
            is_proxy = bool(context.current.get('proxied_group_id'))
            if (not MAPPING_CFG.use_subnetpools or
               (is_proxy and
                context.current.get('proxy_type') == proxy_ext.PROXY_TYPE_L2)):
                self._use_implicit_subnet(context, is_proxy=is_proxy)
            else:
                try:
                    subnet_specifics = {}
                    if context.current.get('proxied_group_id'):
                        # Since this is proxy group, we need to allocate
                        # subnet with proxy-specific prefix len
                        subnet_specifics = {
                            'prefixlen': l3p['proxy_subnet_prefix_length']}

                    subnets = self._use_implicit_subnet_from_subnetpool(
                        context, subnet_specifics)
                    context.add_subnets([sub['id'] for sub in subnets])
                except neutron_exc.SubnetAllocationError:
                    # Translate to GBP exception
                    raise exc.NoSubnetAvailable()

        self._stitch_ptg_to_l3p(context, context.current, l3p,
                                context.current['subnets'])

        self._handle_network_service_policy(context)
        self._handle_policy_rule_sets(context)
        self._update_default_security_group(context._plugin_context,
                                            context.current['id'],
                                            context.current['tenant_id'],
                                            context.current['subnets'])

    @log.log_method_call
    def update_policy_target_group_precommit(self, context):
        if set(context.original['subnets']) - set(context.current['subnets']):
            raise exc.PolicyTargetGroupSubnetRemovalNotSupported()

        self._validate_ptg_subnets(context, context.current['subnets'])
        self._reject_cross_tenant_ptg_l2p(context)
        if (context.current['network_service_policy_id'] !=
            context.original['network_service_policy_id']):
            self._validate_nat_pool_for_nsp(context)

    @log.log_method_call
    def update_policy_target_group_postcommit(self, context):
        # Three conditions where SG association needs to be changed
        # (a) list of policy_targets change
        # (b) provided_policy_rule_sets change
        # (c) consumed_policy_rule_sets change
        ptg_id = context.current['id']
        new_policy_targets = list(
            set(context.current['policy_targets']) - set(
                context.original['policy_targets']))
        if new_policy_targets:
            self._update_sgs_on_pt_with_ptg(context, ptg_id,
                                            new_policy_targets, "ASSOCIATE")
        removed_policy_targets = list(
            set(context.original['policy_targets']) - set(
                context.current['policy_targets']))
        if removed_policy_targets:
            self._update_sgs_on_pt_with_ptg(context, ptg_id,
                                            new_policy_targets, "DISASSOCIATE")
        # generate a list of policy_rule_sets (SGs) to update on the PTG
        orig_provided_policy_rule_sets = context.original[
            'provided_policy_rule_sets']
        curr_provided_policy_rule_sets = context.current[
            'provided_policy_rule_sets']
        new_provided_policy_rule_sets = list(
            set(curr_provided_policy_rule_sets) - set(
                orig_provided_policy_rule_sets))
        orig_consumed_policy_rule_sets = context.original[
            'consumed_policy_rule_sets']
        curr_consumed_policy_rule_sets = context.current[
            'consumed_policy_rule_sets']
        new_consumed_policy_rule_sets = list(
            set(curr_consumed_policy_rule_sets) - set(
                orig_consumed_policy_rule_sets))

        self._handle_nsp_update_on_ptg(context)

        # if PTG associated policy_rule_sets are updated, we need to update
        # the policy rules, then assoicate SGs to ports
        if new_provided_policy_rule_sets or new_consumed_policy_rule_sets:
            subnets = context.current['subnets']
            self._set_sg_rules_for_subnets(context, subnets,
                                  new_provided_policy_rule_sets,
                                  new_consumed_policy_rule_sets)
            self._update_sgs_on_ptg(context, ptg_id,
                                    new_provided_policy_rule_sets,
                                    new_consumed_policy_rule_sets, "ASSOCIATE")
        # generate the list of contracts (SGs) to remove from current ports
        removed_provided_prs = list(set(orig_provided_policy_rule_sets) -
                                    set(curr_provided_policy_rule_sets))
        removed_consumed_prs = list(set(orig_consumed_policy_rule_sets) -
                                    set(curr_consumed_policy_rule_sets))
        if removed_provided_prs or removed_consumed_prs:
            self._update_sgs_on_ptg(context, ptg_id,
                                    removed_provided_prs,
                                    removed_consumed_prs, "DISASSOCIATE")
            subnets = context.original['subnets']
            self._unset_sg_rules_for_subnets(
                context, subnets, removed_provided_prs, removed_consumed_prs)
        # Deal with new added subnets for default SG
        # Subnet removal not possible for now
        new_subnets = list(set(context.current['subnets']) -
                           set(context.original['subnets']))
        self._update_default_security_group(
            context._plugin_context, context.current['id'],
            context.current['tenant_id'], subnets=new_subnets)

    @log.log_method_call
    def delete_policy_target_group_precommit(self, context):
        context.nsp_cleanup_ipaddress = self._get_ptg_policy_ipaddress_mapping(
            context._plugin_context, context.current['id'])
        context.nsp_cleanup_fips = self._get_ptg_policy_fip_mapping(
            context._plugin_context, context.current['id'])

    @log.log_method_call
    def delete_policy_target_group_postcommit(self, context):
        try:
            self._cleanup_network_service_policy(context,
                                                 context.current,
                                                 context.nsp_cleanup_ipaddress,
                                                 context.nsp_cleanup_fips)
        except sa_exc.ObjectDeletedError as err:
            LOG.warning("Object already got deleted. Error: %(err)s",
                    {'err': err})
        # Cleanup SGs
        self._unset_sg_rules_for_subnets(
            context, context.current['subnets'],
            context.current['provided_policy_rule_sets'],
            context.current['consumed_policy_rule_sets'])

        l2p_id = context.current['l2_policy_id']
        l3p = None
        if l2p_id:
            l3p = self._get_l3p_for_l2policy(context, l2p_id)
            for subnet_id in context.current['subnets']:
                self._cleanup_subnet(context._plugin_context, subnet_id,
                                     l3p['routers'][0])
        self._delete_default_security_group(
            context._plugin_context, context.current['id'],
            context.current['tenant_id'])
        if context.current.get('proxied_group_id') and l3p:
            # Attach the Router interfaces to the proxied group
            # Note that proxy PTGs are always deleted starting from the last
            # one in the list.
            proxied = context._plugin.get_policy_target_group(
                context._plugin_context.elevated(),
                context.current['proxied_group_id'])

            self._stitch_ptg_to_l3p(context, proxied, l3p, proxied['subnets'])

    @log.log_method_call
    def create_l2_policy_precommit(self, context):
        self._reject_cross_tenant_l2p_l3p(context)
        self._reject_non_shared_net_on_shared_l2p(context)
        self._reject_invalid_network_access(context)
        if not context.current['inject_default_route']:
            raise exc.UnsettingInjectDefaultRouteOfL2PolicyNotSupported()

    @log.log_method_call
    def create_l2_policy_postcommit(self, context):
        if not context.current['network_id']:
            self._use_implicit_network(context)

    @log.log_method_call
    def update_l2_policy_precommit(self, context):
        if (context.current['inject_default_route'] !=
            context.original['inject_default_route']):
            raise exc.UnsettingInjectDefaultRouteOfL2PolicyNotSupported()
        if (context.current['l3_policy_id'] !=
            context.original['l3_policy_id']):
            raise exc.L3PolicyUpdateOfL2PolicyNotSupported()
        self._reject_cross_tenant_l2p_l3p(context)
        self._reject_non_shared_net_on_shared_l2p(context)

    @log.log_method_call
    def update_l2_policy_postcommit(self, context):
        pass

    @log.log_method_call
    def delete_l2_policy_precommit(self, context):
        pass

    @log.log_method_call
    def delete_l2_policy_postcommit(self, context):
        network_id = context.current['network_id']
        self._cleanup_network(context._plugin_context, network_id)

    @log.log_method_call
    def create_l3_policy_precommit(self, context):
        curr = context.current
        if len(curr['routers']) > 1:
            raise exc.L3PolicyMultipleRoutersNotSupported()
        # Validate non overlapping IPs in the same tenant
        l3ps = context._plugin.get_l3_policies(
            context._plugin_context, {'tenant_id': [curr['tenant_id']]})
        subnets = []
        for l3p in l3ps:
            if l3p['id'] != curr['id']:
                for prefix in gbp_utils.convert_ip_pool_string_to_list(
                        l3p['ip_pool']):
                    if prefix:
                        subnets.append(prefix)
                if 'proxy_ip_pool' in l3p:
                    subnets.extend(gbp_utils.convert_ip_pool_string_to_list(
                        l3p['proxy_ip_pool']))
        l3p_subnets = gbp_utils.convert_ip_pool_string_to_list(curr['ip_pool'])
        if 'proxy_ip_pool' in curr:
            l3p_subnets.extend(gbp_utils.convert_ip_pool_string_to_list(
                curr['proxy_ip_pool']))

        current_set = netaddr.IPSet(subnets)
        l3p_set = netaddr.IPSet(l3p_subnets)

        if l3p_set & current_set:
            raise exc.OverlappingIPPoolsInSameTenantNotAllowed(
                ip_pool=l3p_subnets, overlapping_pools=subnets)
        # In Neutron, one external gateway per router is allowed. Therefore
        # we have to limit the number of ES per L3P to 1
        if len(context.current['external_segments']) > 1:
            raise exc.MultipleESPerL3PolicyNotSupported()
        self._reject_invalid_router_access(context)

    @log.log_method_call
    def create_l3_policy_postcommit(self, context):

        if MAPPING_CFG.use_subnetpools:
            self._create_l3p_subnetpools(context)

        l3p = context.current
        if not l3p['routers']:
            self._use_implicit_router(context)
        if l3p['external_segments']:
            self._plug_router_to_external_segment(
                context, l3p['external_segments'])
            self._set_l3p_external_routes(context)
        if not MAPPING_CFG.use_subnetpools:
            self._process_new_l3p_ip_pool(context, context.current['ip_pool'])

    @log.log_method_call
    def update_l3_policy_precommit(self, context):
        if context.current['routers'] != context.original['routers']:
            raise exc.L3PolicyRoutersUpdateNotSupported()
        if len(context.current['external_segments']) > 1:
            raise exc.MultipleESPerL3PolicyNotSupported()

        if MAPPING_CFG.use_subnetpools:
            self._update_l3p_subnetpools(context)

        # Currently there is no support for router update in l3p update.
        # Added this check just in case it is supported in future.
        self._reject_invalid_router_access(context)
        self._validate_in_use_by_nsp(context)

    @log.log_method_call
    def update_l3_policy_postcommit(self, context):
        new, old = context.current, context.original
        if new['external_segments'] != old['external_segments']:
            added = (set(new['external_segments'].keys()) -
                     set(old['external_segments'].keys()))
            removed = (set(old['external_segments'].keys()) -
                       set(new['external_segments'].keys()))
            if context.current['routers']:
                if removed:
                    self._unplug_router_from_external_segment(
                        context, dict((x, old['external_segments'][x])
                                      for x in removed))
                if added:
                    self._plug_router_to_external_segment(
                        context, dict((x, new['external_segments'][x])
                                      for x in added))
                self._set_l3p_external_routes(context, removed=removed)

    @log.log_method_call
    def delete_l3_policy_precommit(self, context):
        pass

    @log.log_method_call
    def delete_l3_policy_postcommit(self, context):
        for router_id in context.current['routers']:
            self._cleanup_router(context._plugin_context, router_id)

        if MAPPING_CFG.use_subnetpools:
            self._delete_l3p_subnetpools(context)
        else:
            self._process_remove_l3p_ip_pool(context,
                                             context.current['ip_pool'])

    @log.log_method_call
    def create_policy_classifier_precommit(self, context):
        pass

    @log.log_method_call
    def create_policy_classifier_postcommit(self, context):
        pass

    @log.log_method_call
    def update_policy_classifier_precommit(self, context):
        pass

    @log.log_method_call
    def update_policy_classifier_postcommit(self, context):
        policy_rules = (context._plugin.get_policy_classifier(
                context._plugin_context,
                context.current['id'])['policy_rules'])
        policy_rules = context._plugin.get_policy_rules(
            context._plugin_context,
            filters={'id': policy_rules})
        policy_rulesets_to_update = []
        for policy_rule in policy_rules:
            pr_id = policy_rule['id']
            pr_sets = context._plugin._get_policy_rule_policy_rule_sets(
                context._plugin_context, pr_id)
            policy_rulesets_to_update.extend(pr_sets)
            self._update_policy_rule_sg_rules(context, pr_sets,
                policy_rule, context.original, context.current)

    @log.log_method_call
    def delete_policy_classifier_precommit(self, context):
        pass

    @log.log_method_call
    def delete_policy_classifier_postcommit(self, context):
        pass

    @log.log_method_call
    def create_policy_action_precommit(self, context):
        pass

    @log.log_method_call
    def create_policy_action_postcommit(self, context):
        pass

    @log.log_method_call
    def update_policy_action_precommit(self, context):
        pass

    @log.log_method_call
    def update_policy_action_postcommit(self, context):
        pass

    @log.log_method_call
    def delete_policy_action_precommit(self, context):
        pass

    @log.log_method_call
    def delete_policy_action_postcommit(self, context):
        pass

    @log.log_method_call
    def create_policy_rule_precommit(self, context):
        pass

    @log.log_method_call
    def create_policy_rule_postcommit(self, context):
        pass

    @log.log_method_call
    def update_policy_rule_precommit(self, context):
        pass

    @log.log_method_call
    def update_policy_rule_postcommit(self, context):
        old_classifier_id = context.original['policy_classifier_id']
        new_classifier_id = context.current['policy_classifier_id']
        old_action_set = set(context.current['policy_actions'])
        new_action_set = set(context.original['policy_actions'])
        if (old_classifier_id != new_classifier_id or
                old_action_set != new_action_set):
            policy_rule_sets = (
                context._plugin._get_policy_rule_policy_rule_sets(
                    context._plugin_context, context.current['id']))
            for prs in context._plugin.get_policy_rule_sets(
                    context._plugin_context, filters={'id': policy_rule_sets}):
                self._remove_policy_rule_set_rules(context, prs,
                                                   [context.original])
                self._apply_policy_rule_set_rules(context, prs,
                                                  [context.current])

    @log.log_method_call
    def delete_policy_rule_precommit(self, context):
        # REVISIT(ivar): This will be removed once navigability issue is
        # solved (bug/1384397)
        context._rmd_policy_rule_sets_temp = (
            context._plugin._get_policy_rule_policy_rule_sets(
                context._plugin_context, context.current['id']))

    @log.log_method_call
    def delete_policy_rule_postcommit(self, context):
        for prs in context._plugin.get_policy_rule_sets(
                context._plugin_context,
                filters={'id': context.current['policy_rule_sets']}):
            self._remove_policy_rule_set_rules(context, prs, [context.current])

    @log.log_method_call
    def create_policy_rule_set_precommit(self, context):
        self._reject_shared(context.current, 'policy_rule_set')

    @log.log_method_call
    def create_policy_rule_set_postcommit(self, context):
        # creating SGs
        policy_rule_set_id = context.current['id']
        consumed_sg = self._create_policy_rule_set_sg(context, 'consumed')
        provided_sg = self._create_policy_rule_set_sg(context, 'provided')
        consumed_sg_id = consumed_sg['id']
        provided_sg_id = provided_sg['id']
        self._set_policy_rule_set_sg_mapping(
            context._plugin_context.session, policy_rule_set_id,
            consumed_sg_id, provided_sg_id)
        rules = context._plugin.get_policy_rules(
            context._plugin_context,
            {'id': context.current['policy_rules']})
        self._apply_policy_rule_set_rules(context, context.current, rules)
        if context.current['child_policy_rule_sets']:
            self._recompute_policy_rule_sets(
                context, context.current['child_policy_rule_sets'])

    @log.log_method_call
    def update_policy_rule_set_precommit(self, context):
        self._reject_shared(context.current, 'policy_rule_set')

    @log.log_method_call
    def update_policy_rule_set_postcommit(self, context):
        # Update policy_rule_set rules
        old_rules = set(context.original['policy_rules'])
        new_rules = set(context.current['policy_rules'])
        to_add = context._plugin.get_policy_rules(
            context._plugin_context, {'id': new_rules - old_rules})
        to_remove = context._plugin.get_policy_rules(
            context._plugin_context, {'id': old_rules - new_rules})
        self._remove_policy_rule_set_rules(context, context.current, to_remove)
        self._apply_policy_rule_set_rules(context, context.current, to_add)
        # Update children contraint
        to_recompute = (set(context.original['child_policy_rule_sets']) ^
                        set(context.current['child_policy_rule_sets']))
        self._recompute_policy_rule_sets(context, to_recompute)
        if to_add or to_remove:
            to_recompute = (set(context.original['child_policy_rule_sets']) &
                            set(context.current['child_policy_rule_sets']))
            self._recompute_policy_rule_sets(context, to_recompute)

    @log.log_method_call
    def delete_policy_rule_set_precommit(self, context):
        mapping = self._get_policy_rule_set_sg_mapping(
            context._plugin_context.session, context.current['id'])
        context._rmd_sg_list_temp = [mapping['provided_sg_id'],
                                     mapping['consumed_sg_id']]

    @log.log_method_call
    def delete_policy_rule_set_postcommit(self, context):
        # Disassociate SGs
        sg_list = context._rmd_sg_list_temp
        ptg_mapping = [context.current['providing_policy_target_groups'],
                       context.current['consuming_policy_target_groups']]
        for ptgs in ptg_mapping:
            for ptg in ptgs:
                policy_target_list = ptg['policy_targets']
                for pt_id in policy_target_list:
                    self._disassoc_sgs_from_pt(context, pt_id, sg_list)
        # Delete SGs
        for sg in sg_list:
            self._delete_sg(context._plugin_context, sg)

    @log.log_method_call
    def create_network_service_policy_precommit(self, context):
        self._validate_nsp_parameters(context)

    @log.log_method_call
    def create_network_service_policy_postcommit(self, context):
        p = context.current['network_service_params']
        max = burst = 0
        setting_qos = False
        # assumes single value per parameter type, as the API currently states
        params = {p[n]['type']: p[n]['value'] for n in range(len(p))}
        # check for QoS param types..
        if gconst.GP_NETWORK_SVC_PARAM_TYPE_QOS_MAX in params:
            max = params[gconst.GP_NETWORK_SVC_PARAM_TYPE_QOS_MAX]
            setting_qos = True
        if gconst.GP_NETWORK_SVC_PARAM_TYPE_QOS_BURST in params:
            burst = params[gconst.GP_NETWORK_SVC_PARAM_TYPE_QOS_BURST]
            setting_qos = True
        # ..and create needed Neutron resources
        if setting_qos:
            qos_policy_id = self._create_implicit_qos_policy(context)
            nsp_id = context.current['id']
            self._create_implicit_qos_rule(context, qos_policy_id, max, burst)
            self._set_nsp_qos_mapping(context._plugin_context,
                                      nsp_id,
                                      qos_policy_id)

    @log.log_method_call
    def delete_network_service_policy_precommit(self, context):
        nsp = context.current
        mapping = self._get_nsp_qos_mapping(context._plugin_context,
                                            nsp['id'])
        if mapping:
            qos_policy_id = mapping['qos_policy_id']
            context.current['qos_policy_id'] = qos_policy_id

    @log.log_method_call
    def delete_network_service_policy_postcommit(self, context):
        qos_policy_id = context.current.get('qos_policy_id')
        if qos_policy_id:
            self._delete_ptg_qos_policy(context, qos_policy_id)

    def create_external_segment_precommit(self, context):
        if context.current['subnet_id']:
            subnet = self._get_subnet(context._plugin_context,
                                      context.current['subnet_id'])
            network = self._get_network(context._plugin_context,
                                        subnet['network_id'])
            if not network['router:external']:
                raise exc.InvalidSubnetForES(sub_id=subnet['id'],
                                             net_id=network['id'])
            db_es = context._plugin._get_external_segment(
                context._plugin_context, context.current['id'])
            db_es.cidr = subnet['cidr']
            db_es.ip_version = subnet['ip_version']
            context.current['cidr'] = db_es.cidr
            context.current['ip_version'] = db_es.ip_version
        else:
            raise exc.ImplicitSubnetNotSupported()

    def create_external_segment_postcommit(self, context):
        pass

    def update_external_segment_precommit(self, context):
        invalid = ['port_address_translation']
        for attr in invalid:
            if context.current[attr] != context.original[attr]:
                raise exc.InvalidAttributeUpdateForES(attribute=attr)

    def update_external_segment_postcommit(self, context):
        # REVISIT(ivar): concurrency issues
        if (context.current['external_routes'] !=
                context.original['external_routes']):
            # Update SG rules for each EP
            # Get all the EP using this ES
            admin_context = n_context.get_admin_context()
            ep_ids = context._plugin._get_external_segment_external_policies(
                context._plugin_context, context.current['id'])
            eps = context._plugin.get_external_policies(
                admin_context, {'id': ep_ids})
            eps_by_tenant = {}
            for ep in eps:
                if ep['tenant_id'] not in eps_by_tenant:
                    eps_by_tenant[ep['tenant_id']] = []
                eps_by_tenant[ep['tenant_id']].append(ep['id'])
            # Process their routes
            visited_tenants = set()
            for l3p in context._plugin.get_l3_policies(
                    admin_context, {'id': context.current['l3_policies']}):
                if l3p['tenant_id'] in visited_tenants:
                    continue
                visited_tenants.add(l3p['tenant_id'])
                old_cidrs = [x['destination']
                             for x in context.original['external_routes']]
                old_cidrs = self._process_external_cidrs(
                    context, old_cidrs, tenant_id=l3p['tenant_id'])
                new_cidrs = [x['destination']
                             for x in context.current['external_routes']]
                new_cidrs = self._process_external_cidrs(
                    context, new_cidrs, tenant_id=l3p['tenant_id'])
                # Recompute PRS rules
                self._recompute_external_policy_rules(
                    context, eps_by_tenant[l3p['tenant_id']],
                    new_cidrs, old_cidrs)
            old_routes = set((x['destination'], x['nexthop'])
                             for x in context.original['external_routes'])
            new_routes = set((x['destination'], x['nexthop'])
                             for x in context.current['external_routes'])
            # Set the correct list of routes for each L3P
            self._recompute_l3_policy_routes(context, new_routes, old_routes)

    def delete_external_segment_precommit(self, context):
        pass

    def delete_external_segment_postcommit(self, context):
        pass

    def create_external_policy_precommit(self, context):
        self._reject_shared(context.current, 'external_policy')
        # REVISIT(ivar): For security reasons, only one ES allowed per EP.
        # see bug #1398156
        if len(context.current['external_segments']) > 1:
            raise exc.MultipleESPerEPNotSupported()
        # REVISIT(ivar): bug #1398156 only one EP is allowed per tenant
        ep_number = context._plugin.get_external_policies_count(
            context._plugin_context,
            filters={'tenant_id': [context.current['tenant_id']]})
        if ep_number > 1:
            raise exc.OnlyOneEPPerTenantAllowed()

    def create_external_policy_postcommit(self, context):
        # Only *North to South* rules are actually effective.
        # The rules will be calculated as the symmetric difference between
        # the union of all the Tenant's L3P supernets and the union of all the
        # ES routes.
        # REVISIT(ivar): Remove when ES update is supported for EP
        if not context.current['external_segments']:
            raise exc.ESIdRequiredWhenCreatingEP()
        ep = context.current
        if ep['external_segments']:
            if (ep['provided_policy_rule_sets'] or
                    ep['consumed_policy_rule_sets']):
                # Get the full processed list of external CIDRs
                cidr_list = self._get_processed_ep_cidr_list(context, ep)
                # set the rules on the proper SGs
                self._set_sg_rules_for_cidrs(
                    context, cidr_list, ep['provided_policy_rule_sets'],
                    ep['consumed_policy_rule_sets'])

    def update_external_policy_precommit(self, context):
        self._reject_shared(context.current, 'external_policy')
        if context.original['external_segments']:
            if (set(context.current['external_segments']) !=
                    set(context.original['external_segments'])):
                raise exc.ESUpdateNotSupportedForEP()

    def update_external_policy_postcommit(self, context):
        # REVISIT(ivar): Concurrency issue, the cidr_list could be different
        # in the time from adding new PRS to removing old ones. The consequence
        # is that the rules added/removed could be completely wrong.
        prov_cons = {'provided_policy_rule_sets': [],
                     'consumed_policy_rule_sets': []}
        cidr_list = None
        # Removed PRS
        for attr in prov_cons:
            orig_policy_rule_sets = context.original[attr]
            curr_policy_rule_sets = context.current[attr]
            prov_cons[attr] = list(set(orig_policy_rule_sets) -
                                   set(curr_policy_rule_sets))
        if any(prov_cons.values()):
            cidr_list = self._get_processed_ep_cidr_list(
                context, context.current)
            self._unset_sg_rules_for_cidrs(
                context, cidr_list, prov_cons['provided_policy_rule_sets'],
                prov_cons['consumed_policy_rule_sets'])

        # Added PRS
        for attr in prov_cons:
            orig_policy_rule_sets = context.original[attr]
            curr_policy_rule_sets = context.current[attr]
            prov_cons[attr] = list(set(curr_policy_rule_sets) -
                                   set(orig_policy_rule_sets))

        if any(prov_cons.values()):
            cidr_list = cidr_list or self._get_processed_ep_cidr_list(
                context, context.current)
            self._set_sg_rules_for_cidrs(
                context, cidr_list, prov_cons['provided_policy_rule_sets'],
                prov_cons['consumed_policy_rule_sets'])

    def delete_external_policy_precommit(self, context):
        pass

    def delete_external_policy_postcommit(self, context):
        if (context.current['provided_policy_rule_sets'] or
                context.current['consumed_policy_rule_sets']):
            # REVISIT(ivar): concurrency issue, ES may not exist anymore
            cidr_list = self._get_processed_ep_cidr_list(
                context, context.current)
            self._unset_sg_rules_for_cidrs(
                context, cidr_list,
                context.current['provided_policy_rule_sets'],
                context.current['consumed_policy_rule_sets'])

    @log.log_method_call
    def create_network_service_policy_precommit(self, context):
        self._validate_nsp_parameters(context)

    def update_network_service_policy_precommit(self, context):
        self._validate_nsp_parameters(context)

    def create_nat_pool_precommit(self, context):
        self._add_nat_pool_to_segment(context)

    def create_nat_pool_postcommit(self, context):
        self._add_implicit_subnet_for_nat_pool_create(context)

    def update_nat_pool_precommit(self, context):
        self._process_ext_segment_update_for_nat_pool(context)

    def update_nat_pool_postcommit(self, context):
        self._add_implicit_subnet_for_nat_pool_update(context)

    def delete_nat_pool_precommit(self, context):
        self._nat_pool_in_use(context)

    def delete_nat_pool_postcommit(self, context):
        self._delete_subnet_on_nat_pool_delete(context)

    def _plug_router_to_external_segment(self, context, es_dict):
        es_list = context._plugin.get_external_segments(
            context._plugin_context, filters={'id': es_dict.keys()})
        if context.current['routers']:
            router_id = context.current['routers'][0]
            for es in es_list:
                router = self._create_router_gw_for_external_segment(
                    context._plugin_context, es, es_dict, router_id)

                if not es_dict[es['id']] or not es_dict[es['id']][0]:
                    # Update L3P assigned address
                    efi = router['external_gateway_info']['external_fixed_ips']
                    assigned_ips = [x['ip_address'] for x in efi
                                    if x['subnet_id'] == es['subnet_id']]
                    context.set_external_fixed_ips(es['id'], assigned_ips)

    def _unplug_router_from_external_segment(self, context, es_ids):
        es_list = context._plugin.get_external_segments(
            context._plugin_context, filters={'id': es_ids})
        if context.current['routers']:
            router_id = context.current['routers'][0]
            for es in es_list:
                subnet = self._get_subnet(context._plugin_context,
                                          es['subnet_id'])
                interface_info = {'network_id': subnet['network_id']}
                self._remove_router_gw_interface(context._plugin_context,
                                                 router_id, interface_info)

    def _stitch_ptg_to_l3p(self, context, ptg, l3p, subnet_ids):
        if l3p['routers']:
            router_id = l3p['routers'][0]
            if ptg.get('proxied_group_id'):
                self._stitch_proxy_ptg_to_l3p(context, ptg, l3p, subnet_ids)
            else:
                try:
                    for subnet_id in subnet_ids:
                        self._plug_router_to_subnet(
                            context._plugin_context, subnet_id, router_id)
                except n_exc.InvalidInput:
                    # This exception is not expected.
                    LOG.exception("adding subnet to router failed")
                    for subnet_id in subnet_ids:
                        self._delete_subnet(context._plugin_context, subnet_id)
                    raise exc.GroupPolicyInternalError()

    def _stitch_proxy_ptg_to_l3p(self, context, ptg, l3p, subnet_ids):
        """Attach the Proxy PTG properly.
        When a proxy PTG is set, the proxied PTG needs to be detached from
        the current L3P. The proxied PTG will be attached instead on the proper
        subnets. This will completely isolate the proxied PTG, therefore the
        expectation is for a third entity (eg. service chain driver) to create
        a bridging service across the proxy and the proxied PTG.
        This will guarantee that all the traffic goes through the proxy PTG
        before reaching the destination.
        """

        proxied = context._plugin.get_policy_target_group(
            context._plugin_context, ptg['proxied_group_id'])
        try:
            # If the detached PTG is a proxy itself and has a proxy
            # gateway, then the routes should be removed from the L3P and
            # added to the current proxy subnet instead.
            gateway_pt = None
            if proxied.get('proxied_group_id'):
                # Verify if a gateway PT exists
                gateway_pt = context._plugin.get_policy_targets(
                    context._plugin_context.elevated(),
                    {'policy_target_group_id': [proxied['id']],
                     'proxy_gateway': [True]})
                if gateway_pt:
                    self._unset_proxy_gateway_routes(context, gateway_pt[0])

            # Detach Proxied PTG
            for subnet_id in proxied['subnets']:
                self._remove_router_interface(
                    context._plugin_context, l3p['routers'][0],
                    {'subnet_id': subnet_id})

            # Attach Proxy PTG
            for subnet_id in subnet_ids:
                self._plug_router_to_subnet(
                    context._plugin_context, subnet_id, l3p['routers'][0])

            # Reset the proxy gateway PT routes
            if gateway_pt:
                self._set_proxy_gateway_routes(context, gateway_pt[0])
        except n_exc.InvalidInput:
            # This exception is not expected.
            # TODO(ivar): find a better way to rollback
            LOG.exception("adding subnet to router failed")
            for subnet_id in subnet_ids:
                self._delete_subnet(context._plugin_context, subnet_id)
                raise exc.GroupPolicyInternalError()

    def _create_policy_rule_set_sg(self, context, sg_name_prefix):
        return self._create_gbp_sg(
            context._plugin_context, context.current['tenant_id'],
            sg_name_prefix + '_' + context.current['name'])

    def _handle_policy_rule_sets(self, context):
        # This method handles policy_rule_set => SG mapping
        # context is PTG context

        # for all consumed policy_rule_sets, simply associate
        # each EP's port from the PTG
        # rules are expected to be filled out already
        consumed_policy_rule_sets = context.current[
            'consumed_policy_rule_sets']
        provided_policy_rule_sets = context.current[
            'provided_policy_rule_sets']
        subnets = context.current['subnets']
        ptg_id = context.current['id']
        self._set_sg_rules_for_subnets(context, subnets,
                                       provided_policy_rule_sets,
                                       consumed_policy_rule_sets)
        self._update_sgs_on_ptg(context, ptg_id, provided_policy_rule_sets,
                                consumed_policy_rule_sets, "ASSOCIATE")

    # updates sg rules corresponding to a policy rule
    def _update_policy_rule_sg_rules(self, context, policy_rule_sets,
                                     policy_rule, old_classifier=None,
                                     new_classifier=None):
        policy_rule_set_list = context._plugin.get_policy_rule_sets(
                context._plugin_context, filters={'id': policy_rule_sets})
        for policy_rule_set in policy_rule_set_list:
            filtered_rules = self._get_enforced_prs_rules(
                context, policy_rule_set, subset=[policy_rule['id']])
            if filtered_rules:
                policy_rule_set_sg_mappings = (
                    self._get_policy_rule_set_sg_mapping(
                        context._plugin_context.session,
                        policy_rule_set['id']))
                cidr_mapping = self._get_cidrs_mapping(
                    context, policy_rule_set)
                self._add_or_remove_policy_rule_set_rule(
                    context, policy_rule, policy_rule_set_sg_mappings,
                    cidr_mapping, unset=True, unset_egress=True,
                    classifier=old_classifier)
                self._add_or_remove_policy_rule_set_rule(
                    context, policy_rule, policy_rule_set_sg_mappings,
                    cidr_mapping, classifier=new_classifier)

    def _get_rule_ids_for_actions(self, context, action_id):
        policy_rule_qry = context.session.query(
                            gpdb.PolicyRuleActionAssociation.policy_rule_id)
        policy_rule_qry.filter_by(policy_action_id=action_id)
        return policy_rule_qry.all()

    def _set_policy_rule_set_sg_mapping(
        self, session, policy_rule_set_id, consumed_sg_id, provided_sg_id):
        with session.begin(subtransactions=True):
            mapping = PolicyRuleSetSGsMapping(
                policy_rule_set_id=policy_rule_set_id,
                consumed_sg_id=consumed_sg_id, provided_sg_id=provided_sg_id)
            session.add(mapping)

    @staticmethod
    def _get_policy_rule_set_sg_mapping(session, policy_rule_set_id):
        with session.begin(subtransactions=True):
            return (session.query(PolicyRuleSetSGsMapping).
                    filter_by(policy_rule_set_id=policy_rule_set_id).one())

    def _sg_ingress_rule(self, context, sg_id, protocol, port_range, cidr,
                         tenant_id, unset=False):
        return self._sg_rule(
            context._plugin_context, tenant_id, sg_id,
            'ingress', protocol, port_range, cidr, unset=unset)

    def _sg_egress_rule(self, context, sg_id, protocol, port_range,
                        cidr, tenant_id, unset=False):
        return self._sg_rule(
            context._plugin_context, tenant_id, sg_id,
            'egress', protocol, port_range, cidr, unset=unset)

    def _assoc_sgs_to_pt(self, context, pt_id, sg_list):
        try:
            pt = context._plugin.get_policy_target(context._plugin_context,
                                                   pt_id)
        except gp_ext.PolicyTargetNotFound:
            LOG.warning("PT %s doesn't exist anymore", pt_id)
            return
        try:
            port_id = pt['port_id']
            port = self._get_port(context._plugin_context, port_id)
            if ('port_security_enabled' in port and
                    not port['port_security_enabled']):
                LOG.debug("Port security disabled for port %s ", port_id)
                return
            cur_sg_list = port[ext_sg.SECURITYGROUPS]
            new_sg_list = cur_sg_list + sg_list
            port[ext_sg.SECURITYGROUPS] = new_sg_list
            self._update_port(context._plugin_context, port_id, port)
        except n_exc.PortNotFound:
            LOG.warning("Port %s is missing", port_id)

    def _disassoc_sgs_from_pt(self, context, pt_id, sg_list):
        try:
            pt = context._plugin.get_policy_target(context._plugin_context,
                                                   pt_id)
        except gp_ext.PolicyTargetNotFound:
            LOG.warning("PT %s doesn't exist anymore", pt_id)
            return
        port_id = pt['port_id']
        self._disassoc_sgs_from_port(context._plugin_context, port_id, sg_list)

    def _disassoc_sgs_from_port(self, plugin_context, port_id, sg_list):
        try:
            port = self._get_port(plugin_context, port_id)
            if ('port_security_enabled' in port and
                    not port['port_security_enabled']):
                LOG.debug("Port security disabled for port %s ", port_id)
                return
            cur_sg_list = port[ext_sg.SECURITYGROUPS]
            new_sg_list = list(set(cur_sg_list) - set(sg_list))
            port[ext_sg.SECURITYGROUPS] = new_sg_list
            self._update_port(plugin_context, port_id, port)
        except n_exc.PortNotFound:
            LOG.warning("Port %s is missing", port_id)

    def _generate_list_of_sg_from_ptg(self, context, ptg_id):
        ptg = context._plugin.get_policy_target_group(
            context._plugin_context, ptg_id)
        provided_policy_rule_sets = ptg['provided_policy_rule_sets']
        consumed_policy_rule_sets = ptg['consumed_policy_rule_sets']
        return(self._generate_list_sg_from_policy_rule_set_list(
            context, provided_policy_rule_sets, consumed_policy_rule_sets))

    def _generate_list_sg_from_policy_rule_set_list(self, context,
                                                    provided_policy_rule_sets,
                                                    consumed_policy_rule_sets):
        ret_list = []
        for policy_rule_set_id in provided_policy_rule_sets:
            policy_rule_set_sg_mappings = self._get_policy_rule_set_sg_mapping(
                context._plugin_context.session, policy_rule_set_id)
            provided_sg_id = policy_rule_set_sg_mappings['provided_sg_id']
            ret_list.append(provided_sg_id)

        for policy_rule_set_id in consumed_policy_rule_sets:
            policy_rule_set_sg_mappings = self._get_policy_rule_set_sg_mapping(
                context._plugin_context.session, policy_rule_set_id)
            consumed_sg_id = policy_rule_set_sg_mappings['consumed_sg_id']
            ret_list.append(consumed_sg_id)
        return ret_list

    def _assoc_ptg_sg_to_pt(self, context, pt_id, ptg_id):
        sg_list = self._generate_list_of_sg_from_ptg(context, ptg_id)
        self._assoc_sgs_to_pt(context, pt_id, sg_list)

    def _update_sgs_on_pt_with_ptg(self, context, ptg_id, new_pt_list, op):
        sg_list = self._generate_list_of_sg_from_ptg(context, ptg_id)
        for pt_id in new_pt_list:
            if op == "ASSOCIATE":
                self._assoc_sgs_to_pt(context, pt_id, sg_list)
            else:
                self._disassoc_sgs_from_pt(context, pt_id, sg_list)

    def _update_sgs_on_ptg(self, context, ptg_id, provided_policy_rule_sets,
                           consumed_policy_rule_sets, op):
        sg_list = self._generate_list_sg_from_policy_rule_set_list(
            context, provided_policy_rule_sets, consumed_policy_rule_sets)
        ptg = context._plugin.get_policy_target_group(
            context._plugin_context, ptg_id)
        policy_target_list = ptg['policy_targets']
        for pt_id in policy_target_list:
            if op == "ASSOCIATE":
                self._assoc_sgs_to_pt(context, pt_id, sg_list)
            else:
                self._disassoc_sgs_from_pt(context, pt_id, sg_list)

    def _set_or_unset_rules_for_subnets(
            self, context, subnets, provided_policy_rule_sets,
            consumed_policy_rule_sets, unset=False):
        if not provided_policy_rule_sets and not consumed_policy_rule_sets:
            return

        cidr_list = []
        for subnet_id in subnets:
            subnet = self._get_subnet(context._plugin_context, subnet_id)
            cidr = subnet['cidr']
            cidr_list.append(cidr)
        self._set_or_unset_rules_for_cidrs(
            context, cidr_list, provided_policy_rule_sets,
            consumed_policy_rule_sets, unset=unset)

    # context should be PTG
    def _set_sg_rules_for_subnets(
            self, context, subnets, provided_policy_rule_sets,
            consumed_policy_rule_sets):
        self._set_or_unset_rules_for_subnets(
            context, subnets, provided_policy_rule_sets,
            consumed_policy_rule_sets)

    def _unset_sg_rules_for_subnets(
            self, context, subnets, provided_policy_rule_sets,
            consumed_policy_rule_sets):
        self._set_or_unset_rules_for_subnets(
            context, subnets, provided_policy_rule_sets,
            consumed_policy_rule_sets, unset=True)

    def _set_sg_rules_for_cidrs(self, context, cidr_list,
                                provided_policy_rule_sets,
                                consumed_policy_rule_sets):
        self._set_or_unset_rules_for_cidrs(
            context, cidr_list, provided_policy_rule_sets,
            consumed_policy_rule_sets)

    def _unset_sg_rules_for_cidrs(self, context, cidr_list,
                                  provided_policy_rule_sets,
                                  consumed_policy_rule_sets):
        self._set_or_unset_rules_for_cidrs(
            context, cidr_list, provided_policy_rule_sets,
            consumed_policy_rule_sets, unset=True)

    def _set_or_unset_rules_for_cidrs(self, context, cidr_list,
                                      provided_policy_rule_sets,
                                      consumed_policy_rule_sets, unset=False):
        prov_cons = ['providing_cidrs', 'consuming_cidrs']
        for pos, policy_rule_sets in enumerate(
                [provided_policy_rule_sets, consumed_policy_rule_sets]):
            for policy_rule_set_id in policy_rule_sets:
                policy_rule_set = context._plugin.get_policy_rule_set(
                    context._plugin_context, policy_rule_set_id)
                policy_rule_set_sg_mappings = (
                    self._get_policy_rule_set_sg_mapping(
                        context._plugin_context.session, policy_rule_set_id))
                cidr_mapping = {prov_cons[pos]: cidr_list,
                                prov_cons[pos - 1]: []}
                if not unset:
                    policy_rules = self._get_enforced_prs_rules(
                        context, policy_rule_set)
                else:
                    # Not need to filter when removing rules
                    policy_rules = context._plugin.get_policy_rules(
                        context._plugin_context,
                        {'id': policy_rule_set['policy_rules']})
                for policy_rule in policy_rules:
                    self._add_or_remove_policy_rule_set_rule(
                        context, policy_rule, policy_rule_set_sg_mappings,
                        cidr_mapping, unset=unset)

    def _manage_policy_rule_set_rules(self, context, policy_rule_set,
                                      policy_rules, unset=False,
                                      unset_egress=False):
        policy_rule_set_sg_mappings = self._get_policy_rule_set_sg_mapping(
            context._plugin_context.session, policy_rule_set['id'])
        policy_rule_set = context._plugin.get_policy_rule_set(
            context._plugin_context, policy_rule_set['id'])
        cidr_mapping = self._get_cidrs_mapping(context, policy_rule_set)
        for policy_rule in policy_rules:
            self._add_or_remove_policy_rule_set_rule(
                context, policy_rule, policy_rule_set_sg_mappings,
                cidr_mapping, unset=unset, unset_egress=unset_egress)

    def _add_or_remove_policy_rule_set_rule(self, context, policy_rule,
                                            policy_rule_set_sg_mappings,
                                            cidr_mapping, unset=False,
                                            unset_egress=False,
                                            classifier=None):
        in_out = [gconst.GP_DIRECTION_IN, gconst.GP_DIRECTION_OUT]
        prov_cons = [policy_rule_set_sg_mappings['provided_sg_id'],
                     policy_rule_set_sg_mappings['consumed_sg_id']]
        cidr_prov_cons = [cidr_mapping['providing_cidrs'],
                          cidr_mapping['consuming_cidrs']]

        if not classifier:
            classifier_id = policy_rule['policy_classifier_id']
            classifier = context._plugin.get_policy_classifier(
                context._plugin_context, classifier_id)

        protocol = classifier['protocol']
        port_range = classifier['port_range']
        admin_context = n_context.get_admin_context()
        prs = context._plugin.get_policy_rule_set(
            admin_context, policy_rule_set_sg_mappings.policy_rule_set_id)
        tenant_id = prs['tenant_id']
        for pos, sg in enumerate(prov_cons):
            if classifier['direction'] in [gconst.GP_DIRECTION_BI,
                                           in_out[pos]]:
                for cidr in cidr_prov_cons[pos - 1]:
                    self._sg_ingress_rule(context, sg, protocol, port_range,
                                          cidr, tenant_id, unset=unset)
            if classifier['direction'] in [gconst.GP_DIRECTION_BI,
                                           in_out[pos - 1]]:
                for cidr in cidr_prov_cons[pos - 1]:
                    self._sg_egress_rule(context, sg, protocol, port_range,
                                         cidr, tenant_id,
                                         unset=unset or unset_egress)

    def _apply_policy_rule_set_rules(self, context, policy_rule_set,
                                     policy_rules):
        policy_rules = self._get_enforced_prs_rules(
            context, policy_rule_set, subset=[x['id'] for x in policy_rules])
        # Don't add rules unallowed by the parent
        self._manage_policy_rule_set_rules(
            context, policy_rule_set, policy_rules)

    def _remove_policy_rule_set_rules(self, context, policy_rule_set,
                                      policy_rules):
        self._manage_policy_rule_set_rules(
            context, policy_rule_set, policy_rules, unset=True,
            unset_egress=True)

    def _recompute_policy_rule_sets(self, context, children):
        # Rules in child but not in parent shall be removed
        # Child rules will be set after being filtered by the parent
        for child in children:
            child = context._plugin.get_policy_rule_set(
                context._plugin_context, child)
            child_rule_ids = set(child['policy_rules'])
            if child['parent_id']:
                parent = context._plugin.get_policy_rule_set(
                    context._plugin_context, child['parent_id'])
                parent_policy_rules = context._plugin.get_policy_rules(
                                        context._plugin_context,
                                        filters={'id': parent['policy_rules']})
                child_rules = context._plugin.get_policy_rules(
                                        context._plugin_context,
                                        filters={'id': child['policy_rules']})
                parent_classifier_ids = [x['policy_classifier_id']
                                     for x in parent_policy_rules]
                delta_rules = [x['id'] for x in child_rules
                               if x['policy_classifier_id']
                               not in set(parent_classifier_ids)]
                delta_rules = context._plugin.get_policy_rules(
                                context._plugin_context, {'id': delta_rules})
                self._remove_policy_rule_set_rules(context, child, delta_rules)
            # Old parent may have filtered some rules, need to add them again
            child_rules = context._plugin.get_policy_rules(
                context._plugin_context, filters={'id': child_rule_ids})
            self._apply_policy_rule_set_rules(context, child, child_rules)

    def _update_default_security_group(self, plugin_context, ptg_id,
                                       tenant_id, subnets=None):

        sg_id = self._get_default_security_group(plugin_context, ptg_id,
                                                 tenant_id)
        ip_v = {4: n_const.IPv4, 6: n_const.IPv6}
        if not sg_id:
            sg_name = DEFAULT_SG_PREFIX % ptg_id
            sg = self._create_gbp_sg(plugin_context, tenant_id, sg_name,
                                     description='default GBP security group')
            sg_id = sg['id']

        for subnet in self._get_subnets(
                plugin_context, filters={'id': subnets or []}):
            self._sg_rule(plugin_context, tenant_id, sg_id,
                          'ingress', cidr=subnet['cidr'],
                          ethertype=ip_v[subnet['ip_version']])
            self._sg_rule(plugin_context, tenant_id, sg_id,
                          'egress', cidr=subnet['cidr'],
                          ethertype=ip_v[subnet['ip_version']])

        # The following rules are added for access to the link local
        # network (metadata server in most cases), and to the DNS
        # port.
        # TODO(Sumit): The following can be optimized by creating
        # the rules once and then referrig to them in every default
        # SG that gets created. If we do that, then when we delete the
        # default SG we cannot delete all the rules in it.
        # We can also consider reading these rules from a config which
        # would make it more flexible to add any rules if required.
        self._sg_rule(plugin_context, tenant_id, sg_id, 'egress',
                      cidr='169.254.0.0/16', ethertype=ip_v[4])
        for ether_type in ip_v:
            for proto in [n_const.PROTO_NAME_TCP, n_const.PROTO_NAME_UDP]:
                self._sg_rule(plugin_context, tenant_id, sg_id, 'egress',
                              protocol=proto, port_range='53',
                              ethertype=ip_v[ether_type])

        return sg_id

    def _delete_default_security_group(self, plugin_context, ptg_id,
                                       tenant_id):
        sg_id = self._get_default_security_group(plugin_context, ptg_id,
                                                 tenant_id)
        if sg_id:
            self._delete_sg(plugin_context, sg_id)

    def _get_ep_cidrs(self, context, eps):
        cidrs = []
        eps = context._plugin.get_external_policies(
            context._plugin_context, filters={'id': eps})
        for ep in eps:
            cidrs.extend(self._get_processed_ep_cidr_list(context, ep))
        return cidrs

    def _get_cidrs_mapping(self, context, policy_rule_set):
        providing_eps = policy_rule_set['providing_external_policies']
        consuming_eps = policy_rule_set['consuming_external_policies']
        providing_ptgs = policy_rule_set['providing_policy_target_groups']
        consuming_ptgs = policy_rule_set['consuming_policy_target_groups']
        return {
            'providing_cidrs': self._get_ptg_cidrs(
                context, providing_ptgs) + self._get_ep_cidrs(context,
                                                              providing_eps),
            'consuming_cidrs': self._get_ptg_cidrs(
                context, consuming_ptgs) + self._get_ep_cidrs(context,
                                                              consuming_eps)}

    def _get_ep_cidr_list(self, context, ep):
        es_list = context._plugin.get_external_segments(
            context._plugin_context,
            filters={'id': ep['external_segments']})
        cidr_list = []
        for es in es_list:
            cidr_list += [x['destination'] for x in es['external_routes']]
        return cidr_list

    def _process_external_cidrs(self, context, cidrs, exclude=None,
                                tenant_id=None):
        # Get all the tenant's L3P
        exclude = exclude or []
        admin_context = n_context.get_admin_context()
        l3ps = context._plugin.get_l3_policies(
            admin_context,
            filters={'tenant_id': [tenant_id or context.current['tenant_id']]})

        ip_pool_list = []
        for l3p in l3ps:
            for prefix in gbp_utils.convert_ip_pool_string_to_list(
                    l3p['ip_pool']):
                if prefix not in exclude:
                    ip_pool_list.append(prefix)
        l3p_set = netaddr.IPSet(ip_pool_list)
        return [str(x) for x in (netaddr.IPSet(cidrs) - l3p_set).iter_cidrs()]

    def _get_processed_ep_cidr_list(self, context, ep):
        cidr_list = self._get_ep_cidr_list(context, ep)
        return self._process_external_cidrs(context, cidr_list)

    def _recompute_external_policy_rules(self, context, ep_ids, new_cidrs,
                                         old_cidrs):
        # the EPs could belong to different tenants, need admin context
        admin_context = n_context.get_admin_context()
        ep_list = context._plugin.get_external_policies(admin_context,
                                                        filters={'id': ep_ids})
        for ep in ep_list:
            self._refresh_ep_cidrs_rules(context, ep, new_cidrs, old_cidrs)

    def _recompute_l3_policy_routes(self, context, new_routes, old_routes):
        # the L3Ps could belong to different tenants, need admin context
        admin_context = n_context.get_admin_context()
        added_routes = new_routes - old_routes
        removed_routes = old_routes - new_routes
        l3ps = context._plugin.get_l3_policies(
            admin_context, filters={'id': context.current['l3_policies']})
        for l3p in l3ps:
            self._update_l3p_routes(l3p, add=added_routes,
                                    remove=removed_routes)

    def _refresh_ep_cidrs_rules(self, context, ep, new_cidrs, old_cidrs):
        # REVISIT(ivar): calculate cidrs delta to minimize disruption
        # Unset old rules
        self._unset_sg_rules_for_cidrs(
            context, old_cidrs, ep['provided_policy_rule_sets'],
            ep['consumed_policy_rule_sets'])
        # Set new rules
        self._set_sg_rules_for_cidrs(
            context, new_cidrs, ep['provided_policy_rule_sets'],
            ep['consumed_policy_rule_sets'])

    def _process_new_l3p_ip_pool(self, context, ip_pool):
        # Get all the EP for this tenant
        ep_list = context._plugin.get_external_policies(
            context._plugin_context,
            filters={'tenant_id': context.current['tenant_id']})
        for ep in ep_list:
            # Remove rules before the new ip_pool came
            ip_pool_list = gbp_utils.convert_ip_pool_string_to_list(ip_pool)
            cidr_list = self._get_ep_cidr_list(context, ep)
            old_cidrs = self._process_external_cidrs(context, cidr_list,
                                                     exclude=ip_pool_list)
            new_cidrs = [str(x) for x in
                         (netaddr.IPSet(old_cidrs) -
                          netaddr.IPSet(ip_pool_list)).iter_cidrs()]
            self._refresh_ep_cidrs_rules(context, ep, new_cidrs, old_cidrs)

    def _process_remove_l3p_ip_pool(self, context, ip_pool):
        # Get all the EP for this tenant
        ep_list = context._plugin.get_external_policies(
            context._plugin_context,
            filters={'tenant_id': context.current['tenant_id']})
        for ep in ep_list:
            # Cidrs before the ip_pool removal
            ip_pool_list = gbp_utils.convert_ip_pool_string_to_list(ip_pool)
            cidr_list = self._get_ep_cidr_list(context, ep)
            new_cidrs = self._process_external_cidrs(context, cidr_list,
                                                     exclude=ip_pool_list)
            # Cidrs after the ip_pool removal
            old_cidrs = [str(x) for x in
                         (netaddr.IPSet(new_cidrs) |
                          netaddr.IPSet(ip_pool_list)).iter_cidrs()]
            self._refresh_ep_cidrs_rules(context, ep, new_cidrs, old_cidrs)

    def _set_l3p_external_routes(self, context, added=None, removed=None):

        def _routes_from_es_ids(context, es_ids):
            routes = []
            if es_ids:
                es_list = context._plugin.get_external_segments(
                    context._plugin_context, filters={'id': es_ids})
                for es in es_list:
                    routes += es['external_routes']
            return routes

        add = _routes_from_es_ids(
            context, added or context.current['external_segments'].keys())
        remove = _routes_from_es_ids(context, removed)

        self._update_l3p_routes(
            context.current,
            add=set((x['destination'], x['nexthop']) for x in add),
            remove=set((x['destination'], x['nexthop']) for x in remove))

    def _update_l3p_routes(self, l3p, add=None, remove=None):
        add = add or set()
        remove = remove or set()
        # NOTE(ivar): the context needs to be admin because the external
        # gateway port is created by Neutron without any tenant_id! Which makes
        # it visible only from an admin context.
        admin_context = n_context.get_admin_context()
        routers = self._get_routers(admin_context, {'id': l3p['routers']})
        for router in routers:
            current_routes = set((x['destination'], x['nexthop']) for x in
                                 router['routes'])
            current_routes = (current_routes - remove | add)
            current_routes = [{'destination': x[0], 'nexthop': x[1]} for x
                              in current_routes if x[1]]
            self._update_router(admin_context, router['id'],
                                {'routes': current_routes})

    def _update_ptg_routes(self, ptg, add=None, remove=None):
        add = add or set()
        remove = remove or set()
        admin_context = n_context.get_admin_context()
        subnets = self._get_subnets(admin_context, {'id': ptg['subnets']})
        for subnet in subnets:
            current_routes = set((x['destination'], x['nexthop']) for x in
                                 subnet['host_routes'])
            current_routes = (current_routes - remove | add)
            current_routes = [{'destination': x[0], 'nexthop': x[1]} for x
                              in current_routes if x[1]]
            self._update_subnet(admin_context, subnet['id'],
                                {'host_routes': current_routes})

    def _validate_ptg_subnets(self, context, subnets=None):
        if subnets or context.current['subnets']:
            l2p_id = context.current['l2_policy_id']
            l2p = context._plugin.get_l2_policy(context._plugin_context,
                                                l2p_id)
            # Validate explicit subnet belongs to L2P's network
            network_id = l2p['network_id']
            network = self._get_network(context._plugin_context, network_id)
            for subnet_id in subnets or context.current['subnets']:
                if subnet_id not in network['subnets']:
                    raise exc.InvalidSubnetForPTG(subnet_id=subnet_id,
                                                  network_id=network_id,
                                                  l2p_id=l2p['id'],
                                                  ptg_id=context.current['id'])

    def _get_enforced_prs_rules(self, context, prs, subset=None):
        subset = subset or prs['policy_rules']
        if prs['parent_id']:
            parent = context._plugin.get_policy_rule_set(
                context._plugin_context, prs['parent_id'])
            parent_policy_rules = context._plugin.get_policy_rules(
                context._plugin_context,
                filters={'id': parent['policy_rules']})
            subset_rules = context._plugin.get_policy_rules(
                                        context._plugin_context,
                                        filters={'id': subset})
            parent_classifier_ids = set(x['policy_classifier_id']
                                        for x in parent_policy_rules)
            policy_rules = [x['id'] for x in subset_rules
                            if x['policy_classifier_id']
                            in parent_classifier_ids]
            return context._plugin.get_policy_rules(
                context._plugin_context,
                {'id': policy_rules})
        else:
            return context._plugin.get_policy_rules(
                context._plugin_context, {'id': set(subset)})

    def _validate_pt_port_subnets(self, context, subnets=None):
        # Validate if explicit port's subnet
        # is same as the subnet of PTG.
        port_id = context.current['port_id']
        port = self._get_port(context._plugin_context, port_id)

        port_subnet_id = None
        fixed_ips = port['fixed_ips']
        if fixed_ips:
            # TODO(krishna-sunitha): Check if there is a case when
            # there is more than one fixed_ip?
            port_subnet_id = fixed_ips[0]['subnet_id']

        ptg_id = context.current['policy_target_group_id']
        ptg = context._plugin.get_policy_target_group(
                                context._plugin_context,
                                ptg_id)
        for subnet in ptg.get('subnets') or subnets:
            if subnet == port_subnet_id:
                break
        else:
            raise exc.InvalidPortForPTG(
                port_id=port_id, ptg_subnet_id=",".join(ptg.get('subnets')),
                port_subnet_id=port_subnet_id,
                policy_target_group_id=ptg_id)

    def _get_ptg_l3p(self, context, ptg):
        l3p_id = context._plugin.get_l2_policy(
            context._plugin_context, ptg['l2_policy_id'])['l3_policy_id']
        return context._plugin.get_l3_policy(context._plugin_context, l3p_id)

    def _validate_proxy_ptg(self, context):
        # Validate that proxied PTG is in the same L3P
        current = context.current
        if current.get('proxied_group_id') and current.get('l2_policy_id'):
            l3p_curr = self._get_ptg_l3p(context, current)

            proxied = context._plugin.get_policy_target_group(
                context._plugin_context, current['proxied_group_id'])
            l3p_proxied = self._get_ptg_l3p(context, proxied)
            if l3p_curr['id'] != l3p_proxied['id']:
                raise exc.InvalidProxiedGroupL3P(
                    ptg_id=proxied['id'], l3p_id=l3p_proxied['id'])
            if (context.current['proxy_type'] == proxy_ext.PROXY_TYPE_L2 and
                    context.current['l2_policy_id'] ==
                    proxied['l2_policy_id']):
                raise exc.InvalidProxiedGroupL2P(ptg_id=proxied['id'])

    def _update_proxy_gateway_routes(self, context, pt, unset=False):
        ptg = context._plugin.get_policy_target_group(
            context._plugin_context, pt['policy_target_group_id'])
        l3p = self._get_ptg_l3p(context, ptg)
        port = self._get_port(context._plugin_context, pt['port_id'])
        nexthop = None
        for fixed_ip in port['fixed_ips']:
            if fixed_ip.get('ip_address'):
                nexthop = fixed_ip.get('ip_address')
                break
        routes = set()
        if nexthop:
            # Add all the subnets in the chain
            curr = ptg
            while curr['proxied_group_id']:
                proxied = context._plugin.get_policy_target_group(
                    context._plugin_context.elevated(),
                    curr['proxied_group_id'])
                subnets = self._get_subnets(context._plugin_context,
                                            {'id': proxied['subnets']})
                routes |= set((subnet['cidr'], nexthop) for subnet in subnets)
                curr = proxied

            if unset:
                # Remove from L3P anyways, since it could be a consequence of
                # L3 stitching
                self._update_l3p_routes(l3p, remove=routes)
                # In any case, routes should be set in self proxy subnets
                self._update_ptg_routes(ptg, remove=routes)
            else:
                if not ptg['proxy_group_id']:
                    self._update_l3p_routes(l3p, add=routes)
                self._update_ptg_routes(ptg, add=routes)

    def _set_proxy_gateway_routes(self, context, pt):
        self._update_proxy_gateway_routes(context, pt)

    def _unset_proxy_gateway_routes(self, context, pt):
        self._update_proxy_gateway_routes(context, pt, unset=True)

    def _validate_cluster_id(self, context):
        # In RMD, cluster_id can only point to a preexisting PT.
        if context.current['cluster_id']:
            try:
                pt = self._get_policy_target(
                    context._plugin_context, context.current['cluster_id'])
                if pt['policy_target_group_id'] != context.current[
                        'policy_target_group_id']:
                    raise exc.InvalidClusterPtg()
            except gp_ext.PolicyTargetNotFound:
                raise exc.InvalidClusterId()

    def _validate_pt_in_use_by_cluster(self, context):
        # Useful for avoiding to delete a cluster master
        pts = [x for x in self._get_policy_targets(
            context._plugin_context.elevated(),
            {'cluster_id': [context.current['id']]})
               if x['id'] != context.current['id']]
        if pts:
            raise exc.PolicyTargetInUse()

    def _check_allowed_address_pairs(self):
        return ("allowed-address-pairs" in
                self._core_plugin.supported_extension_aliases)

    def _update_cluster_membership(self, context, new_cluster_id=None,
                                   old_cluster_id=None):
        if self._check_allowed_address_pairs():
            curr_port = self._get_port(
                    context._plugin_context, context.current['port_id'])
            curr_pairs = curr_port['allowed_address_pairs']
            if old_cluster_id:
                # Remove allowed address
                master_mac, master_ips = self._get_cluster_master_pairs(
                    context._plugin_context, old_cluster_id)
                curr_pairs = [x for x in curr_port['allowed_address_pairs']
                              if not ((x['ip_address'] in master_ips) and
                                      (x['mac_address'] == master_mac))]
            if new_cluster_id:
                master_mac, master_ips = self._get_cluster_master_pairs(
                    context._plugin_context, new_cluster_id)
                curr_pairs += [
                    {'mac_address': master_mac,
                     'ip_address': x} for x in master_ips]
            self._update_port(context._plugin_context, curr_port['id'],
                              {'allowed_address_pairs': curr_pairs})

    def _get_cluster_master_pairs(self, plugin_context, cluster_id):
        master_pt = self._get_policy_target(plugin_context, cluster_id)
        master_port = self._get_port(plugin_context,
                                     master_pt['port_id'])
        master_mac = master_port['mac_address']
        master_ips = [x['ip_address'] for x in master_port['fixed_ips']]
        return master_mac, master_ips

    def _create_implicit_qos_policy(self, context):
        attrs = {
            'name': 'gbp_' + context.current['name'],
            'description': 'Group-Based Policy QoS policy',
            'project_id': context.current['tenant_id']}
        qos_policy = self._create_qos_policy(context._plugin_context, attrs)
        qos_policy_id = qos_policy['id']
        return qos_policy_id

    def _delete_ptg_qos_policy(self, context, qos_policy_id):
        qos_rules = self._get_qos_rules(context._plugin_context, qos_policy_id)
        with db_api.context_manager.writer.using(context._plugin_context):
            for qos_rule in qos_rules:
                self._delete_qos_rule(context._plugin_context,
                                      qos_rule['id'], qos_policy_id)
            self._delete_qos_policy(context._plugin_context, qos_policy_id)

    def _create_implicit_qos_rule(self, context, qos_policy_id, max, burst):
        attrs = {
            'max_kbps': max,
            'max_burst_kbps': burst}
        qos_rule = self._create_qos_rule(context._plugin_context,
                                         qos_policy_id, attrs)
        qos_rule_id = qos_rule['id']
        return qos_rule_id
