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

import hashlib
import re
import six

from aim import aim_manager
from aim.api import resource as aim_resource
from aim import context as aim_context
from aim import utils as aim_utils
from neutron.agent.linux import dhcp
from neutron import policy
from neutron_lib import constants as n_constants
from neutron_lib import context as n_context
from neutron_lib import exceptions as n_exc
from oslo_concurrency import lockutils
from oslo_config import cfg
from oslo_log import helpers as log
from oslo_log import log as logging
from oslo_utils import excutils

from gbpservice._i18n import _LE
from gbpservice._i18n import _LI
from gbpservice._i18n import _LW
from gbpservice.network.neutronv2 import local_api
from gbpservice.neutron.db.grouppolicy import group_policy_db as gpdb
from gbpservice.neutron.db.grouppolicy import group_policy_mapping_db as gpmdb
from gbpservice.neutron.extensions import cisco_apic
from gbpservice.neutron.extensions import cisco_apic_gbp as aim_ext
from gbpservice.neutron.extensions import cisco_apic_l3
from gbpservice.neutron.extensions import group_policy as gpolicy
from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import (
    exceptions as md_exc)
from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import (
    mechanism_driver as md)
from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import apic_mapper
from gbpservice.neutron.services.grouppolicy.common import (
    constants as gp_const)
from gbpservice.neutron.services.grouppolicy.common import constants as g_const
from gbpservice.neutron.services.grouppolicy.common import exceptions as exc
from gbpservice.neutron.services.grouppolicy.drivers import (
    neutron_resources as nrd)
from gbpservice.neutron.services.grouppolicy.drivers.cisco.apic import (
    aim_mapping_rpc as aim_rpc)
from gbpservice.neutron.services.grouppolicy.drivers.cisco.apic import (
    aim_validation)
from gbpservice.neutron.services.grouppolicy.drivers.cisco.apic import (
    apic_mapping_lib as alib)
from gbpservice.neutron.services.grouppolicy.drivers.cisco.apic import (
    nova_client as nclient)
from gbpservice.neutron.services.grouppolicy import plugin as gbp_plugin

LOG = logging.getLogger(__name__)
FORWARD = 'Forward'
REVERSE = 'Reverse'
FILTER_DIRECTIONS = {FORWARD: False, REVERSE: True}
FORWARD_FILTER_ENTRIES = 'Forward-FilterEntries'
REVERSE_FILTER_ENTRIES = 'Reverse-FilterEntries'
AUTO_PTG_NAME_PREFIX = 'ptg-for-l2p-%s'
# Note that this prefix should not exceede 4 characters
AUTO_PTG_PREFIX = 'auto'
AUTO_PTG_ID_PREFIX = AUTO_PTG_PREFIX + '%s'

# Definitions duplicated from apicapi lib
APIC_OWNED = 'apic_owned_'
PROMISCUOUS_TYPES = [n_constants.DEVICE_OWNER_DHCP,
                     n_constants.DEVICE_OWNER_LOADBALANCER]
# TODO(ivar): define a proper promiscuous API
PROMISCUOUS_SUFFIX = 'promiscuous'

CONTRACTS = 'contracts'
CONTRACT_SUBJECTS = 'contract_subjects'
FILTERS = 'filters'
FILTER_ENTRIES = 'filter_entries'
ENFORCED = aim_resource.EndpointGroup.POLICY_ENFORCED
UNENFORCED = aim_resource.EndpointGroup.POLICY_UNENFORCED
DEFAULT_SG_NAME = 'gbp_default'
COMMON_TENANT_AIM_RESOURCES = [aim_resource.Contract.__name__,
                               aim_resource.ContractSubject.__name__,
                               aim_resource.Filter.__name__,
                               aim_resource.FilterEntry.__name__]
# REVISIT: override add_router_interface L3 API check for now
NO_VALIDATE = cisco_apic_l3.OVERRIDE_NETWORK_ROUTING_TOPOLOGY_VALIDATION

# REVISIT: Auto-PTG is currently config driven to align with the
# config driven behavior of the older driver but is slated for
# removal.
opts = [
    cfg.BoolOpt('create_auto_ptg',
                default=True,
                help=_("Automatically create a PTG when a L2 Policy "
                       "gets created. This is currently an aim_mapping "
                       "policy driver specific feature.")),
    cfg.BoolOpt('create_per_l3p_implicit_contracts',
                default=True,
                help=_("This configuration is set to True to migrate a "
                       "deployment that has l3_policies without implicit "
                       "AIM contracts (these are deployments which have "
                       "AIM implicit contracts per tenant). A Neutron server "
                       "restart is required for this configuration to take "
                       "effect. The creation of the implicit contracts "
                       "happens at the time of the AIM policy driver "
                       "initialization. The configuration can be set to "
                       "False to avoid recreating the implicit contracts "
                       "on subsequent Neutron server restarts. This "
                       "option will be removed in the O release")),
    cfg.BoolOpt('advertise_mtu',
                default=True,
                help=_('If True, advertise network MTU values if core plugin '
                       'calculates them. MTU is advertised to running '
                       'instances via DHCP and RA MTU options.')),
    cfg.IntOpt('nested_host_vlan',
               default=4094,
               help=_("This is a locally siginificant VLAN used to provide "
                      "connectivity to the OpenStack VM when configured "
                      "to host the nested domain (Kubernetes/OpenShift).  "
                      "Any traffic originating from the VM and intended "
                      "to go on the Neutron network, is tagged with this "
                      "VLAN. The VLAN is stripped by the Opflex installed "
                      "flows on the integration bridge and the traffic is "
                      "forwarded on the Neutron network.")),
]


cfg.CONF.register_opts(opts, "aim_mapping")


class InvalidVrfForDualStackAddressScopes(exc.GroupPolicyBadRequest):
    message = _("User-specified address scopes for both address families, "
                "(IPv4 and IPv6) must use the same ACI VRF.")


class AutoPTGDeleteNotSupported(exc.GroupPolicyBadRequest):
    message = _("Auto PTG %(id)s cannot be deleted.")


class ExplicitAPGAssociationNotSupportedForAutoPTG(
    exc.GroupPolicyBadRequest):
    message = _("Explicit APG association not supported for Auto PTG, "
                "with AIM GBP driver")


class SharedAttributeUpdateNotSupported(exc.GroupPolicyBadRequest):
    message = _("Resource shared attribute update not supported with AIM "
                "GBP driver for resource of type %(type)s")


class IncorrectSubnetpoolUpdate(exc.GroupPolicyBadRequest):
    message = _("Subnetpool %(subnetpool_id)s cannot be disassociated "
                "from L3 Policy %(l3p_id)s since it has allocated subnet(s) "
                "associated with that L3 Policy")


class AIMMappingDriver(nrd.CommonNeutronBase, aim_rpc.AIMMappingRPCMixin):
    """AIM Mapping Orchestration driver.

    This driver maps GBP resources to the ACI-Integration-Module (AIM).
    """

    @log.log_method_call
    def initialize(self):
        LOG.info(_LI("APIC AIM Policy Driver initializing"))
        super(AIMMappingDriver, self).initialize()
        self._apic_aim_mech_driver = None
        self._apic_segmentation_label_driver = None
        self._apic_allowed_vm_name_driver = None
        self._aim = None
        self._name_mapper = None
        self.create_auto_ptg = cfg.CONF.aim_mapping.create_auto_ptg
        if self.create_auto_ptg:
            LOG.info(_LI('Auto PTG creation configuration set, '
                         'this will result in automatic creation of a PTG '
                         'per L2 Policy'))
        self.create_per_l3p_implicit_contracts = (
                cfg.CONF.aim_mapping.create_per_l3p_implicit_contracts)
        self.advertise_mtu = cfg.CONF.aim_mapping.advertise_mtu
        local_api.QUEUE_OUT_OF_PROCESS_NOTIFICATIONS = True
        if self.create_per_l3p_implicit_contracts:
            LOG.info(_LI('Implicit AIM contracts will be created '
                         'for l3_policies which do not have them.'))
            self._create_per_l3p_implicit_contracts()
        self._nested_host_vlan = (
                cfg.CONF.aim_mapping.nested_host_vlan)

    @log.log_method_call
    def start_rpc_listeners(self):
        return self.setup_opflex_rpc_listeners()

    def validate_state(self, repair):
        mgr = aim_validation.ValidationManager()
        return mgr.validate(repair)

    @property
    def aim_mech_driver(self):
        if not self._apic_aim_mech_driver:
            self._apic_aim_mech_driver = (
                self._core_plugin.mechanism_manager.mech_drivers[
                    'apic_aim'].obj)
        return self._apic_aim_mech_driver

    @property
    def aim(self):
        if not self._aim:
            self._aim = self.aim_mech_driver.aim
        return self._aim

    @property
    def name_mapper(self):
        if not self._name_mapper:
            self._name_mapper = self.aim_mech_driver.name_mapper
        return self._name_mapper

    @property
    def apic_segmentation_label_driver(self):
        if not self._apic_segmentation_label_driver:
            ext_drivers = self.gbp_plugin.extension_manager.ordered_ext_drivers
            for driver in ext_drivers:
                if 'apic_segmentation_label' == driver.name:
                    self._apic_segmentation_label_driver = (
                        driver.obj)
                    break
        return self._apic_segmentation_label_driver

    @property
    def apic_allowed_vm_name_driver(self):
        if self._apic_allowed_vm_name_driver is False:
            return False
        if not self._apic_allowed_vm_name_driver:
            ext_drivers = (self.gbp_plugin.extension_manager.
                           ordered_ext_drivers)
            for driver in ext_drivers:
                if 'apic_allowed_vm_name' == driver.name:
                    self._apic_allowed_vm_name_driver = driver.obj
                    break
        if not self._apic_allowed_vm_name_driver:
            self._apic_allowed_vm_name_driver = False
        return self._apic_allowed_vm_name_driver

    @log.log_method_call
    def ensure_tenant(self, plugin_context, tenant_id):
        self.aim_mech_driver.ensure_tenant(plugin_context, tenant_id)

    def aim_display_name(self, name):
        return aim_utils.sanitize_display_name(name)

    def _use_implicit_address_scope(self, context, ip_version, **kwargs):
        # Ensure ipv4 and ipv6 address scope have same vrf
        kwargs = {}
        if context.saved_scope_vrf:
            kwargs.update({cisco_apic.DIST_NAMES: context.saved_scope_vrf})
        address_scope = super(AIMMappingDriver,
                              self)._use_implicit_address_scope(context,
                                                                ip_version,
                                                                **kwargs)
        context.saved_scope_vrf = address_scope[cisco_apic.DIST_NAMES]
        return address_scope

    # TODO(tbachman): remove once non-isomorphic address scopes
    #                 are supported
    def _validate_address_scopes(self, context):
        l3p_db = context._plugin._get_l3_policy(
            context._plugin_context, context.current['id'])
        v4_scope_id = l3p_db['address_scope_v4_id']
        v6_scope_id = l3p_db['address_scope_v6_id']
        if v4_scope_id and v6_scope_id:
            v4_scope = self._get_address_scope(
                context._plugin_context, v4_scope_id)
            v6_scope = self._get_address_scope(
                context._plugin_context, v6_scope_id)
            if (v4_scope[cisco_apic.DIST_NAMES][cisco_apic.VRF] !=
                    v6_scope[cisco_apic.DIST_NAMES][cisco_apic.VRF]):
                raise InvalidVrfForDualStackAddressScopes()

    @log.log_method_call
    def create_l3_policy_precommit(self, context):
        l3p_req = context.current
        self._check_l3policy_ext_segment(context, l3p_req)

        # save VRF DN from v4 family address scope, if implicitly created,
        # as we will need to reuse it if we also implicitly create a v6
        # address scopes
        context.saved_scope_vrf = None
        self._create_l3p_subnetpools(context)
        # reset the temporarily saved scope
        context.saved_scope_vrf = None

        self._validate_address_scopes(context)

        # REVISIT: Check if the following constraint still holds
        if len(l3p_req['routers']) > 1:
            raise exc.L3PolicyMultipleRoutersNotSupported()
        # REVISIT: Validate non overlapping IPs in the same tenant.
        #          Currently this validation is not required for the
        #          AIM driver, and since the AIM driver is the only
        #          driver inheriting from this driver, we are okay
        #          without the check.
        self._reject_invalid_router_access(context)
        if not l3p_req['routers']:
            self._use_implicit_router(context)
        if not context.current['external_segments']:
            self._use_implicit_external_segment(context)
        external_segments = context.current['external_segments']
        if external_segments:
            self._plug_l3p_routers_to_ext_segment(context, l3p_req,
                                                  external_segments)
        self._create_implicit_contracts(context, l3p_req)

    @log.log_method_call
    def update_l3_policy_precommit(self, context):
        self._reject_shared_update(context, 'l3_policy')
        if context.current['routers'] != context.original['routers']:
            raise exc.L3PolicyRoutersUpdateNotSupported()
        # Currently there is no support for router update in l3p update.
        # Added this check just in case it is supported in future.
        self._reject_invalid_router_access(context)

        self._validate_in_use_by_nsp(context)
        self._update_l3p_subnetpools(context)

        # TODO(Sumit): For extra safety add validation for address_scope change
        l3p_orig = context.original
        l3p_curr = context.current
        self._check_l3policy_ext_segment(context, l3p_curr)
        old_segment_dict = l3p_orig['external_segments']
        new_segment_dict = l3p_curr['external_segments']
        if (l3p_curr['external_segments'] !=
                l3p_orig['external_segments']):
            new_segments = set(new_segment_dict.keys())
            old_segments = set(old_segment_dict.keys())
            removed = old_segments - new_segments
            self._unplug_l3p_routers_from_ext_segment(context,
                                                      l3p_curr,
                                                      removed)
            added_dict = {s: new_segment_dict[s]
                          for s in (new_segments - old_segments)}
            if added_dict:
                self._plug_l3p_routers_to_ext_segment(context,
                                                      l3p_curr,
                                                      added_dict)

    @log.log_method_call
    def delete_l3_policy_precommit(self, context):
        external_segments = context.current['external_segments']
        if external_segments:
            self._unplug_l3p_routers_from_ext_segment(context,
                context.current, external_segments.keys())
        l3p_db = context._plugin._get_l3_policy(
            context._plugin_context, context.current['id'])

        v4v6subpools = {4: l3p_db.subnetpools_v4, 6: l3p_db.subnetpools_v6}

        for k, v in six.iteritems(v4v6subpools):
            subpools = [sp.subnetpool_id for sp in v]
            for sp_id in subpools:
                self._db_plugin(
                    context._plugin)._remove_subnetpool_from_l3_policy(
                        context._plugin_context, l3p_db['id'], sp_id,
                        ip_version=k)
                self._cleanup_subnetpool(context._plugin_context, sp_id)

        for ascp in self.L3P_ADDRESS_SCOPE_KEYS.values():
            if l3p_db[ascp]:
                ascp_id = l3p_db[ascp]
                l3p_db.update({ascp: None})
                self._cleanup_address_scope(context._plugin_context, ascp_id)

        for router_id in context.current['routers']:
            self._db_plugin(context._plugin)._remove_router_from_l3_policy(
                context._plugin_context, l3p_db['id'], router_id)
            self._cleanup_router(context._plugin_context, router_id)
        self._delete_implicit_contracts(context, context.current)

    @log.log_method_call
    def get_l3_policy_status(self, context):
        # Not all of the neutron resources that l3_policy maps to
        # has a status attribute, hence we derive the status
        # from the AIM resources that the neutron resources map to
        session = context._plugin_context.session
        l3p_db = context._plugin._get_l3_policy(
            context._plugin_context, context.current['id'])
        mapped_aim_resources = []
        # Note: Subnetpool is not mapped to any AIM resource, hence it is not
        # considered for deriving the status
        mapped_status = []

        for ascp in self.L3P_ADDRESS_SCOPE_KEYS.values():
            if l3p_db[ascp]:
                ascp_id = l3p_db[ascp]
                ascope = self._get_address_scope(
                    context._plugin_context, ascp_id)
                vrf_dn = ascope[cisco_apic.DIST_NAMES][cisco_apic.VRF]
                aim_vrf = self._get_vrf_by_dn(context, vrf_dn)
                mapped_aim_resources.append(aim_vrf)

        routers = [router.router_id for router in l3p_db.routers]
        for router_id in routers:
            # elevated context is used here to enable router retrieval in
            # shared L3P cases wherein the call to get_l3_policy might be
            # made in the context of a different tenant
            router = self._get_router(
                context._plugin_context.elevated(), router_id)
            mapped_status.append(
                {'status': self._map_ml2plus_status(router)})

        mapped_status.append({'status': self._merge_aim_status(
            session, mapped_aim_resources)})
        context.current['status'] = self._merge_gbp_status(mapped_status)

    @log.log_method_call
    def create_l2_policy_precommit(self, context):
        self._reject_invalid_network_access(context)
        self._reject_non_shared_net_on_shared_l2p(context)
        l2p_db = context._plugin._get_l2_policy(
            context._plugin_context, context.current['id'])
        if not context.current['l3_policy_id']:
            self._create_implicit_l3_policy(context)
            l2p_db['l3_policy_id'] = context.current['l3_policy_id']
        l3p_db = context._plugin._get_l3_policy(
            context._plugin_context, l2p_db['l3_policy_id'])
        if not context.current['network_id']:
            self._use_implicit_network(
                context, address_scope_v4=l3p_db['address_scope_v4_id'],
                address_scope_v6=l3p_db['address_scope_v6_id'])
            l2p_db['network_id'] = context.current['network_id']
        l2p = context.current
        net = self._get_network(context._plugin_context,
                                l2p['network_id'])
        default_epg_dn = net[cisco_apic.DIST_NAMES][cisco_apic.EPG]
        self._configure_contracts_for_default_epg(
            context, l3p_db, default_epg_dn)
        if self.create_auto_ptg:
            default_epg = self._get_epg_by_dn(context, default_epg_dn)
            desc = "System created PTG for L2P (UUID: %s)" % l2p['id']
            data = {
                "id": self._get_auto_ptg_id(l2p['id']),
                "name": self._get_auto_ptg_name(l2p),
                "description": desc,
                "l2_policy_id": l2p['id'],
                "proxied_group_id": None,
                "proxy_type": None,
                "proxy_group_id": n_constants.ATTR_NOT_SPECIFIED,
                "network_service_policy_id": None,
                "service_management": False,
                "shared": l2p['shared'],
                "intra_ptg_allow":
                self._map_policy_enforcement_pref(default_epg),
            }
            self._create_policy_target_group(context._plugin_context, data)

    @log.log_method_call
    def delete_l2_policy_precommit(self, context):
        l2p_id = context.current['id']
        auto_ptg_id = self._get_auto_ptg_id(l2p_id)
        try:
            auto_ptg = context._plugin._get_policy_target_group(
                context._plugin_context, auto_ptg_id)
            self._process_subnets_for_ptg_delete(
                context, auto_ptg, l2p_id)
            if auto_ptg['l2_policy_id']:
                auto_ptg.update({'l2_policy_id': None})
            # REVISIT: Consider calling the actual GBP plugin
            # instead of it's base DB mixin class.
            self._db_plugin(
                context._plugin).delete_policy_target_group(
                    context._plugin_context, auto_ptg['id'])
        except gpolicy.PolicyTargetGroupNotFound:
            LOG.info(_LI("Auto PTG with ID %(id)s for "
                         "for L2P %(l2p)s not found. If create_auto_ptg "
                         "configuration was not set at the time of the L2P "
                         "creation, you can safely ignore this, else this "
                         "could potentially be indication of an error."),
                     {'id': auto_ptg_id, 'l2p': l2p_id})
        super(AIMMappingDriver, self).delete_l2_policy_precommit(context)

    @log.log_method_call
    def get_l2_policy_status(self, context):
        l2p_db = context._plugin._get_l2_policy(
            context._plugin_context, context.current['id'])
        net = self._get_network(context._plugin_context,
                                l2p_db['network_id'])

        if net:
            context.current['status'] = net['status']
            default_epg_dn = net[cisco_apic.DIST_NAMES][cisco_apic.EPG]
            l3p_db = context._plugin._get_l3_policy(
                context._plugin_context, l2p_db['l3_policy_id'])
            aim_resources = self._get_implicit_contracts_for_default_epg(
                context, l3p_db, default_epg_dn)
            aim_resources_list = []
            for k in aim_resources.keys():
                if not aim_resources[k] or not all(
                    x for x in aim_resources[k]):
                    # We expected a AIM mapped resource but did not find
                    # it, so something seems to be wrong
                    context.current['status'] = gp_const.STATUS_ERROR
                    return
                aim_resources_list.extend(aim_resources[k])
            merged_aim_status = self._merge_aim_status(
                context._plugin_context.session, aim_resources_list)
            context.current['status'] = self._merge_gbp_status(
                [context.current, {'status': merged_aim_status}])
        else:
            context.current['status'] = gp_const.STATUS_ERROR

    @log.log_method_call
    def create_policy_target_group_precommit(self, context):
        session = context._plugin_context.session

        if self._is_auto_ptg(context.current):
            if context.current['application_policy_group_id']:
                raise ExplicitAPGAssociationNotSupportedForAutoPTG()
            self._use_implicit_subnet(context)
            self._handle_create_network_service_policy(context)
            return

        if context.current['subnets']:
            raise alib.ExplicitSubnetAssociationNotSupported()

        if not context.current['l2_policy_id']:
            self._create_implicit_l2_policy(context)
            ptg_db = context._plugin._get_policy_target_group(
                context._plugin_context, context.current['id'])
            ptg_db['l2_policy_id'] = l2p_id = context.current['l2_policy_id']
        else:
            l2p_id = context.current['l2_policy_id']

        l2p_db = context._plugin._get_l2_policy(
            context._plugin_context, l2p_id)

        net = self._get_network(
            context._plugin_context, l2p_db['network_id'])

        self._use_implicit_subnet(context)

        self._handle_create_network_service_policy(context)

        bd = self.aim_mech_driver.get_bd_for_network(session, net)

        provided_contracts = self._get_aim_contract_names(
            session, context.current['provided_policy_rule_sets'])
        consumed_contracts = self._get_aim_contract_names(
            session, context.current['consumed_policy_rule_sets'])

        self._create_aim_ap_for_ptg_conditionally(context, context.current)
        aim_epg = self._aim_endpoint_group(
            session, context.current, bd.name, bd.tenant_name,
            provided_contracts=provided_contracts,
            consumed_contracts=consumed_contracts,
            policy_enforcement_pref=
            self._get_policy_enforcement_pref(context.current))

        # AIM EPG will be persisted in the following call
        self._add_implicit_svc_contracts_to_epg(context, l2p_db, aim_epg)

    @log.log_method_call
    def update_policy_target_group_precommit(self, context):
        self._reject_shared_update(context, 'policy_target_group')
        session = context._plugin_context.session
        old_provided_contracts = self._get_aim_contract_names(
            session, context.original['provided_policy_rule_sets'])
        old_consumed_contracts = self._get_aim_contract_names(
            session, context.original['consumed_policy_rule_sets'])
        new_provided_contracts = self._get_aim_contract_names(
            session, context.current['provided_policy_rule_sets'])
        new_consumed_contracts = self._get_aim_contract_names(
            session, context.current['consumed_policy_rule_sets'])

        if (context.current['network_service_policy_id'] !=
            context.original['network_service_policy_id']):
            self._validate_nat_pool_for_nsp(context)
            self._handle_nsp_update_on_ptg(context)

        # The "original" version of the ptg is being used here since we
        # want to retrieve the aim_epg based on the existing AP that is
        # a part of its indentity
        aim_epg = self._get_aim_endpoint_group(session, context.original)
        if aim_epg:
            if not self._is_auto_ptg(context.current):
                aim_epg.display_name = (
                    self.aim_display_name(context.current['name']))
                if (context.current['application_policy_group_id'] !=
                    context.original['application_policy_group_id']):
                    ap = self._create_aim_ap_for_ptg_conditionally(
                        context, context.current)
                    aim_epg = self._move_epg_to_new_ap(context, aim_epg, ap)
                    self._delete_aim_ap_for_ptg_conditionally(
                        context, context.original)
            elif context.current['application_policy_group_id']:
                raise ExplicitAPGAssociationNotSupportedForAutoPTG()
            aim_epg.policy_enforcement_pref = (
                self._get_policy_enforcement_pref(context.current))
            aim_epg.provided_contract_names = (
                list((set(aim_epg.provided_contract_names) -
                      set(old_provided_contracts)) |
                     set(new_provided_contracts)))
            aim_epg.consumed_contract_names = (
                list((set(aim_epg.consumed_contract_names) -
                      set(old_consumed_contracts)) |
                     set(new_consumed_contracts)))

            self._add_contracts_for_epg(
                aim_context.AimContext(session), aim_epg)

    @log.log_method_call
    def update_policy_target_group_postcommit(self, context):
        if (context.current['application_policy_group_id'] !=
            context.original['application_policy_group_id']):
            ptargets = context._plugin.get_policy_targets(
                context._plugin_context, {'policy_target_group_id':
                                          [context.current['id']]})
            for pt in ptargets:
                self.aim_mech_driver._notify_port_update(
                    context._plugin_context, pt['port_id'])

    @log.log_method_call
    def delete_policy_target_group_precommit(self, context):
        plugin_context = context._plugin_context
        auto_ptg_id = self._get_auto_ptg_id(context.current['l2_policy_id'])
        context.nsp_cleanup_ipaddress = self._get_ptg_policy_ipaddress_mapping(
            context._plugin_context.session, context.current['id'])
        context.nsp_cleanup_fips = self._get_ptg_policy_fip_mapping(
            context._plugin_context.session, context.current['id'])
        if context.current['id'] == auto_ptg_id:
            raise AutoPTGDeleteNotSupported(id=context.current['id'])
        ptg_db = context._plugin._get_policy_target_group(
            plugin_context, context.current['id'])
        session = context._plugin_context.session

        aim_ctx = self._get_aim_context(context)
        epg = self._aim_endpoint_group(session, context.current)
        self.aim.delete(aim_ctx, epg)
        self._process_subnets_for_ptg_delete(
            context, ptg_db, context.current['l2_policy_id'])

        self._delete_aim_ap_for_ptg_conditionally(context, ptg_db)
        ptg_db.update({'application_policy_group_id': None})

        if ptg_db['l2_policy_id']:
            l2p_id = ptg_db['l2_policy_id']
            ptg_db.update({'l2_policy_id': None})
            l2p_db = context._plugin._get_l2_policy(
                plugin_context, l2p_id)
            if not l2p_db['policy_target_groups'] or (
                (len(l2p_db['policy_target_groups']) == 1) and (
                    self._is_auto_ptg(l2p_db['policy_target_groups'][0]))):
                self._cleanup_l2_policy(context, l2p_id)

        if ptg_db['network_service_policy_id']:
            ptg_db.update({'network_service_policy_id': None})
            # REVISIT: Note that the RMD puts the following call in
            # try/except block since in deployment it was observed
            # that there are certain situations when the
            # sa_exc.ObjectDeletedError is thrown.
            self._cleanup_network_service_policy(
                context, ptg_db, context.nsp_cleanup_ipaddress,
                context.nsp_cleanup_fips)

    @log.log_method_call
    def extend_policy_target_group_dict(self, session, result):
        epg = self._aim_endpoint_group(session, result)
        if epg:
            result[cisco_apic.DIST_NAMES] = {cisco_apic.EPG: epg.dn}

    @log.log_method_call
    def get_policy_target_group_status(self, context):
        session = context._plugin_context.session
        epg = self._aim_endpoint_group(session, context.current)
        context.current['status'] = self._map_aim_status(session, epg)

    def _get_application_profiles_mapped_to_apg(self, session, apg):
        aim_ctx = aim_context.AimContext(session)
        ap_name = self.apic_ap_name_for_application_policy_group(
            session, apg['id'])
        return self.aim.find(
            aim_ctx, aim_resource.ApplicationProfile, name=ap_name)

    @log.log_method_call
    def extend_application_policy_group_dict(self, session, result):
        aim_aps = self._get_application_profiles_mapped_to_apg(session, result)
        dn_list = [ap.dn for ap in aim_aps]
        result[cisco_apic.DIST_NAMES] = {cisco_apic.AP: dn_list}

    @log.log_method_call
    def get_application_policy_group_status(self, context):
        session = context._plugin_context.session
        aim_aps = self._get_application_profiles_mapped_to_apg(
            session, context.current)
        context.current['status'] = self._merge_aim_status(
            context._plugin_context.session, aim_aps)

    @log.log_method_call
    def create_policy_target_precommit(self, context):
        ptg = self._get_policy_target_group(
            context._plugin_context, context.current['policy_target_group_id'])
        policy.enforce(context._plugin_context, 'get_policy_target_group',
                       ptg, pluralized='policy_target_groups')
        if not context.current['port_id']:
            subnets = self._get_subnets(
                context._plugin_context, {'id': ptg['subnets']})
            self._use_implicit_port(context, subnets=subnets)
        # explicit port case
        else:
            port_context = self._core_plugin.get_bound_port_context(
                        context._plugin_context, context.current['port_id'])
            self.aim_mech_driver.associate_domain(port_context)
        self._associate_fip_to_pt(context)

    @log.log_method_call
    def update_policy_target_precommit(self, context):
        # TODO(Sumit): Implement
        pass

    @log.log_method_call
    def update_policy_target_postcommit(self, context):
        if self.apic_segmentation_label_driver and (
            set(context.current['segmentation_labels']) != (
                set(context.original['segmentation_labels']))):
            self.aim_mech_driver._notify_port_update(
                context._plugin_context, context.current['port_id'])

    @log.log_method_call
    def delete_policy_target_precommit(self, context):
        fips = self._get_pt_floating_ip_mapping(
            context._plugin_context.session, context.current['id'])
        for fip in fips:
            self._delete_fip(context._plugin_context, fip.floatingip_id)
        pt_db = context._plugin._get_policy_target(
            context._plugin_context, context.current['id'])
        if pt_db['port_id']:
            if not self._port_is_owned(context._plugin_context.session,
                                       pt_db['port_id']):
                port_context = self._core_plugin.get_bound_port_context(
                        context._plugin_context, context.current['port_id'])
                self.aim_mech_driver.disassociate_domain(port_context)
            self._cleanup_port(context._plugin_context, pt_db['port_id'])

    @log.log_method_call
    def update_policy_classifier_precommit(self, context):
        o_dir = context.original['direction']
        c_dir = context.current['direction']
        o_prot = context.original['protocol']
        c_prot = context.current['protocol']
        o_port_min, o_port_max = (
            gpmdb.GroupPolicyMappingDbPlugin._get_min_max_ports_from_range(
                context.original['port_range']))
        c_port_min, c_port_max = (
            gpmdb.GroupPolicyMappingDbPlugin._get_min_max_ports_from_range(
                context.current['port_range']))

        if ((o_dir == c_dir) and (o_prot == c_prot) and (
            o_port_min == c_port_min) and (o_port_max == c_port_max)):
            # none of the fields relevant to the aim_mapping have changed
            # so no further processing is required
            return

        prules = self._db_plugin(context._plugin).get_policy_rules(
            context._plugin_context,
            filters={'policy_classifier_id': [context.current['id']]})

        if not prules:
            # this policy_classifier has not yet been assocaited with
            # a policy_rule and hence will not have any mapped aim
            # resources
            return

        prule_ids = [x['id'] for x in prules]

        prule_sets = self._get_prss_for_policy_rules(context, prule_ids)

        for pr in prules:
            session = context._plugin_context.session
            aim_ctx = self._get_aim_context(context)
            # delete old filter_entries
            self._delete_filter_entries_for_policy_rule(
                session, aim_ctx, pr)

            aim_filter = self._aim_filter(session, pr)
            aim_reverse_filter = self._aim_filter(
                session, pr, reverse_prefix=True)

            entries = alib.get_filter_entries_for_policy_classifier(
                context.current)

            remove_aim_reverse_filter = None
            if not entries['reverse_rules']:
                # the updated classifier's protocol does not have
                # reverse filter_entries
                if self.aim.get(aim_ctx, aim_reverse_filter):
                    # so remove the older reverse filter if it exists
                    self.aim.delete(aim_ctx, aim_reverse_filter)
                    remove_aim_reverse_filter = aim_reverse_filter.name
                    # Unset the reverse filter name so that its not
                    # used in further processing
                    aim_reverse_filter.name = None

            # create new filter_entries mapping to the updated
            # classifier and associated with aim_filters
            self._create_policy_rule_aim_mappings(
                session, aim_ctx, pr, entries)

            # update contract_subject to put the filter in the
            # appropriate in/out buckets corresponding to the
            # updated direction of the policy_classifier
            if remove_aim_reverse_filter or (o_dir != c_dir):
                for prs in prule_sets:
                    aim_contract_subject = self._get_aim_contract_subject(
                        session, prs)
                    # Remove the older reverse filter if needed
                    for filters in [aim_contract_subject.in_filters,
                                    aim_contract_subject.out_filters]:
                        if remove_aim_reverse_filter in filters:
                            filters.remove(remove_aim_reverse_filter)
                    if o_dir != c_dir:
                        # First remove the filter from the older
                        # direction list
                        for flist in [aim_contract_subject.in_filters,
                                      aim_contract_subject.out_filters]:
                            for fname in [aim_filter.name,
                                          aim_reverse_filter.name]:
                                if fname in flist:
                                    flist.remove(fname)
                        # Now add it to the relevant direction list(s)
                        if c_dir == g_const.GP_DIRECTION_IN:
                            aim_contract_subject.in_filters.append(
                                    aim_filter.name)
                            aim_contract_subject.out_filters.append(
                                    aim_reverse_filter.name)
                        elif c_dir == g_const.GP_DIRECTION_OUT:
                            aim_contract_subject.in_filters.append(
                                    aim_reverse_filter.name)
                            aim_contract_subject.out_filters.append(
                                    aim_filter.name)
                        else:
                            aim_contract_subject.in_filters.append(
                                    aim_filter.name)
                            aim_contract_subject.out_filters.append(
                                    aim_reverse_filter.name)
                            aim_contract_subject.in_filters.append(
                                    aim_reverse_filter.name)
                            aim_contract_subject.out_filters.append(
                                    aim_filter.name)
                    self.aim.create(aim_ctx, aim_contract_subject,
                                    overwrite=True)

    @log.log_method_call
    def create_policy_rule_precommit(self, context):
        entries = alib.get_filter_entries_for_policy_rule(context)
        session = context._plugin_context.session
        aim_ctx = self._get_aim_context(context)
        self._create_policy_rule_aim_mappings(
            session, aim_ctx, context.current, entries)

    @log.log_method_call
    def update_policy_rule_precommit(self, context):
        self.delete_policy_rule_precommit(context)
        self.create_policy_rule_precommit(context)

    @log.log_method_call
    def delete_policy_rule_precommit(self, context):
        session = context._plugin_context.session
        aim_ctx = self._get_aim_context(context)
        self._delete_filter_entries_for_policy_rule(session,
                                                    aim_ctx, context.current)
        aim_filter = self._aim_filter(session, context.current)
        aim_reverse_filter = self._aim_filter(
            session, context.current, reverse_prefix=True)
        for afilter in filter(None, [aim_filter, aim_reverse_filter]):
            self.aim.delete(aim_ctx, afilter)

    @log.log_method_call
    def extend_policy_rule_dict(self, session, result):
        result[cisco_apic.DIST_NAMES] = {}
        aim_filter_entries = self._get_aim_filter_entries(session, result)
        for k, v in six.iteritems(aim_filter_entries):
            dn_list = []
            for entry in v:
                dn_list.append(entry.dn)
            if k == FORWARD:
                result[cisco_apic.DIST_NAMES].update(
                    {aim_ext.FORWARD_FILTER_ENTRIES: dn_list})
            else:
                result[cisco_apic.DIST_NAMES].update(
                    {aim_ext.REVERSE_FILTER_ENTRIES: dn_list})

    @log.log_method_call
    def get_policy_rule_status(self, context):
        session = context._plugin_context.session
        aim_filters = self._get_aim_filters(session, context.current)
        aim_filter_entries = self._get_aim_filter_entries(
            session, context.current)
        context.current['status'] = self._merge_aim_status(
            session, aim_filters.values() + aim_filter_entries.values())

    @log.log_method_call
    def create_policy_rule_set_precommit(self, context):
        if context.current['child_policy_rule_sets']:
            raise alib.HierarchicalContractsNotSupported()
        aim_ctx = self._get_aim_context(context)
        session = context._plugin_context.session
        aim_contract = self._aim_contract(session, context.current)
        self.aim.create(aim_ctx, aim_contract)
        rules = self._db_plugin(context._plugin).get_policy_rules(
            context._plugin_context,
            filters={'id': context.current['policy_rules']})
        self._populate_aim_contract_subject(context, aim_contract, rules)

    @log.log_method_call
    def update_policy_rule_set_precommit(self, context):
        if context.current['child_policy_rule_sets']:
            raise alib.HierarchicalContractsNotSupported()
        session = context._plugin_context.session
        aim_contract = self._aim_contract(session, context.current)
        rules = self._db_plugin(context._plugin).get_policy_rules(
            context._plugin_context,
            filters={'id': context.current['policy_rules']})
        self._populate_aim_contract_subject(
            context, aim_contract, rules)

    @log.log_method_call
    def delete_policy_rule_set_precommit(self, context):
        aim_ctx = self._get_aim_context(context)
        session = context._plugin_context.session
        aim_contract = self._aim_contract(session, context.current)
        self._delete_aim_contract_subject(aim_ctx, aim_contract)
        self.aim.delete(aim_ctx, aim_contract)

    @log.log_method_call
    def extend_policy_rule_set_dict(self, session, result):
        result[cisco_apic.DIST_NAMES] = {}
        aim_contract = self._aim_contract(session, result)
        aim_contract_subject = self._aim_contract_subject(aim_contract)
        result[cisco_apic.DIST_NAMES].update(
            {aim_ext.CONTRACT: aim_contract.dn,
             aim_ext.CONTRACT_SUBJECT: aim_contract_subject.dn})

    @log.log_method_call
    def get_policy_rule_set_status(self, context):
        session = context._plugin_context.session
        aim_contract = self._aim_contract(session, context.current)
        aim_contract_subject = self._aim_contract_subject(aim_contract)
        context.current['status'] = self._merge_aim_status(
            session, [aim_contract, aim_contract_subject])

    @log.log_method_call
    def create_external_segment_precommit(self, context):
        self._validate_default_external_segment(context)
        if not context.current['subnet_id']:
            raise exc.ImplicitSubnetNotSupported()
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

        cidrs = sorted([x['destination']
                        for x in context.current['external_routes']])
        self._update_network(context._plugin_context,
                             subnet['network_id'],
                             {cisco_apic.EXTERNAL_CIDRS: cidrs})

    @log.log_method_call
    def update_external_segment_precommit(self, context):
        # REVISIT: what other attributes should we prevent an update on?
        invalid = ['port_address_translation']
        for attr in invalid:
            if context.current[attr] != context.original[attr]:
                raise exc.InvalidAttributeUpdateForES(attribute=attr)

        old_cidrs = sorted([x['destination']
                            for x in context.original['external_routes']])
        new_cidrs = sorted([x['destination']
                            for x in context.current['external_routes']])
        if old_cidrs != new_cidrs:
            subnet = self._get_subnet(context._plugin_context,
                                      context.current['subnet_id'])
            self._update_network(context._plugin_context,
                                 subnet['network_id'],
                                 {cisco_apic.EXTERNAL_CIDRS: new_cidrs})

    @log.log_method_call
    def delete_external_segment_precommit(self, context):
        subnet = self._get_subnet(context._plugin_context,
                                  context.current['subnet_id'])
        self._update_network(context._plugin_context,
                             subnet['network_id'],
                             {cisco_apic.EXTERNAL_CIDRS: ['0.0.0.0/0']})

    @log.log_method_call
    def create_external_policy_precommit(self, context):
        self._check_external_policy(context, context.current)
        if not context.current['external_segments']:
            self._use_implicit_external_segment(context)

        routers = self._get_ext_policy_routers(context,
            context.current, context.current['external_segments'])
        for r in routers:
            self._set_router_ext_contracts(context, r, context.current)

    @log.log_method_call
    def update_external_policy_precommit(self, context):
        ep = context.current
        old_ep = context.original
        self._check_external_policy(context, ep)
        removed_segments = (set(old_ep['external_segments']) -
                            set(ep['external_segments']))
        added_segment = (set(ep['external_segments']) -
                         set(old_ep['external_segments']))
        if removed_segments:
            routers = self._get_ext_policy_routers(context, ep,
                                                   removed_segments)
            for r in routers:
                self._set_router_ext_contracts(context, r, None)

        if (added_segment or
            sorted(old_ep['provided_policy_rule_sets']) !=
                sorted(ep['provided_policy_rule_sets']) or
            sorted(old_ep['consumed_policy_rule_sets']) !=
                sorted(ep['consumed_policy_rule_sets'])):
            routers = self._get_ext_policy_routers(context, ep,
                                                   ep['external_segments'])
            for r in routers:
                self._set_router_ext_contracts(context, r, ep)

    @log.log_method_call
    def delete_external_policy_precommit(self, context):
        routers = self._get_ext_policy_routers(context,
            context.current, context.current['external_segments'])
        for r in routers:
            self._set_router_ext_contracts(context, r, None)

    @log.log_method_call
    def create_network_service_policy_precommit(self, context):
        self._validate_nsp_parameters(context)

    @log.log_method_call
    def update_network_service_policy_precommit(self, context):
        self._validate_nsp_parameters(context)

    @log.log_method_call
    def create_nat_pool_precommit(self, context):
        self._add_nat_pool_to_segment(context)
        self._add_implicit_subnet_for_nat_pool_create(context)

    @log.log_method_call
    def update_nat_pool_precommit(self, context):
        self._process_ext_segment_update_for_nat_pool(context)
        self._add_implicit_subnet_for_nat_pool_update(context)

    @log.log_method_call
    def delete_nat_pool_precommit(self, context):
        self._nat_pool_in_use(context)
        np_db = context._plugin._get_nat_pool(
            context._plugin_context, context.current['id'])
        np_db.update({'subnet_id': None})
        self._delete_subnet_on_nat_pool_delete(context)

    def check_allow_vm_names(self, context, port):
        ok_to_bind = True
        ptg, pt = self._port_id_to_ptg(context._plugin_context, port['id'])
        # enforce the allowed_vm_names rules if possible
        if (ptg and port['device_id'] and
                self.apic_allowed_vm_name_driver):
            l2p = self._get_l2_policy(context._plugin_context,
                                      ptg['l2_policy_id'])
            l3p = self.gbp_plugin.get_l3_policy(
                context._plugin_context, l2p['l3_policy_id'])
            if l3p.get('allowed_vm_names'):
                ok_to_bind = False
                vm = nclient.NovaClient().get_server(port['device_id'])
                for allowed_vm_name in l3p['allowed_vm_names']:
                    match = re.search(allowed_vm_name, vm.name)
                    if match:
                        ok_to_bind = True
                        break
        if not ok_to_bind:
            LOG.warning(_LW("Failed to bind the port due to "
                            "allowed_vm_names rules %(rules)s "
                            "for VM: %(vm)s"),
                        {'rules': l3p['allowed_vm_names'],
                         'vm': vm.name})
        return ok_to_bind

    def get_ptg_port_ids(self, context, ptg):
        pts = self.gbp_plugin.get_policy_targets(
            context, {'id': ptg['policy_targets']})
        return [x['port_id'] for x in pts]

    def _reject_shared_update(self, context, type):
        if context.original.get('shared') != context.current.get('shared'):
            raise SharedAttributeUpdateNotSupported(type=type)

    def _aim_tenant_name(self, session, tenant_id, aim_resource_class=None,
                         gbp_resource=None, gbp_obj=None):
        if aim_resource_class and (
            aim_resource_class.__name__ in COMMON_TENANT_AIM_RESOURCES):
            # COMMON_TENANT_AIM_RESOURCES will always be created in the
            # ACI common tenant
            aim_ctx = aim_context.AimContext(session)
            self.aim_mech_driver._ensure_common_tenant(aim_ctx)
            tenant_name = md.COMMON_TENANT_NAME
        else:
            l3p_id = None
            if aim_resource_class.__name__ == (
                aim_resource.EndpointGroup.__name__):
                # the gbp_obj here should be a ptg
                l2p_id = gbp_obj['l2_policy_id']
                if l2p_id:
                    l2p_db = session.query(
                        gpmdb.L2PolicyMapping).filter_by(id=l2p_id).first()
                    l3p_id = l2p_db['l3_policy_id']
            elif aim_resource_class.__name__ == (
                aim_resource.BridgeDomain.__name__):
                # the gbp_obj here should be a l2p
                l3p_id = gbp_obj['l3_policy_id']
            if l3p_id:
                l3p_db = session.query(
                    gpmdb.L3PolicyMapping).filter_by(id=l3p_id).first()
                tenant_id = l3p_db['tenant_id']
            tenant_name = self.name_mapper.project(session, tenant_id)
        LOG.debug("Mapped tenant_id %(id)s to %(apic_name)s",
                  {'id': tenant_id, 'apic_name': tenant_name})
        return tenant_name

    def _aim_application_profile_for_ptg(self, context, ptg):
        # This returns a new AIM ApplicationProfile resource if apg_id
        # is set, else returns None
        apg_id = ptg['application_policy_group_id']
        if apg_id:
            apg = context._plugin._get_application_policy_group(
                context._plugin_context, apg_id)
            return self._aim_application_profile(
                context._plugin_context.session, apg)

    def _aim_application_profile(self, session, apg):
        # This returns a new AIM ApplicationProfile resource
        tenant_id = apg['tenant_id']
        tenant_name = self._aim_tenant_name(
            session, tenant_id,
            aim_resource_class=aim_resource.ApplicationProfile, gbp_obj=apg)
        display_name = self.aim_display_name(apg['name'])
        ap_name = self.apic_ap_name_for_application_policy_group(
            session, apg['id'])
        ap = aim_resource.ApplicationProfile(tenant_name=tenant_name,
                                             display_name=display_name,
                                             name=ap_name)
        LOG.debug("Mapped apg_id %(id)s with name %(name)s to %(apic_name)s",
                  {'id': apg['id'], 'name': display_name,
                   'apic_name': ap_name})
        return ap

    def _get_aim_application_profile_for_ptg(self, context, ptg):
        # This gets an AP from the AIM DB
        ap = self._aim_application_profile_for_ptg(context, ptg)
        if ap:
            return self._get_aim_application_profile_from_db(
                context._plugin_context.session, ap)

    def _get_aim_application_profile(self, session, apg):
        # This gets an AP from the AIM DB
        ap = self._aim_application_profile(session, apg)
        return self._get_aim_application_profile_from_db(session, ap)

    def _get_aim_application_profile_from_db(self, session, ap):
        aim_ctx = aim_context.AimContext(session)
        ap_fetched = self.aim.get(aim_ctx, ap)
        if not ap_fetched:
            LOG.debug("No ApplicationProfile found in AIM DB")
        else:
            LOG.debug("Got ApplicationProfile: %s", ap_fetched.__dict__)
        return ap_fetched

    def _create_aim_ap_for_ptg_conditionally(self, context, ptg):
        if ptg and ptg['application_policy_group_id'] and not (
            self._get_aim_application_profile_for_ptg(context, ptg)):
            ap = self._aim_application_profile_for_ptg(context, ptg)
            aim_ctx = aim_context.AimContext(context._plugin_context.session)
            self.aim.create(aim_ctx, ap)
            return ap

    def _move_epg_to_new_ap(self, context, old_epg, new_ap):
        session = context._plugin_context.session
        aim_ctx = aim_context.AimContext(session)
        self.aim.delete(aim_ctx, old_epg)
        old_epg.app_profile_name = (
            self.apic_ap_name_for_application_policy_group(
                session, context.current['application_policy_group_id']))
        self.aim.create(aim_ctx, old_epg)
        return old_epg

    def _delete_aim_ap_for_ptg_conditionally(self, context, ptg):
        # It is assumed that this method is called after the EPG corresponding
        # to the PTG has been deleted in AIM
        if ptg and ptg['application_policy_group_id']:
            ap = self._aim_application_profile_for_ptg(context, ptg)
            apg_id = ptg['application_policy_group_id']
            apg_db = context._plugin._get_application_policy_group(
                context._plugin_context, apg_id)
            if not apg_db['policy_target_groups'] or (
                len(apg_db['policy_target_groups']) == 1 and (
                    apg_db['policy_target_groups'][0]['id'] == ptg['id'])):
                # We lazily create the ApplicationProfile, so we delete
                # it when the last PTG associated with this APG is deleted
                aim_ctx = aim_context.AimContext(
                    context._plugin_context.session)
                self.aim.delete(aim_ctx, ap)

    def _aim_endpoint_group(self, session, ptg, bd_name=None,
                            bd_tenant_name=None,
                            provided_contracts=None,
                            consumed_contracts=None,
                            policy_enforcement_pref=UNENFORCED):
        # This returns a new AIM EPG resource
        tenant_id = ptg['tenant_id']
        tenant_name = self._aim_tenant_name(
            session, tenant_id, aim_resource_class=aim_resource.EndpointGroup,
            gbp_obj=ptg)
        id = ptg['id']
        name = ptg['name']
        display_name = self.aim_display_name(ptg['name'])
        ap_name = self.apic_ap_name_for_application_policy_group(
            session, ptg['application_policy_group_id'])
        epg_name = self.apic_epg_name_for_policy_target_group(
            session, id, name)
        LOG.debug("Using application_profile %(ap_name)s "
                  "for epg %(epg_name)s",
                  {'ap_name': ap_name, 'epg_name': epg_name})
        LOG.debug("Mapped ptg_id %(id)s with name %(name)s to %(apic_name)s",
                  {'id': id, 'name': name, 'apic_name': epg_name})
        kwargs = {'tenant_name': str(tenant_name),
                  'name': str(epg_name),
                  'display_name': display_name,
                  'app_profile_name': ap_name,
                  'policy_enforcement_pref': policy_enforcement_pref}
        if bd_name:
            kwargs['bd_name'] = bd_name
        if bd_tenant_name:
            kwargs['bd_tenant_name'] = bd_tenant_name

        if provided_contracts:
            kwargs['provided_contract_names'] = provided_contracts

        if consumed_contracts:
            kwargs['consumed_contract_names'] = consumed_contracts

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
            LOG.debug("Got epg: %s", vars(epg_fetched))
        return epg_fetched

    def _aim_filter(self, session, pr, reverse_prefix=False):
        # This returns a new AIM Filter resource
        tenant_id = pr['tenant_id']
        tenant_name = self._aim_tenant_name(session, tenant_id,
                                            aim_resource.Filter)
        id = pr['id']
        name = pr['name']
        display_name = self.aim_display_name(pr['name'])
        if reverse_prefix:
            filter_name = self.name_mapper.policy_rule(
                session, id, prefix=alib.REVERSE_PREFIX)
        else:
            filter_name = self.name_mapper.policy_rule(session, id)
        LOG.debug("Mapped policy_rule_id %(id)s with name %(name)s to"
                  "%(apic_name)s",
                  {'id': id, 'name': name, 'apic_name': filter_name})
        kwargs = {'tenant_name': str(tenant_name),
                  'name': str(filter_name),
                  'display_name': display_name}

        aim_filter = aim_resource.Filter(**kwargs)
        return aim_filter

    def _aim_filter_entry(self, session, aim_filter, filter_entry_name,
                          filter_entry_attrs):
        # This returns a new AIM FilterEntry resource
        tenant_name = aim_filter.tenant_name
        filter_name = aim_filter.name
        display_name = self.aim_display_name(filter_name)
        kwargs = {'tenant_name': tenant_name,
                  'filter_name': filter_name,
                  'name': filter_entry_name,
                  'display_name': display_name}
        kwargs.update(filter_entry_attrs)

        aim_filter_entry = aim_resource.FilterEntry(**kwargs)
        return aim_filter_entry

    def _create_policy_rule_aim_mappings(
        self, session, aim_context, pr, entries):
        if entries['forward_rules']:
            aim_filter = self._aim_filter(session, pr)
            self.aim.create(aim_context, aim_filter, overwrite=True)
            self._create_aim_filter_entries(session, aim_context, aim_filter,
                                            entries['forward_rules'])
            if entries['reverse_rules']:
                # Also create reverse rule
                aim_filter = self._aim_filter(session, pr,
                                              reverse_prefix=True)
                self.aim.create(aim_context, aim_filter, overwrite=True)
                self._create_aim_filter_entries(
                    session, aim_context, aim_filter, entries['reverse_rules'])

    def _delete_aim_filter_entries(self, aim_context, aim_filter):
        aim_filter_entries = self.aim.find(
            aim_context, aim_resource.FilterEntry,
            tenant_name=aim_filter.tenant_name,
            filter_name=aim_filter.name)
        for entry in aim_filter_entries:
            self.aim.delete(aim_context, entry)

    def _delete_filter_entries_for_policy_rule(self, session, aim_context, pr):
        aim_filter = self._aim_filter(session, pr)
        aim_reverse_filter = self._aim_filter(
            session, pr, reverse_prefix=True)
        for afilter in filter(None, [aim_filter, aim_reverse_filter]):
            self._delete_aim_filter_entries(aim_context, afilter)

    def _create_aim_filter_entries(self, session, aim_ctx, aim_filter,
                                   filter_entries):
        for k, v in six.iteritems(filter_entries):
            self._create_aim_filter_entry(
                session, aim_ctx, aim_filter, k, v)

    def _create_aim_filter_entry(self, session, aim_ctx, aim_filter,
                                 filter_entry_name, filter_entry_attrs,
                                 overwrite=False):
        aim_filter_entry = self._aim_filter_entry(
            session, aim_filter, filter_entry_name,
            alib.map_to_aim_filter_entry(filter_entry_attrs))
        self.aim.create(aim_ctx, aim_filter_entry, overwrite)

    def _get_aim_filters(self, session, policy_rule):
        # This gets the Forward and Reverse Filters from the AIM DB
        aim_ctx = aim_context.AimContext(session)
        filters = {}
        for k, v in six.iteritems(FILTER_DIRECTIONS):
            aim_filter = self._aim_filter(session, policy_rule, v)
            aim_filter_fetched = self.aim.get(aim_ctx, aim_filter)
            if not aim_filter_fetched:
                LOG.debug("No %s Filter found in AIM DB", k)
            else:
                LOG.debug("Got Filter: %s", vars(aim_filter_fetched))
            filters[k] = aim_filter_fetched
        return filters

    def _get_aim_filter_names(self, session, policy_rule):
        # Forward and Reverse AIM Filter names for a Policy Rule
        aim_filters = self._get_aim_filters(session, policy_rule)
        aim_filter_names = [f.name for f in aim_filters.values() if f]
        return aim_filter_names

    def _get_aim_filter_entries(self, session, policy_rule):
        # This gets the Forward and Reverse FilterEntries from the AIM DB
        aim_ctx = aim_context.AimContext(session)
        filters = self._get_aim_filters(session, policy_rule)
        filters_entries = {}
        for k, v in six.iteritems(filters):
            if v:
                aim_filter_entries = self.aim.find(
                    aim_ctx, aim_resource.FilterEntry,
                    tenant_name=v.tenant_name, filter_name=v.name)
                if not aim_filter_entries:
                    LOG.debug("No %s FilterEntry found in AIM DB", k)
                else:
                    LOG.debug("Got FilterEntry: %s", str(aim_filter_entries))
                filters_entries[k] = aim_filter_entries
        return filters_entries

    def _aim_contract(self, session, policy_rule_set):
        # This returns a new AIM Contract resource
        return aim_resource.Contract(
            tenant_name=self._aim_tenant_name(
                session, policy_rule_set['tenant_id'], aim_resource.Contract),
            name=self.name_mapper.policy_rule_set(
                session, policy_rule_set['id']),
            display_name=policy_rule_set['name'])

    def _aim_contract_subject(self, aim_contract, in_filters=None,
                              out_filters=None, bi_filters=None):
        # This returns a new AIM ContractSubject resource
        if not in_filters:
            in_filters = []
        if not out_filters:
            out_filters = []
        if not bi_filters:
            bi_filters = []
        display_name = self.aim_display_name(aim_contract.name)
        # Since we create one ContractSubject per Contract,
        # ContractSubject is given the Contract name
        kwargs = {'tenant_name': aim_contract.tenant_name,
                  'contract_name': aim_contract.name,
                  'name': aim_contract.name,
                  'display_name': display_name,
                  'in_filters': in_filters,
                  'out_filters': out_filters,
                  'bi_filters': bi_filters}

        aim_contract_subject = aim_resource.ContractSubject(**kwargs)
        return aim_contract_subject

    def _populate_aim_contract_subject(self, context, aim_contract,
                                       policy_rules):
        in_filters, out_filters = [], []
        session = context._plugin_context.session
        for rule in policy_rules:
            aim_filters = self._get_aim_filter_names(session, rule)
            classifier = context._plugin.get_policy_classifier(
                context._plugin_context, rule['policy_classifier_id'])
            if classifier['direction'] == g_const.GP_DIRECTION_IN:
                for fltr in aim_filters:
                    if fltr.startswith(alib.REVERSE_PREFIX):
                        out_filters.append(fltr)
                    else:
                        in_filters.append(fltr)
            elif classifier['direction'] == g_const.GP_DIRECTION_OUT:
                for fltr in aim_filters:
                    if fltr.startswith(alib.REVERSE_PREFIX):
                        in_filters.append(fltr)
                    else:
                        out_filters.append(fltr)
            else:
                in_filters += aim_filters
                out_filters += aim_filters
        self._populate_aim_contract_subject_by_filters(
            context, aim_contract, in_filters, out_filters)

    def _populate_aim_contract_subject_by_filters(
        self, context, aim_contract, in_filters=None, out_filters=None,
        bi_filters=None):
        if not in_filters:
            in_filters = []
        if not out_filters:
            out_filters = []
        if not bi_filters:
            bi_filters = []
        aim_ctx = self._get_aim_context(context)
        aim_contract_subject = self._aim_contract_subject(
            aim_contract, in_filters, out_filters, bi_filters)
        self.aim.create(aim_ctx, aim_contract_subject, overwrite=True)

    def _get_aim_contract(self, session, policy_rule_set):
        # This gets a Contract from the AIM DB
        aim_ctx = aim_context.AimContext(session)
        contract = self._aim_contract(session, policy_rule_set)
        contract_fetched = self.aim.get(aim_ctx, contract)
        if not contract_fetched:
            LOG.debug("No Contract found in AIM DB")
        else:
            LOG.debug("Got Contract: %s", vars(contract_fetched))
        return contract_fetched

    def _get_aim_contract_names(self, session, prs_id_list):
        contract_list = []
        for prs_id in prs_id_list:
            contract_name = self.name_mapper.policy_rule_set(session, prs_id)
            contract_list.append(contract_name)
        return contract_list

    def _get_aim_contract_subject(self, session, policy_rule_set):
        # This gets a ContractSubject from the AIM DB
        aim_ctx = aim_context.AimContext(session)
        contract = self._aim_contract(session, policy_rule_set)
        contract_subject = self._aim_contract_subject(contract)
        contract_subject_fetched = self.aim.get(aim_ctx, contract_subject)
        if not contract_subject_fetched:
            LOG.debug("No Contract found in AIM DB")
        else:
            LOG.debug("Got ContractSubject: %s",
                      vars(contract_subject_fetched))
        return contract_subject_fetched

    def _delete_aim_contract_subject(self, aim_context, aim_contract):
        aim_contract_subject = self._aim_contract_subject(aim_contract)
        self.aim.delete(aim_context, aim_contract_subject)

    def _get_aim_default_endpoint_group(self, session, network):
        return self.aim_mech_driver.get_epg_for_network(session, network)

    def _get_l2p_subnets(self, context, l2p_id):
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

    def _use_implicit_subnet(self, context, force_add=False):
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
                    AIMMappingDriver,
                    self)._use_implicit_subnet_from_subnetpool(
                        context, subnet_specifics={'name': name})
            context.add_subnets(subs - set(context.current['subnets']))
            if added:
                self._sync_ptg_subnets(context, l2p)
                l3p = self._get_l3p_for_l2policy(context, l2p_id)
                for r in l3p['routers']:
                    self._attach_router_to_subnets(context._plugin_context,
                                                   r, added)

    def _create_implicit_contracts(self, context, l3p):
        self._process_contracts_for_default_epg(context, l3p)

    def _configure_contracts_for_default_epg(self, context, l3p, epg_dn):
        self._process_contracts_for_default_epg(
            context, l3p, epg_dn=epg_dn, create=False, delete=False)

    def _delete_implicit_contracts(self, context, l3p):
        self._process_contracts_for_default_epg(
            context, l3p, epg_dn=None, create=False, delete=True)

    def _get_implicit_contracts_for_default_epg(
        self, context, l3p, epg_dn):
        return self._process_contracts_for_default_epg(
            context, l3p, epg_dn=epg_dn, get=True)

    def _process_contracts_for_default_epg(
        self, context, l3p, epg_dn=None, create=True, delete=False, get=False):
        # get=True overrides the create and delete cases, and returns a dict
        # with the Contracts, ContractSubjects, Filters, and FilterEntries
        # for the default EPG
        # create=True, delete=False means create everything and add Contracts
        # to the default EPG
        # create=False, delete=False means only add Contracts to the default
        # EPG
        # create=False, delete=True means only remove Contracts from the
        # default EPG and delete them
        # create=True, delete=True is not a valid combination
        if create and delete:
            LOG.error(_LE("Incorrect use of internal method "
                          "_process_contracts_for_default_epg(), create and "
                          "delete cannot be True at the same time"))
            raise
        session = context._plugin_context.session
        aim_ctx = aim_context.AimContext(session)

        # Infra Services' FilterEntries and attributes
        infra_entries = alib.get_service_contract_filter_entries()
        # ARP FilterEntry and attributes
        arp_entries = alib.get_arp_filter_entry()
        contracts = {alib.SERVICE_PREFIX: infra_entries,
                     alib.IMPLICIT_PREFIX: arp_entries}

        for contract_name_prefix, entries in six.iteritems(contracts):
            contract_name = self.name_mapper.l3_policy(
                session, l3p['id'], prefix=contract_name_prefix)
            # Create Contract (one per l3_policy)
            aim_contract = aim_resource.Contract(
                    tenant_name=self._aim_tenant_name(
                        session, l3p['tenant_id'], aim_resource.Contract),
                    name=contract_name, display_name=contract_name)

            if get:
                aim_resources = {}
                aim_resources[FILTERS] = []
                aim_resources[FILTER_ENTRIES] = []
                aim_resources[CONTRACT_SUBJECTS] = []
                contract_fetched = self.aim.get(aim_ctx, aim_contract)
                aim_resources[CONTRACTS] = [contract_fetched]
            else:
                if create:
                    self.aim.create(aim_ctx, aim_contract, overwrite=True)

                if not delete and epg_dn:
                    aim_epg = self.aim.get(
                        aim_ctx, aim_resource.EndpointGroup.from_dn(epg_dn))
                    # Add Contracts to the default EPG
                    if contract_name_prefix == alib.IMPLICIT_PREFIX:
                        # Default EPG provides and consumes ARP Contract
                        self._add_contracts_for_epg(
                            aim_ctx, aim_epg,
                            provided_contracts=[contract_name],
                            consumed_contracts=[contract_name])
                    else:
                        # Default EPG provides Infra Services' Contract
                        self._add_contracts_for_epg(
                            aim_ctx, aim_epg,
                            provided_contracts=[contract_name])
                    continue

            filter_names = []
            for k, v in six.iteritems(entries):
                filter_name = self.name_mapper.l3_policy(
                    session, l3p['id'],
                    prefix=''.join([contract_name_prefix, k, '-']))
                # Create Filter (one per l3_policy)
                aim_filter = aim_resource.Filter(
                        tenant_name=self._aim_tenant_name(
                            session, l3p['tenant_id'], aim_resource.Filter),
                        name=filter_name, display_name=filter_name)
                if get:
                    filter_fetched = self.aim.get(aim_ctx, aim_filter)
                    aim_resources[FILTERS].append(filter_fetched)
                    aim_filter_entry = self._aim_filter_entry(
                        session, aim_filter, k,
                        alib.map_to_aim_filter_entry(v))
                    entry_fetched = self.aim.get(aim_ctx, aim_filter_entry)
                    aim_resources[FILTER_ENTRIES].append(entry_fetched)
                else:
                    if create:
                        self.aim.create(aim_ctx, aim_filter, overwrite=True)
                        # Create FilterEntries (one per l3_policy) and
                        # associate with Filter
                        self._create_aim_filter_entry(
                            session, aim_ctx, aim_filter, k, v, overwrite=True)
                        filter_names.append(aim_filter.name)
                    if delete:
                        self._delete_aim_filter_entries(aim_ctx, aim_filter)
                        self.aim.delete(aim_ctx, aim_filter)
            if get:
                aim_contract_subject = self._aim_contract_subject(aim_contract)
                subject_fetched = self.aim.get(aim_ctx, aim_contract_subject)
                aim_resources[CONTRACT_SUBJECTS].append(subject_fetched)
                return aim_resources
            else:
                if create:
                    # Create ContractSubject (one per l3_policy) with relevant
                    # Filters, and associate with Contract
                    self._populate_aim_contract_subject_by_filters(
                        context, aim_contract, bi_filters=filter_names)
                if delete:
                    self._delete_aim_contract_subject(aim_ctx, aim_contract)
                    self.aim.delete(aim_ctx, aim_contract)

    def _add_implicit_svc_contracts_to_epg(self, context, l2p, aim_epg):
        session = context._plugin_context.session
        aim_ctx = aim_context.AimContext(session)
        implicit_contract_name = self.name_mapper.l3_policy(
            session, l2p['l3_policy_id'], prefix=alib.IMPLICIT_PREFIX)
        service_contract_name = self.name_mapper.l3_policy(
            session, l2p['l3_policy_id'], prefix=alib.SERVICE_PREFIX)
        self._add_contracts_for_epg(aim_ctx, aim_epg,
            provided_contracts=[implicit_contract_name],
            consumed_contracts=[implicit_contract_name, service_contract_name])

    def _add_contracts_for_epg(self, aim_ctx, aim_epg, provided_contracts=None,
                               consumed_contracts=None):
        if provided_contracts:
            aim_epg.provided_contract_names += provided_contracts

        if consumed_contracts:
            aim_epg.consumed_contract_names += consumed_contracts
        self.aim.create(aim_ctx, aim_epg, overwrite=True)

    def _merge_gbp_status(self, gbp_resource_list):
        merged_status = gp_const.STATUS_ACTIVE
        for gbp_resource in gbp_resource_list:
            if gbp_resource['status'] == gp_const.STATUS_BUILD:
                merged_status = gp_const.STATUS_BUILD
            elif gbp_resource['status'] == gp_const.STATUS_ERROR:
                merged_status = gp_const.STATUS_ERROR
                break
        return merged_status

    def _map_ml2plus_status(self, sync_status):
        if not sync_status:
            # REVIST(Sumit)
            return gp_const.STATUS_BUILD
        if sync_status == cisco_apic.SYNC_ERROR:
            return gp_const.STATUS_ERROR
        elif sync_status == cisco_apic.SYNC_BUILD:
            return gp_const.STATUS_BUILD
        else:
            return gp_const.STATUS_ACTIVE

    def _process_subnets_for_ptg_delete(self, context, ptg, l2p_id):
        session = context._plugin_context.session
        plugin_context = context._plugin_context
        subnet_ids = [assoc['subnet_id'] for assoc in ptg['subnets']]

        context._plugin._remove_subnets_from_policy_target_group(
            plugin_context, ptg['id'])
        if subnet_ids:
            for subnet_id in subnet_ids:
                # clean-up subnet if this is the last PTG using the L2P
                if not context._plugin._get_ptgs_for_subnet(
                    plugin_context, subnet_id):
                    if l2p_id:
                        l3p = self._get_l3p_for_l2policy(context, l2p_id)
                        for router_id in l3p['routers']:
                            # If the subnet interface for this router has
                            # already been removed (say manually), the
                            # call to Neutron's remove_router_interface
                            # will cause the transaction to exit immediately.
                            # To avoid this, we first check if this subnet
                            # still has an interface on this router.
                            if self._get_router_interface_port_by_subnet(
                                plugin_context, router_id, subnet_id):
                                with session.begin(nested=True):
                                    self._detach_router_from_subnets(
                                        plugin_context, router_id, [subnet_id])
                    self._cleanup_subnet(plugin_context, subnet_id)

    def _map_aim_status(self, session, aim_resource_obj):
        # Note that this implementation assumes that this driver
        # is the only policy driver configured, and no merging
        # with any previous status is required.
        aim_ctx = aim_context.AimContext(session)
        aim_status = self.aim.get_status(
            aim_ctx, aim_resource_obj, create_if_absent=False)
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

    def _get_aim_context(self, context):
        if hasattr(context, 'session'):
            session = context.session
        else:
            session = context._plugin_context.session
        return aim_context.AimContext(session)

    def _is_port_promiscuous(self, plugin_context, port):
        pt = self._port_id_to_pt(plugin_context, port['id'])
        if (pt and pt.get('cluster_id') and
                pt.get('cluster_id') != pt['id']):
            master = self._get_policy_target(plugin_context, pt['cluster_id'])
            if master.get('group_default_gateway'):
                return True
        if (port['device_owner'] in PROMISCUOUS_TYPES or
                port['name'].endswith(PROMISCUOUS_SUFFIX) or
                (pt and pt.get('group_default_gateway'))):
            return True
        if not port.get('port_security_enabled', True):
            return True
        return False

    def _is_dhcp_optimized(self, plugin_context, port):
        return self.aim_mech_driver.enable_dhcp_opt

    def _is_metadata_optimized(self, plugin_context, port):
        return self.aim_mech_driver.enable_metadata_opt

    def _set_dhcp_lease_time(self, details):
        if self.aim_mech_driver.apic_optimized_dhcp_lease_time > 0:
            details['dhcp_lease_time'] = (
                self.aim_mech_driver.apic_optimized_dhcp_lease_time)

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
        # if not l2p and self._ptg_needs_shadow_network(context, ptg):
        #    l2p = self._get_l2_policy(context._plugin_context,
        #                              ptg['l2_policy_id'])

        subnets = self._get_subnets(
            plugin_context,
            filters={'id': [ip['subnet_id'] for ip in port['fixed_ips']]})
        for subnet in subnets:
            dhcp_ports = {}
            subnet_dhcp_ips = set()
            for dhcp_port in self._get_ports(
                    plugin_context,
                    filters={
                        'network_id': [subnet['network_id']],
                        'device_owner': [n_constants.DEVICE_OWNER_DHCP]}):
                dhcp_ips = set([x['ip_address'] for x in dhcp_port['fixed_ips']
                                if x['subnet_id'] == subnet['id']])
                dhcp_ports.setdefault(dhcp_port['mac_address'], list(dhcp_ips))
                subnet_dhcp_ips |= dhcp_ips
            subnet_dhcp_ips = list(subnet_dhcp_ips)
            if not subnet['dns_nameservers']:
                # Use DHCP namespace port IP
                subnet['dns_nameservers'] = subnet_dhcp_ips
            # Set Default & Metadata routes if needed
            default_route = metadata_route = {}
            if subnet['ip_version'] == 4:
                for route in subnet['host_routes']:
                    if route['destination'] == '0.0.0.0/0':
                        default_route = route
                    if route['destination'] == dhcp.METADATA_DEFAULT_CIDR:
                        metadata_route = route
                if l2p and not l2p['inject_default_route']:
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
                    optimized = self._is_metadata_optimized(plugin_context,
                                                            port)
                    # REVISIT: We need to decide if we should provide
                    # host-routes for all of the DHCP agents. For now
                    # use the first DHCP agent in our list for the
                    # metadata host-route next-hop IPs
                    if not metadata_route and dhcp_ports and (
                        not optimized or (optimized and not default_route)):
                        for ip in dhcp_ports[dhcp_ports.keys()[0]]:
                            subnet['host_routes'].append(
                                {'destination': dhcp.METADATA_DEFAULT_CIDR,
                                 'nexthop': ip})
            subnet['dhcp_server_ips'] = subnet_dhcp_ips
            if dhcp_ports:
                subnet['dhcp_server_ports'] = dhcp_ports
        return subnets

    def _send_port_update_notification(self, plugin_context, port):
        self.aim_mech_driver._notify_port_update(plugin_context, port)

    def _get_aap_details(self, plugin_context, port, details):
        aaps = port['allowed_address_pairs']
        # Set the correct address ownership for this port
        owned_addresses = self._get_owned_addresses(
            plugin_context, port['id'])
        for allowed in aaps:
            if allowed['ip_address'] in owned_addresses:
                # Signal the agent that this particular address is active
                # on its port
                allowed['active'] = True
        return aaps

    def _get_port_vrf(self, plugin_context, port, details):
        net_db = self._core_plugin._get_network(plugin_context,
                                                port['network_id'])
        return self.aim_mech_driver.get_vrf_for_network(
            plugin_context.session, net_db)

    def _get_vrf_subnets(self, plugin_context, vrf_tenant_name, vrf_name,
                         details):
        session = plugin_context.session
        result = []
        # get all subnets of the specified VRF
        with session.begin(subtransactions=True):
            # Find VRF's address_scope first
            address_scope_ids = (
                self.aim_mech_driver._get_address_scope_ids_for_vrf(
                    session,
                    aim_resource.VRF(tenant_name=vrf_tenant_name,
                                     name=vrf_name)))
            if address_scope_ids:
                for address_scope_id in address_scope_ids:
                    subnetpools = self._get_subnetpools(
                        plugin_context,
                        filters={'address_scope_id': [address_scope_id]})
                    for pool in subnetpools:
                        result.extend(pool['prefixes'])
            else:
                aim_ctx = aim_context.AimContext(db_session=session)
                if vrf_tenant_name != md.COMMON_TENANT_NAME:
                    bds = self.aim.find(aim_ctx, aim_resource.BridgeDomain,
                                        tenant_name=vrf_tenant_name,
                                        vrf_name=vrf_name)
                else:
                    bds = self.aim.find(aim_ctx, aim_resource.BridgeDomain,
                                        vrf_name=vrf_name)
                    other_vrfs = self.aim.find(aim_ctx, aim_resource.VRF,
                                               name=vrf_name)
                    bd_tenants = set([x.tenant_name for x in bds])
                    vrf_tenants = set([x.tenant_name for x in other_vrfs
                                       if x.tenant_name != vrf_tenant_name])
                    valid_tenants = bd_tenants - vrf_tenants
                    # Only keep BDs that don't have a VRF with that name
                    # already
                    bds = [x for x in bds if x.tenant_name in valid_tenants]
                # Retrieve subnets from BDs
                net_ids = []
                for bd in bds:
                    try:
                        net_ids.append(self.name_mapper.reverse_network(
                            session, bd.name))
                    except md_exc.InternalError:
                        # Check if BD maps to an external network
                        ext_ids = self.aim_mech_driver.get_network_ids_for_bd(
                            session, bd)
                        net_ids.extend(ext_ids)
                        # If no external network is found, we ignore reverse
                        # mapping failures because there may be APIC BDs in the
                        # concerned VRF that Neutron is unaware of. This is
                        # especially true for VRFs in the common tenant.
                if net_ids:
                    subnets = self._get_subnets(plugin_context,
                                                {'network_id': net_ids})
                    result = [x['cidr'] for x in subnets]
        return result

    def _get_segmentation_labels(self, plugin_context, port, details):
        pt = self._port_id_to_pt(plugin_context, port['id'])
        if self.apic_segmentation_label_driver and pt and (
                    'segmentation_labels' in pt):
            return pt['segmentation_labels']

    def _get_nat_details(self, plugin_context, port, host, details):
        """ Add information about IP mapping for DNAT/SNAT """

        fips = []
        ipms = []
        host_snat_ips = []

        # Find all external networks connected to the port.
        # Handle them depending on whether there is a FIP on that
        # network.
        ext_nets = []

        port_sn = set([x['subnet_id'] for x in port['fixed_ips']])
        router_intf_ports = self._get_ports(
            plugin_context,
            filters={'device_owner': [n_constants.DEVICE_OWNER_ROUTER_INTF],
                     'fixed_ips': {'subnet_id': port_sn}})
        if router_intf_ports:
            routers = self._get_routers(
                plugin_context,
                filters={'device_id': [x['device_id']
                                       for x in router_intf_ports]})
            ext_nets = self._get_networks(
                plugin_context,
                filters={'id': [r['external_gateway_info']['network_id']
                                for r in routers
                                if r.get('external_gateway_info')]})
        if not ext_nets:
            return fips, ipms, host_snat_ips

        # Handle FIPs of owned addresses - find other ports in the
        # network whose address is owned by this port.
        # If those ports have FIPs, then steal them.
        fips_filter = [port['id']]
        active_addrs = [a['ip_address']
                        for a in details['allowed_address_pairs']
                        if a.get('active')]
        if active_addrs:
            others = self._get_ports(
                plugin_context,
                filters={'network_id': [port['network_id']],
                         'fixed_ips': {'ip_address': active_addrs}})
            fips_filter.extend([p['id'] for p in others])
        fips = self._get_fips(plugin_context,
                              filters={'port_id': fips_filter})

        for ext_net in ext_nets:
            dn = ext_net.get(cisco_apic.DIST_NAMES, {}).get(
                cisco_apic.EXTERNAL_NETWORK)
            ext_net_epg_dn = ext_net.get(cisco_apic.DIST_NAMES, {}).get(
                cisco_apic.EPG)
            if not dn or not ext_net_epg_dn:
                continue
            if 'distributed' != ext_net.get(cisco_apic.NAT_TYPE):
                continue

            # TODO(amitbose) Handle per-tenant NAT EPG
            ext_net_epg = aim_resource.EndpointGroup.from_dn(ext_net_epg_dn)

            fips_in_ext_net = [fip for fip in fips
                               if fip['floating_network_id'] == ext_net['id']]
            if not fips_in_ext_net:
                ext_segment_name = dn.replace('/', ':')
                ipms.append({'external_segment_name': ext_segment_name,
                             'nat_epg_name': ext_net_epg.name,
                             'nat_epg_app_profile': (
                                 ext_net_epg.app_profile_name),
                             'nat_epg_tenant': ext_net_epg.tenant_name})
                # TODO(amitbose) Set next_hop_ep_tenant for per-tenant NAT EPG
                if host:
                    snat_ip = self.aim_mech_driver.get_or_allocate_snat_ip(
                        plugin_context, host, ext_net)
                    if snat_ip:
                        snat_ip['external_segment_name'] = ext_segment_name
                        host_snat_ips.append(snat_ip)
            else:
                for f in fips_in_ext_net:
                    f['nat_epg_name'] = ext_net_epg.name
                    f['nat_epg_app_profile'] = ext_net_epg.app_profile_name
                    f['nat_epg_tenant'] = ext_net_epg.tenant_name
        return fips, ipms, host_snat_ips

    def _get_vrf_by_dn(self, context, vrf_dn):
        aim_context = self._get_aim_context(context)
        vrf = self.aim.get(
            aim_context, aim_resource.VRF.from_dn(vrf_dn))
        return vrf

    def _check_l3policy_ext_segment(self, context, l3policy):
        if l3policy['external_segments']:
            for allocations in l3policy['external_segments'].values():
                if len(allocations) > 1:
                    raise alib.OnlyOneAddressIsAllowedPerExternalSegment()
            # if NAT is disabled, allow only one L3P per ES
            ess = context._plugin.get_external_segments(
                context._plugin_context,
                filters={'id': l3policy['external_segments'].keys()})
            for es in ess:
                ext_net = self._ext_segment_2_ext_network(context, es)
                if (ext_net and
                    ext_net.get(cisco_apic.NAT_TYPE) in
                        ('distributed', 'edge')):
                    continue
                if [x for x in es['l3_policies'] if x != l3policy['id']]:
                    raise alib.OnlyOneL3PolicyIsAllowedPerExternalSegment()

    def _check_external_policy(self, context, ep):
        if ep.get('shared', False):
            # REVISIT(amitbose) This could be relaxed
            raise alib.SharedExternalPolicyUnsupported()
        ess = context._plugin.get_external_segments(
            context._plugin_context,
            filters={'id': ep['external_segments']})
        for es in ess:
            other_eps = context._plugin.get_external_policies(
                context._plugin_context,
                filters={'id': es['external_policies'],
                         'tenant_id': [ep['tenant_id']]})
            if [x for x in other_eps if x['id'] != ep['id']]:
                raise alib.MultipleExternalPoliciesForL3Policy()

    def _get_l3p_subnets(self, context, l3policy):
        l2p_sn = []
        for l2p_id in l3policy['l2_policies']:
            l2p_sn.extend(self._get_l2p_subnets(context, l2p_id))
        return l2p_sn

    def _ext_segment_2_ext_network(self, context, ext_segment):
        subnet = self._get_subnet(context._plugin_context,
                                  ext_segment['subnet_id'])
        if subnet:
            return self._get_network(context._plugin_context,
                                     subnet['network_id'])

    def _map_ext_segment_to_routers(self, context, ext_segments,
                                    routers):
        net_to_router = {r['external_gateway_info']['network_id']: r
                         for r in routers
                         if r.get('external_gateway_info')}
        result = {}
        for es in ext_segments:
            sn = self._get_subnet(context._plugin_context, es['subnet_id'])
            router = net_to_router.get(sn['network_id']) if sn else None
            if router:
                result[es['id']] = router
        return result

    def _plug_l3p_routers_to_ext_segment(self, context, l3policy,
                                         ext_seg_info):
        plugin_context = context._plugin_context
        es_list = self._get_external_segments(plugin_context,
            filters={'id': ext_seg_info.keys()})
        l3p_subs = self._get_l3p_subnets(context, l3policy)

        # REVISIT: We are not re-using the first router created
        # implicitly for the L3Policy (or provided explicitly by the
        # user). Consider using that for the first external segment

        for es in es_list:
            router_id = self._use_implicit_router(context,
                  router_name=l3policy['name'] + '-' + es['name'])
            router = self._create_router_gw_for_external_segment(
                context._plugin_context, es, ext_seg_info, router_id)
            if not ext_seg_info[es['id']] or not ext_seg_info[es['id']][0]:
                # Update L3P assigned address
                efi = router['external_gateway_info']['external_fixed_ips']
                assigned_ips = [x['ip_address'] for x in efi
                                if x['subnet_id'] == es['subnet_id']]
                context.set_external_fixed_ips(es['id'], assigned_ips)
            if es['external_policies']:
                ext_policy = self._get_external_policies(plugin_context,
                   filters={'id': es['external_policies'],
                            'tenant_id': [l3policy['tenant_id']]})
                if ext_policy:
                    self._set_router_ext_contracts(context, router_id,
                                                   ext_policy[0])
            self._attach_router_to_subnets(plugin_context, router_id, l3p_subs)

    def _unplug_l3p_routers_from_ext_segment(self, context, l3policy,
                                             ext_seg_ids):
        plugin_context = context._plugin_context
        es_list = self._get_external_segments(plugin_context,
                                              filters={'id': ext_seg_ids})
        routers = self._get_routers(plugin_context,
                                    filters={'id': l3policy['routers']})
        es_2_router = self._map_ext_segment_to_routers(context, es_list,
                                                       routers)
        for r in es_2_router.values():
            router_subs = self._get_router_interface_subnets(plugin_context,
                                                             r['id'])
            self._detach_router_from_subnets(plugin_context, r['id'],
                                             router_subs)
            context.remove_router(r['id'])
            self._cleanup_router(plugin_context, r['id'])

    def _get_router_interface_subnets(self, plugin_context, router_id):
        router_ports = self._get_ports(plugin_context,
            filters={'device_owner': [n_constants.DEVICE_OWNER_ROUTER_INTF],
                     'device_id': [router_id]})
        return set(y['subnet_id']
                   for x in router_ports for y in x['fixed_ips'])

    def _get_router_interface_port_by_subnet(self, plugin_context,
                                             router_id, subnet_id):
        router_ports = self._get_ports(plugin_context,
            filters={'device_owner': [n_constants.DEVICE_OWNER_ROUTER_INTF],
                     'device_id': [router_id],
                     'fixed_ips': {'subnet_id': [subnet_id]}})
        return (router_ports or [None])[0]

    def _attach_router_to_subnets(self, plugin_context, router_id, subs):
        # On account of sharing configuration, the router and subnets might
        # be in different tenants, hence we need to use admin context
        plugin_context = plugin_context.elevated()
        rtr_sn = self._get_router_interface_subnets(plugin_context, router_id)
        for subnet in subs:
            if subnet['id'] in rtr_sn:  # already attached
                continue
            gw_port = self._get_ports(plugin_context,
               filters={'fixed_ips': {'ip_address': [subnet['gateway_ip']],
                                      'subnet_id': [subnet['id']]}})
            if gw_port:
                # Gateway port is in use, create new interface port
                attrs = {'tenant_id': subnet['tenant_id'],
                         'network_id': subnet['network_id'],
                         'fixed_ips': [{'subnet_id': subnet['id']}],
                         'device_id': '',
                         'device_owner': n_constants.DEVICE_OWNER_ROUTER_INTF,
                         'mac_address': n_constants.ATTR_NOT_SPECIFIED,
                         'name': '%s-%s' % (router_id, subnet['id']),
                         'admin_state_up': True}
                try:
                    intf_port = self._create_port(plugin_context, attrs)
                except n_exc.NeutronException:
                    with excutils.save_and_reraise_exception():
                        LOG.exception(_LE('Failed to create explicit router '
                                          'interface port in subnet '
                                          '%(subnet)s'),
                                      {'subnet': subnet['id']})
                interface_info = {'port_id': intf_port['id'],
                                  NO_VALIDATE: True}
                try:
                    self._add_router_interface(plugin_context, router_id,
                                               interface_info)
                except n_exc.BadRequest:
                    self._delete_port(plugin_context, intf_port['id'])
                    with excutils.save_and_reraise_exception():
                        LOG.exception(_LE('Attaching router %(router)s to '
                                          '%(subnet)s with explicit port '
                                          '%(port) failed'),
                                      {'subnet': subnet['id'],
                                       'router': router_id,
                                       'port': intf_port['id']})
            else:
                self._plug_router_to_subnet(plugin_context, subnet['id'],
                                            router_id)

    def _plug_router_to_subnet(self, plugin_context, subnet_id, router_id):
        interface_info = {'subnet_id': subnet_id,
                          NO_VALIDATE: True}
        if router_id:
            try:
                self._add_router_interface(plugin_context, router_id,
                                           interface_info)
            except n_exc.BadRequest as e:
                LOG.exception(_LE("Adding subnet to router failed, exception:"
                                  "%s"), e)
                raise exc.GroupPolicyInternalError()

    def _detach_router_from_subnets(self, plugin_context, router_id, sn_ids):
        for subnet_id in sn_ids:
            # Use admin context because router and subnet may be in
            # different tenants
            self._remove_router_interface(plugin_context.elevated(),
                                          router_id,
                                          {'subnet_id': subnet_id})

    def _set_router_ext_contracts(self, context, router_id, ext_policy):
        session = context._plugin_context.session
        prov = []
        cons = []
        if ext_policy:
            prov = self._get_aim_contract_names(session,
                ext_policy['provided_policy_rule_sets'])
            cons = self._get_aim_contract_names(session,
                ext_policy['consumed_policy_rule_sets'])
        attr = {cisco_apic_l3.EXTERNAL_PROVIDED_CONTRACTS: prov,
                cisco_apic_l3.EXTERNAL_CONSUMED_CONTRACTS: cons}
        self._update_router(context._plugin_context, router_id, attr)

    def _get_ext_policy_routers(self, context, ext_policy, ext_seg_ids):
        plugin_context = context._plugin_context
        es = self._get_external_segments(plugin_context,
                                         filters={'id': ext_seg_ids})
        subs = self._get_subnets(context._plugin_context,
            filters={'id': [e['subnet_id'] for e in es]})
        ext_net = {s['network_id'] for s in subs}
        l3ps = set([l3p for e in es for l3p in e['l3_policies']])
        l3ps = self._get_l3_policies(plugin_context,
             filters={'id': l3ps,
                      'tenant_id': [ext_policy['tenant_id']]})
        routers = self._get_routers(plugin_context,
            filters={'id': [r for l in l3ps for r in l['routers']]})
        return [r['id'] for r in routers
            if (r['external_gateway_info'] or {}).get('network_id') in ext_net]

    def _get_auto_ptg_name(self, l2p):
        return AUTO_PTG_NAME_PREFIX % l2p['id']

    def _get_auto_ptg_id(self, l2p_id):
        if l2p_id:
            return AUTO_PTG_ID_PREFIX % hashlib.md5(l2p_id).hexdigest()

    def _is_auto_ptg(self, ptg):
        return ptg['id'].startswith(AUTO_PTG_PREFIX)

    def _get_policy_enforcement_pref(self, ptg):
        if ptg['intra_ptg_allow']:
            policy_enforcement_pref = UNENFORCED
        else:
            policy_enforcement_pref = ENFORCED
        return policy_enforcement_pref

    def _map_policy_enforcement_pref(self, epg):
        if epg.policy_enforcement_pref == UNENFORCED:
            return True
        else:
            return False

    def _get_bd_by_dn(self, context, bd_dn):
        aim_context = self._get_aim_context(context)
        bd = self.aim.get(
            aim_context, aim_resource.BridgeDomain.from_dn(bd_dn))
        return bd

    def _get_epg_by_dn(self, context, epg_dn):
        aim_context = self._get_aim_context(context)
        epg = self.aim.get(
            aim_context, aim_resource.EndpointGroup.from_dn(epg_dn))
        return epg

    def _get_epg_name_from_dn(self, context, epg_dn):
        aim_context = self._get_aim_context(context)
        default_epg_name = self.aim.get(
            aim_context, aim_resource.EndpointGroup.from_dn(epg_dn)).name
        return default_epg_name

    def apic_epg_name_for_policy_target_group(self, session, ptg_id,
                                              name=None):
        ptg_db = session.query(gpmdb.PolicyTargetGroupMapping).filter_by(
            id=ptg_id).first()
        if ptg_db and self._is_auto_ptg(ptg_db):
            l2p_db = session.query(gpmdb.L2PolicyMapping).filter_by(
                id=ptg_db['l2_policy_id']).first()
            network_id = l2p_db['network_id']
            admin_context = self._get_admin_context_reuse_session(session)
            net = self._get_network(admin_context, network_id)
            default_epg_dn = net[cisco_apic.DIST_NAMES][cisco_apic.EPG]
            default_epg_name = self._get_epg_name_from_dn(
                admin_context, default_epg_dn)
            return default_epg_name
        else:
            return ptg_id

    def apic_ap_name_for_application_policy_group(self, session, apg_id):
        if apg_id:
            return self.name_mapper.application_policy_group(
                session, apg_id)
        else:
            return self.aim_mech_driver.ap_name

    def _get_default_security_group(self, plugin_context, ptg_id,
                                    tenant_id):
        filters = {'name': [DEFAULT_SG_NAME], 'tenant_id': [tenant_id]}
        default_group = self._get_sgs(plugin_context, filters)
        return default_group[0]['id'] if default_group else None

    def _create_default_security_group(self, plugin_context, tenant_id):
        # Allow all
        sg_id = self._get_default_security_group(plugin_context, '', tenant_id)
        ip_v = [(n_constants.IPv4, '0.0.0.0/0'), (n_constants.IPv6, '::/0')]
        if not sg_id:
            sg_name = DEFAULT_SG_NAME
            sg = self._create_gbp_sg(plugin_context, tenant_id, sg_name,
                                     description='default GBP security group')
            sg_id = sg['id']

            for v, g in ip_v:
                self._sg_rule(plugin_context, tenant_id, sg_id,
                              'ingress', cidr=g, ethertype=v)
                self._sg_rule(plugin_context, tenant_id, sg_id,
                              'egress', cidr=g, ethertype=v)

    def _use_implicit_port(self, context, subnets=None):
        self._create_default_security_group(context._plugin_context,
                                            context.current['tenant_id'])
        super(AIMMappingDriver, self)._use_implicit_port(
            context, subnets=subnets)

    def _handle_create_network_service_policy(self, context):
        self._validate_nat_pool_for_nsp(context)
        self._handle_network_service_policy(context)

    def _get_prss_for_policy_rules(self, context, pr_ids):
        return [self._get_policy_rule_set(
            context._plugin_context, x['id']) for x in (
                context._plugin_context.session.query(
                    gpdb.PolicyRuleSet).join(
                        gpdb.PRSToPRAssociation,
                        gpdb.PRSToPRAssociation.policy_rule_set_id ==
                        gpdb.PolicyRuleSet.id).join(
                            gpdb.PolicyRule,
                            gpdb.PRSToPRAssociation.policy_rule_id ==
                            gpdb.PolicyRule.id).filter(
                                gpdb.PolicyRule.id.in_(pr_ids)).all())]

    def _get_port_mtu(self, context, port):
        if self.advertise_mtu:
            for dhcp_opt in port.get('extra_dhcp_opts'):
                if (dhcp_opt.get('opt_name') == 'interface-mtu' or
                        dhcp_opt.get('opt_name') == '26'):
                    if dhcp_opt.get('opt_value'):
                        try:
                            return int(dhcp_opt['opt_value'])
                        except ValueError:
                            continue
            network = self._get_network(context, port['network_id'])
            return network.get('mtu')
        return None

    def _get_dns_domain(self, context, port):
        network = self._get_network(context, port['network_id'])
        return network.get('dns_domain')

    def _get_admin_context_reuse_session(self, session):
        admin_context = n_context.get_admin_context()
        admin_context._session = session
        return admin_context

    def _get_nested_domain(self, context, port):
        network = self._get_network(context, port['network_id'])
        return (network.get('apic:nested_domain_name'),
                network.get('apic:nested_domain_type'),
                network.get('apic:nested_domain_infra_vlan'),
                network.get('apic:nested_domain_service_vlan'),
                network.get('apic:nested_domain_node_network_vlan'),
                network.get('apic:nested_domain_allowed_vlans'),
                self._nested_host_vlan if network.get(
                    'apic:nested_domain_infra_vlan') else None)

    def _create_per_l3p_implicit_contracts(self):
        admin_context = n_context.get_admin_context()
        context = type('', (object,), {})()
        context._plugin_context = admin_context
        session = admin_context.session
        aim_ctx = aim_context.AimContext(session)
        contract_name_prefix = alib.get_service_contract_filter_entries(
                ).keys()[0]
        l3ps = session.query(gpmdb.L3PolicyMapping).all()
        name_mapper = apic_mapper.APICNameMapper()
        aim_mgr = aim_manager.AimManager()
        self._aim = aim_mgr
        self._name_mapper = name_mapper
        orig_aim_tenant_name = self._aim_tenant_name

        def _aim_tenant_name(self, session, tenant_id, aim_resource_class=None,
                gbp_resource=None, gbp_obj=None):
            attrs = aim_resource.Tenant(
                name=md.COMMON_TENANT_NAME, display_name='')
            tenant = aim_mgr.get(aim_ctx, attrs)
            if not tenant:
                tenant = aim_mgr.create(aim_ctx, attrs)
            return md.COMMON_TENANT_NAME

        self._aim_tenant_name = _aim_tenant_name

        for l3p in l3ps:
            implicit_contract_name = name_mapper.l3_policy(
                session, l3p['id'], prefix=contract_name_prefix)
            if not aim_mgr.find(
                    aim_ctx, aim_resource.Contract,
                    name=implicit_contract_name):
                self._create_implicit_contracts(context, l3p)

        self._aim = None
        self._name_mapper = None
        self._aim_tenant_name = orig_aim_tenant_name

    def validate_neutron_mapping(self, mgr):
        # REVISIT: Implement.
        pass

    def validate_aim_mapping(self, mgr):
        # REVISIT: Register all AIM resource types used by GBP mapping
        # but not the Neutron mapping.

        # REVISIT:  Register DB tables to be validated.

        # Determine expected AIM resources and DB records for each
        # GBP resource type.
        self._validate_l3_policies(mgr)
        self._validate_l2_policies(mgr)
        self._validate_policy_target_groups(mgr)
        self._validate_policy_targets(mgr)
        self._validate_application_policy_groups(mgr)
        self._validate_policy_classifiers(mgr)
        self._validate_policy_rule_sets(mgr)
        self._validate_external_segments(mgr)
        self._validate_external_policies(mgr)

        # REVISIT: Do any of the following top-level GBP resources map
        # to or effect AIM resources: NetworkServicePolicy,
        # PolicyAction, NATPool?

    def _validate_l3_policies(self, mgr):
        # REVISIT: Implement validation of actual mapping to AIM
        # resources.
        if mgr.actual_session.query(gpdb.L3Policy).first():
            mgr.validation_failed(
                "GBP->AIM validation for L3P not yet implemented")

    def _validate_l2_policies(self, mgr):
        # REVISIT: Implement validation of actual mapping to AIM
        # resources.
        if mgr.actual_session.query(gpdb.L2Policy).first():
            mgr.validation_failed(
                "GBP->AIM validation for L2P not yet implemented")

    def _validate_policy_target_groups(self, mgr):
        # REVISIT: Implement validation of actual mapping to AIM
        # resources.
        if mgr.actual_session.query(gpdb.PolicyTargetGroup).first():
            mgr.validation_failed(
                "GBP->AIM validation for PTG not yet implemented")

    def _validate_policy_targets(self, mgr):
        # REVISIT: Implement validation of actual mapping to AIM
        # resources.
        if mgr.actual_session.query(gpdb.PolicyTarget).first():
            mgr.validation_failed(
                "GBP->AIM validation for PT not yet implemented")

    def _validate_application_policy_groups(self, mgr):
        # REVISIT: Implement validation of actual mapping to AIM
        # resources.
        if mgr.actual_session.query(gpdb.ApplicationPolicyGroup).first():
            mgr.validation_failed(
                "GBP->AIM validation for APG not yet implemented")

    def _validate_policy_classifiers(self, mgr):
        # REVISIT: Implement validation of actual mapping to AIM
        # resources.
        if mgr.actual_session.query(gpdb.PolicyClassifier).first():
            mgr.validation_failed(
                "GBP->AIM validation for PC not yet implemented")

    def _validate_policy_rule_sets(self, mgr):
        # REVISIT: Implement validation of actual mapping to AIM
        # resources.
        if mgr.actual_session.query(gpdb.PolicyRuleSet).first():
            mgr.validation_failed(
                "GBP->AIM validation for PRS not yet implemented")

    def _validate_external_segments(self, mgr):
        # REVISIT: Implement validation of actual mapping to AIM
        # resources. This should probably be called from
        # validate_neutron_mapping rather than validate_aim_mapping,
        # since external_routes maps to the cisco_apic.EXTERNAL_CIDRS
        # network extension.
        if mgr.actual_session.query(gpdb.ExternalSegment).first():
            mgr.validation_failed(
                "GBP->AIM validation for ES not yet implemented")

    def _validate_external_policies(self, mgr):
        # REVISIT: Implement validation of actual mapping to AIM
        # resources.
        if mgr.actual_session.query(gpdb.ExternalPolicy).first():
            mgr.validation_failed(
                "GBP->AIM validation for EP not yet implemented")
