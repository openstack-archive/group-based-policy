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
import uuid

#from keystoneclient.v2_0 import client as keyclient
from neutron.common import log
from neutron.extensions import providernet as pn
from neutron.extensions import securitygroup as ext_sg
from neutron import manager
from neutron.openstack.common import lockutils
from neutron.openstack.common import log as logging
#from neutron.plugins.ml2.drivers.cisco.apic import apic_model
#from neutron.plugins.ml2.drivers.cisco.apic import config
from neutron.plugins.ml2 import models
from oslo.config import cfg

from gbp.neutron.db.grouppolicy import group_policy_mapping_db as gpdb
from gbp.neutron.services.grouppolicy.common import constants as g_const
from gbp.neutron.services.grouppolicy.common import exceptions as gpexc
from gbp.neutron.services.grouppolicy.drivers import resource_mapping as api
from gbp.neutron.services.grouppolicy.drivers.odl import odl_manager


LOG = logging.getLogger(__name__)


class UpdatePTNotSupportedOnOdlDriver(gpexc.GroupPolicyBadRequest):
    message = _("Update Policy Target currently not supported on ODL driver.")

class L2PolicyMultiplePolicyTargetGroupNotSupportedOnOdlDriver(
        gpexc.GroupPolicyBadRequest):
    message = _("An L2 policy can't have multiple policy target groups on "
                "ODL GBP driver.")


class RedirectActionNotSupportedOnOdlDriver(gpexc.GroupPolicyBadRequest):
    message = _("Redirect action is currently not supported for ODL GBP "
                "driver.")


class PolicyRuleUpdateNotSupportedOnOdlDriver(gpexc.GroupPolicyBadRequest):
    message = _("Policy rule update is not supported on for ODL GBP"
                "driver.")


class ExactlyOneActionPerRuleIsSupportedOnOdlDriver(
        gpexc.GroupPolicyBadRequest):
    message = _("Exactly one action per rule is supported on ODL GBP driver.")



class OdlMappingDriver(api.ResourceMappingDriver):
    """ODL Mapping driver for Group Policy plugin.

    This driver implements group policy semantics by mapping group
    policy resources to various other neutron resources, and leverages
    ODL backend for enforcing the policies.
    """

    me = None
    manager = None

    @staticmethod
    def get_odl_manager():
        if not OdlMappingDriver.manager:
            OdlMappingDriver.manager = odl_manager.OdlManager()
        return OdlMappingDriver.manager

    def initialize(self):
        super(OdlMappingDriver, self).initialize()
        self.odl_manager = OdlMappingDriver.get_odl_manager()
        self._gbp_plugin = None
        OdlMappingDriver.me = self

    @property
    def gbp_plugin(self):
        if not self._gbp_plugin:
            self._gbp_plugin = (manager.NeutronManager.get_service_plugins()
                                .get("GROUP_POLICY"))
        return self._gbp_plugin

    @staticmethod
    def get_initialized_instance():
        return OdlMappingDriver.me

    def create_dhcp_policy_target_if_needed(self, plugin_context, port):
        session = plugin_context.session
        if (self._port_is_owned(session, port['id'])):
            # Nothing to do
            return

        # Retrieve PTG
        filters = {'network_id': [port['network_id']]}
        ptgs = self.gbp_plugin.get_policy_target_groups(
            plugin_context, filters=filters)
        if ptgs:
            ptg = ptgs[0]
            # Create PolicyTarget
            attrs = {'policy_target':
                     {'tenant_id': port['tenant_id'],
                      'name': 'dhcp-%s' % ptg['id'],
                      'description': _("Implicitly created DHCP policy "
                                       "target"),
                      'policy_target_group_id': ptg['id'],
                      'port_id': port['id']}}
            self.gbp_plugin.create_policy_target(plugin_context, attrs)
        sg_id = self._ensure_default_security_group(plugin_context,
                                                    port['tenant_id'])
        data = {'port': {'security_groups': [sg_id]}}
        self._core_plugin.update_port(plugin_context, port['id'], data)

    def create_policy_target_postcommit(self, context):
        super(OdlMappingDriver, self).create_policy_target_postcommit(context)
        pt = self._get_pt_detail(context)
        ep = {
            "endpoint-group": pt['ptg_id'],
            "l2-context": pt['l2ctx_id'],
            "l3-address": pt['l3_list'],
            "mac-address": pt['mac_address'],
            "neutron-port-id": pt['neutron_port_id'],
            "tenant": pt['tenant_id']
        }
        self.odl_manager.register_endpoints([ep])

    def update_policy_target_precommit(self, context):
        raise UpdatePTNotSupportedOnOdlDriver()

    def delete_policy_target_postcommit(self, context):
        pt = self._get_pt_detail(context)
        ep = {
            "l2": pt['l2_list'],
            "l3": pt['l3_list']
        }
        self.odl_manager.unregister_endpoints([ep])
        # Delete Neutron's port
        super(OdlMappingDriver, self).delete_policy_target_postcommit(context)

    def create_l3_policy_postcommit(self, context):
        #TODO: provide tenant name and description in future
        tenant_id = uuid.UUID(context.current['tenant_id']).urn[9:]
        l3ctx = {
            "id": context.current['id']
        }
        self.odl_manager.create_l3_context(tenant_id,l3ctx)

    def delete_l3_policy_postcommit(self, context):
        #TODO: provide tenant name and description in future
        tenant_id = uuid.UUID(context.current['tenant_id']).urn[9:]
        l3ctx= {
            "id": context.current['id']
        }
        self.odl_manager.delete_l3_context(tenant_id,l3ctx)

    def create_policy_action_precommit(self, context):
        # TODO: allow redirect for service chaining
        if context.current['action_type'] == g_const.GP_ACTION_REDIRECT:
            raise RedirectActionNotSupportedOnOdlDriver()

        self._update_tenant(context)

    def create_policy_rule_precommit(self, context):
        if ('policy_actions' in context.current and
                len(context.current['policy_actions']) != 1):
            # TODO: to be fixed when redirect is supported
            raise ExactlyOneActionPerRuleIsSupportedOnOdlDriver()

    def update_policy_rule_precommit(self, context):
        # TODO(ivar): add support for action update on policy rules
        raise PolicyRuleUpdateNotSupportedOnOdlDriver()

    def create_policy_rule_postcommit(self, context):
        action = context._plugin.get_policy_action(
            context._plugin_context, context.current['policy_actions'][0])
        classifier = context._plugin.get_policy_classifier(
            context._plugin_context,
            context.current['policy_classifier_id'])
        if action['action_type'] == g_const.GP_ACTION_ALLOW:
            port_min, port_max = (
                gpdb.GroupPolicyMappingDbPlugin._get_min_max_ports_from_range(
                    classifier['port_range']))
            attrs = {'etherT': 'ip',
                     'prot': classifier['protocol'].lower()}
            if port_min and port_max:
                attrs['dToPort'] = port_max
                attrs['dFromPort'] = port_min
            # TODO: need to call Odl manager here to set up the rule, or save it somewhere for later

    def delete_policy_rule_postcommit(self, context):
        # TODO: need to revisit this
        pass

    def create_policy_rule_set_postcommit(self, context):
        # Create ODL contract
        # TODO: need to revisit this method when it's clear how to create contract with ODL manager
        pass

    def create_policy_target_group_postcommit(self, context):
        #TODO: need to revisit this part when odl_manager is clear
        pass

    def create_l2_policy_postcommit(self, context):
        #TODO: need to revisit this
        pass


    def create_l3_policy_postcommit(self, context):
        #TODO: need to revisit this
        pass

    def delete_policy_rule_set_precommit(self, context):
        # TODO: need to revisit this
        pass

    def delete_policy_rule_set_postcommit(self, context):
        # TODO: need to revisit this
        pass

    def delete_policy_target_group_postcommit(self, context):
        # TODO: need to revisit this
        pass

    def delete_l2_policy_postcommit(self, context):
        # TODO: need to revisit this
        pass

    def delete_l3_policy_postcommit(self, context):
        # TODO: need to revisit this
        pass

    def update_policy_target_postcommit(self, context):
        # TODO: need to revisit this
        pass

    def update_policy_target_group_postcommit(self, context):
        # TODO: need to revisit this
        pass

    def process_subnet_changed(self, context, old, new):
        # TODO: need to revisit this
        pass

    def process_port_changed(self, context, old, new):
        # TODO: need to revisit this
        pass

    def process_path_deletion(self, context, port, policy_target=None):
        # TODO; what is this path deletion? do it later?
        # TODO: need to revisit this
        pass

    def _apply_policy_rule_set_rules(
            self, context, policy_rule_set, policy_rules, transaction=None):
        # TODO: need to revisit this
        pass

    def _remove_policy_rule_set_rules(
            self, context, policy_rule_set, policy_rules, transaction=None):
        # TODO: need to revisit this
        pass

    def _manage_policy_rule_set_rules(
            self, context, policy_rule_set, policy_rules, unset=False,
            transaction=None):
        # TODO: need to revisit this
        pass

    def _manage_policy_target_port(self, plugin_context, pt):
        port = self._core_plugin.get_port(plugin_context, pt['port_id'])

        port_details = self._get_gbp_details(
            plugin_context, port_id=port['id'],
            host=port['binding:host_id'])
        if port_details:
            # TODO(ivar): change APICAPI to not expect a resource context
            plugin_context._plugin = self.gbp_plugin
            plugin_context._plugin_context = plugin_context
            tenant_id = self.name_mapper.tenant(plugin_context,
                                                port['tenant_id'])
            ptg = self.name_mapper.policy_target_group(
                plugin_context, port_details['ptg_id'])
            bd = self.name_mapper.l2_policy(
                plugin_context, port_details['l2_policy_id'])
            seg = port_details['segmentation_id']
            # Create a static path attachment for the host/epg/switchport
            with self.apic_manager.apic.transaction() as trs:
                self.apic_manager.ensure_path_created_for_port(
                    tenant_id, ptg, port['binding:host_id'], seg,
                    bd_name=bd,
                    transaction=trs)

    def _manage_ptg_policy_rule_sets(
            self, plugin_context, ptg, added_provided, added_consumed,
            removed_provided, removed_consumed, transaction=None):
        # TODO: need to revisit this
        pass

    def _manage_ptg_subnets(self, plugin_context, ptg, added_subnets,
                            removed_subnets, transaction=None):
        # TODO: need to revisit this
        pass

    def _get_active_path_count(self, plugin_context, port_info):
        # TODO: need to revisit this
        pass

    @lockutils.synchronized('apic-portlock')
    def _delete_port_path(self, context, atenant_id, ptg, port_info):
        # TODO: need to revisit this
        pass

    def _delete_path_if_last(self, context, port_info):
        # TODO: need to revisit this
        pass

    def _get_default_security_group(self, context, ptg_id, tenant_id):
        # TODO: need to revisit this
        pass

    def _update_default_security_group(self, plugin_context, ptg_id,
                                       tenant_id, subnets=None):
        # TODO: need to revisit this
        pass

    def _assoc_ptg_sg_to_pt(self, context, pt_id, ptg_id):
        # TODO: need to revisit this
        pass

    def _handle_policy_rule_sets(self, context):
        # TODO: need to revisit this
        pass

    def _gateway_ip(self, subnet):
        cidr = netaddr.IPNetwork(subnet['cidr'])
        return '%s/%s' % (subnet['gateway_ip'], str(cidr.prefixlen))

    def _subnet_ids_to_objects(self, plugin_context, ids):
        return self._core_plugin.get_subnets(plugin_context,
                                             filters={'id': ids})

    def _port_to_ptg_network(self, context, port, host=None):
        ptg = self._port_id_to_ptg(context, port['id'])
        if not ptg:
            # Not GBP port
            return None, None
        network = self._l2p_id_to_network(context, ptg['l2_policy_id'])
        return ptg, network

    def _port_id_to_pt(self, context, port_id):
        pt = (context.session.query(gpdb.PolicyTargetMapping).
              filter_by(port_id=port_id).first())
        if pt:
            db_utils = gpdb.GroupPolicyMappingDbPlugin()
            return db_utils._make_policy_target_dict(pt)

    def _port_id_to_ptg(self, context, port_id):
        pt = self._port_id_to_pt(context, port_id)
        if pt:
            return self.gbp_plugin.get_policy_target_group(
                context, pt['policy_target_group_id'])
        return

    def _l2p_id_to_network(self, context, l2p_id):
        l2_policy = self.gbp_plugin.get_l2_policy(context, l2p_id)
        return self._core_plugin.get_network(context, l2_policy['network_id'])

    def _network_id_to_l2p(self, context, network_id):
        l2ps = self.gbp_plugin.get_l2_policies(
            context, filters={'network_id': [network_id]})
        return l2ps[0] if l2ps else None

    def _subnet_to_ptg(self, context, subnet_id):
        ptg = (context.session.query(gpdb.PolicyTargetGroupMapping).
               join(gpdb.PolicyTargetGroupMapping.subnets).
               filter(gpdb.PTGToSubnetAssociation.subnet_id ==
                      subnet_id).
               first())
        if ptg:
            db_utils = gpdb.GroupPolicyMappingDbPlugin()
            return db_utils._make_policy_target_group_dict(ptg)

    def _get_gbp_details(self, context, **kwargs):
        port_id = (kwargs.get('port_id') or
                   self._core_plugin._device_to_port_id(kwargs['device']))
        port = self._core_plugin.get_port(context, port_id)
        # retrieve PTG and network from a given Port
        if not kwargs.get('policy_target'):
            ptg, network = self._port_to_ptg_network(context, port,
                                                     kwargs['host'])
            if not ptg:
                return
        else:
            pt = kwargs['policy_target']
            ptg = self.gbp_plugin.get_policy_target_group(
                context, pt['policy_target_group_id'])
            network = self._l2p_id_to_network(context, ptg['l2_policy_id'])

        return {'port_id': port_id,
                'mac_address': port['mac_address'],
                'ptg_id': ptg['id'],
                'segmentation_id': network[pn.SEGMENTATION_ID],
                'network_type': network[pn.NETWORK_TYPE],
                'l2_policy_id': ptg['l2_policy_id'],
                'tenant_id': port['tenant_id'],
                'host': port['binding:host_id']
                }

    def _get_pt_detail(self, context):
        port_id = context.current['port_id']
        port = self._core_plugin.get_port(context._plugin_context, port_id)
        tenant_id = uuid.UUID(context.current['tenant_id']).urn[9:]
        ptg_id = context.current['policy_target_group_id']
        ptg = self.gbp_plugin.get_policy_target_group(context, ptg_id)
        l2ctx_id =  ptg['l2_policy_id']
        l2ctx = self.gbp_plugin.get_l2_policy(context, l2ctx_id)
        l3ctx_id = l2ctx['l3_policy_id']
        mac_address = port['mac_address']
        neutron_port_id = 'tap' + port_id[:11]

        l3_list =[]
        for fixed_ip in port['fixed_ips']:
            l3_list.append(
                {
                 "ip_address": fixed_ip['ip_address'],
                 "l3-context": l3ctx_id
                }
            )

        l2_list = []
        l2_list.append(
            {
                "l2-context": l2ctx_id,
                "mac-address": mac_address
            }
        )

        return {
            "port_id": port_id,
            "tenant_id": tenant_id,
            "ptg_id": ptg_id,
            "l2ctx_id": l2ctx_id,
            "l3ctx_id": l3ctx_id,
            "mac_address": mac_address,
            "neutron_port_id": neutron_port_id,
            "l3_list": l3_list
            "l2-list": l2_list
        }


    def _update_tenant(self, context):
        #TODO: provide tenant name and description in future
        tenant_id = uuid.UUID(context.current['tenant_id']).urn[9:]
        tenant = {
            "id": tenant_id
        }
        self.odl_manager.create_update_tenant(tenant)