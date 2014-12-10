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
from neutron import manager
from neutron.common import log
from neutron.extensions import providernet as pn
from neutron.extensions import securitygroup as ext_sg
from neutron.plugins.common import constants
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
    message = _("Update Policy Target currently not supported on ODL GBP "
                "driver.")


class UpdatePTGNotSupportedOnOdlDriver(gpexc.GroupPolicyBadRequest):
    message = _("Update Policy Target Group currently not supported on ODL "
                "GBP driver.")


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

class ClassifierTcpUdpPortRangeNotSupportedOnOdlDriver(
        gpexc.GroupPolicyBadRequest):
    message = _("Tcp or Udp port range is not supported on ODL GBP driver.")

class ClassifierUnknownIPProtocolNotSupportedOnOdlDriver(
        gpexc.GroupPolicyBadRequest):
    message = _("Unknown IP Protocol is not supported on ODL GBP driver.")


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
        tenant_id = uuid.UUID(context.current['tenant_id']).urn[9:]
        l3ctx = {
            "id": context.current['id'],
            "name": context.current['name'],
            "description": context.current['description']
        }
        self.odl_manager.create_update_l3_context(tenant_id,l3ctx)

    def delete_l3_policy_postcommit(self, context):
        tenant_id = uuid.UUID(context.current['tenant_id']).urn[9:]
        l3ctx= {
            "id": context.current['id']
        }
        self.odl_manager.delete_l3_context(tenant_id,l3ctx)

    def create_l2_policy_postcommit(self, context):
        super(OdlMappingDriver, self).create_l2_policy_postcommit(context)
        tenant_id = uuid.UUID(context.current['tenant_id']).urn[9:]

        #l2_policy mapped to l2_bridge_domain in ODL
        l2bd = {
            "id": context.current['id'],
            "name": context.current['name'],
            "description": context.current['description'],
            "parent": context.current['l3_policy_id']
        }
        self.odl_manager.create_update_l2_bridge_domain(tenant_id,l2bd)

        # Implicit network within l2 policy creation is mapped to l2 flood domain in ODL
        net_id = context.current['network_id']
        network =  self._core_plugin.get_network(context._plugin_context, net_id)
        l2fd = {
            "id": net_id,
            "name": network['name'],
            "parent": context.current['id']
        }
        self.odl_manager.create_update_l2_flood_domain(tenant_id, l2fd)

    def delete_l2_policy_postcommit(self, context):
        super(OdlMappingDriver, self).delete_l2_policy_postcommit(context)
        tenant_id = uuid.UUID(context.current['tenant_id']).urn[9:]

        #l2_policy mapped to l2_bridge_domain in ODL
        l2bd= {
            "id": context.current['id']
        }
        self.odl_manager.delete_l2_bridge_domain(tenant_id,l2bd)

        # Implicit network within l2 policy creation is mapped to l2 flood domain in ODL
        net_id = context.current['network_id']
        l2fd = {
            "id": net_id,
        }
        self.odl_manager.delete_l2_flood_domain(tenant_id, l2fd)

    def create_policy_target_group_postcommit(self, context):
        super(OdlMappingDriver, self).create_policy_target_group_postcommit(
            context)
        tenant_id = uuid.UUID(context.current['tenant_id']).urn[9:]
        subnets = context.current['subnets']

        #PTG mapped to EPG in ODL
        epg = {
            "id": context.current['id'],
            "name": context.current['name'],
            "description": context.current['description'],
            "network-domain": subnets[0]
        }
        self.odl_manager.create_update_endpoint_group(tenant_id, epg)

        #Implicit subnet within policy target group mapped to subnet in ODL
        for subnet_id in subnets:
            neutron_subnet =  self._core_plugin.get_subnet(context._plugin_context, subnet_id)
            odl_subnet = {
                "id": subnet_id,
                "ip-prefix": neutron_subnet['cidr'],
                "parent": neutron_subnet['network_id'],
                "virtual-router-ip": neutron_subnet['gateway_ip']
            }
            self.odl_manager.create_update_subnet(tenant_id, odl_subnet)

    def update_policy_target_group_precommit(self, context):
        raise UpdatePTGNotSupportedOnOdlDriver()

    def delete_policy_target_group_postcommit(self, context):
        tenant_id = uuid.UUID(context.current['tenant_id']).urn[9:]
        subnets = context.current['subnets']

        #delete mapped subnets in ODL, and clean them up from neutron
        for subnet_id in subnets:
            self._cleanup_subnet(context._plugin_context, subnet_id, None)
            odl_subnet = {
                "id": subnet_id
            }
            self.odl_manager.delete_subnet(tenant_id, odl_subnet)

        #delete mapped EPG in ODL
        epg = {
            "id": context.current['id'],
        }
        self.odl_manager.delete_endpoint_group(tenant_id, epg)

    def create_policy_action_precommit(self, context):
        # TODO(odl): allow redirect for service chaining
        if context.current['action_type'] == g_const.GP_ACTION_REDIRECT:
            raise RedirectActionNotSupportedOnOdlDriver()

    def create_policy_action_postcommit(self, context):
        super(OdlMappingDriver, self).create_policy_action_postcommit(context)
        tenant_id = uuid.UUID(context.current['tenant_id']).urn[9:]

        # fill in action instance data
        action_instance = {
            "action-definition-id": context.current['id'],
            "name": context.current['name'],
            "parameter-value": [
                {
                    "name": context.current['name'],
                    "string-value": context.current['action_type'],
                }
            ]
        }
        self.odl_manager.create_action(tenant_id, action_instance)

    def delete_policy_action_postcommit(self, context):
        super(OdlMappingDriver, self).delete_policy_action_postcommit(context)
        tenant_id = uuid.UUID(context.current['tenant_id']).urn[9:]

        # fill in action instance data
        action_instance= {
            "name": context.current['name']
        }
        self.odl_manager.delete_action(tenant_id, action_instance)

    def create_policy_classifier_postcommit(self, context):
        tenant_id = uuid.UUID(context.current['tenant_id']).urn[9:]

        if context.current['protocol'] == constants.ICMP:
            # fill in classifier instance data
            classifier_instance = {
                # Use hard coded value based on current ODL implementation
                "classifier-definition-id":
                    '79c6fdb2-1e1a-4832-af57-c65baf5c2335',
                "name": context.current['name'],
                "parameter-value": [
                    {
                        "name": "proto",
                        #TODO(yapeng): change the hard code value
                        "int-value": 1,
                    }
                ]
            }
            self.odl_manager.create_classifier(tenant_id, classifier_instance)
            return

        # For TCP and UDP protoocol create two classifier (in and out)
        # fill in dst port classifier instance data
        classifier_instance = {
            # Use hard coded value based on current ODL implementation
            "classifier-definition-id":
                '4250ab32-e8b8-445a-aebb-e1bd2cdd291f',
            "name": context.current['name'] + '-dest',
            "parameter-value": [
                {
                    "name": "type",
                    "string-value": context.current['protocol'],
                },
                {
                    "name": "destport",
                    "int-value": context.current['port_range'],
                }
            ]
        }
        self.odl_manager.create_classifier(tenant_id, classifier_instance)

        # fill in src port classifier instance data
        classifier_instance = {
            # Use hard coded value based on current ODL implementation
            "classifier-definition-id":
                '4250ab32-e8b8-445a-aebb-e1bd2cdd291f',
            "name": context.current['name'] + '-src',
            "parameter-value": [
                {
                    "name": "type",
                    "string-value": context.current['protocol'],
                },
                {
                    "name": "sourceport",
                    "int-value": context.current['port_range'],
                }
            ]
        }
        self.odl_manager.create_classifier(tenant_id, classifier_instance)

    def delete_policy_classifier_postcommit(self, context):
        tenant_id = uuid.UUID(context.current['tenant_id']).urn[9:]

        if context.current['protocol'] == constants.ICMP:
            # fill in classifier instance data
            classifier_instance = {
                "name": context.current['name']
            }
            self.odl_manager.delete_classifier(tenant_id, classifier_instance)
            return

        # fill in classifier instance data
        classifier_instance = {
            "name": context.current['name'] + '-dest',
        }
        self.odl_manager.delete_classifier(tenant_id, classifier_instance)

        # fill in classifier instance data
        classifier_instance = {
            "name": context.current['name'] + '-src',
        }
        self.odl_manager.delete_classifier(tenant_id, classifier_instance)


    def create_policy_rule_precommit(self, context):
        if ('policy_actions' in context.current and
                len(context.current['policy_actions']) != 1):
            # TODO(odl): to be fixed when redirect is supported
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


    def _get_pt_detail(self, context):
        port_id = context.current['port_id']
        port = self._core_plugin.get_port(context._plugin_context, port_id)
        tenant_id = uuid.UUID(context.current['tenant_id']).urn[9:]
        ptg_id = context.current['policy_target_group_id']
        ptg = self.gbp_plugin.get_policy_target_group(context._plugin_context,
                                                      ptg_id)
        l2ctx_id =  ptg['l2_policy_id']
        l2ctx = self.gbp_plugin.get_l2_policy(context._plugin_context,
                                              l2ctx_id)
        l3ctx_id = l2ctx['l3_policy_id']
        mac_address = port['mac_address']
        neutron_port_id = 'tap' + port_id[:11]

        l3_list =[]
        for fixed_ip in port['fixed_ips']:
            l3_list.append(
                {
                 "ip-address": fixed_ip['ip_address'],
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
            "l3_list": l3_list,
            "l2_list": l2_list,
        }
