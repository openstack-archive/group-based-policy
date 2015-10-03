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

import uuid

from neutron.common import constants
from neutron import manager
from oslo_concurrency import lockutils  # noqa
from oslo_log import log as logging

from gbpservice.neutron.db.grouppolicy import group_policy_mapping_db as gpdb
from gbpservice.neutron.services.grouppolicy.common import constants as g_const
from gbpservice.neutron.services.grouppolicy.common import exceptions as gpexc
from gbpservice.neutron.services.grouppolicy.drivers import (
    resource_mapping as api)
from gbpservice.neutron.services.grouppolicy.drivers.odl import odl_manager


LOG = logging.getLogger(__name__)


class ExternalSegmentNotSupportedOnOdlDriver(gpexc.GroupPolicyBadRequest):
    message = _("External Segment currently not supported on ODL GBP "
                "driver.")


class UpdateL3PolicyNotSupportedOnOdlDriver(gpexc.GroupPolicyBadRequest):
    message = _("Update L3 Policy currently not supported on ODL GBP "
                "driver.")


class UpdateL2PolicyNotSupportedOnOdlDriver(gpexc.GroupPolicyBadRequest):
    message = _("Update L2 Policy currently not supported on ODL GBP "
                "driver.")


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


class UpdatePolicyActionNotSupportedOnOdlDriver(gpexc.GroupPolicyBadRequest):
    message = _("Update Policy Action currently not supported on ODL GBP "
                "driver.")


class RedirectActionNotSupportedOnOdlDriver(gpexc.GroupPolicyBadRequest):
    message = _("Redirect action is currently not supported for ODL GBP "
                "driver.")


class OnlyAllowActionSupportedOnOdlDriver(gpexc.GroupPolicyBadRequest):
    message = _("Currently only allow action is supported for ODL GBP "
                "driver.")


class UpdateClassifierNotSupportedOnOdlDriver(gpexc.GroupPolicyBadRequest):
    message = _("Update Policy Classifier currently not supported on ODL GBP "
                "driver.")


class PolicyRuleUpdateNotSupportedOnOdlDriver(gpexc.GroupPolicyBadRequest):
    message = _("Policy rule update is not supported on for ODL GBP "
                "driver.")


class PolicyRuleSetUpdateNotSupportedOnOdlDriver(gpexc.GroupPolicyBadRequest):
    message = _("Policy rule set update is not supported on for ODL GBP "
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
        # TODO(ywu): optimize later
        subnets = self._core_plugin._get_subnets_by_network(
            plugin_context, port['network_id']
        )
        ptg = (plugin_context.session.query(gpdb.PolicyTargetGroupMapping).
               join(gpdb.PolicyTargetGroupMapping.subnets).
               filter(gpdb.PTGToSubnetAssociation.subnet_id ==
                      subnets[0]['id']).
               first())

        # Create PolicyTarget
        attrs = {'policy_target':
                 {'tenant_id': port['tenant_id'],
                  'name': 'dhcp-%s' % ptg['id'],
                  'description': ("Implicitly created DHCP policy "
                                  "target"),
                  'policy_target_group_id': ptg['id'],
                  'port_id': port['id']}}
        self.gbp_plugin.create_policy_target(plugin_context, attrs)
        # TODO(ODL): security group is not required
        # sg_id = self._ensure_default_security_group(plugin_context,
        #                                            port['tenant_id'])
        # data = {'port': {'security_groups': [sg_id]}}
        # self._core_plugin.update_port(plugin_context, port['id'], data)

    def create_external_segment_precommit(self, context):
        raise ExternalSegmentNotSupportedOnOdlDriver()

    def update_external_segment_precommit(self, context):
        raise ExternalSegmentNotSupportedOnOdlDriver()

    def delete_external_segment_precommit(self, context):
        raise ExternalSegmentNotSupportedOnOdlDriver()

    def create_external_policy_precommit(self, context):
        raise ExternalSegmentNotSupportedOnOdlDriver()

    def update_external_policy_precommit(self, context):
        raise ExternalSegmentNotSupportedOnOdlDriver()

    def delete_external_policy_precommit(self, context):
        raise ExternalSegmentNotSupportedOnOdlDriver()

    def create_nat_pool_precommit(self, context):
        raise ExternalSegmentNotSupportedOnOdlDriver()

    def update_nat_pool_precommit(self, context):
        raise ExternalSegmentNotSupportedOnOdlDriver()

    def delete_nat_pool_precommit(self, context):
        raise ExternalSegmentNotSupportedOnOdlDriver()

    def create_policy_target_postcommit(self, context):
        super(OdlMappingDriver, self).create_policy_target_postcommit(context)
        pt = self._get_pt_detail(context)
        ep = {
            "endpoint-group": pt['ptg_id'],
            "l2-context": pt['l2ctx_id'],
            "l3-address": pt['l3_list'],
            "mac-address": pt['mac_address'],
            "port-name": pt['neutron_port_id'],
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
        self.odl_manager.create_update_l3_context(tenant_id, l3ctx)

    def update_l3_policy_precommit(self, context):
        raise UpdateL3PolicyNotSupportedOnOdlDriver()

    def delete_l3_policy_postcommit(self, context):
        tenant_id = uuid.UUID(context.current['tenant_id']).urn[9:]
        l3ctx = {
            "id": context.current['id']
        }
        self.odl_manager.delete_l3_context(tenant_id, l3ctx)

    def create_l2_policy_postcommit(self, context):
        super(OdlMappingDriver, self).create_l2_policy_postcommit(context)
        tenant_id = uuid.UUID(context.current['tenant_id']).urn[9:]

        # l2_policy mapped to l2_bridge_domain in ODL
        l2bd = {
            "id": context.current['id'],
            "name": context.current['name'],
            "description": context.current['description'],
            "parent": context.current['l3_policy_id']
        }
        self.odl_manager.create_update_l2_bridge_domain(tenant_id, l2bd)

        # Implicit network within l2 policy mapped to l2 FD in ODL
        net_id = context.current['network_id']
        network = self._core_plugin.get_network(context._plugin_context,
                                                net_id)
        l2fd = {
            "id": net_id,
            "name": network['name'],
            "parent": context.current['id']
        }
        self.odl_manager.create_update_l2_flood_domain(tenant_id, l2fd)

    def update_l2_policy_precommit(self, context):
        raise UpdateL2PolicyNotSupportedOnOdlDriver()

    def delete_l2_policy_postcommit(self, context):
        super(OdlMappingDriver, self).delete_l2_policy_postcommit(context)
        tenant_id = uuid.UUID(context.current['tenant_id']).urn[9:]

        # l2_policy mapped to l2_bridge_domain in ODL
        l2bd = {
            "id": context.current['id']
        }
        self.odl_manager.delete_l2_bridge_domain(tenant_id, l2bd)

        # Implicit network within l2 policy mapped to l2 FD in ODL
        net_id = context.current['network_id']
        l2fd = {
            "id": net_id,
        }
        self.odl_manager.delete_l2_flood_domain(tenant_id, l2fd)

    def create_policy_target_group_postcommit(self, context):
        super(OdlMappingDriver, self).create_policy_target_group_postcommit(
            context)

        # consumed_policy_rule_sets mapped to consumer_named_selectors
        consumer_named_selectors = []
        for prs_id in context.current['consumed_policy_rule_sets']:
            prs = context._plugin.get_policy_rule_set(
                context._plugin_context, prs_id
            )
            consumer_named_selectors.append(
                {
                    "name": prs['name'],
                    "contract": prs_id
                }
            )

        # provided_policy_rule_sets mapped to provider_named_selectors
        provider_named_selectors = []
        for prs_id in context.current['provided_policy_rule_sets']:
            prs = context._plugin.get_policy_rule_set(
                context._plugin_context, prs_id
            )
            provider_named_selectors.append(
                {
                    "name": prs['name'],
                    "contract": prs_id
                }
            )

        # PTG mapped to EPG in ODL
        subnets = context.current['subnets']
        epg = {
            "id": context.current['id'],
            "name": context.current['name'],
            "description": context.current['description'],
            "network-domain": subnets[0],
            "consumer-named-selector": consumer_named_selectors,
            "provider-named-selector": provider_named_selectors
        }
        tenant_id = uuid.UUID(context.current['tenant_id']).urn[9:]
        self.odl_manager.create_update_endpoint_group(tenant_id, epg)

        # Implicit subnet within policy target group mapped to subnet in ODL
        for subnet_id in subnets:
            neutron_subnet = self._core_plugin.get_subnet(
                context._plugin_context, subnet_id
            )
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

        # delete mapped subnets in ODL, and clean them up from neutron
        for subnet_id in subnets:
            self._cleanup_subnet(context._plugin_context, subnet_id, None)
            odl_subnet = {
                "id": subnet_id
            }
            self.odl_manager.delete_subnet(tenant_id, odl_subnet)

        # delete mapped EPG in ODL
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
        # TODO(ODL): remove comment out after PoC
        # tenant_id = uuid.UUID(context.current['tenant_id']).urn[9:]

        # fill in action instance data
        if context.current['action_type'] == g_const.GP_ACTION_ALLOW:
            # TODO(ODL): remove the return and comment out after POC
            return
            # action_definition_id = "f942e8fd-e957-42b7-bd18-f73d11266d17"
            # action_instance = {
            #     "action-definition-id": action_definition_id,
            #     "name": context.current['name'],
            #     "parameter-value": [
            #         {
            #             "name": context.current['name'],
            #             "string-value": context.current['action_type'],
            #         }
            #     ]
            # }
            # self.odl_manager.create_action(tenant_id, action_instance)
        else:
            raise OnlyAllowActionSupportedOnOdlDriver()

    def update_policy_action_precommit(self, context):
        raise UpdatePolicyActionNotSupportedOnOdlDriver()

    def delete_policy_action_postcommit(self, context):
        super(OdlMappingDriver, self).delete_policy_action_postcommit(context)
        # TODO(ODL): remove comment out after PoC
        # tenant_id = uuid.UUID(context.current['tenant_id']).urn[9:]
        #
        # # fill in action instance data
        # action_instance = {
        #     "name": context.current['name']
        # }
        # self.odl_manager.delete_action(tenant_id, action_instance)

    def create_policy_classifier_postcommit(self, context):
        tenant_id = uuid.UUID(context.current['tenant_id']).urn[9:]
        classifiers = self._make_odl_classifiers(context.current)

        for classifier in classifiers:
            classifier_instance = {
                "classifier-definition-id":
                    classifier['classifier-definition-id'],
                "name": classifier['name'],
                "parameter-value": classifier['parameter-value']
            }
            self.odl_manager.create_classifier(tenant_id, classifier_instance)

    def _make_odl_classifiers(self, stack_classifier):
        classifiers = []
        if stack_classifier['protocol'] == constants.PROTO_NAME_ICMP:
            direction = stack_classifier['direction']
            if direction == 'bi':
                direction = "bidirectional"
            classifier = {
                # Use hard coded value based on current ODL implementation
                "classifier-definition-id":
                    '79c6fdb2-1e1a-4832-af57-c65baf5c2335',
                "name": stack_classifier['name'],
                "parameter-value": [
                    {
                        "name": "proto",
                        # TODO(yapeng): change the hard code value
                        "int-value": 1,
                    }
                ],
                "direction": direction
            }
            classifiers.append(classifier)
        else:
            # For TCP and UDP protoocol create two classifier (in and out)
            for port in ['sourceport', 'destport']:
                if stack_classifier['direction'] == 'in':
                    if port == 'destport':
                        direction = 'in'
                    else:
                        direction = 'out'
                elif stack_classifier['direction'] == 'out':
                    if port == 'destport':
                        direction = 'out'
                    else:
                        direction = 'in'
                else:
                    direction = 'bidirectional'

                classifier = {
                    # Use hard coded value based on current ODL implementation
                    "classifier-definition-id":
                        '4250ab32-e8b8-445a-aebb-e1bd2cdd291f',
                    "direction": direction,
                    "name": stack_classifier['name'] + '-' + port,
                    "parameter-value": [
                        {
                            "name": "type",
                            "string-value": stack_classifier['protocol'],
                        },
                        {
                            "name": port,
                            "int-value": stack_classifier['port_range'],
                        }
                    ]
                }
                classifiers.append(classifier)
        return classifiers

    def update_policy_classifier_precommit(self, context):
        raise UpdateClassifierNotSupportedOnOdlDriver()

    def delete_policy_classifier_postcommit(self, context):
        tenant_id = uuid.UUID(context.current['tenant_id']).urn[9:]

        if context.current['protocol'] == constants.PROTO_NAME_ICMP:
            # fill in classifier instance data
            classifier_instance = {
                "name": context.current['name']
            }
            self.odl_manager.delete_classifier(tenant_id, classifier_instance)
            return

        # fill in classifier instance data
        for port in ['sourceport', 'destport']:
            classifier_instance = {
                "name": context.current['name'] + '-' + port,
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

    def create_policy_rule_set_postcommit(self, context):
        """Each Policy Rule Set is mapped to a contract, with a single clause

        Each included Policy Rule will be mapped to one subject, which includes
        one rule.

        The clause has no matcher, but refers to all the subjects
        """
        subjects = []
        subject_names = []
        for rule_id in context.current['policy_rules']:
            subject = self._make_odl_subject(context, rule_id)
            subjects.append(subject)
            subject_names.append(subject['name'])

        clauses = [
            {
                "name": context.current['name'],
                "subject-refs": subject_names
            }
        ]

        contract_id = context.current['id']
        contract_desc = context.current['name']
        contract = {
            "id": contract_id,
            "description": contract_desc,
            "clause": clauses,
            "subject": subjects
        }

        tenant_id = uuid.UUID(context.current['tenant_id']).urn[9:]
        self.odl_manager.create_update_contract(tenant_id, contract)

    def _make_odl_subject(self, context, rule_id):
        gbp_rule = context._plugin.get_policy_rule(
            context._plugin_context, rule_id
        )
        odl_rules = []
        odl_rule = self._make_odl_rule(context, rule_id)
        odl_rules.append(odl_rule)
        return {
            "name": gbp_rule['name'],
            "rule": odl_rules
        }

    def _make_odl_rule(self, context, rule_id):
        rule = context._plugin.get_policy_rule(
            context._plugin_context, rule_id
        )
        stack_classifier = context._plugin.get_policy_classifier(
            context._plugin_context, rule['policy_classifier_id']
        )

        # while openstack supports only one classifier per rule, the classifier
        # may mapped to multi classifier in ODL
        classifier_refs = []
        classifiers = self._make_odl_classifiers(stack_classifier)
        for classifier in classifiers:
            classifier_ref = {
                "name": classifier['name']
            }
            if classifier['direction'] != "bidirectional":
                classifier_ref['direction'] = classifier['direction']
            classifier_refs.append(classifier_ref)
        action_refs = []
        for action_id in rule['policy_actions']:
            action = context._plugin.get_policy_action(
                context._plugin_context, action_id
            )
            action_refs.append(
                {
                    "name": action['name']
                }
            )

        # TODO(ODL): send action_refs later but not for PoC
        return {
            "name": rule['name'],
            "classifier-ref": classifier_refs,
        }

    def update_policy_rule_set_precommit(self, context):
        # TODO(Yi): add support for action update on policy rule sets
        raise PolicyRuleSetUpdateNotSupportedOnOdlDriver()

    def _get_pt_detail(self, context):
        port_id = context.current['port_id']
        port = self._core_plugin.get_port(context._plugin_context, port_id)
        tenant_id = uuid.UUID(context.current['tenant_id']).urn[9:]
        ptg_id = context.current['policy_target_group_id']
        ptg = self.gbp_plugin.get_policy_target_group(context._plugin_context,
                                                      ptg_id)
        l2ctx_id = ptg['l2_policy_id']
        l2ctx = self.gbp_plugin.get_l2_policy(context._plugin_context,
                                              l2ctx_id)
        l3ctx_id = l2ctx['l3_policy_id']
        mac_address = port['mac_address']
        neutron_port_id = 'tap' + port_id[:11]

        l3_list = []
        for fixed_ip in port['fixed_ips']:
            l3_list.append(
                {
                    "ip-address": fixed_ip['ip_address'],
                    "l3-context": l3ctx_id
                }
            )

        l2_list = [
            {
                "l2-context": l2ctx_id,
                "mac-address": mac_address
            }
        ]

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
