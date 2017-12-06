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

from neutron_lib.db import model_base
import sqlalchemy as sa

from gbpservice.neutron.services.grouppolicy import (
    group_policy_driver_api as api)
from gbpservice.neutron.tests.unit.services.grouppolicy.extensions import (
    test_extension as test_extension)


class TestPolicyTargetExtension(model_base.BASEV2):
    __tablename__ = 'test_policy_target_extension'
    policy_target_id = sa.Column(sa.String(36),
                       sa.ForeignKey('gp_policy_targets.id',
                                     ondelete="CASCADE"),
                       primary_key=True)
    pt_extension = sa.Column(sa.String(64))


class TestPolicyTargetGroupExtension(model_base.BASEV2):
    __tablename__ = 'test_policy_target_group_extension'
    policy_target_group_id = sa.Column(
        sa.String(36), sa.ForeignKey('gp_policy_target_groups.id',
                                     ondelete="CASCADE"),
        primary_key=True)
    ptg_extension = sa.Column(sa.String(64))


class TestL2PolicyExtension(model_base.BASEV2):
    __tablename__ = 'test_l2_policy_extension'
    l2_policy_id = sa.Column(sa.String(36), sa.ForeignKey('gp_l2_policies.id',
                                                          ondelete="CASCADE"),
                             primary_key=True)
    l2p_extension = sa.Column(sa.String(64))


class TestL3PolicyExtension(model_base.BASEV2):
    __tablename__ = 'test_l3_policy_extension'
    l3_policy_id = sa.Column(sa.String(36),
                       sa.ForeignKey('gp_l3_policies.id',
                                     ondelete="CASCADE"),
                       primary_key=True)
    l3p_extension = sa.Column(sa.String(64))


class TestPolicyClassifierExtension(model_base.BASEV2):
    __tablename__ = 'test_policy_classifier_extension'
    policy_classifier_id = sa.Column(sa.String(36),
                      sa.ForeignKey('gp_policy_classifiers.id',
                                    ondelete="CASCADE"),
                      primary_key=True)
    pc_extension = sa.Column(sa.String(64))


class TestPolicyActionExtension(model_base.BASEV2):
    __tablename__ = 'test_policy_action_extension'
    policy_action_id = sa.Column(sa.String(36),
                      sa.ForeignKey('gp_policy_actions.id',
                                    ondelete="CASCADE"),
                      primary_key=True)
    pa_extension = sa.Column(sa.String(64))


class TestPolicyRuleExtension(model_base.BASEV2):
    __tablename__ = 'test_policy_rule_extension'
    policy_rule_id = sa.Column(sa.String(36),
                      sa.ForeignKey('gp_policy_rules.id',
                                    ondelete="CASCADE"),
                      primary_key=True)
    pr_extension = sa.Column(sa.String(64))


class TestPolicyRuleSetExtension(model_base.BASEV2):
    __tablename__ = 'test_policy_rule_set_extension'
    policy_rule_set_id = sa.Column(sa.String(36),
                       sa.ForeignKey('gp_policy_rule_sets.id',
                                     ondelete="CASCADE"),
                       primary_key=True)
    prs_extension = sa.Column(sa.String(64))


class TestNetworkServicePolicyExtension(model_base.BASEV2):
    __tablename__ = 'test_network_service_policy_extension'
    network_service_policy_id = sa.Column(sa.String(36),
                       sa.ForeignKey('gp_network_service_policies.id',
                                     ondelete="CASCADE"),
                       primary_key=True)
    nsp_extension = sa.Column(sa.String(64))


class TestExternalSegmentExtension(model_base.BASEV2):
    __tablename__ = 'test_external_segment_extension'
    external_segment_id = sa.Column(sa.String(36),
                      sa.ForeignKey('gp_external_segments.id',
                                    ondelete="CASCADE"),
                      primary_key=True)
    es_extension = sa.Column(sa.String(64))


class TestExternalPolicyExtension(model_base.BASEV2):
    __tablename__ = 'test_external_policy_extension'
    external_policy_id = sa.Column(sa.String(36),
                      sa.ForeignKey('gp_external_policies.id',
                                    ondelete="CASCADE"),
                      primary_key=True)
    ep_extension = sa.Column(sa.String(64))


class TestNatPoolExtension(model_base.BASEV2):
    __tablename__ = 'test_nat_pool_extension'
    nat_pool_id = sa.Column(sa.String(36),
                      sa.ForeignKey('gp_nat_pools.id',
                                    ondelete="CASCADE"),
                      primary_key=True)
    np_extension = sa.Column(sa.String(64))


class TestExtensionDriver(api.ExtensionDriver):
    _supported_extension_alias = 'test_extension'
    _extension_dict = test_extension.EXTENDED_ATTRIBUTES_2_0

    def initialize(self):
        pass

    @property
    def extension_alias(self):
        return self._supported_extension_alias

    @api.default_extension_behavior(TestPolicyTargetExtension)
    def process_create_policy_target(self, session, data, result):
        pass

    @api.default_extension_behavior(TestPolicyTargetExtension)
    def process_update_policy_target(self, session, data, result):
        pass

    @api.default_extension_behavior(TestPolicyTargetExtension)
    def extend_policy_target_dict(self, session, result):
        pass

    @api.default_extension_behavior(TestPolicyTargetGroupExtension)
    def process_create_policy_target_group(self, session, data, result):
        pass

    @api.default_extension_behavior(TestPolicyTargetGroupExtension)
    def process_update_policy_target_group(self, session, data, result):
        pass

    @api.default_extension_behavior(TestPolicyTargetGroupExtension)
    def extend_policy_target_group_dict(self, session, result):
        pass

    @api.default_extension_behavior(TestL2PolicyExtension)
    def process_create_l2_policy(self, session, data, result):
        pass

    @api.default_extension_behavior(TestL2PolicyExtension)
    def process_update_l2_policy(self, session, data, result):
        pass

    @api.default_extension_behavior(TestL2PolicyExtension)
    def extend_l2_policy_dict(self, session, result):
        pass

    @api.default_extension_behavior(TestL3PolicyExtension)
    def process_create_l3_policy(self, session, data, result):
        pass

    @api.default_extension_behavior(TestL3PolicyExtension)
    def process_update_l3_policy(self, session, data, result):
        pass

    @api.default_extension_behavior(TestL3PolicyExtension)
    def extend_l3_policy_dict(self, session, result):
        pass

    @api.default_extension_behavior(TestPolicyClassifierExtension)
    def process_create_policy_classifier(self, session, data, result):
        pass

    @api.default_extension_behavior(TestPolicyClassifierExtension)
    def process_update_policy_classifier(self, session, data, result):
        pass

    @api.default_extension_behavior(TestPolicyClassifierExtension)
    def extend_policy_classifier_dict(self, session, result):
        pass

    @api.default_extension_behavior(TestPolicyActionExtension)
    def process_create_policy_action(self, session, data, result):
        pass

    @api.default_extension_behavior(TestPolicyActionExtension)
    def process_update_policy_action(self, session, data, result):
        pass

    @api.default_extension_behavior(TestPolicyActionExtension)
    def extend_policy_action_dict(self, session, result):
        pass

    @api.default_extension_behavior(TestPolicyRuleExtension)
    def process_create_policy_rule(self, session, data, result):
        pass

    @api.default_extension_behavior(TestPolicyRuleExtension)
    def process_update_policy_rule(self, session, data, result):
        pass

    @api.default_extension_behavior(TestPolicyRuleExtension)
    def extend_policy_rule_dict(self, session, result):
        pass

    @api.default_extension_behavior(TestPolicyRuleSetExtension)
    def process_create_policy_rule_set(self, session, data, result):
        pass

    @api.default_extension_behavior(TestPolicyRuleSetExtension)
    def process_update_policy_rule_set(self, session, data, result):
        pass

    @api.default_extension_behavior(TestPolicyRuleSetExtension)
    def extend_policy_rule_set_dict(self, session, result):
        pass

    @api.default_extension_behavior(TestNetworkServicePolicyExtension)
    def process_create_network_service_policy(self, session, data, result):
        pass

    @api.default_extension_behavior(TestNetworkServicePolicyExtension)
    def process_update_network_service_policy(self, session, data, result):
        pass

    @api.default_extension_behavior(TestNetworkServicePolicyExtension)
    def extend_network_service_policy_dict(self, session, result):
        pass

    @api.default_extension_behavior(TestExternalSegmentExtension)
    def process_create_external_segment(self, session, data, result):
        pass

    @api.default_extension_behavior(TestExternalSegmentExtension)
    def process_update_external_segment(self, session, data, result):
        pass

    @api.default_extension_behavior(TestExternalSegmentExtension)
    def extend_external_segment_dict(self, session, result):
        pass

    @api.default_extension_behavior(TestExternalPolicyExtension)
    def process_create_external_policy(self, session, data, result):
        pass

    @api.default_extension_behavior(TestExternalPolicyExtension)
    def process_update_external_policy(self, session, data, result):
        pass

    @api.default_extension_behavior(TestExternalPolicyExtension)
    def extend_external_policy_dict(self, session, result):
        pass

    @api.default_extension_behavior(TestNatPoolExtension)
    def process_create_nat_pool(self, session, data, result):
        pass

    @api.default_extension_behavior(TestNatPoolExtension)
    def process_update_nat_pool(self, session, data, result):
        pass

    @api.default_extension_behavior(TestNatPoolExtension)
    def extend_nat_pool_dict(self, session, result):
        pass
