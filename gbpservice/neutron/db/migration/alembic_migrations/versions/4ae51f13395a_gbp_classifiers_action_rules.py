# Copyright 2014 OpenStack Foundation
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
#

"""gbp_classifiers_actions_rules

Revision ID: 4ae51f13395a
Create Date: 2014-07-30 14:16:05.660561

"""

# revision identifiers, used by Alembic.
revision = '4ae51f13395a'
down_revision = '1bf7555fa01a'


from alembic import op
from neutron_lib import constants
import sqlalchemy as sa

from gbpservice.neutron.services.grouppolicy.common import (
    constants as gp_constants)


def upgrade(active_plugins=None, options=None):
    op.create_table(
        'gp_policy_classifiers',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.Column('name', sa.String(length=50), nullable=True),
        sa.Column('description', sa.String(length=255), nullable=True),
        sa.Column('protocol', sa.Enum(constants.PROTO_NAME_TCP,
                                      constants.PROTO_NAME_UDP,
                                      constants.PROTO_NAME_ICMP,
                                      name="protocol_type"),
                  nullable=True),
        sa.Column('port_range_min', sa.Integer),
        sa.Column('port_range_max', sa.Integer),
        sa.Column('direction', sa.Enum(gp_constants.GP_DIRECTION_IN,
                                       gp_constants.GP_DIRECTION_OUT,
                                       gp_constants.GP_DIRECTION_BI,
                                       name='direction'),
                  nullable=True),
        sa.PrimaryKeyConstraint('id'))

    op.create_table(
        'gp_policy_rules',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.Column('name', sa.String(length=50), nullable=True),
        sa.Column('description', sa.String(length=255), nullable=True),
        sa.Column('enabled', sa.Boolean),
        sa.Column('policy_classifier_id', sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(['policy_classifier_id'],
                                ['gp_policy_classifiers.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'))

    op.create_table(
        'gp_policy_actions',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.Column('name', sa.String(length=50), nullable=True),
        sa.Column('description', sa.String(length=255), nullable=True),

        sa.Column('action_type', sa.Enum(gp_constants.GP_ACTION_ALLOW,
                                         gp_constants.GP_ACTION_REDIRECT,
                                         name='action_type'),
                  nullable=True),
        sa.Column('action_value', sa.String(36), nullable=True),
        sa.PrimaryKeyConstraint('id'))

    op.create_table(
        'gp_policy_rule_action_associations',
        sa.Column('policy_rule_id', sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(['policy_rule_id'],
                                ['gp_policy_rules.id'], ondelete='CASCADE'),
        sa.Column('policy_action_id', sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(['policy_action_id'],
                                ['gp_policy_actions.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('policy_rule_id', 'policy_action_id'))


def downgrade(active_plugins=None, options=None):
    op.drop_table('gp_policy_rule_action_associations')
    op.drop_table('gp_policy_rules')
    op.drop_table('gp_policy_classifiers')
    op.drop_table('gp_policy_actions')
