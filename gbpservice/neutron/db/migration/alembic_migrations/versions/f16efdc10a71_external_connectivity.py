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

""" external_connectivity

Revision ID: f16efdc10a71
"""

# revision identifiers, used by Alembic.
revision = 'f16efdc10a71'
down_revision = 'f4d890a9c126'


from alembic import op
import sqlalchemy as sa


def upgrade():

    op.create_table(
        'gp_external_segments',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.Column('name', sa.String(length=50), nullable=True),
        sa.Column('description', sa.String(length=255), nullable=True),
        sa.Column('shared', sa.Boolean),
        sa.Column('ip_version', sa.Integer, nullable=False),
        sa.Column('cidr', sa.String(64), nullable=False),
        sa.Column('port_address_translation', sa.Boolean),
        sa.PrimaryKeyConstraint('id'))

    op.create_table(
        'gp_external_policies',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.Column('name', sa.String(length=50), nullable=True),
        sa.Column('description', sa.String(length=255), nullable=True),
        sa.Column('shared', sa.Boolean),
        sa.PrimaryKeyConstraint('id'))

    op.create_table(
        'gp_ep_to_prs_providing_associations',
        sa.Column('policy_rule_set_id', sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(['policy_rule_set_id'],
                                ['gp_policy_rule_sets.id'],
                                ondelete='CASCADE'),
        sa.Column('external_policy_id', sa.String(length=36),
                  nullable=True),
        sa.ForeignKeyConstraint(['external_policy_id'],
                                ['gp_external_policies.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('policy_rule_set_id',
                                'external_policy_id'))

    op.create_table(
        'gp_ep_to_prs_consuming_associations',
        sa.Column('policy_rule_set_id', sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(['policy_rule_set_id'],
                                ['gp_policy_rule_sets.id'],
                                ondelete='CASCADE'),
        sa.Column('external_policy_id', sa.String(length=36),
                  nullable=True),
        sa.ForeignKeyConstraint(['external_policy_id'],
                                ['gp_external_policies.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('policy_rule_set_id',
                                'external_policy_id'))

    op.create_table(
        'gp_es_to_ep_associations',
        sa.Column('external_policy_id', sa.String(length=36),
                  nullable=True),
        sa.ForeignKeyConstraint(['external_policy_id'],
                                ['gp_external_policies.id'],
                                ondelete='CASCADE'),
        sa.Column('external_segment_id', sa.String(length=36),
                  nullable=True),
        sa.ForeignKeyConstraint(['external_segment_id'],
                                ['gp_external_segments.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('external_policy_id',
                                'external_segment_id'))

    op.create_table(
        'gp_external_routes',
        sa.Column('destination', sa.String(64)),
        sa.Column('nexthop', sa.String(64)),
        sa.Column('external_segment_id', sa.String(length=36),
                  nullable=True),
        sa.ForeignKeyConstraint(['external_segment_id'],
                                ['gp_external_segments.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('external_segment_id',
                                'destination', 'nexthop'))

    op.create_table(
        'gp_nat_pools',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.Column('name', sa.String(length=50), nullable=True),
        sa.Column('description', sa.String(length=255), nullable=True),
        sa.Column('shared', sa.Boolean),
        sa.Column('ip_version', sa.Integer, nullable=False),
        sa.Column('ip_pool', sa.String(64), nullable=False),
        sa.Column('external_segment_id', sa.String(length=36),
                  nullable=True),
        sa.ForeignKeyConstraint(['external_segment_id'],
                                ['gp_external_segments.id']),
        sa.PrimaryKeyConstraint('id'))

    op.create_table(
        'gp_es_to_l3p_associations',
        sa.Column('l3_policy_id', sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(['l3_policy_id'],
                                ['gp_l3_policies.id'],
                                ondelete='CASCADE'),
        sa.Column('external_segment_id', sa.String(length=36),
                  nullable=True),
        sa.ForeignKeyConstraint(['external_segment_id'],
                                ['gp_external_segments.id'],
                                ondelete='CASCADE'),
        sa.Column('allocated_address', sa.String(64), nullable=False,
                  primary_key=True),
        sa.PrimaryKeyConstraint(
            'l3_policy_id', 'external_segment_id', 'allocated_address'),
        sa.UniqueConstraint('external_segment_id', 'allocated_address'),
    )


def downgrade():

    op.drop_table('gp_es_to_l3p_associations')
    op.drop_table('gp_nat_pools')
    op.drop_table('gp_external_routes')
    op.drop_table('gp_es_to_ep_associations')
    op.drop_table('gp_ep_to_prs_consuming_associations')
    op.drop_table('gp_ep_to_prs_providing_associations')
    op.drop_table('gp_external_policies')
    op.drop_table('gp_external_segments')
