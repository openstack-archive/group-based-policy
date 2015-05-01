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

"""Scope SG by L3P and Tenant (gpm_db_1)
"""

revision = '57fc117a7d86'
down_revision = '2f3834ea746b'

from alembic import op
import sqlalchemy as sa
from sqlalchemy.engine import reflection


def upgrade():

    op.add_column(
        'gpm_policy_rule_set_sg_mapping',
        sa.Column('l3_policy_id', sa.String(length=36), nullable=True)
    )
    op.add_column(
        'gpm_policy_rule_set_sg_mapping',
        sa.Column('tenant_id', sa.String(length=255), nullable=True)
    )
    op.create_foreign_key('gp_sg_mapping_ibfk_2',
                          source='gpm_policy_rule_set_sg_mapping',
                          referent='gp_l3_policies',
                          local_cols=['l3_policy_id'], remote_cols=['id'],
                          ondelete='CASCADE')

    inspector = reflection.Inspector.from_engine(op.get_bind())
    pk_name = [pk['name'] for pk in
               inspector.get_pk_constraint('gpm_policy_rule_set_sg_mapping')
               if 'policy_rule_set_id' in pk['constrained_columns']]
    op.drop_constraint(pk_name[0], 'gpm_ptgs_servicechain_mapping',
                       'primarykey')

    op.create_primary_key(
            "gp_sg_mapping_pk", "gpm_policy_rule_set_sg_mapping",
            ["policy_rule_set_id", "tenant_id", "l3_policy_id"]
    )

    fk_names = [fk['name'] for fk in
                inspector.get_foreign_keys('gpm_policy_rule_set_sg_mapping')
                if 'provided_sg_id' in fk['constrained_columns'] or
                   'consumed_sg_id' in fk['constrained_columns']]
    for name in fk_names:
        op.drop_constraint(name, 'gpm_ptgs_servicechain_mapping',
                           'foreignkey')

    op.create_foreign_key('gp_sg_mapping_ibfk_3',
                          source='gpm_policy_rule_set_sg_mapping',
                          referent='securitygroups',
                          local_cols=['consumed_sg_id'], remote_cols=['id'],
                          ondelete='CASCADE')

    op.create_foreign_key('gp_sg_mapping_ibfk_4',
                          source='gpm_policy_rule_set_sg_mapping',
                          referent='securitygroups',
                          local_cols=['provided_sg_id'], remote_cols=['id'],
                          ondelete='CASCADE')


def downgrade():
    pass