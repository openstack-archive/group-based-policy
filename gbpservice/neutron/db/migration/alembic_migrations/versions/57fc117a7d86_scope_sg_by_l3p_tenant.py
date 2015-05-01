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
from neutron.db import migration
import sqlalchemy as sa
from sqlalchemy.engine import reflection

TABLE_NAME = 'gpm_policy_rule_set_sg_mapping'


def upgrade():

    op.add_column(
        TABLE_NAME,
        sa.Column('l3_policy_id', sa.String(length=36))
    )
    op.add_column(
        TABLE_NAME,
        sa.Column('tenant_id', sa.String(length=255))
    )
    op.add_column(
        TABLE_NAME,
        sa.Column('reference_count', sa.Integer)
    )
    op.create_foreign_key('gp_sg_mapping_ibfk_2',
                          source=TABLE_NAME,
                          referent='gp_l3_policies',
                          local_cols=['l3_policy_id'], remote_cols=['id'],
                          ondelete='CASCADE')

    inspector = reflection.Inspector.from_engine(op.get_bind())
    pk_name = inspector.get_pk_constraint(
        TABLE_NAME)['name']

    with migration.remove_fks_from_table(TABLE_NAME):
        op.drop_constraint(pk_name, TABLE_NAME, 'primary')

        op.create_primary_key(
            'gp_sg_mapping_pk', TABLE_NAME,
            ['policy_rule_set_id', 'tenant_id', 'l3_policy_id']
        )

    fk_names = [fk['name'] for fk in
                inspector.get_foreign_keys(TABLE_NAME)
                if 'provided_sg_id' in fk['constrained_columns'] or
                   'consumed_sg_id' in fk['constrained_columns']]
    for name in fk_names:
        op.drop_constraint(name, TABLE_NAME, 'foreignkey')

    op.create_foreign_key('gp_sg_mapping_ibfk_3',
                          source=TABLE_NAME,
                          referent='securitygroups',
                          local_cols=['consumed_sg_id'], remote_cols=['id'],
                          ondelete='CASCADE')

    op.create_foreign_key('gp_sg_mapping_ibfk_4',
                          source=TABLE_NAME,
                          referent='securitygroups',
                          local_cols=['provided_sg_id'], remote_cols=['id'],
                          ondelete='CASCADE')


def downgrade():
    pass
