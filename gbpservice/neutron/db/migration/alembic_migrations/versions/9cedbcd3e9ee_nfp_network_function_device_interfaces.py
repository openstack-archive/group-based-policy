"""nfp_network_function_device_interface

Revision ID: 9cedbcd3e9ee
Revises: 5629167be1d1
Create Date: 2016-10-24 19:52:17.140960

"""

# revision identifiers, used by Alembic.
revision = '9cedbcd3e9ee'
down_revision = '5629167be1d1'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.create_table(
        'nfp_network_function_device_interfaces',
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('plugged_in_port_id', sa.String(length=36), nullable=True),
        sa.Column('interface_position',
                  sa.Integer(),
                  nullable=True),
        sa.Column('mapped_real_port_id', sa.String(length=36), nullable=True),
        sa.Column('network_function_device_id',
                  sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(['plugged_in_port_id'],
                                ['nfp_port_infos.id'],
                                ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['network_function_device_id'],
                                ['nfp_network_function_devices.id'],
                                ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )


def downgrade():
    pass
