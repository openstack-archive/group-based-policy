"""segmentation labels for PT (apic_mapping)

Revision ID: 092e4b1aeb0a
Revises: d4bb487a81b8
Create Date: 2016-09-18 18:58:26.810742

"""

# revision identifiers, used by Alembic.
revision = '092e4b1aeb0a'
down_revision = 'd4bb487a81b8'

from alembic import op
import sqlalchemy as sa


def upgrade():

    op.create_table(
        'gp_apic_mapping_segmentation_labels',
        sa.Column('policy_target_id', sa.String(length=36), nullable=False),
        sa.Column('segmentation_label', sa.String(length=1024),
                  nullable=False),
        sa.ForeignKeyConstraint(
            ['policy_target_id'], ['gp_policy_targets.id'],
            name='gp_apic_mapping_segmentation_lablel_fk_ptid',
            ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('policy_target_id', 'segmentation_label')
    )


def downgrade():
    pass
