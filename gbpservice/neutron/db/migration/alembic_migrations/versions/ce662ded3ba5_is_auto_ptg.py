"""is_auto_ptg

Revision ID: ce662ded3ba5
Revises: ef5a69e5bcc5
Create Date: 2016-12-15 16:13:23.836874

"""

# revision identifiers, used by Alembic.
revision = 'ce662ded3ba5'
down_revision = 'ef5a69e5bcc5'

from alembic import op
import sqlalchemy as sa


def upgrade():

    op.create_table(
        'gp_apic_auto_ptg',
        sa.Column('policy_target_group_id', sa.String(length=36),
                  nullable=False),
        sa.Column('is_auto_ptg', sa.Boolean,
                  server_default=sa.sql.true(), nullable=False),
        sa.ForeignKeyConstraint(
            ['policy_target_group_id'], ['gp_policy_target_groups.id'],
            name='gp_apic_auto_ptg_fk_ptgid', ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('policy_target_group_id')
    )


def downgrade():
    pass
