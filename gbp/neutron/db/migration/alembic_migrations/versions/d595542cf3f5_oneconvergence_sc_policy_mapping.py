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

"""oneconvergence_sc_policy_mapping

Revision ID: d595542cf3f5
Revises: ceba6e091b2a
Create Date: 2014-10-25 21:13:08.98888

"""

# revision identifiers, used by Alembic.
revision = 'd595542cf3f5'
down_revision = 'ceba6e091b2a'

from alembic import op
import sqlalchemy as sa


def upgrade(active_plugins=None, options=None):
    op.create_table('nvsd_sc_instance_policies',
                    sa.Column('instance_id',
                              sa.String(length=36),
                              nullable=False),
                    sa.Column('policy_id',
                              sa.String(length=36),
                              nullable=True),
                    sa.PrimaryKeyConstraint('instance_id', 'policy_id'))

    op.create_table('nvsd_sc_instance_vip_eps',
                    sa.Column('instance_id',
                              sa.String(length=36),
                              nullable=False),
                    sa.Column('vip_port',
                              sa.String(length=36),
                              nullable=True),
                    sa.Column('nvsd_ep_id',
                              sa.String(length=36),
                              nullable=True),
                    sa.PrimaryKeyConstraint('instance_id', 'vip_port',
                                            'nvsd_ep_id'))


def downgrade(active_plugins=None, options=None):
    op.drop_table('nvsd_sc_instance_vip_eps')
    op.drop_table('nvsd_sc_instance_policies')
