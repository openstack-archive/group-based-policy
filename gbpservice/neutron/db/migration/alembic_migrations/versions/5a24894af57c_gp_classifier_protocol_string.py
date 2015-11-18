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

"""gp_classifier_protocol_string

Revision ID: 5a24894af57c

"""

# revision identifiers, used by Alembic.
revision = '5a24894af57c'
down_revision = '4121adfbac30'


from alembic import op
import sqlalchemy as sa


def upgrade():

    op.alter_column('gp_policy_classifiers', 'protocol',
                    existing_type=sa.Enum('tcp', 'udp', 'icmp'),
                    type_=sa.String(length=50))


def downgrade():
    pass
