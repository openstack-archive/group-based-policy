# Copyright 2017 OpenStack Foundation
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

"""fix migrations

Revision ID: d978a7a73785
Revises: 4c0c1e2c0160
Create Date: 2017-09-18 17:34:18.856803

"""

# revision identifiers, used by Alembic.
revision = 'd978a7a73785'
down_revision = '4c0c1e2c0160'

import os
import sys

from neutron.db import migration

from oslo_utils import importutils

from gbpservice.neutron.db.migration import alembic_migrations as am

# This is a hack to get around the fact that the versions
# directory has no __init__.py
filepath = os.path.abspath(am.__file__)
basepath = filepath[:filepath.rfind("/")] + "/versions"
sys.path.append(basepath)

DB_5239b0a50036 = '5239b0a50036_rename_tenant_to_project'
DB_bff1774e749e = 'bff1774e749e_ncp_sci_nf_status'
DB_c460c5682e74 = 'c460c5682e74_nfp_rename_tenant_to_project'
DB_da6a25bbcfa8 = 'da6a25bbcfa8_initial_qos_via_nsp'


def upgrade():
    ensure_5239b0a50036_migration()
    ensure_c460c5682e74_migration()
    ensure_da6a25bbcfa8_migration()
    ensure_bff1774e749e_migration()
    # remove the appended path
    del sys.path[sys.path.index(basepath)]


def ensure_5239b0a50036_migration():
    if not migration.schema_has_column('gp_l2_policies',
                                       'project_id'):
        db_5239b0a50036 = importutils.import_module(DB_5239b0a50036)
        db_5239b0a50036.upgrade()


def ensure_bff1774e749e_migration():
    if not migration.schema_has_column(
        'ncp_node_instance_network_function_mappings',
            'status_details'):
        db_bff1774e749e = importutils.import_module(DB_bff1774e749e)
        db_bff1774e749e.upgrade()


def ensure_c460c5682e74_migration():
    if not migration.schema_has_column('nfp_port_infos',
                                       'project_id'):
        db_c460c5682e74 = importutils.import_module(DB_c460c5682e74)
        db_c460c5682e74.upgrade()


def ensure_da6a25bbcfa8_migration():
    if not migration.schema_has_table('gpm_qos_policy_mappings'):
        db_da6a25bbcfa8 = importutils.import_module(DB_da6a25bbcfa8)
        db_da6a25bbcfa8.upgrade()


def downgrade():
    pass
