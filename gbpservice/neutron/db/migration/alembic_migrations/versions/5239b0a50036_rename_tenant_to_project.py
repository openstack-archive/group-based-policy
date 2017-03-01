# Copyright 2016 Intel Corporation
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

"""rename tenant to project

Revision ID: 5239b0a50036
Create Date: 2016-06-29 19:42:17.862721

"""

# revision identifiers, used by Alembic.
revision = '5239b0a50036'
down_revision = 'b6e301d5757f'

from alembic import op
import sqlalchemy as sa


_INSPECTOR = None


def get_inspector():
    """Reuse inspector"""

    global _INSPECTOR

    if _INSPECTOR:
        return _INSPECTOR

    else:
        bind = op.get_bind()
        _INSPECTOR = sa.engine.reflection.Inspector.from_engine(bind)

    return _INSPECTOR


def get_tables():
    """
    Returns hardcoded list of GBP tables which have ``tenant_id`` column.

    """

    tables = [
        'gp_apic_tenant_specific_nat_epg',
        'gp_application_policy_groups',
        'gp_external_policies',
        'gp_external_segments',
        'gp_l2_policies',
        'gp_l3_policies',
        'gp_nat_pools',
        'gp_network_service_params',
        'gp_network_service_policies',
        'gp_policy_actions',
        'gp_policy_classifiers',
        'gp_policy_rule_sets',
        'gp_policy_rules',
        'gp_policy_target_groups',
        'gp_policy_targets',
        'gpm_ptgs_servicechain_mapping',
        'sc_instances',
        'sc_nodes',
        'sc_specs',
        'service_profiles',
    ]

    return tables


def get_columns(table):
    """Returns list of columns for given table."""
    inspector = get_inspector()
    return inspector.get_columns(table)


def get_data():
    """Returns combined list of tuples: [(table, column)].

    List is built, based on retrieved tables, where column with name
    ``tenant_id`` exists.
    """

    output = []
    tables = get_tables()
    for table in tables:
        columns = get_columns(table)

        for column in columns:
            if column['name'] == 'tenant_id':
                output.append((table, column))

    return output


def alter_column(table, column):
    old_name = 'tenant_id'
    new_name = 'project_id'

    op.alter_column(
        table_name=table,
        column_name=old_name,
        new_column_name=new_name,
        existing_type=column['type'],
        existing_nullable=column['nullable']
    )


def recreate_index(index, table_name):
    old_name = index['name']
    new_name = old_name.replace('tenant', 'project')

    op.drop_index(op.f(old_name), table_name)
    op.create_index(new_name, table_name, ['project_id'])


def upgrade():
    inspector = get_inspector()

    data = get_data()
    for table, column in data:
        alter_column(table, column)

        indexes = inspector.get_indexes(table)
        for index in indexes:
            if 'tenant_id' in index['name']:
                recreate_index(index, table)


def contract_creation_exceptions():
    """Special migration for the blueprint to support Keystone V3.
    We drop all tenant_id columns and create project_id columns instead.
    """
    return {
        sa.Column: ['.'.join([table, 'project_id']) for table in get_tables()],
        sa.Index: get_tables()
    }
