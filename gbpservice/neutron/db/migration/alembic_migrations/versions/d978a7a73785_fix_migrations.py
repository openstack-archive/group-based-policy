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
Revises: 27b724002081
Create Date: 2017-09-18 17:34:18.856803

"""

# revision identifiers, used by Alembic.
revision = 'd978a7a73785'
down_revision = '27b724002081'

from alembic import op
import sqlalchemy as sa

from neutron.db import migration

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


def get_columns(table):
    """Returns list of columns for given table."""
    inspector = get_inspector()
    return inspector.get_columns(table)


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
    ensure_5239b0a50036_migration()
    ensure_c460c5682e74_migration()
    ensure_da6a25bbcfa8_migration()
    ensure_bff1774e749e_migration()


def ensure_5239b0a50036_migration():
    if not migration.schema_has_column('gp_l2_policies',
                                       'project_id'):
        upgrade_5239b0a50036()


def ensure_bff1774e749e_migration():
    if not migration.schema_has_column(
        'ncp_node_instance_network_function_mappings',
            'status_details'):
        upgrade_bff1774e749e()


def ensure_c460c5682e74_migration():
    if not migration.schema_has_column('nfp_port_infos',
                                       'project_id'):
        upgrade_c460c5682e74()


def ensure_da6a25bbcfa8_migration():
    if not migration.schema_has_table('gpm_qos_policy_mappings'):
        upgrade_da6a25bbcfa8()


def upgrade_5239b0a50036():

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

    def contract_creation_exceptions():
        """Special migration for the blueprint to support Keystone V3.
        We drop all tenant_id columns and create project_id columns instead.
        """
        return {
            sa.Column: ['.'.join([table,
                                  'project_id']) for table in get_tables()],
            sa.Index: get_tables()
        }

    inspector = get_inspector()

    data = get_data()
    for table, column in data:
        alter_column(table, column)

        indexes = inspector.get_indexes(table)
        for index in indexes:
            if 'tenant_id' in index['name']:
                recreate_index(index, table)


def upgrade_c460c5682e74():

    def get_tables():
        """
        Returns hardcoded list of NFP tables which have ``tenant_id`` column.

        """

        tables = [
            'nfp_port_infos',
            'nfp_network_infos',
            'nfp_network_function_instances',
            'nfp_network_functions',
            'nfp_network_function_devices',
            'nfd_cluster_mapping_info',
        ]

        return tables

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

    def contract_creation_exceptions():
        """Special migration for the blueprint to support Keystone V3.
        We drop all tenant_id columns and create project_id columns instead.
        """
        return {
            sa.Column: ['.'.join([table,
                                  'project_id']) for table in get_tables()],
            sa.Index: get_tables()
        }

    inspector = get_inspector()

    data = get_data()
    for table, column in data:
        alter_column(table, column)

        indexes = inspector.get_indexes(table)
        for index in indexes:
            if 'tenant_id' in index['name']:
                recreate_index(index, table)


def upgrade_da6a25bbcfa8():
    op.create_table(
        'gpm_qos_policy_mappings',
        sa.Column('service_policy_id', sa.String(length=36), nullable=False),
        sa.Column('qos_policy_id', sa.String(length=36), nullable=False),
        sa.PrimaryKeyConstraint('service_policy_id'),
        sa.ForeignKeyConstraint(['service_policy_id'],
                                ['gp_network_service_policies.id'],
                                ondelete='CASCADE',
                                name='gbp_qos_policy_mapping_nsp_fk'),
        sa.ForeignKeyConstraint(['qos_policy_id'],
                                ['qos_policies.id'],
                                ondelete='RESTRICT',
                                name='gbp_qos_policy_mapping_qosp_fk')
    )


def upgrade_bff1774e749e():
    op.drop_constraint('PRIMARY',
                       'ncp_node_instance_network_function_mappings',
                       type_='primary')
    op.create_primary_key("ncp_node_instance_network_function_mappings_pk",
                          "ncp_node_instance_network_function_mappings",
                          ['sc_instance_id', 'sc_node_id'])
    op.alter_column('ncp_node_instance_network_function_mappings',
                    'network_function_id',
                    nullable=True, existing_type=sa.String(length=36))
    op.add_column('ncp_node_instance_network_function_mappings',
                  sa.Column('status', sa.String(length=50), nullable=True))
    op.add_column('ncp_node_instance_network_function_mappings',
                  sa.Column('status_details', sa.String(length=4096),
                      nullable=True))


def downgrade():
    pass
