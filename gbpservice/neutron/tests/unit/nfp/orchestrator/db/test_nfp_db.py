# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import copy
import fixtures

from neutron import context
from neutron.db import api as db_api
from neutron.tests import base

from gbpservice.nfp.common import constants as nfp_constants
from gbpservice.nfp.common import exceptions as nfp_exc
from gbpservice.nfp.orchestrator.db import nfp_db
from gbpservice.nfp.orchestrator.db import nfp_db_model


class SqlFixture(fixtures.Fixture):

    # flag to indicate that the models have been loaded
    _TABLES_ESTABLISHED = False

    def _setUp(self):
        # Register all data models
        engine = db_api.get_engine()
        if not SqlFixture._TABLES_ESTABLISHED:
            nfp_db_model.BASE.metadata.create_all(engine)
            SqlFixture._TABLES_ESTABLISHED = True

        def clear_tables():
            with engine.begin() as conn:
                for table in reversed(
                        nfp_db_model.BASE.metadata.sorted_tables):
                    conn.execute(table.delete())

        self.addCleanup(clear_tables)


class SqlTestCaseLight(base.DietTestCase):
    """All SQL taste, zero plugin/rpc sugar"""

    def setUp(self):
        super(SqlTestCaseLight, self).setUp()
        self.useFixture(SqlFixture())


class SqlTestCase(base.BaseTestCase):

    def setUp(self):
        super(SqlTestCase, self).setUp()
        self.useFixture(SqlFixture())


class NFPDB(nfp_db.NFPDbBase):
    pass


class NFPDBTestCase(SqlTestCase):

    def setUp(self):
        super(NFPDBTestCase, self).setUp()
        self.ctx = context.get_admin_context()
        self.nfp_db = NFPDB()
        self.session = db_api.get_session()

    def create_network_function(self, attributes=None):
        if attributes is None:
            attributes = {
                'name': 'name',
                'description': 'description',
                'tenant_id': 'tenant_id',
                'service_id': 'service_id',
                'service_chain_id': 'service_chain_id',
                'service_profile_id': 'service_profile_id',
                'service_config': 'service_config',
                'heat_stack_id': 'heat_stack_id',
                'status': 'status'
            }
        return self.nfp_db.create_network_function(self.session, attributes)

    def test_create_network_function(self):
        attrs = {
            'name': 'name',
            'description': 'description',
            'tenant_id': 'tenant_id',
            'service_id': 'service_id',
            'service_chain_id': 'service_chain_id',
            'service_profile_id': 'service_profile_id',
            'service_config': 'service_config',
            'heat_stack_id': 'heat_stack_id',
            'status': 'status'
        }

        network_function = self.create_network_function(attrs)
        for key in attrs:
            self.assertEqual(attrs[key], network_function[key])
        self.assertIsNotNone(network_function['id'])

    def test_create_network_function_with_mandatory_values(self):
        attrs_mandatory = {
            'name': 'name',
            'tenant_id': 'tenant_id',
            'service_id': 'service_id',
            'service_profile_id': 'service_profile_id',
            'status': 'status'
        }
        network_function = self.create_network_function(attrs_mandatory)
        for key in attrs_mandatory:
            self.assertEqual(attrs_mandatory[key], network_function[key])
        self.assertIsNotNone(network_function['id'])
        non_mandatory_args = ['service_chain_id', 'service_config',
                              'heat_stack_id']
        for arg in non_mandatory_args:
            self.assertIsNone(network_function[arg])

    def test_get_network_function(self):
        attrs_all = {
            'name': 'name',
            'description': 'description',
            'tenant_id': 'tenant_id',
            'service_id': 'service_id',
            'service_chain_id': 'service_chain_id',
            'service_profile_id': 'service_profile_id',
            'service_config': 'service_config',
            'heat_stack_id': 'heat_stack_id',
            'status': 'status'
        }
        network_function = self.create_network_function(attrs_all)
        db_network_function = self.nfp_db.get_network_function(
            self.session, network_function['id'])
        for key in attrs_all:
            self.assertEqual(attrs_all[key], db_network_function[key])

    def test_list_network_function(self):
        network_function = self.create_network_function()
        network_functions = self.nfp_db.get_network_functions(self.session)
        self.assertEqual(1, len(network_functions))
        self.assertEqual(network_function['id'], network_functions[0]['id'])

    def test_list_network_function_with_filters(self):
        attrs = {
            'name': 'name',
            'tenant_id': 'tenant_id',
            'service_id': 'service_id',
            'service_profile_id': 'service_profile_id',
            'status': 'status'
        }
        network_function = self.create_network_function(attrs)
        filters = {'service_id': ['service_id']}
        network_functions = self.nfp_db.get_network_functions(
            self.session, filters=filters)
        self.assertEqual(1, len(network_functions))
        self.assertEqual(network_function['id'], network_functions[0]['id'])
        filters = {'service_id': ['nonexisting']}
        network_functions = self.nfp_db.get_network_functions(
            self.session, filters=filters)
        self.assertEqual([], network_functions)

    def test_update_network_function(self):
        network_function = self.create_network_function()
        self.assertIsNotNone(network_function['id'])
        updated_network_function = {'status': 'ERROR'}
        network_function = self.nfp_db.update_network_function(
            self.session, network_function['id'], updated_network_function)
        self.assertEqual('ERROR', network_function['status'])

    def test_delete_network_function(self):
        network_function = self.create_network_function()
        self.assertIsNotNone(network_function['id'])
        self.nfp_db.delete_network_function(
            self.session, network_function['id'])
        self.assertRaises(nfp_exc.NetworkFunctionNotFound,
                          self.nfp_db.get_network_function,
                          self.session, network_function['id'])

    def create_network_function_instance(self, attributes=None,
                                         create_nfd=True):
        if attributes is None:
            nfd = (self.create_network_function_device()['id']
                   if create_nfd else None)
            attributes = {
                'name': 'name',
                'description': 'description',
                'tenant_id': 'tenant_id',
                'network_function_id': self.create_network_function()['id'],
                'network_function_device_id': nfd,
                'ha_state': "Active",
                'port_info': [
                    {'id': 'myportid1',
                     'port_model': nfp_constants.NEUTRON_PORT,
                     'port_classification': nfp_constants.PROVIDER,
                     'port_role': nfp_constants.ACTIVE_PORT},
                    {'id': 'myportid2',
                     'port_model': nfp_constants.GBP_PORT,
                     'port_classification': nfp_constants.CONSUMER,
                     'port_role': nfp_constants.MASTER_PORT}
                ],
                'status': 'status'
            }
        return self.nfp_db.create_network_function_instance(
            self.session, attributes)

    def test_create_network_function_instance(self):
        network_function = self.create_network_function()
        attrs = {
            'name': 'name',
            'description': 'description',
            'tenant_id': 'tenant_id',
            'network_function_id': network_function['id'],
            'network_function_device_id': (
                self.create_network_function_device()['id']),
            'ha_state': 'Active',
            'port_info': [
                {'id': 'my_nfi_port_id1',
                 'port_model': nfp_constants.NEUTRON_PORT,
                 'port_classification': nfp_constants.PROVIDER,
                 'port_role': nfp_constants.ACTIVE_PORT},
                {'id': 'my_nfi_port_id2',
                 'port_model': nfp_constants.GBP_PORT,
                 'port_classification': nfp_constants.CONSUMER,
                 'port_role': nfp_constants.MASTER_PORT}
            ],
            'status': 'status'
        }
        network_function_instance = (
            self.nfp_db.create_network_function_instance(self.session, attrs))
        for key in attrs:
            self.assertEqual(attrs[key], network_function_instance[key])
        self.assertIsNotNone(network_function_instance['id'])

    def test_create_network_function_instance_mandatory_values(self):
        network_function = self.create_network_function()
        attrs_mandatory = {
            'name': 'name',
            'tenant_id': 'tenant_id',
            'network_function_id': network_function['id'],
            'status': 'status'
        }
        network_function_instance = (
            self.nfp_db.create_network_function_instance(
                self.session, attrs_mandatory))
        for key in attrs_mandatory:
            self.assertEqual(attrs_mandatory[key],
                             network_function_instance[key])
        self.assertIsNotNone(network_function_instance['id'])
        non_mandatory_args = ['network_function_device_id', 'ha_state']
        for arg in non_mandatory_args:
            self.assertIsNone(network_function_instance[arg])
        self.assertEqual([], network_function_instance['port_info'])

    def test_get_network_function_instance(self):
        network_function = self.create_network_function()
        attrs_all = {
            'name': 'name',
            'description': 'description',
            'tenant_id': 'tenant_id',
            'network_function_id': network_function['id'],
            'network_function_device_id': (
                self.create_network_function_device()['id']),
            'ha_state': 'Active',
            'port_info': [
                {'id': 'my_nfi_port_id1',
                 'port_model': nfp_constants.NEUTRON_PORT,
                 'port_classification': nfp_constants.PROVIDER,
                 'port_role': nfp_constants.ACTIVE_PORT},
                {'id': 'my_nfi_port_id2',
                 'port_model': nfp_constants.GBP_PORT,
                 'port_classification': nfp_constants.CONSUMER,
                 'port_role': nfp_constants.MASTER_PORT}
            ],
            'status': 'status'
        }
        network_function_instance = (
            self.nfp_db.create_network_function_instance(
                self.session, attrs_all))
        db_network_function_instance = (
            self.nfp_db.get_network_function_instance(
                self.session, network_function_instance['id']))
        for key in attrs_all:
            self.assertEqual(attrs_all[key], db_network_function_instance[key])

    def test_list_network_function_instance(self):
        self.test_create_network_function_instance()
        nf_instances = self.nfp_db.get_network_function_instances(
            self.session)
        self.assertEqual(1, len(nf_instances))

    def test_list_network_function_instances_with_filters(self):
        self.test_create_network_function_instance()
        filters = {'ha_state': ['Active']}
        nf_instances = self.nfp_db.get_network_function_instances(
            self.session, filters=filters)
        self.assertEqual(1, len(nf_instances))
        filters = {'ha_state': ['nonexisting']}
        nf_instances = self.nfp_db.get_network_function_instances(
            self.session, filters=filters)
        self.assertEqual([], nf_instances)

    def test_update_network_function_instance(self):
        network_function_instance = self.create_network_function_instance()
        self.assertIsNotNone(network_function_instance['id'])
        updated_nfi = {'status': 'ERROR'}
        nf_instance = self.nfp_db.update_network_function_instance(
            self.session, network_function_instance['id'], updated_nfi)
        self.assertEqual('ERROR', nf_instance['status'])

    def test_delete_network_function_instance(self):
        network_function_instance = self.create_network_function_instance()
        port_info = network_function_instance['port_info']
        self.assertIsNotNone(network_function_instance['id'])
        self.nfp_db.delete_network_function_instance(
            self.session, network_function_instance['id'])
        self.assertRaises(nfp_exc.NetworkFunctionInstanceNotFound,
                          self.nfp_db.get_network_function_instance,
                          self.session, network_function_instance['id'])
        for port_id in port_info:
            self.assertRaises(nfp_exc.NFPPortNotFound,
                              self.nfp_db.get_port_info,
                              self.session,
                              port_id)

    def create_network_function_device(self, attributes=None):
        if attributes is None:
            attributes = {
                'name': 'name',
                'description': 'description',
                'tenant_id': 'tenant_id',
                'mgmt_ip_address': 'mgmt_ip_address',
                'monitoring_port_id': {
                    'id': 'myid1_ha_port',
                    'port_model': nfp_constants.NEUTRON_PORT,
                    'port_classification': nfp_constants.MONITOR,
                    'port_role': nfp_constants.ACTIVE_PORT
                },
                'monitoring_port_network': {
                    'id': 'mynetwork_id',
                    'network_model': nfp_constants.NEUTRON_NETWORK
                },
                'service_vendor': 'service_vendor',
                'max_interfaces': 3,
                'reference_count': 2,
                'interfaces_in_use': 1,
                'mgmt_port_id': {
                    'id': 'myid1',
                    'port_model': nfp_constants.NEUTRON_PORT,
                    'port_classification': nfp_constants.MANAGEMENT,
                    'port_role': nfp_constants.ACTIVE_PORT},
                'status': 'status'
            }
        return self.nfp_db.create_network_function_device(
            self.session, attributes)

    def test_create_network_function_device(self):
        attrs = {
            'name': 'name',
            'description': 'description',
            'tenant_id': 'tenant_id',
            'mgmt_ip_address': 'mgmt_ip_address',
            'monitoring_port_id': {
                'id': 'myid1_ha_port',
                'port_model': nfp_constants.NEUTRON_PORT,
                'port_classification': nfp_constants.MONITOR,
                'port_role': nfp_constants.ACTIVE_PORT
            },
            'monitoring_port_network': {
                'id': 'mynetwork_id',
                'network_model': nfp_constants.NEUTRON_NETWORK
            },
            'service_vendor': 'service_vendor',
            'max_interfaces': 3,
            'reference_count': 2,
            'interfaces_in_use': 1,
            'mgmt_port_id': {
                'id': 'myid1',
                'port_model': nfp_constants.NEUTRON_PORT,
                'port_classification': nfp_constants.MANAGEMENT,
                'port_role': nfp_constants.ACTIVE_PORT},
            'status': 'status'
        }
        network_function_device = self.nfp_db.create_network_function_device(
            self.session, attrs)
        for key in attrs:
            if key == 'mgmt_port_id':
                self.assertEqual(attrs[key]['id'],
                                 network_function_device[key])
                continue
            self.assertEqual(attrs[key], network_function_device[key])
        self.assertIsNotNone(network_function_device['id'])

    def test_create_network_function_device_mandatory_values(self):
        attrs_mandatory = {
            'name': 'name',
            'tenant_id': 'tenant_id',
            'mgmt_ip_address': 'mgmt_ip_address',
            'service_vendor': 'service_vendor',
            'max_interfaces': 3,
            'reference_count': 2,
            'interfaces_in_use': 1,
            'status': 'status'
        }
        nf_device = self.nfp_db.create_network_function_device(
            self.session, attrs_mandatory)
        for key in attrs_mandatory:
            self.assertEqual(attrs_mandatory[key], nf_device[key])
        self.assertIsNotNone(nf_device['id'])
        non_mandatory_args = ['monitoring_port_id',
                              'monitoring_port_network']
        for arg in non_mandatory_args:
            self.assertIsNone(nf_device[arg])
        self.assertEqual(None, nf_device['mgmt_port_id'])

    def test_get_network_function_device(self):
        attrs = {
            'name': 'name',
            'description': 'description',
            'tenant_id': 'tenant_id',
            'mgmt_ip_address': 'mgmt_ip_address',
            'monitoring_port_id': {
                'id': 'myid1_ha_port',
                'port_model': nfp_constants.NEUTRON_PORT,
                'port_classification': nfp_constants.MONITOR,
                'port_role': nfp_constants.ACTIVE_PORT
            },
            'monitoring_port_network': {
                'id': 'mynetwork_id',
                'network_model': nfp_constants.NEUTRON_NETWORK
            },
            'service_vendor': 'service_vendor',
            'max_interfaces': 3,
            'reference_count': 2,
            'interfaces_in_use': 1,
            'mgmt_port_id': {
                'id': 'myid1',
                'port_model': nfp_constants.NEUTRON_PORT,
                'port_classification': nfp_constants.MANAGEMENT,
                'port_role': nfp_constants.ACTIVE_PORT},
            'status': 'status'
        }
        network_function_device = self.nfp_db.create_network_function_device(
            self.session, attrs)
        db_network_function_device = self.nfp_db.get_network_function_device(
            self.session, network_function_device['id'])
        for key in attrs:
            if key == 'mgmt_port_id':
                self.assertEqual(attrs[key]['id'],
                                 network_function_device[key])
                continue
            self.assertEqual(attrs[key], db_network_function_device[key])

    def test_list_network_function_device(self):
        self.test_create_network_function_device()
        network_function_devices = self.nfp_db.get_network_function_devices(
            self.session)
        self.assertEqual(1, len(network_function_devices))

    def test_list_network_function_devices_with_filters(self):
        self.test_create_network_function_device()
        filters = {'service_vendor': ['service_vendor']}
        network_function_devices = self.nfp_db.get_network_function_devices(
            self.session, filters=filters)
        self.assertEqual(1, len(network_function_devices))
        filters = {'service_vendor': ['nonexisting']}
        network_function_devices = self.nfp_db.get_network_function_devices(
            self.session, filters=filters)
        self.assertEqual([], network_function_devices)

    def test_update_network_function_device(self):
        attrs = {
            'name': 'name',
            'description': 'description',
            'tenant_id': 'tenant_id',
            'mgmt_ip_address': 'mgmt_ip_address',
            'monitoring_port_id': {
                'id': 'myid1_ha_port',
                'port_model': nfp_constants.NEUTRON_PORT,
                'port_classification': nfp_constants.MONITOR,
                'port_role': nfp_constants.ACTIVE_PORT
            },
            'monitoring_port_network': {
                'id': 'mynetwork_id',
                'network_model': nfp_constants.NEUTRON_NETWORK
            },
            'service_vendor': 'service_vendor',
            'max_interfaces': 3,
            'reference_count': 2,
            'interfaces_in_use': 1,
            'mgmt_port_id': {
                'id': 'myid1',
                'port_model': nfp_constants.NEUTRON_PORT,
                'port_classification': nfp_constants.MANAGEMENT,
                'port_role': nfp_constants.ACTIVE_PORT},
            'status': 'status'
        }
        network_function_device = self.nfp_db.create_network_function_device(
            self.session, attrs)
        for key in attrs:
            if key == 'mgmt_port_id':
                self.assertEqual(attrs[key]['id'],
                                 network_function_device[key])
                continue

            self.assertEqual(attrs[key], network_function_device[key])
        self.assertIsNotNone(network_function_device['id'])

        # update name
        updated_network_function_device = {
            'name': 'new_name'
        }
        updated_nfd = self.nfp_db.update_network_function_device(
            self.session,
            network_function_device['id'],
            updated_network_function_device)
        self.assertEqual('new_name', updated_nfd['name'])
        del updated_nfd['name']
        for key in attrs:
            if key == 'mgmt_port_id':
                self.assertEqual(attrs[key]['id'],
                                 network_function_device[key])
                continue
            if key != 'name':
                self.assertEqual(attrs[key], updated_nfd[key])

        # Update mgmt port
        updated_network_function_device = {
            'mgmt_port_id': {
                'id': 'myid3',
                'port_model': nfp_constants.NEUTRON_PORT,
                'port_classification': nfp_constants.MANAGEMENT,
                'port_role': nfp_constants.ACTIVE_PORT},
            'name': 'name'
        }
        updated_nfd = self.nfp_db.update_network_function_device(
            self.session,
            network_function_device['id'],
            copy.deepcopy(updated_network_function_device))
        self.assertEqual(updated_nfd['mgmt_port_id'], 'myid3')
        del updated_nfd['mgmt_port_id']
        for key in attrs:
            if key != 'mgmt_port_id':
                self.assertEqual(attrs[key], updated_nfd[key])

    def test_delete_network_function_device(self):
        network_function_device = self.create_network_function_device()
        mgmt_port_id = network_function_device['mgmt_port_id']
        self.assertIsNotNone(network_function_device['id'])
        self.nfp_db.delete_network_function_device(
            self.session, network_function_device['id'])
        self.assertRaises(nfp_exc.NetworkFunctionDeviceNotFound,
                          self.nfp_db.get_network_function_device,
                          self.session, network_function_device['id'])
        self.assertRaises(nfp_exc.NFPPortNotFound,
                          self.nfp_db.get_port_info,
                          self.session,
                          mgmt_port_id)
