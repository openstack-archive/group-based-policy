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

import fixtures


from neutron import context
from neutron.tests import base

from gbpservice.neutron.nsf.db import api as db_api
from gbpservice.neutron.nsf.db import nsf_db
from gbpservice.neutron.nsf.db import nsf_db_model


class SqlFixture(fixtures.Fixture):

    # flag to indicate that the models have been loaded
    _TABLES_ESTABLISHED = False

    def _setUp(self):
        # Register all data models
        engine = db_api.get_engine()
        if not SqlFixture._TABLES_ESTABLISHED:
            nsf_db_model.BASE.metadata.create_all(engine)
            SqlFixture._TABLES_ESTABLISHED = True

        def clear_tables():
            with engine.begin() as conn:
                for table in reversed(
                        nsf_db_model.BASE.metadata.sorted_tables):
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


class NSFDB(nsf_db.NSFDbBase):
    pass


class NSFDBTestCase(SqlTestCase):

    def setUp(self):
        super(NSFDBTestCase, self).setUp()
        self.ctx = context.get_admin_context()
        self.nsf_db = NSFDB()

    def _create_network_service(self, attributes=None):
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
        session = db_api.get_session()
        return self.nsf_db.create_network_service(session, attributes)

    def test_create_network_service(self):
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

        network_service = self._create_network_service(attrs_all)
        for key in attrs_all:
            self.assertEqual(attrs_all[key], network_service[key])
        self.assertIsNotNone(network_service['id'])

    def test_create_network_service_mandatory_values(self):
        attrs_mandatory = {
            'name': 'name',
            'tenant_id': 'tenant_id',
            'service_id': 'service_id',
            'service_profile_id': 'service_profile_id',
            'status': 'status'
        }
        network_service = self._create_network_service(attrs_mandatory)
        for key in attrs_mandatory:
            self.assertEqual(attrs_mandatory[key], network_service[key])
        self.assertIsNotNone(network_service['id'])
        non_mandatory_args = ['service_chain_id', 'service_config',
                              'heat_stack_id']
        for arg in non_mandatory_args:
            self.assertIsNone(network_service[arg])

    def test_get_network_service(self):
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
        network_service = self._create_network_service(attrs_all)
        session = db_api.get_session()
        db_network_service = self.nsf_db.get_network_service(
            session, network_service['id'])
        for key in attrs_all:
            self.assertEqual(attrs_all[key], db_network_service[key])

    def test_list_network_service(self):
        network_service = self._create_network_service()
        session = db_api.get_session()
        network_services = self.nsf_db.get_network_services(session)
        self.assertEqual(1, len(network_services))
        self.assertEqual(network_service['id'], network_services[0]['id'])

    def test_list_network_service_with_filters(self):
        session = db_api.get_session()
        attrs = {
            'name': 'name',
            'tenant_id': 'tenant_id',
            'service_id': 'service_id',
            'service_profile_id': 'service_profile_id',
            'status': 'status'
        }
        network_service = self._create_network_service(attrs)
        filters = {'service_id': ['service_id']}
        network_services = self.nsf_db.get_network_services(
            session, filters=filters)
        self.assertEqual(1, len(network_services))
        self.assertEqual(network_service['id'], network_services[0]['id'])
        filters = {'service_id': ['nonexisting']}
        network_services = self.nsf_db.get_network_services(
            session, filters=filters)
        self.assertEqual([], network_services)

    def _create_network_service_instance(self, attributes=None):
        if attributes is None:
            attributes = {
                'name': 'name',
                'description': 'description',
                'tenant_id': 'tenant_id',
                'network_service_id': 'network_service_id',
                'network_service_device_id': (
                    self._create_network_service_device()['id']),
                'ha_state': "Active",
                'data_ports': [
                    {'id': 'myid1',
                     'port_policy': 'neutron',
                     'port_classification': 'provider',
                     'port_type': 'active'},
                    {'id': 'myid2',
                     'port_policy': 'gbp',
                     'port_classification': 'consumer',
                     'port_type': 'master'}
                ],
                'status': 'status'
            }
        session = db_api.get_session()
        return self.nsf_db.create_network_service_instance(session, attributes)

    def test_create_network_service_instance(self):
        network_service = self._create_network_service()
        attrs_all = {
            'name': 'name',
            'description': 'description',
            'tenant_id': 'tenant_id',
            'network_service_id': network_service['id'],
            'network_service_device_id': (
                self._create_network_service_device()['id']),
            'ha_state': 'Active',
            'port_info': [
                {'id': 'my_nsi_port_id1',
                 'port_policy': 'neutron',
                 'port_classification': 'provider',
                 'port_type': 'active'},
                {'id': 'my_nsi_port_id2',
                 'port_policy': 'gbp',
                 'port_classification': 'consumer',
                 'port_type': 'master'}
            ],
            'status': 'status'
        }
        session = db_api.get_session()
        network_service_instance = self.nsf_db.create_network_service_instance(
            session, attrs_all)
        for key in attrs_all:
            self.assertEqual(attrs_all[key], network_service_instance[key])
        self.assertIsNotNone(network_service_instance['id'])

    def test_create_network_service_instance_mandatory_values(self):
        network_service = self._create_network_service()
        attrs_mandatory = {
            'name': 'name',
            'tenant_id': 'tenant_id',
            'network_service_id': network_service['id'],
            'status': 'status'
        }
        session = db_api.get_session()
        network_service_instance = self.nsf_db.create_network_service_instance(
            session, attrs_mandatory)
        for key in attrs_mandatory:
            self.assertEqual(attrs_mandatory[key],
                             network_service_instance[key])
        self.assertIsNotNone(network_service_instance['id'])
        non_mandatory_args = ['network_service_device_id', 'ha_state']
        for arg in non_mandatory_args:
            self.assertIsNone(network_service_instance[arg])
        self.assertEqual([], network_service_instance['port_info'])

    def test_get_network_service_instance(self):
        network_service = self._create_network_service()
        attrs_all = {
            'name': 'name',
            'description': 'description',
            'tenant_id': 'tenant_id',
            'network_service_id': network_service['id'],
            'network_service_device_id': (
                self._create_network_service_device()['id']),
            'ha_state': 'Active',
            'port_info': [
                {'id': 'my_nsi_port_id1',
                 'port_policy': 'neutron',
                 'port_classification': 'provider',
                 'port_type': 'active'},
                {'id': 'my_nsi_port_id2',
                 'port_policy': 'gbp',
                 'port_classification': 'consumer',
                 'port_type': 'master'}
            ],
            'status': 'status'
        }
        session = db_api.get_session()
        network_service_instance = self.nsf_db.create_network_service_instance(
            session, attrs_all)
        db_network_service_instance = self.nsf_db.get_network_service_instance(
            session, network_service_instance['id'])
        for key in attrs_all:
            self.assertEqual(attrs_all[key], db_network_service_instance[key])

    def test_list_network_service_instance(self):
        session = db_api.get_session()
        self.test_create_network_service_instance()
        network_service_instances = self.nsf_db.get_network_service_instances(
            session)
        self.assertEqual(1, len(network_service_instances))

    def test_list_network_service_instances_with_filters(self):
        session = db_api.get_session()
        self.test_create_network_service_instance()
        filters = {'ha_state': ['Active']}
        network_service_instances = self.nsf_db.get_network_service_instances(
            session, filters=filters)
        self.assertEqual(1, len(network_service_instances))
        filters = {'ha_state': ['nonexisting']}
        network_service_instances = self.nsf_db.get_network_service_instances(
            session, filters=filters)
        self.assertEqual([], network_service_instances)

    def _create_network_service_device(self, attributes=None):
        if attributes is None:
            attributes = {
                'name': 'name',
                'description': 'description',
                'tenant_id': 'tenant_id',
                'mgmt_ip_address': 'mgmt_ip_address',
                'ha_monitoring_data_port': {
                    'id': 'myid1_ha_port',
                    'port_policy': 'neutron',
                    'port_classification': 'monitoring',
                    'port_type': 'active'
                },
                'ha_monitoring_data_network': {
                    'id': 'mynetwork_id',
                    'network_policy': 'neutron'
                },
                'service_vendor': 'service_vendor',
                'max_interfaces': 3,
                'reference_count': 2,
                'interfaces_in_use': 1,
                'mgmt_data_ports': [
                    {'id': 'myid1',
                     'port_policy': 'neutron',
                     'port_classification': 'management',
                     'port_type': 'active'},
                    {'id': 'myid2',
                     'port_policy': 'gbp',
                     'port_classification': 'management',
                     'port_type': 'master'}
                ],
                'status': 'status'
            }
        session = db_api.get_session()
        return self.nsf_db.create_network_service_device(session, attributes)

    def test_create_network_service_device(self):
        attrs_all = {
            'name': 'name',
            'description': 'description',
            'tenant_id': 'tenant_id',
            'mgmt_ip_address': 'mgmt_ip_address',
            'ha_monitoring_data_port': {
                'id': 'myid1_ha_port',
                'port_policy': 'neutron',
                'port_classification': 'monitoring',
                'port_type': 'active'
            },
            'ha_monitoring_data_network': {
                'id': 'mynetwork_id',
                'network_policy': 'neutron'
            },
            'service_vendor': 'service_vendor',
            'max_interfaces': 3,
            'reference_count': 2,
            'interfaces_in_use': 1,
            'mgmt_data_ports': [
                {'id': 'myid1',
                 'port_policy': 'neutron',
                 'port_classification': 'management',
                 'port_type': 'active'},
                {'id': 'myid2',
                 'port_policy': 'gbp',
                 'port_classification': 'management',
                 'port_type': 'master'}
            ],
            'status': 'status'
        }
        session = db_api.get_session()
        network_service_device = self.nsf_db.create_network_service_device(
            session, attrs_all)
        for key in attrs_all:
            self.assertEqual(attrs_all[key], network_service_device[key])
        self.assertIsNotNone(network_service_device['id'])

    def test_create_network_service_device_mandatory_values(self):
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
        session = db_api.get_session()
        network_service_device = self.nsf_db.create_network_service_device(
            session, attrs_mandatory)
        for key in attrs_mandatory:
            self.assertEqual(attrs_mandatory[key], network_service_device[key])
        self.assertIsNotNone(network_service_device['id'])
        non_mandatory_args = ['ha_monitoring_data_port',
                              'ha_monitoring_data_network']
        for arg in non_mandatory_args:
            self.assertIsNone(network_service_device[arg])
        self.assertEqual([], network_service_device['mgmt_data_ports'])

    def test_get_network_service_device(self):
        attrs_all = {
            'name': 'name',
            'description': 'description',
            'tenant_id': 'tenant_id',
            'mgmt_ip_address': 'mgmt_ip_address',
            'ha_monitoring_data_port': {
                'id': 'myid1_ha_port',
                'port_policy': 'neutron',
                'port_classification': 'monitoring',
                'port_type': 'active'
            },
            'ha_monitoring_data_network': {
                'id': 'mynetwork_id',
                'network_policy': 'neutron'
            },
            'service_vendor': 'service_vendor',
            'max_interfaces': 3,
            'reference_count': 2,
            'interfaces_in_use': 1,
            'mgmt_data_ports': [
                {'id': 'myid1',
                 'port_policy': 'neutron',
                 'port_classification': 'management',
                 'port_type': 'active'},
                {'id': 'myid2',
                 'port_policy': 'gbp',
                 'port_classification': 'management',
                 'port_type': 'master'}
            ],
            'status': 'status'
        }
        session = db_api.get_session()
        network_service_device = self.nsf_db.create_network_service_device(
            session, attrs_all)
        db_network_service_device = self.nsf_db.get_network_service_device(
            session, network_service_device['id'])
        for key in attrs_all:
            self.assertEqual(attrs_all[key], db_network_service_device[key])

    def test_list_network_service_device(self):
        session = db_api.get_session()
        self.test_create_network_service_device()
        network_service_devices = self.nsf_db.get_network_service_devices(
            session)
        self.assertEqual(1, len(network_service_devices))

    def test_list_network_service_devices_with_filters(self):
        session = db_api.get_session()
        self.test_create_network_service_device()
        filters = {'service_vendor': ['service_vendor']}
        network_service_devices = self.nsf_db.get_network_service_devices(
            session, filters=filters)
        self.assertEqual(1, len(network_service_devices))
        filters = {'service_vendor': ['nonexisting']}
        network_service_devices = self.nsf_db.get_network_service_devices(
            session, filters=filters)
        self.assertEqual([], network_service_devices)
