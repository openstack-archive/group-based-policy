# Copyright (c) 2016 OpenStack Foundation.
#
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

from oslo_log import log as logging
from oslo_utils import uuidutils
from sqlalchemy.orm import exc

from gbpservice.neutron.nsf.db import common_db_mixin
from gbpservice.neutron.nsf.db import nsf_db_model

LOG = logging.getLogger(__name__)


class NSFDbBase(common_db_mixin.CommonDbMixin):

    def __init__(self, *args, **kwargs):
        super(NSFDbBase, self).__init__(*args, **kwargs)

    def create_network_service(self, session, network_service):
        with session.begin(subtransactions=True):
            network_service_db = nsf_db_model.NetworkService(
                id=uuidutils.generate_uuid(),
                name=network_service['name'],
                description=network_service.get('description'),
                tenant_id=network_service['tenant_id'],
                service_id=network_service['service_id'],
                service_chain_id=network_service.get('service_chain_id'),
                service_profile_id=network_service['service_profile_id'],
                service_config=network_service.get('service_config'),
                heat_stack_id=network_service.get('heat_stack_id'),
                status=network_service['status'])
            session.add(network_service_db)
            return self._make_network_service_dict(network_service_db)

    def _get_network_service(self, session, network_service_id):
        try:
            return self._get_by_id(
                session, nsf_db_model.NetworkService, network_service_id)
        except exc.NoResultFound:
            raise Exception()  # Raise appropriate error class here

    def update_network_service(self, session, network_service_id,
                               updated_network_service):
        with session.begin(subtransactions=True):
            network_service_db = self._get_network_service(
                session, network_service_id)
            network_service_db.update(updated_network_service)
        return self._make_network_service_dict(network_service_db)

    def delete_network_service(self, session, network_service_id):
        with session.begin(subtransactions=True):
            network_service_db = self._get_network_service(
                session, network_service_id)
            session.delete(network_service_db)

    def get_network_service(self, session, network_service_id, fields=None):
        service = self._get_network_service(session, network_service_id)
        return self._make_network_service_dict(service, fields)

    def get_network_services(self, session, filters=None, fields=None,
                             sorts=None, limit=None, marker=None,
                             page_reverse=False):
        marker_obj = self._get_marker_obj(
            'network_services', limit, marker)
        return self._get_collection(session, nsf_db_model.NetworkService,
                                    self._make_network_service_dict,
                                    filters=filters, fields=fields,
                                    sorts=sorts, limit=limit,
                                    marker_obj=marker_obj,
                                    page_reverse=page_reverse)

    def _set_port_info_for_nsi(self, session, network_service_instance_db,
                               network_service_instance):
        nsi_db = network_service_instance_db
        port_info = network_service_instance.get('port_info')
        if not port_info:
            nsi_db.port_info = []
            return
        with session.begin(subtransactions=True):
            nsi_db.port_info = []
            for port in port_info:
                port_info_db = nsf_db_model.PortInfo(
                    id=port['id'],
                    port_policy=port['port_policy'],
                    port_classification=port['port_classification'],
                    port_type=port['port_type'])
                session.add(port_info_db)
                session.flush()  # Any alternatives for flush ??
                assoc = nsf_db_model.NSIPortAssociation(
                    network_service_instance_id=(
                        network_service_instance_db['id']),
                    data_port_id=port['id'])
                nsi_db.port_info.append(assoc)
            del network_service_instance['port_info']

    def create_network_service_instance(self, session,
                                        network_service_instance):
        with session.begin(subtransactions=True):
            network_service_instance_db = nsf_db_model.NetworkServiceInstance(
                id=uuidutils.generate_uuid(),
                name=network_service_instance['name'],
                tenant_id=network_service_instance['tenant_id'],
                description=network_service_instance.get('description'),
                network_service_id=network_service_instance[
                    'network_service_id'],
                network_service_device_id=network_service_instance.get(
                    'network_service_device_id'),
                ha_state=network_service_instance.get('ha_state'),
                status=network_service_instance['status'])
            session.add(network_service_instance_db)
            self._set_port_info_for_nsi(session, network_service_instance_db,
                                        network_service_instance)
        return self._make_network_service_instance_dict(
            network_service_instance_db)

    def _get_network_service_instance(self, session,
                                      network_service_instance_id):
        try:
            return self._get_by_id(
                session,
                nsf_db_model.NetworkServiceInstance,
                network_service_instance_id)
        except exc.NoResultFound:
            raise Exception()  # Raise appropriate error class here

    def update_network_service_instance(self, session,
                                        network_service_instance_id,
                                        updated_network_service_instance):
        with session.begin(subtransactions=True):
            network_service_instance_db = self._get_network_service_instance(
                session, network_service_instance_id)
            network_service_instance_db.update(
                updated_network_service_instance)
        return self._make_network_service_instance_dict(
            network_service_instance_db)

    def delete_network_service_instance(self, session,
                                        network_service_instance_id):
        with session.begin(subtransactions=True):
            network_service_instance_db = self._get_network_service_instance(
                session, network_service_instance_id)
            session.delete(network_service_instance_db)

    def get_network_service_instance(self, session,
                                     network_service_instance_id,
                                     fields=None):
        network_service_instance = self._get_network_service_instance(
            session, network_service_instance_id)
        return self._make_network_service_instance_dict(
            network_service_instance, fields)

    def get_network_service_instances(self, session, filters=None, fields=None,
                                      sorts=None, limit=None, marker=None,
                                      page_reverse=False):
        marker_obj = self._get_marker_obj(
            'network_service_instances', limit, marker)
        return self._get_collection(
            session, nsf_db_model.NetworkServiceInstance,
            self._make_network_service_instance_dict,
            filters=filters, fields=fields, sorts=sorts, limit=limit,
            marker_obj=marker_obj, page_reverse=page_reverse)

    def _set_mgmt_ports_for_nsd(self, session, network_service_device_db,
                                network_service_device):
        nsd_db = network_service_device_db
        mgmt_data_ports = network_service_device.get('mgmt_data_ports')
        if not mgmt_data_ports:
            nsd_db.mgmt_data_ports = []
            return
        with session.begin(subtransactions=True):
            nsd_db.mgmt_data_ports = []
            for port in mgmt_data_ports:
                port_info_db = nsf_db_model.PortInfo(
                    id=port['id'],
                    port_policy=port['port_policy'],
                    port_classification=port['port_classification'],
                    port_type=port['port_type'])
                session.add(port_info_db)
                assoc = nsf_db_model.NSDPortAssociation(
                    network_service_device_id=network_service_device_db['id'],
                    data_port_id=port['id'])
                nsd_db.mgmt_data_ports.append(assoc)
            del network_service_device['mgmt_data_ports']

    def _set_ha_monitoring_data_port_for_nsd(self, session,
                                             network_service_device_db,
                                             network_service_device):
        nsd_db = network_service_device_db
        ha_monitoring_data_port = network_service_device.get(
            'ha_monitoring_data_port')
        if not ha_monitoring_data_port:
            nsd_db.ha_monitoring_data_port = None
            return
        with session.begin(subtransactions=True):
            port_info_db = nsf_db_model.PortInfo(
                id=ha_monitoring_data_port['id'],
                port_policy=ha_monitoring_data_port['port_policy'],
                port_classification=ha_monitoring_data_port[
                    'port_classification'],
                port_type=ha_monitoring_data_port['port_type'])
            session.add(port_info_db)
            session.flush()
            nsd_db.ha_monitoring_data_port = ha_monitoring_data_port['id']
            del network_service_device['ha_monitoring_data_port']

    def _set_ha_monitoring_data_network_for_nsd(self, session,
                                                network_service_device_db,
                                                network_service_device):
        nsd_db = network_service_device_db
        ha_monitoring_data_network = network_service_device.get(
            'ha_monitoring_data_network')
        if not ha_monitoring_data_network:
            nsd_db.ha_monitoring_data_network = None
            return
        with session.begin(subtransactions=True):
            network_info_db = nsf_db_model.NetworkInfo(
                id=ha_monitoring_data_network['id'],
                network_policy=ha_monitoring_data_network['network_policy'])
            session.add(network_info_db)
            session.flush()
            nsd_db.ha_monitoring_data_network = (
                ha_monitoring_data_network['id'])
            del network_service_device['ha_monitoring_data_network']

    def create_network_service_device(self, session, network_service_device):
        with session.begin(subtransactions=True):
            network_service_device_db = nsf_db_model.NetworkServiceDevice(
                id=(network_service_device.get('id')
                    or uuidutils.generate_uuid()),
                name=network_service_device['name'],
                description=network_service_device.get('description'),
                tenant_id=network_service_device['tenant_id'],
                cluster_id=network_service_device.get('cluster_id'),
                mgmt_ip_address=network_service_device[
                    'mgmt_ip_address'],
                service_vendor=network_service_device.get('service_vendor'),
                max_interfaces=network_service_device['max_interfaces'],
                reference_count=network_service_device['reference_count'],
                interfaces_in_use=network_service_device['interfaces_in_use'],
                status=network_service_device['status'])
            session.add(network_service_device_db)
            self._set_mgmt_ports_for_nsd(
                session, network_service_device_db, network_service_device)
            self._set_ha_monitoring_data_port_for_nsd(
                session, network_service_device_db, network_service_device)
            self._set_ha_monitoring_data_network_for_nsd(
                session, network_service_device_db, network_service_device)
            return self._make_network_service_device_dict(
                network_service_device_db)

    def _get_network_service_device(self, session, network_service_device_id):
        return self._get_by_id(
            session,
            nsf_db_model.NetworkServiceDevice,
            network_service_device_id)

    def update_network_service_device(self, session, network_service_device_id,
                                      updated_network_service_device):
        with session.begin(subtransactions=True, nested=True):
            network_service_device_db = self._get_network_service_device(
                session, network_service_device_id)
            network_service_device_db.update(updated_network_service_device)
        return self._make_network_service_device_dict(
            network_service_device_db)

    def delete_network_service_device(self, session,
                                      network_service_device_id):
        with session.begin(subtransactions=True):
            network_service_device_db = self._get_network_service_device(
                session, network_service_device_id)
            session.delete(network_service_device_db)

    def get_network_service_device(self, session, network_service_device_id,
                                   fields=None):
        network_service_device = self._get_network_service_device(
            session, network_service_device_id)
        return self._make_network_service_device_dict(
            network_service_device, fields)

    def get_network_service_devices(self, session, filters=None, fields=None,
                                    sorts=None, limit=None, marker=None,
                                    page_reverse=False):
        marker_obj = self._get_marker_obj(
            'network_service_devices', limit, marker)
        return self._get_collection(session, nsf_db_model.NetworkServiceDevice,
                                    self._make_network_service_device_dict,
                                    filters=filters, fields=fields,
                                    sorts=sorts, limit=limit,
                                    marker_obj=marker_obj,
                                    page_reverse=page_reverse)

    def _make_network_service_dict(self, network_service, fields=None):
        res = {'id': network_service['id'],
               'tenant_id': network_service['tenant_id'],
               'name': network_service['name'],
               'description': network_service['description'],
               'service_id': network_service['service_id'],
               'service_chain_id': network_service['service_chain_id'],
               'service_profile_id': network_service['service_profile_id'],
               'service_config': network_service['service_config'],
               'heat_stack_id': network_service['heat_stack_id'],
               'status': network_service['status']
               }
        res['network_service_instances'] = [
            nsi['id'] for nsi in network_service['network_service_instances']]
        return res

    def _make_network_service_instance_dict(self, nsi, fields=None):
        res = {'id': nsi['id'],
               'tenant_id': nsi['tenant_id'],
               'name': nsi['name'],
               'description': nsi['description'],
               'ha_state': nsi['ha_state'],
               'network_service_id': nsi['network_service_id'],
               'network_service_device_id': nsi['network_service_device_id'],
               'status': nsi['status']
               }
        #res['port_info'] = [
        #    port['data_port_id'] for port in nsi['port_info']]
        res['port_info'] = nsi['port_info']
        return res

    def _make_network_service_device_dict(self, nsd, fields=None):
        res = {'id': nsd['id'],
               'tenant_id': nsd['tenant_id'],
               'name': nsd['name'],
               'description': nsd['description'],
               'cluster_id': nsd['cluster_id'],
               'mgmt_ip_address': nsd['mgmt_ip_address'],
               'ha_monitoring_data_port': nsd['ha_monitoring_data_port'],
               'ha_monitoring_data_network': nsd['ha_monitoring_data_network'],
               'service_vendor': nsd['service_vendor'],
               'max_interfaces': nsd['max_interfaces'],
               'reference_count': nsd['reference_count'],
               'interfaces_in_use': nsd['interfaces_in_use'],
               'status': nsd['status']
               }
        #res['mgmt_data_ports'] = [
        #    port['data_port_id'] for port in nsd['mgmt_data_ports']]
        res['mgmt_data_ports'] = nsd['mgmt_data_ports']
        return res
