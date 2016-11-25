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

from oslo_serialization import jsonutils
from oslo_utils import uuidutils
from sqlalchemy.orm import exc

from gbpservice.nfp.common import exceptions as nfp_exc
from gbpservice.nfp.orchestrator.db import common_db_mixin
from gbpservice.nfp.orchestrator.db import nfp_db_model

from gbpservice.nfp.core import log as nfp_logging
LOG = nfp_logging.getLogger(__name__)


class NFPDbBase(common_db_mixin.CommonDbMixin):

    def __init__(self, *args, **kwargs):
        super(NFPDbBase, self).__init__(*args, **kwargs)

    def create_network_function(self, session, network_function):
        with session.begin(subtransactions=True):
            network_function_db = nfp_db_model.NetworkFunction(
                id=uuidutils.generate_uuid(),
                name=network_function['name'],
                description=network_function.get('description'),
                tenant_id=network_function['tenant_id'],
                service_id=network_function['service_id'],
                service_chain_id=network_function.get('service_chain_id'),
                service_profile_id=network_function['service_profile_id'],
                service_config=network_function.get('service_config'),
                config_policy_id=network_function.get('config_policy_id'),
                status=network_function['status'])
            session.add(network_function_db)
            return self._make_network_function_dict(network_function_db)

    def _get_network_function(self, session, network_function_id):
        try:
            return self._get_by_id(
                session, nfp_db_model.NetworkFunction, network_function_id)
        except exc.NoResultFound:
            raise nfp_exc.NetworkFunctionNotFound(
                network_function_id=network_function_id)

    def update_network_function(self, session, network_function_id,
                                updated_network_function):
        with session.begin(subtransactions=True):
            network_function_db = self._get_network_function(
                session, network_function_id)
            network_function_db.update(updated_network_function)
        return self._make_network_function_dict(network_function_db)

    def delete_network_function(self, session, network_function_id):
        with session.begin(subtransactions=True):
            network_function_db = self._get_network_function(
                session, network_function_id)
            session.delete(network_function_db)

    def get_network_function(self, session, network_function_id, fields=None):
        service = self._get_network_function(session, network_function_id)
        return self._make_network_function_dict(service, fields)

    def get_network_functions(self, session, filters=None, fields=None,
                              sorts=None, limit=None, marker=None,
                              page_reverse=False):
        marker_obj = self._get_marker_obj(
            'network_functions', limit, marker)
        return self._get_collection(session, nfp_db_model.NetworkFunction,
                                    self._make_network_function_dict,
                                    filters=filters, fields=fields,
                                    sorts=sorts, limit=limit,
                                    marker_obj=marker_obj,
                                    page_reverse=page_reverse)

    def _set_port_info_for_nfi(self, session, network_function_instance_db,
                               network_function_instance, is_update=False):
        nfi_db = network_function_instance_db
        port_info = network_function_instance.get('port_info')
        with session.begin(subtransactions=True):
            nfi_db.port_info = []
            for port in port_info:
                port_info_db = nfp_db_model.PortInfo(
                    id=port['id'],
                    port_model=port['port_model'],
                    port_classification=port.get('port_classification'),
                    port_role=port.get('port_role'))
                if is_update:
                    session.merge(port_info_db)
                else:
                    session.add(port_info_db)
                session.flush()  # Any alternatives for flush ??
                assoc = nfp_db_model.NSIPortAssociation(
                    network_function_instance_id=(
                        network_function_instance_db['id']),
                    data_port_id=port['id'])
                nfi_db.port_info.append(assoc)
            del network_function_instance['port_info']

    def create_network_function_instance(self, session,
                                         network_function_instance):
        with session.begin(subtransactions=True):
            network_function_instance_db = (
                nfp_db_model.NetworkFunctionInstance(
                    id=uuidutils.generate_uuid(),
                    name=network_function_instance['name'],
                    tenant_id=network_function_instance['tenant_id'],
                    description=network_function_instance.get('description'),
                    network_function_id=network_function_instance[
                        'network_function_id'],
                    network_function_device_id=network_function_instance.get(
                        'network_function_device_id'),
                    ha_state=network_function_instance.get('ha_state'),
                    status=network_function_instance['status']))
            session.add(network_function_instance_db)
            self._set_port_info_for_nfi(session, network_function_instance_db,
                                        network_function_instance)
        return self._make_network_function_instance_dict(
            network_function_instance_db)

    def _get_network_function_instance(self, session,
                                       network_function_instance_id):
        try:
            return self._get_by_id(
                session,
                nfp_db_model.NetworkFunctionInstance,
                network_function_instance_id)
        except exc.NoResultFound:
            raise nfp_exc.NetworkFunctionInstanceNotFound(
                network_function_instance_id=network_function_instance_id)

    def update_network_function_instance(self, session,
                                         network_function_instance_id,
                                         updated_network_function_instance):
        with session.begin(subtransactions=True):
            network_function_instance_db = self._get_network_function_instance(
                session, network_function_instance_id)
            if 'port_info' in updated_network_function_instance:
                self._set_port_info_for_nfi(
                    session,
                    network_function_instance_db,
                    updated_network_function_instance, is_update=True)
            network_function_instance_db.update(
                updated_network_function_instance)
        return self._make_network_function_instance_dict(
            network_function_instance_db)

    def delete_network_function_instance(self, session,
                                         network_function_instance_id):
        with session.begin(subtransactions=True):
            network_function_instance_db = self._get_network_function_instance(
                session, network_function_instance_id)
            for port in network_function_instance_db.port_info:
                self.delete_port_info(session, port['data_port_id'])
            session.delete(network_function_instance_db)

    def get_network_function_instance(self, session,
                                      network_function_instance_id,
                                      fields=None):
        network_function_instance = self._get_network_function_instance(
            session, network_function_instance_id)
        return self._make_network_function_instance_dict(
            network_function_instance, fields)

    def get_network_function_instances(self, session, filters=None,
                                       fields=None, sorts=None, limit=None,
                                       marker=None, page_reverse=False):
        marker_obj = self._get_marker_obj(
            'network_function_instances', limit, marker)
        return self._get_collection(
            session, nfp_db_model.NetworkFunctionInstance,
            self._make_network_function_instance_dict,
            filters=filters, fields=fields, sorts=sorts, limit=limit,
            marker_obj=marker_obj, page_reverse=page_reverse)

    def _set_mgmt_port_for_nfd(self, session, network_function_device_db,
                               network_function_device, is_update=False):
        nfd_db = network_function_device_db
        mgmt_port_id = network_function_device.get('mgmt_port_id')
        if not mgmt_port_id:
            nfd_db.mgmt_port_id = None
            return
        with session.begin(subtransactions=True):
            port_info_db = nfp_db_model.PortInfo(
                id=mgmt_port_id['id'],
                port_model=mgmt_port_id['port_model'],
                port_classification=mgmt_port_id['port_classification'],
                port_role=mgmt_port_id['port_role'])
            if is_update:
                session.merge(port_info_db)
            else:
                session.add(port_info_db)
            session.flush()
            nfd_db.mgmt_port_id = port_info_db['id']

    def _set_monitoring_port_id_for_nfd(self, session,
                                        network_function_device_db,
                                        network_function_device,
                                        is_update=False):
        nfd_db = network_function_device_db
        monitoring_port_id = network_function_device.get(
            'monitoring_port_id')
        if not monitoring_port_id:
            nfd_db.monitoring_port_id = None
            return
        with session.begin(subtransactions=True):
            port_info_db = nfp_db_model.PortInfo(
                id=monitoring_port_id['id'],
                port_model=monitoring_port_id['port_model'],
                port_classification=monitoring_port_id[
                    'port_classification'],
                port_role=monitoring_port_id['port_role'])
            if is_update:
                session.merge(port_info_db)
            else:
                session.add(port_info_db)
            session.flush()
            nfd_db.monitoring_port_id = monitoring_port_id['id']

    def _set_monitoring_port_network_for_nfd(self, session,
                                             network_function_device_db,
                                             network_function_device,
                                             is_update=False):
        nfd_db = network_function_device_db
        monitoring_port_network = network_function_device.get(
            'monitoring_port_network')
        if not monitoring_port_network:
            nfd_db.monitoring_port_network = None
            return
        with session.begin(subtransactions=True):
            network_info_db = nfp_db_model.NetworkInfo(
                id=monitoring_port_network['id'],
                network_model=monitoring_port_network['network_model'])
            session.add(network_info_db)
            session.flush()
            nfd_db.monitoring_port_network = (
                monitoring_port_network['id'])
            del network_function_device['monitoring_port_network']

    def _set_vendor_data_for_nfd(self, session,
                                 network_function_device_db,
                                 network_function_device,
                                 is_update=False):
        nfd_db = network_function_device_db
        vendor_data = nfd_db['vendor_data']

        if is_update:
            if vendor_data:
                vendor_data = jsonutils.loads(vendor_data)
            updated_vendor_data_str = network_function_device.pop(
                    'vendor_data', {})
            if not updated_vendor_data_str:
                return
            if updated_vendor_data_str:
                updated_vendor_data = jsonutils.loads(updated_vendor_data_str)
            if (type(updated_vendor_data) is dict
                    and updated_vendor_data and vendor_data):
                updated_vendor_data.update(vendor_data)
            vendor_data_str = jsonutils.dumps(updated_vendor_data)
        else:
            if not vendor_data:
                vendor_data_str = ''
                return
            vendor_data_str = jsonutils.dumps(vendor_data)
        nfd_db.vendor_data = vendor_data_str

    def create_network_function_device(self, session, network_function_device):
        with session.begin(subtransactions=True):
            network_function_device_db = nfp_db_model.NetworkFunctionDevice(
                id=(network_function_device.get('id') or
                    uuidutils.generate_uuid()),
                name=network_function_device['name'],
                description=network_function_device.get('description'),
                tenant_id=network_function_device['tenant_id'],
                mgmt_ip_address=network_function_device[
                    'mgmt_ip_address'],
                service_vendor=network_function_device.get('service_vendor'),
                max_interfaces=network_function_device['max_interfaces'],
                reference_count=network_function_device['reference_count'],
                interfaces_in_use=network_function_device['interfaces_in_use'],
                status=network_function_device['status'])
            session.add(network_function_device_db)
            self._set_mgmt_port_for_nfd(
                session, network_function_device_db, network_function_device)
            self._set_monitoring_port_id_for_nfd(
                session, network_function_device_db, network_function_device)
            self._set_monitoring_port_network_for_nfd(
                session, network_function_device_db, network_function_device)
            self._set_vendor_data_for_nfd(
                session, network_function_device_db, network_function_device)
            return self._make_network_function_device_dict(
                network_function_device_db)

    def _get_network_function_device(self, session,
                                     network_function_device_id):
        try:
            nfd = self._get_by_id(
                session,
                nfp_db_model.NetworkFunctionDevice,
                network_function_device_id)
            return nfd
        except exc.NoResultFound:
            raise nfp_exc.NetworkFunctionDeviceNotFound(
                network_function_device_id=network_function_device_id)

    def update_network_function_device(self, session,
                                       network_function_device_id,
                                      updated_network_function_device):
        with session.begin(subtransactions=True):
            network_function_device_db = self._get_network_function_device(
                session, network_function_device_id)
            if updated_network_function_device.get('vendor_data'):
                updated_network_function_device[
                        'vendor_data'] = jsonutils.dumps(
                                updated_network_function_device['vendor_data'])
            if updated_network_function_device.get('mgmt_port_id'):
                self._set_mgmt_port_for_nfd(
                    session,
                    network_function_device_db,
                    updated_network_function_device,
                    is_update=True)

            if 'monitoring_port_id' in updated_network_function_device:
                self._set_monitoring_port_id_for_nfd(
                    session,
                    network_function_device_db,
                    updated_network_function_device,
                    is_update=True)
            if 'monitoring_port_network' in updated_network_function_device:
                self._set_monitoring_port_network_for_nfd(
                    session,
                    network_function_device_db,
                    updated_network_function_device,
                    is_update=True)
            self._set_vendor_data_for_nfd(
                    session, network_function_device_db,
                    updated_network_function_device,
                    is_update=True)
            mgmt_port_id = (
                updated_network_function_device.pop('mgmt_port_id', None))
            if mgmt_port_id:
                updated_network_function_device[
                    'mgmt_port_id'] = mgmt_port_id['id']

            monitoring_port_id = (
                updated_network_function_device.pop('monitoring_port_id',
                                                    None))
            if monitoring_port_id:
                updated_network_function_device[
                    'monitoring_port_id'] = monitoring_port_id['id']
            network_function_device_db.update(updated_network_function_device)
            updated_network_function_device['mgmt_port_id'] = mgmt_port_id
            updated_network_function_device[
                    'monitoring_port_id'] = monitoring_port_id

            return self._make_network_function_device_dict(
                network_function_device_db)

    def delete_network_function_device(self, session,
                                       network_function_device_id):
        with session.begin(subtransactions=True):
            network_function_device_db = self._get_network_function_device(
                session, network_function_device_id)
            if network_function_device_db.mgmt_port_id:
                self.delete_port_info(session,
                                      network_function_device_db.mgmt_port_id)
            if network_function_device_db.monitoring_port_id:
                self.delete_port_info(
                    session,
                    network_function_device_db.monitoring_port_id)
            if network_function_device_db.monitoring_port_network:
                self.delete_network_info(
                    session,
                    network_function_device_db.monitoring_port_network)
            session.delete(network_function_device_db)

    def get_network_function_device(self, session, network_function_device_id,
                                    fields=None):
        network_function_device = self._get_network_function_device(
            session, network_function_device_id)
        return self._make_network_function_device_dict(
            network_function_device, fields)

    def get_network_function_devices(self, session, filters=None, fields=None,
                                     sorts=None, limit=None, marker=None,
                                     page_reverse=False):
        marker_obj = self._get_marker_obj(
            'network_function_devices', limit, marker)
        return self._get_collection(session,
                                    nfp_db_model.NetworkFunctionDevice,
                                    self._make_network_function_device_dict,
                                    filters=filters, fields=fields,
                                    sorts=sorts, limit=limit,
                                    marker_obj=marker_obj,
                                    page_reverse=page_reverse)

    def increment_network_function_device_count(self, session,
                                                network_function_device_id,
                                                field_name):
        with session.begin(subtransactions=True):
            network_function_device = self._get_network_function_device(
                session, network_function_device_id)
            value = network_function_device[field_name]
            value += 1
            update_device = (
                    {field_name: value})
            self.update_network_function_device(session,
                    network_function_device_id,
                    update_device)

    def decrement_network_function_device_count(self, session,
                                                network_function_device_id,
                                                field_name):
        with session.begin(subtransactions=True):
            network_function_device = self._get_network_function_device(
                session, network_function_device_id)
            value = network_function_device[field_name]
            value -= 1
            update_device = (
                    {field_name: value})
            self.update_network_function_device(session,
                    network_function_device_id,
                    update_device)

    def get_port_info(self, session, port_id, fields=None):
        port_info = self._get_port_info(session, port_id)
        return self._make_port_info_dict(port_info, fields)

    def _get_port_info(self, session, port_id):
        try:
            return self._get_by_id(
                session, nfp_db_model.PortInfo, port_id)
        except exc.NoResultFound:
            raise nfp_exc.NFPPortNotFound(port_id=port_id)

    def delete_port_info(self, session, port_id):
        with session.begin(subtransactions=True):
            port_info_db = self._get_port_info(session, port_id)
            session.delete(port_info_db)

    def delete_network_info(self, session, network_id):
        with session.begin(subtransactions=True):
            network_info_db = self._get_network_info(session, network_id)
            session.delete(network_info_db)

    def get_network_info(self, session, network_id, fields=None):
        network_info = self._get_network_info(session, network_id)
        return self._make_network_info_dict(network_info, fields)

    def _get_network_info(self, session, network_id):
        return self._get_by_id(
            session, nfp_db_model.NetworkInfo, network_id)

    def _set_plugged_in_port_for_nfd_interface(self, session, nfd_interface_db,
                                               interface, is_update=False):
        plugged_in_port_id = interface.get('plugged_in_port_id')
        if not plugged_in_port_id:
            if not is_update:
                nfd_interface_db.plugged_in_port_id = None
            return
        with session.begin(subtransactions=True):
            port_info_db = nfp_db_model.PortInfo(
                id=plugged_in_port_id['id'],
                port_model=plugged_in_port_id['port_model'],
                port_classification=plugged_in_port_id['port_classification'],
                port_role=plugged_in_port_id['port_role'])
            if is_update:
                session.merge(port_info_db)
            else:
                session.add(port_info_db)
            session.flush()
            nfd_interface_db.plugged_in_port_id = port_info_db['id']
            del interface['plugged_in_port_id']

    def create_network_function_device_interface(self, session,
                                                 nfd_interface):
        with session.begin(subtransactions=True):
            mapped_real_port_id = nfd_interface.get('mapped_real_port_id')
            nfd_interface_db = nfp_db_model.NetworkFunctionDeviceInterface(
                id=(nfd_interface.get('id') or uuidutils.generate_uuid()),
                tenant_id=nfd_interface['tenant_id'],
                interface_position=nfd_interface['interface_position'],
                mapped_real_port_id=mapped_real_port_id,
                network_function_device_id=(
                    nfd_interface['network_function_device_id']))
            self._set_plugged_in_port_for_nfd_interface(
                session, nfd_interface_db, nfd_interface)
            session.add(nfd_interface_db)

            return self._make_network_function_device_interface_dict(
                nfd_interface_db)

    def update_network_function_device_interface(self, session,
                                                 nfd_interface_id,
                                                 updated_nfd_interface):
        with session.begin(subtransactions=True):
            nfd_interface_db = self._get_network_function_device_interface(
                session, nfd_interface_id)
            self._set_plugged_in_port_for_nfd_interface(
                session, nfd_interface_db, updated_nfd_interface,
                is_update=True)
            nfd_interface_db.update(updated_nfd_interface)
            return self._make_network_function_device_interface_dict(
                nfd_interface_db)

    def delete_network_function_device_interface(
            self, session, network_function_device_interface_id):
        with session.begin(subtransactions=True):
            network_function_device_interface_db = (
                self._get_network_function_device_interface(
                    session, network_function_device_interface_id))
            if network_function_device_interface_db.plugged_in_port_id:
                self.delete_port_info(
                    session,
                    network_function_device_interface_db.plugged_in_port_id)
            session.delete(network_function_device_interface_db)

    def _get_network_function_device_interface(self, session,
                                       network_function_device_interface_id):
        try:
            return self._get_by_id(
                session,
                nfp_db_model.NetworkFunctionDeviceInterface,
                network_function_device_interface_id)
        except exc.NoResultFound:
            raise nfp_exc.NetworkFunctionDeviceInterfaceNotFound(
                network_function_device_interface_id=(
                    network_function_device_interface_id))

    def get_network_function_device_interface(
            self, session, network_function_device_interface_id,
            fields=None):
        network_function_device_interface = (
            self._get_network_function_device_interface(
                session, network_function_device_interface_id))
        return self._make_network_function_device_interface_dict(
            network_function_device_interface, fields)

    def get_network_function_device_interfaces(self, session, filters=None,
                                               fields=None, sorts=None,
                                               limit=None, marker=None,
                                               page_reverse=False):
        marker_obj = self._get_marker_obj(
            'network_function_device_interfaces', limit, marker)
        return self._get_collection(
            session,
            nfp_db_model.NetworkFunctionDeviceInterface,
            self._make_network_function_device_interface_dict,
            filters=filters, fields=fields,
            sorts=sorts, limit=limit,
            marker_obj=marker_obj,
            page_reverse=page_reverse)

    def _make_network_function_device_interface_dict(self, nfd_interface,
                                                     fields=None):
        res = {
            'id': nfd_interface['id'],
            'tenant_id': nfd_interface['tenant_id'],
            'plugged_in_port_id': nfd_interface['plugged_in_port_id'],
            'interface_position': nfd_interface['interface_position'],
            'mapped_real_port_id': nfd_interface['mapped_real_port_id'],
            'network_function_device_id': (
                   nfd_interface['network_function_device_id'])
        }
        return res

    def _make_port_info_dict(self, port_info, fields):
        res = {
            'id': port_info['id'],
            'port_classification': port_info['port_classification'],
            'port_model': port_info['port_model'],
            'port_role': port_info['port_role']
        }
        return res

    def _make_network_info_dict(self, network_info, fields):
        res = {
            'id': network_info['id'],
            'network_model': network_info['network_model'],
        }
        return res

    def _make_network_function_dict(self, network_function, fields=None):
        res = {'id': network_function['id'],
               'tenant_id': network_function['tenant_id'],
               'name': network_function['name'],
               'description': network_function['description'],
               'service_id': network_function['service_id'],
               'service_chain_id': network_function['service_chain_id'],
               'service_profile_id': network_function['service_profile_id'],
               'service_config': network_function['service_config'],
               'config_policy_id': network_function['config_policy_id'],
               'status': network_function['status']
               }
        res['network_function_instances'] = [
            nfi['id'] for nfi in network_function[
                'network_function_instances']]
        return res

    def _make_network_function_instance_dict(self, nfi, fields=None):
        res = {'id': nfi['id'],
               'tenant_id': nfi['tenant_id'],
               'name': nfi['name'],
               'description': nfi['description'],
               'ha_state': nfi['ha_state'],
               'network_function_id': nfi['network_function_id'],
               'network_function_device_id': nfi['network_function_device_id'],
               'status': nfi['status']
               }
        res['port_info'] = [
            port['data_port_id'] for port in nfi['port_info']]
        return res

    def _make_network_function_device_dict(self, nfd, fields=None):
        res = {'id': nfd['id'],
               'tenant_id': nfd['tenant_id'],
               'name': nfd['name'],
               'description': nfd['description'],
               'mgmt_ip_address': nfd['mgmt_ip_address'],
               'mgmt_port_id': nfd['mgmt_port_id'],
               'monitoring_port_id': nfd['monitoring_port_id'],
               'monitoring_port_network': nfd['monitoring_port_network'],
               'service_vendor': nfd['service_vendor'],
               'max_interfaces': nfd['max_interfaces'],
               'reference_count': nfd['reference_count'],
               'interfaces_in_use': nfd['interfaces_in_use'],
               'status': nfd['status']
               }
        if nfd.get('vendor_data'):
            res.update({'vendor_data': nfd['vendor_data']})
        return res

    def add_ha_info(self, session, ha_info):
        with session.begin(subtransactions=True):
            ha_info = nfp_db_model.HAInfo(
                id=ha_info['id'], tenant_id=ha_info['tenant_id'],
                network_function_device_id=ha_info[
                    'network_function_device_id'],
                vrrp_group=ha_info[
                        'vrrp_group'], vip_ip=ha_info['vip_ip'],
                multicast_ip=ha_info.get('multicast_ip', None),
                cluster_name=ha_info.get('cluster_name', None)
            )
            session.add(ha_info)
            return ha_info

    def insert_ha_records(self, session, ha_infos):
        with session.begin(subtransactions=True):
            for ha_info in ha_infos:
                ha_info = nfp_db_model.HAInfo(
                        id=ha_info['id'], tenant_id=ha_info['tenant_id'],
                        network_function_device_id=ha_info[
                            'network_function_device_id'],
                        vrrp_group=ha_info['vrrp_group'],
                        vip_ip=ha_info['vip_ip'],
                        multicast_ip=ha_info.get('multicast_ip', None),
                        cluster_name=ha_info.get('cluster_name', None))
                session.add(ha_info)

    def get_ha_info(self, session, _id):
        try:
            return self._get_by_id(
                    session,
                    nfp_db_model.HAInfo, _id)
        except exc.NoResultFound:
            raise nfp_exc.HAInfoNotFound(id=_id)

    def get_all_ha_info(self, session, filters=None, fields=None, sorts=None,
                        limit=None, marker=None, page_reverse=False):
        marker_obj = self._get_marker_obj(
                'nfp_ha_mapping_info', limit, marker)
        return self._get_collection(session,
                                    nfp_db_model.HAInfo,
                                    self._get_ha_info_dict,
                                    filters=filters, fields=fields,
                                    sorts=sorts, limit=limit,
                                    marker_obj=marker_obj,
                                    page_reverse=page_reverse)

    def del_ha_info(self, session, _id):
        with session.begin(subtransactions=True):
            ha_info = self.get_ha_info(session, _id)
            session.delete(ha_info)

    def delete_ha_info(self, session, port_id_list):
        for port_id in port_id_list:
            self.del_ha_info(session, port_id)

    def _get_ha_info_dict(self, ha_info, filters=None, fields=None, sorts=None,
                          limit=None, marker=None, page_reverse=False):
        return {
            'id': ha_info['id'], 'tenant_id': ha_info['tenant_id'],
            'network_function_device_id': ha_info[
                'network_function_device_id'],
            'vrrp_group': ha_info['vrrp_group'],
            'multicast_ip': ha_info['multicast_ip'],
            'cluster_name': ha_info['cluster_name']
        }
