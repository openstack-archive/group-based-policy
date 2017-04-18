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
from neutron._i18n import _LW

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
        port_info = None
        marker_obj = self._get_marker_obj(
            'network_function_instances', limit, marker)
        if filters:
            port_info = filters.pop('port_info', None)
        nfis = self._get_collection(
            session, nfp_db_model.NetworkFunctionInstance,
            self._make_network_function_instance_dict,
            filters=filters, fields=fields, sorts=sorts, limit=limit,
            marker_obj=marker_obj, page_reverse=page_reverse)
        filtered_nfis = []
        if port_info:
            for nfi in nfis:
                if port_info == nfi['port_info']:
                    filtered_nfis.append(nfi)
            return filtered_nfis
        return nfis

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

    def _set_provider_metadata_for_nfd(self, session,
                                       network_function_device_db,
                                       network_function_device,
                                       is_update=False):
        nfd_db = network_function_device_db
        provider_metadata = nfd_db['provider_metadata']

        if is_update:
            if provider_metadata:
                provider_metadata = jsonutils.loads(provider_metadata)
            updated_provider_metadata_str = network_function_device.pop(
                'provider_metadata', {})
            if not updated_provider_metadata_str:
                return
            if updated_provider_metadata_str:
                updated_provider_metadata = jsonutils.loads(
                    updated_provider_metadata_str)
            if (type(updated_provider_metadata) is dict and
                    updated_provider_metadata and provider_metadata):
                updated_provider_metadata.update(provider_metadata)
            provider_metadata_str = jsonutils.dumps(updated_provider_metadata)
        else:
            if not provider_metadata:
                provider_metadata_str = ''
                return
            provider_metadata_str = jsonutils.dumps(provider_metadata)
        nfd_db.provider_metadata = provider_metadata_str

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
                status=network_function_device['status'],
                gateway_port=network_function_device.get('gateway_port'))
            session.add(network_function_device_db)
            self._set_mgmt_port_for_nfd(
                session, network_function_device_db, network_function_device)
            self._set_monitoring_port_id_for_nfd(
                session, network_function_device_db, network_function_device)
            self._set_monitoring_port_network_for_nfd(
                session, network_function_device_db, network_function_device)
            self._set_provider_metadata_for_nfd(
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
            if updated_network_function_device.get('provider_metadata'):
                updated_network_function_device[
                    'provider_metadata'] = jsonutils.dumps(
                    updated_network_function_device[
                        'provider_metadata'])
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
            self._set_provider_metadata_for_nfd(
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
                                                field_name,
                                                updated_value=1):
        with session.begin(subtransactions=True):
            network_function_device = self._get_network_function_device(
                session, network_function_device_id)
            value = network_function_device[field_name]
            value += updated_value
            update_device = (
                {field_name: value})
            self.update_network_function_device(session,
                                                network_function_device_id,
                                                update_device)

    def decrement_network_function_device_count(self, session,
                                                network_function_device_id,
                                                field_name,
                                                updated_value=1):
        with session.begin(subtransactions=True):
            network_function_device = self._get_network_function_device(
                session, network_function_device_id)
            value = network_function_device[field_name]
            value -= updated_value
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
               'status': nfd['status'],
               'gateway_port': nfd.get('gateway_port')
               }
        if nfd.get('provider_metadata'):
            res.update({'provider_metadata': nfd['provider_metadata']})
        return res

    def add_cluster_info(self, session, cluster_info):
        with session.begin(subtransactions=True):
            cluster_info = nfp_db_model.ClusterInfo(
                id=cluster_info['id'], tenant_id=cluster_info['tenant_id'],
                network_function_device_id=cluster_info[
                    'network_function_device_id'],
                cluster_group=cluster_info[
                    'cluster_group'], virtual_ip=cluster_info['virtual_ip'],
                multicast_ip=cluster_info.get('multicast_ip', None),
                cluster_name=cluster_info.get('cluster_name', None)
            )
            session.add(cluster_info)
            return cluster_info

    def insert_cluster_records(self, session, cluster_infos):
        with session.begin(subtransactions=True):
            for cluster_info in cluster_infos:
                cluster_info = nfp_db_model.ClusterInfo(
                    id=cluster_info['id'],
                    tenant_id=cluster_info['tenant_id'],
                    network_function_device_id=cluster_info[
                        'network_function_device_id'],
                    cluster_group=cluster_info['cluster_group'],
                    virtual_ip=cluster_info['virtual_ip'],
                    multicast_ip=cluster_info.get('multicast_ip', None),
                    cluster_name=cluster_info.get('cluster_name', None))
                session.add(cluster_info)

    def get_cluster_info(self, session, _id):
        try:
            return self._get_by_id(
                session,
                nfp_db_model.ClusterInfo, _id)
        except exc.NoResultFound:
            raise nfp_exc.ClusterInfoNotFound(id=_id)

    def get_all_cluster_info(self, session, filters=None, fields=None,
                             sorts=None, limit=None, marker=None,
                             page_reverse=False):
        marker_obj = self._get_marker_obj(
            'nfd_cluster_mapping_info', limit, marker)
        return self._get_collection(session,
                                    nfp_db_model.ClusterInfo,
                                    self._get_cluster_info_dict,
                                    filters=filters, fields=fields,
                                    sorts=sorts, limit=limit,
                                    marker_obj=marker_obj,
                                    page_reverse=page_reverse)

    def del_cluster_info(self, session, _id):
        with session.begin(subtransactions=True):
            cluster_info = self.get_cluster_info(session, _id)
            session.delete(cluster_info)

    def delete_cluster_info(self, session, port_id_list):
        for port_id in port_id_list:
            self.del_cluster_info(session, port_id)

    def _get_cluster_info_dict(self, cluster_info, filters=None, fields=None,
                               sorts=None, limit=None, marker=None,
                               page_reverse=False):
        return {
            'id': cluster_info['id'], 'tenant_id': cluster_info['tenant_id'],
            'network_function_device_id': cluster_info[
                'network_function_device_id'],
            'cluster_group': cluster_info['cluster_group'],
            'multicast_ip': cluster_info['multicast_ip'],
            'cluster_name': cluster_info['cluster_name']
        }

    def add_service_gateway_details(self, session, service_gw_details):
        primary_gw_vip_pt, secondary_gw_vip_pt = self._get_vip_pt_ids(
            service_gw_details.get('gateway_vips'))
        if isinstance(service_gw_details['primary_instance_gw_pt'], dict):
            primary_instance_gw_pt = service_gw_details[
                'primary_instance_gw_pt']['id']
            secondary_instance_gw_pt = service_gw_details.get(
                'secondary_instance_gw_pt', {}).get('id')
        else:
            primary_instance_gw_pt = service_gw_details[
                'primary_instance_gw_pt']
            secondary_instance_gw_pt = service_gw_details.get(
                'secondary_instance_gw_pt')
        with session.begin(subtransactions=True):
            gw_detail = nfp_db_model.ServiceGatewayDetails(
                id=service_gw_details['id'],
                network_function_id=service_gw_details[
                    'network_function_id'],
                gateway_ptg=service_gw_details['gw_ptg'],
                primary_instance_gw_pt=primary_instance_gw_pt,
                secondary_instance_gw_pt=secondary_instance_gw_pt,
                primary_gw_vip_pt=primary_gw_vip_pt,
                secondary_gw_vip_pt=secondary_gw_vip_pt
            )
            session.add(gw_detail)
            return gw_detail

    def _get_vip_pt_ids(self, vips):
        if not vips:
            return None, None
        else:
            if isinstance(vips, list):
                primary_gw_vip_pt = vips[0]['id']
                secondary_gw_vip_pt = vips[1]['id'] if len(vips) == 2 else None
                return primary_gw_vip_pt, secondary_gw_vip_pt
            elif isinstance(vips, dict):
                return vips['primary_gw_vip_pt'], vips['secondary_gw_vip_pt']
            else:
                return None, None

    def get_providers_for_gateway(self, session, _id):
        svc_gw = nfp_db_model.ServiceGatewayDetails
        try:
            with session.begin(subtransactions=True):
                return self._get_gw_info_dict(session.query(svc_gw).filter(
                    svc_gw.gateway_ptg == _id).all())
        except exc.NoResultFound:
            raise

    def get_gateway_detail(self, session, nf_id):
        svc_gw = nfp_db_model.ServiceGatewayDetails
        try:
            with session.begin(subtransactions=True):
                return self._get_gw_info_dict(session.query(svc_gw).filter(
                    svc_gw.network_function_id == nf_id).one())
        except exc.NoResultFound:
            LOG.warning(_LW("Gateway detail doesn't exist for Network Function"
                            " %s ") % nf_id)
            raise

    def _get_gw_info_dict(self, gw):
        if not gw:
            return
        if isinstance(gw, list):
            return [dict(id=info['id'],
                         network_function_id=info['network_function_id'],
                         gateway_ptg=info['gateway_ptg'],
                         primary_instance_gw_pt=info['primary_instance_gw_pt'],
                         secondary_instance_gw_pt=info[
                             'secondary_instance_gw_pt'],
                         primary_gw_vip_pt=info['primary_gw_vip_pt'],
                         secondary_gw_vip_pt=info['secondary_gw_vip_pt']
                         ) for info in gw]

        return {'id': gw['id'],
                'network_function_id': gw['network_function_id'],
                'gateway_ptg': gw['gateway_ptg'],
                'primary_instance_gw_pt': gw['primary_instance_gw_pt'],
                'secondary_instance_gw_pt': gw['secondary_instance_gw_pt'],
                'primary_gw_vip_pt': gw['primary_gw_vip_pt'],
                'secondary_gw_vip_pt': gw['secondary_gw_vip_pt']}
