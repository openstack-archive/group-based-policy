# Copyright (c) 2013 OpenStack Foundation.
# All Rights Reserved.
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

from gbpservice.contrib.nfp.config_orchestrator.common import topics
from gbpservice.contrib.nfp.configurator.drivers.loadbalancer.v1.haproxy\
    import haproxy_lb_driver
from neutron.api.v2 import attributes
from neutron.plugins.common import constants
from neutron_lbaas.db.loadbalancer import loadbalancer_db as lb_db
from neutron_lbaas.extensions import loadbalancer
from neutron_lbaas.services.loadbalancer.drivers.common import (
    agent_driver_base as adb
)
from neutron_lib import constants as n_constants
from neutron_lib import exceptions as n_exc
from oslo_db import exception
from oslo_utils import excutils
from oslo_utils import uuidutils


class HaproxyOnVMPluginDriver(adb.AgentDriverBase):
    device_driver = haproxy_lb_driver.DRIVER_NAME

    def __init__(self, plugin):
        # Monkey patch LB agent topic and LB agent type
        adb.l_const.LOADBALANCER_AGENT = topics.LB_NFP_CONFIGAGENT_TOPIC
        adb.q_const.AGENT_TYPE_LOADBALANCER = 'NFP Loadbalancer agent'

        super(HaproxyOnVMPluginDriver, self).__init__(plugin)


def _nfp_create_port_for_vip(self, context, vip_db, subnet_id, ip_address):
        # resolve subnet and create port
        subnet = self._core_plugin.get_subnet(context, subnet_id)
        fixed_ip = {'subnet_id': subnet['id']}
        if ip_address and ip_address != attributes.ATTR_NOT_SPECIFIED:
            fixed_ip['ip_address'] = ip_address
            if subnet.get('gateway_ip') == ip_address:
                raise n_exc.IpAddressInUse(net_id=subnet['network_id'],
                                           ip_address=ip_address)

        port_data = {
            'tenant_id': vip_db.tenant_id,
            'name': 'vip-' + vip_db.id,
            'network_id': subnet['network_id'],
            'mac_address': attributes.ATTR_NOT_SPECIFIED,
            'admin_state_up': False,
            'device_id': '',
            'device_owner': n_constants.DEVICE_OWNER_LOADBALANCER,
            'fixed_ips': [fixed_ip]
        }

        port = self._core_plugin.create_port(context, {'port': port_data})
        vip_db.port_id = port['id']
        with context.session.begin(subtransactions=True):
                vip = self._get_resource(context, lb_db.Vip, vip_db.id)
                vip.update({'port_id': port['id']})
                context.session.flush()

        # explicitly sync session with db
        # context.session.flush()
        vip_db = self._get_resource(context, lb_db.Vip, vip_db.id)

lb_db.LoadBalancerPluginDb._create_port_for_vip = _nfp_create_port_for_vip


def nfp_create_vip(self, context, vip):
    v = vip['vip']
    tenant_id = v['tenant_id']

    with context.session.begin(subtransactions=True):
        if v['pool_id']:
            pool = self._get_resource(context, lb_db.Pool, v['pool_id'])
            # validate that the pool has same tenant
            if pool['tenant_id'] != tenant_id:
                raise n_exc.NotAuthorized()
            # validate that the pool has same protocol
            if pool['protocol'] != v['protocol']:
                raise loadbalancer.ProtocolMismatch(
                    vip_proto=v['protocol'],
                    pool_proto=pool['protocol'])
            if pool['status'] == constants.PENDING_DELETE:
                raise loadbalancer.StateInvalid(state=pool['status'],
                                                id=pool['id'])
        vip_db = lb_db.Vip(id=uuidutils.generate_uuid(),
                           tenant_id=tenant_id,
                           name=v['name'],
                           description=v['description'],
                           port_id=None,
                           protocol_port=v['protocol_port'],
                           protocol=v['protocol'],
                           pool_id=v['pool_id'],
                           connection_limit=v['connection_limit'],
                           admin_state_up=v['admin_state_up'],
                           status=constants.PENDING_CREATE)

        session_info = v['session_persistence']

        if session_info:
            s_p = self._create_session_persistence_db(
                session_info,
                vip_db['id'])
            vip_db.session_persistence = s_p

        try:
            context.session.add(vip_db)
            context.session.flush()
        except exception.DBDuplicateEntry:
            raise loadbalancer.VipExists(pool_id=v['pool_id'])

    try:
        # create a port to reserve address for IPAM
        # do it outside the transaction to avoid rpc calls
        self._create_port_for_vip(
            context, vip_db, v['subnet_id'], v.get('address'))
    except Exception:
        # catch any kind of exceptions
        with excutils.save_and_reraise_exception():
            context.session.delete(vip_db)
            context.session.flush()

    if v['pool_id']:
        # fetching pool again
        pool = self._get_resource(context, lb_db.Pool, v['pool_id'])
        # (NOTE): we rely on the fact that pool didn't change between
        # above block and here
        vip_db['pool_id'] = v['pool_id']
        pool['vip_id'] = vip_db['id']

    vip_db = self._get_resource(context, lb_db.Vip, vip_db['id'])
    return self._make_vip_dict(vip_db)

lb_db.LoadBalancerPluginDb.create_vip = nfp_create_vip
