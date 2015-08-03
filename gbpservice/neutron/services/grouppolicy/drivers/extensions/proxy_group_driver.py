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

from neutron.api.v2 import attributes
from neutron.openstack.common import log as logging

from gbpservice.neutron.db.grouppolicy.extensions import group_proxy_db as db
from gbpservice.neutron.db.grouppolicy import group_policy_db as gp_db
from gbpservice.neutron.extensions import driver_proxy_group
from gbpservice.neutron.services.grouppolicy import (
    group_policy_driver_api as api)

LOG = logging.getLogger(__name__)


class ProxyGroupDriver(api.ExtensionDriver):
    _supported_extension_alias = 'proxy_group'
    _extension_dict = driver_proxy_group.EXTENDED_ATTRIBUTES_2_0

    def initialize(self):
        pass

    @property
    def extension_alias(self):
        return self._supported_extension_alias

    @api.default_extension_behavior(db.GroupProxyMapping)
    def process_create_policy_target_group(self, session, data, result):
        data = data['policy_target_group']
        proxied = data.get('proxied_group_id')
        if attributes.is_attr_set(proxied):
            # Set value for proxied group
            record = (session.query(db.GroupProxyMapping).filter_by(
                policy_target_group_id=proxied).first())
            if record:
                if record.proxy_group_id:
                    raise driver_proxy_group.InvalidProxiedGroup(
                        group_id=proxied)
                record.proxy_group_id = result['id']
            else:
                # Record may not exist for that PTG yet
                record = db.GroupProxyMapping(
                    policy_target_group_id=proxied,
                    proxy_group_id=result['id'],
                    proxied_group_id=None)
                session.add(record)
            if not attributes.is_attr_set(data.get('proxy_type')):
                data['proxy_type'] = driver_proxy_group.DEFAULT_PROXY_TYPE
                record = (session.query(db.GroupProxyMapping).filter_by(
                    policy_target_group_id=result['id']).one())
                record.proxy_type = data['proxy_type']
                result['proxy_type'] = data['proxy_type']
        elif attributes.is_attr_set(data.get('proxy_type')):
            raise driver_proxy_group.ProxyTypeSetWithoutProxiedPTG()

    @api.default_extension_behavior(db.GroupProxyMapping)
    def process_update_policy_target_group(self, session, data, result):
        pass

    @api.default_extension_behavior(db.GroupProxyMapping)
    def extend_policy_target_group_dict(self, session, result):
        pass

    @api.default_extension_behavior(db.ProxyGatewayMapping)
    def process_create_policy_target(self, session, data, result):
        self._validate_proxy_gateway(session, data, result)

    @api.default_extension_behavior(db.ProxyGatewayMapping)
    def process_update_policy_target(self, session, data, result):
        self._validate_proxy_gateway(session, data, result)

    @api.default_extension_behavior(db.ProxyGatewayMapping)
    def extend_policy_target_dict(self, session, result):
        pass

    def _validate_proxy_gateway(self, session, data, result):
        data = data['policy_target']
        if data.get('proxy_gateway'):
            ptg_id = result['policy_target_group_id']
            record = session.query(db.GroupProxyMapping).filter_by(
                proxy_group_id=ptg_id).first()
            if not record:
                # The group of this PT is not a proxy
                raise driver_proxy_group.InvalidProxyGatewayGroup(
                    group_id=ptg_id)

    @api.default_extension_behavior(db.ProxyIPPoolMapping)
    def process_create_l3_policy(self, session, data, result):
        data = data['l3_policy']
        gp_db.GroupPolicyDbPlugin.validate_ip_pool(
            data['proxy_ip_pool'], data['ip_version'])
        gp_db.GroupPolicyDbPlugin.validate_subnet_prefix_length(
            data['ip_version'], data['proxy_subnet_prefix_length'],
            data['proxy_ip_pool'])

    @api.default_extension_behavior(db.ProxyIPPoolMapping)
    def process_update_l3_policy(self, session, data, result):
        data = data['l3_policy']
        if 'proxy_subnet_prefix_length' in data:
            gp_db.GroupPolicyDbPlugin.validate_subnet_prefix_length(
                result['ip_version'], data['proxy_subnet_prefix_length'],
                result['proxy_ip_pool'])

    @api.default_extension_behavior(db.ProxyIPPoolMapping)
    def extend_l3_policy_dict(self, session, result):
        pass
