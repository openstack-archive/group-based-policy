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
from gbpservice.neutron.extensions import driver_proxy_group

from neutron.api.v2 import attributes
from oslo_log import log as logging
from sqlalchemy import exc as db_exc

from gbpservice.neutron.db.grouppolicy.extensions import group_proxy_db as db
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
    def process_create_policy_target_group(self, session, data, result,
                                           error=None):
        if error:
            if isinstance(error.inner_exception, db_exc.IntegrityError):
                raise driver_proxy_group.ProxyGroupBadRequest(
                    msg=error.message)
            else:
                raise error
        data = data['policy_target_group']
        proxied = data.get('proxied_group_id')
        if attributes.is_attr_set(proxied):
            # Set value for proxied group
            record = (session.query(db.GroupProxyMapping).filter_by(
                policy_target_group_id=proxied).one())
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

    @api.default_extension_behavior(db.GroupProxyMapping)
    def process_update_policy_target_group(self, session, data, result,
                                           error=None):
        if error:
            raise error

    @api.default_extension_behavior(db.GroupProxyMapping)
    def extend_policy_target_group_dict(self, session, result, error=None):
        if error:
            raise error
