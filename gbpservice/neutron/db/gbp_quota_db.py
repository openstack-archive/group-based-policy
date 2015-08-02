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

from neutron.common import exceptions as nexcp
from neutron import context
from neutron.db import common_db_mixin
from neutron.db import quota_db
from neutron import quota


QUOTA_DRIVER = quota_db.DbQuotaDriver

DB_CLASS_TO_RESOURCE_NAMES = {}


class GBPQuotaBase(common_db_mixin.CommonDbMixin):

    def __init__(self, *args, **kwargs):
        super(GBPQuotaBase, self).__init__(*args, **kwargs)

        tenant_id = kwargs['tenant_id']
        ctx = context.Context(user_id=None, tenant_id=tenant_id)
        class_name = self.__class__.__name__
        resource = DB_CLASS_TO_RESOURCE_NAMES[class_name]
        d = {resource: quota.CountableResource(resource, None,
                                               "quota_" + resource)}
        resource_quota = QUOTA_DRIVER.get_tenant_quotas(ctx, d,
                                                        tenant_id)[resource]
        if resource_quota == -1:
            return
        count = self._get_collection_count(ctx, self.__class__)
        if count >= resource_quota:
            raise nexcp.OverQuota(overs=[resource])
