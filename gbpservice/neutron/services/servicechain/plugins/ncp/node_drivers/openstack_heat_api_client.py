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

from heatclient import client as heat_client
from heatclient import exc as heat_exc
from oslo_log import log as logging

from gbpservice._i18n import _LW

LOG = logging.getLogger(__name__)


class HeatClient(object):

    def __init__(self, context, heat_uri, password=None,
                 auth_token=None):
        api_version = "1"
        endpoint = "%s/%s" % (heat_uri, context.tenant)
        kwargs = {
            'token': auth_token or context.auth_token,
            'username': context.user_name,
            'password': password
        }
        self.client = heat_client.Client(api_version, endpoint, **kwargs)
        self.stacks = self.client.stacks

    def create(self, name, data, parameters=None):
        fields = {
            'stack_name': name,
            'timeout_mins': 30,
            'disable_rollback': True,
            'password': data.get('password')
        }
        fields['template'] = data
        fields['parameters'] = parameters
        return self.stacks.create(**fields)

    def update(self, stack_id, data, parameters=None):
        fields = {
            'password': data.get('password')
        }
        fields['template'] = data
        fields['parameters'] = parameters
        return self.stacks.update(stack_id, **fields)

    def delete(self, stack_id):
        try:
            self.stacks.delete(stack_id)
        except heat_exc.HTTPNotFound:
            LOG.warning(_LW(
                "Stack %(stack)s created by service chain driver is "
                "not found at cleanup"), {'stack': stack_id})

    def get(self, stack_id):
        return self.stacks.get(stack_id)
