# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
from heatclient import client as heat_client
from heatclient import exc as heat_exc
from neutron._i18n import _LW

from gbpservice.nfp.core import log as nfp_logging
LOG = nfp_logging.getLogger(__name__)

# We are overriding create and update for now because the upstream
# heat client class does not take timeout as argument


class HeatClient(object):

    def __init__(self, user_name, tenant, heat_uri, password=None,
                 auth_token=None, timeout_mins=30):
        api_version = "1"
        endpoint = "%s/%s" % (heat_uri, tenant)
        kwargs = {
            'token': auth_token,
            'username': user_name,
            'password': password
        }
        self.client = heat_client.Client(api_version, endpoint, **kwargs)
        self.stacks = self.client.stacks

        self.timeout_mins = timeout_mins
        # REVISIT(ashu): The base class is a old style class. We have to
        # change when it is updated
        # gbp_heat_api_client.HeatClient.__init__(
        #    self, context, heat_uri, password, auth_token)

    def create(self, name, data, parameters=None):
        fields = {
            'stack_name': name,
            'timeout_mins': self.timeout_mins,
            'disable_rollback': True,
            'password': data.get('password')
        }
        fields['template'] = data
        fields['parameters'] = parameters
        return self.stacks.create(**fields)

    def update(self, stack_id, data, parameters=None):
        fields = {
            'timeout_mins': self.timeout_mins,
            'password': data.get('password')
        }
        fields['template'] = data
        fields['parameters'] = parameters
        return self.stacks.update(stack_id, **fields)

    def delete(self, stack_id):
        try:
            self.stacks.delete(stack_id)
        except heat_exc.HTTPNotFound:
            LOG.warning(_LW("Stack %(stack)s created by service chain driver "
                            "is not found at cleanup"), {'stack': stack_id})

    def get(self, stack_id):
        return self.stacks.get(stack_id)
