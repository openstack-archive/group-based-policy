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
from neutron.agent import securitygroups_rpc
from neutron.api import extensions
from neutron.quota import resource
from neutron.quota import resource_registry
from neutron.scheduler import l3_agent_scheduler
from stevedore import named

from gbpservice.network.neutronv2 import local_api


# The following is to avoid excessive logging in the UTs
extensions.LOG.warning = extensions.LOG.info
resource_registry.LOG.warning = resource_registry.LOG.info
l3_agent_scheduler.LOG.warning = l3_agent_scheduler.LOG.info
securitygroups_rpc.LOG.warning = securitygroups_rpc.LOG.info
local_api.LOG.warning = local_api.LOG.info
named.LOG.warning = named.LOG.info


import sys
orig_warning = resource.LOG.warning


def warning(*args):
    try:
        for val in sys._getframe(1).f_locals.itervalues():
            if isinstance(val, resource.TrackedResource) and (
                sys._getframe(1).f_code.co_name == (
                    'unregister_events')):
                return
    except Exception:
        pass
    orig_warning(*args)


resource.LOG.warning = warning
