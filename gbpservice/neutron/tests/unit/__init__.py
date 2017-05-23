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
from neutron.api import extensions
from neutron.quota import resource_registry


# The following is to avoid excessive logging in the UTs
extensions._LW = extensions._LI
extensions.LOG.warning = extensions.LOG.info
resource_registry._LW = resource_registry._LI
resource_registry.LOG.warning = resource_registry.LOG.info


from neutron._i18n import _LI
from neutron.neutron.scheduler import l3_agent_scheduler


l3_agent_scheduler._LW = l3_agent_scheduler._LI
l3_agent_scheduler.LOG.warning = l3_agent_scheduler.LOG.info
