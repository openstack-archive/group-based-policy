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

SERVICE_TYPE = 'generic_config'
EVENT_CONFIGURE_INTERFACES = 'CONFIGURE_INTERFACES'
EVENT_CLEAR_INTERFACES = 'CLEAR_INTERFACES'
EVENT_CONFIGURE_ROUTES = 'CONFIGURE_ROUTES'
EVENT_CLEAR_ROUTES = 'CLEAR_ROUTES'
EVENT_CONFIGURE_HEALTHMONITOR = 'CONFIGURE_HEALTHMONITOR'
EVENT_CLEAR_HEALTHMONITOR = 'CLEAR_HEALTHMONITOR'

# REVISIT: Need to make this configurable
MAX_FAIL_COUNT = 5
INITIAL = 'initial'
FOREVER = 'forever'

DEVICE_TO_BECOME_DOWN = 'DEVICE_TO_BECOME_DOWN'
DEVICE_TO_BECOME_UP = 'DEVICE_TO_BECOME_UP'
PERIODIC_HM = 'periodic_healthmonitor'

DEVICE_NOT_REACHABLE = 'PERIODIC_HM_DEVICE_NOT_REACHABLE'
DEVICE_REACHABLE = 'PERIODIC_HM_DEVICE_REACHABLE'

# POLLING EVENTS SPACING AND MAXRETRIES
EVENT_CONFIGURE_HEALTHMONITOR_SPACING = 10  # unit in sec.
EVENT_CONFIGURE_HEALTHMONITOR_MAXRETRY = 100
