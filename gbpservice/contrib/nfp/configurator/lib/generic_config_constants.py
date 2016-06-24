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

DRIVERS_DIR = 'gbpservice.contrib.nfp.configurator.drivers'
SERVICE_TYPE = 'generic_config'
EVENT_CONFIGURE_INTERFACES = 'CONFIGURE_INTERFACES'
EVENT_CLEAR_INTERFACES = 'CLEAR_INTERFACES'
EVENT_CONFIGURE_ROUTES = 'CONFIGURE_ROUTES'
EVENT_CLEAR_ROUTES = 'CLEAR_ROUTES'
EVENT_CONFIGURE_HEALTHMONITOR = 'CONFIGURE_HEALTHMONITOR'
EVENT_CLEAR_HEALTHMONITOR = 'CLEAR_HEALTHMONITOR'

MAX_FAIL_COUNT = 12  # 5 secs delay * 12 = 60 secs
INITIAL = 'initial'
FOREVER = 'forever'
INITIAL_HM_RETRIES = 24  # 5 secs delay * 24 = 120 secs
