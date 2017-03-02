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

import pecan

from gbpservice.nfp.pecan.constants import controller_mode_map
from gbpservice.nfp.pecan.constants import controllers


class RootController(object):
    """This is root controller that forward the request to __init__.py
    file inside controller folder inside v1

    """

    controller = __import__(controllers[controller_mode_map[pecan.mode]],
                            globals(), locals(), ['controllers'], -1)
    v1 = controller.V1Controller()

    @pecan.expose()
    def get(self):
        return {'versions': [{'status': 'CURRENT',
                              'updated': '2014-12-11T00:00:00Z',
                              'id': 'v1'}]}
