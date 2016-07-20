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

from gbpservice.nfp.pecan import constants


class RootController(object):
    """This is root controller that forward the request to __init__.py
    file inside controller folder inside v1

    """
    _controllers = {}

    for name, controller in constants.controllers.items():
        try:
            _controllers.update({name: __import__(controller,
                                                  globals(),
                                                  locals(),
                                                  ['controllers'], -1)})
        except Exception:
            pass

    if pecan.mode == constants.base:
        v1 = _controllers[constants.BASE_CONTROLLER].V1Controller()
    elif pecan.mode == constants.base_with_vm:
        v1 = _controllers[constants.REFERENCE_CONTROLLER].V1Controller()
    elif pecan.mode == constants.advanced:
        v1 = _controllers[constants.ADVANCED_CONTROLLER].V1Controller()

    @pecan.expose()
    def get(self):
        return {'versions': [{'status': 'CURRENT',
                              'updated': '2014-12-11T00:00:00Z',
                              'id': 'v1'}]}
