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


class FakeObjects(object):
    """ Implements fake objects for assertion.

    """

    sc = 'sc'
    conf = 'conf'
    context = 'APIcontext'
    kwargs = {'vmid': 'vmid'}
    rpcmgr = 'rpcmgr'
    drivers = 'drivers'


class FakeEventNfpService(object):
    """ Implements a fake event class for generic config for
        process framework to use

    """

    def __init__(self):
        self.data = {
                    'context': {
                            'resource': 'heat',
                            'notification_data': {},
                            'resource_type': 'firewall',
                            'service_vendor': 'vyos',
                            'context': 'APIcontext'},
                    'resource_data': 'some data'}
        self.id = 'dummy'
