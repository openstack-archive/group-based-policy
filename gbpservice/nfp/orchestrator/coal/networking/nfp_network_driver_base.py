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


class NFPNetworkDriverBase(object):
    """ NFP Network Driver Base class

    Handles ports, operations on them
    """

    def __init__(self):
        pass

    def setup_traffic_steering(self):
        pass

    def create_port(self, token, admin_id, net_id, name=None):
        pass

    def delete_port(self, token, port_id):
        pass

    def get_port_id(self, token, port_id):
        pass

    def get_port_details(self, token, port_id):
        pass

    def set_promiscuos_mode(self, token, port_id, enable_port_security):
        pass
