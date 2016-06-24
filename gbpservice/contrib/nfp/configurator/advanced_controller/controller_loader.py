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

from gbpservice.contrib.nfp.configurator.advanced_controller import (
    controller as controller)

"""This class forwards HTTP request to controller class.

This class create an object of Controller class with appropriate
parameter according to the path of HTTP request. According to the
parameter passed to Controller class it sends an RPC call/cast to
configurator.

"""


class ControllerResolver(object):

    create_network_function_device_config = controller.Controller(
        "create_network_function_device_config")
    delete_network_function_device_config = controller.Controller(
        "delete_network_function_device_config")
    update_network_function_device_config = controller.Controller(
        "update_network_function_device_config")
    create_network_function_config = controller.Controller(
        "create_network_function_config")
    delete_network_function_config = controller.Controller(
        "delete_network_function_config")
    update_network_function_config = controller.Controller(
        "update_network_function_config")
    get_notifications = controller.Controller("get_notifications")
    network_function_event = controller.Controller("network_function_event")
    get_requests = controller.Controller("get_requests")

""" This class forwards HTTP requests starting with /v1/nfp.

All HTTP requests with path starting from /v1
land here. This class forward request with path starting from /v1/nfp
to ControllerResolver.

"""


class V1Controller(object):

    nfp = ControllerResolver()

    @pecan.expose()
    def get(self):
        return {'versions': [{'status': 'CURRENT',
                              'updated': '2014-12-11T00:00:00Z',
                              'id': 'v1'}]}
