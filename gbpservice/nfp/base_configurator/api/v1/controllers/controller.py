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

import oslo_serialization.jsonutils as jsonutils

from oslo_log import log as logging
import pecan
from pecan import rest

LOG = logging.getLogger(__name__)
TOPIC = 'configurator'

"""Implements all the APIs Invoked by HTTP requests.

Implements following HTTP methods.
    -get
    -post

"""

notifications = []


class Controller(rest.RestController):

    def __init__(self, method_name):
        try:
            self.method_name = method_name
            super(Controller, self).__init__()
        except Exception as err:
            msg = (
                "Failed to initialize Controller class  %s." %
                str(err).capitalize())
            LOG.error(msg)

    def _push_notification(self, context, request_info, result):
        response = {
            'receiver': 'service_orchestrator',
            'resource': 'heat',
            'method': 'network_function_device_notification',
            'kwargs': [
                {
                    'context': context,
                    'resource': 'heat',
                    'request_info': request_info,
                    'result': result
                }
            ]
        }

        notifications.append(response)

    @pecan.expose(method='GET', content_type='application/json')
    def get(self):
        """Method of REST server to handle request get_notifications.

        This method send an RPC call to configurator and returns Notification
        data to config-agent

        Returns: Dictionary that contains Notification data

        """

        global notifications
        try:
            notification_data = jsonutils.dumps(notifications)
            msg = ("NOTIFICATION_DATA sent to config_agent %s"
                   % notification_data)
            LOG.info(msg)
            notifications = []
            return notification_data
        except Exception as err:
            pecan.response.status = 400
            msg = ("Failed to get notification_data  %s."
                % str(err).capitalize())
            LOG.error(msg)
            error_data = self._format_description(msg)
            return jsonutils.dumps(error_data)

    @pecan.expose(method='POST', content_type='application/json')
    def post(self, **body):
        """Method of REST server to handle all the post requests.

        This method sends an RPC cast to configurator according to the
        HTTP request.

        :param body: This method excepts dictionary as a parameter in HTTP
        request and send this dictionary to configurator with RPC cast.

        Returns: None

        """

        try:
            body = None
            if pecan.request.is_body_readable:
                body = pecan.request.json_body

            service_type = body['info'].get('service_type')

            # Assuming config list will have only one element
            config_data = body['config'][0]
            context = config_data['kwargs']['context']
            request_info = config_data['kwargs']['request_info']

            # Only heat is supported presently
            if (service_type == "heat"):
                result = "unhandled"
                self._push_notification(context, request_info, result)
            else:
                result = "error"
                self._push_notification(context, request_info, result)
        except Exception as err:
            pecan.response.status = 400
            msg = ("Failed to serve HTTP post request %s %s."
                   % (self.method_name, str(err).capitalize()))
            LOG.error(msg)
            error_data = self._format_description(msg)
            return jsonutils.dumps(error_data)

    def _format_description(self, msg):
        """This methgod formats error description.

        :param msg: An error message that is to be formatted

        Returns: error_data dictionary
        """

        error_data = {'failure_desc': {'msg': msg}}
        return error_data
