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
import requests
import subprocess
import time

from gbpservice.nfp.pecan import base_controller

LOG = logging.getLogger(__name__)
TOPIC = 'configurator'
NFP_SERVICE_LIST = ['heat', 'ansible']
SUCCESS_RESULTS = ['unhandled', 'success']
FAILURE = 'failure'


notifications = []
cache_ips = set()


class Controller(base_controller.BaseController):

    """Implements all the APIs Invoked by HTTP requests.

    Implements following HTTP methods.
        -get
        -post

    """
    def __init__(self, method_name):
        try:
            self.method_name = method_name
            super(Controller, self).__init__()
        except Exception as err:
            msg = (
                "Failed to initialize Controller class  %s." %
                str(err).capitalize())
            LOG.error(msg)
        self.vm_port = '8080'
        self.max_retries = 60

    def _push_notification(self, context, result, config_data, service_type):
        global notifications
        resource = config_data['resource']

        if result.lower() in SUCCESS_RESULTS:
            data = {'status_code': result}
        else:
            data = {'status_code': FAILURE,
                    'error_msg': result}

        response = {'info': {'service_type': service_type,
                             'context': context},
                    'notification': [{
                        'resource': resource,
                        'data': data}]
                    }

        notifications.append(response)

    def _verify_vm_reachability(self, vm_ip, vm_port):
        reachable = False
        command = 'nc ' + vm_ip + ' ' + vm_port + ' -z'
        for _ in range(self.max_retries):
            try:
                subprocess.check_output(command, stderr=subprocess.STDOUT,
                                        shell=True)
                reachable = True
                break
            except Exception:
                time.sleep(5)
        return reachable

    @pecan.expose(method='GET', content_type='application/json')
    def get(self):
        """Method of REST server to handle request get_notifications.

        This method send an RPC call to configurator and returns Notification
        data to config-agent

        Returns: Dictionary that contains Notification data

        """
        global cache_ips
        global notifications
        try:
            if not cache_ips:
                notification_data = jsonutils.dumps(notifications)
                msg = ("Notification sent. Notification Data: %s"
                       % notification_data)
                LOG.info(msg)
                notifications = []
                return notification_data
            else:
                for ip in cache_ips:
                    notification_response = requests.get(
                        'http://' + str(ip) + ':' + self.vm_port +
                        '/v1/nfp/get_notifications')
                    notification = jsonutils.loads(notification_response.text)
                    notifications.extend(notification)
                    cache_ips.remove(ip)
                    if ip not in cache_ips:
                        break
                notification_data = jsonutils.dumps(notifications)
                msg = ("Notification sent. Notification Data: %s"
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
            global cache_ips
            global notifications
            body = None
            if pecan.request.is_body_readable:
                body = pecan.request.json_body

            # Assuming config list will have only one element
            config_data = body['config'][0]
            info_data = body['info']

            context = info_data['context']
            service_type = info_data['service_type']
            resource = config_data['resource']

            if 'device_ip' in context:
                msg = ("POSTING DATA TO VM :: %s" % body)
                LOG.info(msg)
                device_ip = context['device_ip']
                ip = str(device_ip)
                is_vm_reachable = self._verify_vm_reachability(ip,
                                                               self.vm_port)
                if is_vm_reachable:
                    requests.post(
                        'http://' + ip + ':' + self.vm_port + '/v1/nfp/' +
                        self.method_name, data=jsonutils.dumps(body))
                else:
                    raise Exception('VM is not reachable')
                cache_ips.add(device_ip)
            else:
                if (resource in NFP_SERVICE_LIST):
                    result = "unhandled"
                    self._push_notification(context,
                                            result, config_data, service_type)
                else:
                    result = "Unsupported resource type"
                    self._push_notification(context,
                                            result, config_data, service_type)
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
