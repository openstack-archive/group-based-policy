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

import requests
import subprocess

from oslo_serialization import jsonutils

from gbpservice.contrib.nfp.configurator.lib import constants as const
from gbpservice.nfp.core import log as nfp_logging

LOG = nfp_logging.getLogger(__name__)


def set_class_attr(**kwargs):
    def f(class_obj):
        for key, value in kwargs.items():
            setattr(class_obj, key.lower(), value.lower())
        return class_obj
    return f


class BaseDriver(object):
    """ Implements common functions for drivers.

    Every service vendor must inherit this class. If any service vendor wants
    to add extra methods for their service, apart from below given, they should
    add method definition here and implement the method in their driver
    """

    def __init__(self, conf):
        pass

    def configure_healthmonitor(self, context, resource_data):
        """Checks if the Service VM is reachable.

           It does netcat to the CONFIGURATION_SERVER_PORT of the Service VM.
           Configuration agent runs inside Service VM. Once agent is up and
           reachable, Service VM is assumed to be active.

           :param context - context
           :param resource_data - data coming from orchestrator

           Returns: SUCCESS/FAILED

        """

        resource_data = self.parse.parse_data(const.HEALTHMONITOR,
                                              resource_data)
        ip = resource_data.get('mgmt_ip')
        port = str(self.port)
        command = 'nc ' + ip + ' ' + port + ' -z'
        return self._check_vm_health(command)

    def configure_interfaces(self, context, kwargs):
        return const.SUCCESS

    def clear_interfaces(self, context, kwargs):
        return const.SUCCESS

    def configure_routes(self, context, kwargs):
        return const.SUCCESS

    def clear_routes(self, context, kwargs):
        return const.SUCCESS

    def clear_healthmonitor(self, context, kwargs):
        return const.SUCCESS

    def register_agent_object_with_driver(self, name, agent_obj):
        setattr(BaseDriver, name, agent_obj)

    def _check_vm_health(self, command):
        """Ping based basic HM support provided by BaseDriver.
           Service provider can override the method implementation
           if they want to support other types.

           :param command - command to execute

           Returns: SUCCESS/FAILED
        """
        msg = ("Executing command %s for VM health check" % (command))
        LOG.debug(msg)
        try:
            subprocess.check_output(command, stderr=subprocess.STDOUT,
                                    shell=True)
        except Exception as e:
            msg = ("VM health check failed. Command '%s' execution failed."
                   " Reason=%s" % (command, e))
            LOG.debug(msg)
            return const.FAILED
        return const.SUCCESS

    def _configure_log_forwarding(self, url, mgmt_ip, port, headers=None):
        """ Configures log forwarding IP address in Service VMs.

            :param url: url format that is used to invoke the Service VM API
            :param mgmt_ip: management IP of the Service VM
            :param port: port that is listened to by the Service VM agent

            Returns: SUCCESS/Error msg

        """

        url = url % (mgmt_ip, port, 'configure-rsyslog-as-client')

        log_forward_ip_address = self.conf.configurator.log_forward_ip_address
        if not log_forward_ip_address:
            msg = ("Log forwarding IP address not configured "
                   "for service at %s." % mgmt_ip)
            LOG.info(msg)
            return const.UNHANDLED

        data = dict(
            server_ip=log_forward_ip_address,
            server_port=self.conf.configurator.log_forward_port,
            log_level=self.conf.configurator.log_level)
        data = jsonutils.dumps(data)

        msg = ("Initiating POST request to configure log forwarding "
               "for service at: %r" % mgmt_ip)
        LOG.info(msg)

        try:
            resp = requests.post(url, data=data,
                                 timeout=self.timeout, headers=headers)
        except requests.exceptions.ConnectionError as err:
            msg = ("Failed to establish connection to service at: "
                   "%r for configuring log forwarding. ERROR: %r" %
                   (mgmt_ip, str(err).capitalize()))
            LOG.error(msg)
            return msg
        except requests.exceptions.RequestException as err:
            msg = ("Unexpected ERROR happened while configuring "
                   "log forwarding for service at: %r. "
                   "ERROR: %r" %
                   (mgmt_ip, str(err).capitalize()))
            LOG.error(msg)
            return msg

        try:
            result = resp.json()
        except ValueError as err:
            msg = ("Unable to parse response of configure log forward API, "
                   "invalid JSON. URL: %r. %r" % (url, str(err).capitalize()))
            LOG.error(msg)
            return msg
        if not result['status']:
            msg = ("Error configuring log forwarding for service "
                   "at %s. URL: %r. Reason: %s." %
                   (mgmt_ip, url, result['reason']))
            LOG.error(msg)
            return msg

        msg = ("Successfully configured log forwarding for "
               "service at %s." % mgmt_ip)
        LOG.info(msg)
        return const.SUCCESS
