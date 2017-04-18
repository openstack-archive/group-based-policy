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
import time


from oslo_serialization import jsonutils

from gbpservice.contrib.nfp.configurator.drivers.base import base_driver
from gbpservice.contrib.nfp.configurator.drivers.firewall.vyos import (
    vyos_fw_constants as const)
from gbpservice.contrib.nfp.configurator.lib import (
    generic_config_constants as gen_cfg_const)
from gbpservice.contrib.nfp.configurator.lib import constants as common_const
from gbpservice.contrib.nfp.configurator.lib import data_parser
from gbpservice.contrib.nfp.configurator.lib import fw_constants as fw_const
from gbpservice.nfp.core import log as nfp_logging
from neutron._i18n import _LI

LOG = nfp_logging.getLogger(__name__)


class RestApi(object):
    """ Issues REST calls to the Service VMs

    REST API wrapper class that provides POST method to
    communicate with the Service VM.

    """

    def __init__(self, timeout):
        self.timeout = timeout

    def request_type_to_api_map(self, url, data, request_type, headers):
        return getattr(requests, request_type)(url,
                                               data=data, timeout=self.timeout,
                                               headers=headers)

    def fire(self, url, data, request_type, headers):
        """ Invokes REST POST call to the Service VM.

        :param url: URL to connect.
        :param data: data to be sent.
        :param request_type: POST/PUT/DELETE

        Returns: SUCCESS/Error message

        """

        try:
            msg = ("SENDING CURL request to URL: %s, request_type:%s, "
                   "vm with data %s"
                   % (url, request_type, data))
            LOG.debug(msg)
            resp = self.request_type_to_api_map(url, data,
                                                request_type.lower(), headers)
        except requests.exceptions.ConnectionError as err:
            msg = ("Failed to establish connection to the service at URL: %r. "
                   "ERROR: %r" % (url, str(err).capitalize()))
            return msg
        except Exception as err:
            msg = ("Failed to issue %r call "
                   "to service. URL: %r, Data: %r. Error: %r" %
                   (request_type.upper(), url, data, str(err).capitalize()))
            return msg

        try:
            result = resp.json()
        except ValueError as err:
            msg = ("Unable to parse response, invalid JSON. URL: "
                   "%r. %r" % (url, str(err).capitalize()))
            return msg
        if resp.status_code not in common_const.SUCCESS_CODES or (
                result.get('status') is False):
            return result
        return common_const.STATUS_SUCCESS


class FwGenericConfigDriver(base_driver.BaseDriver):
    """ Implements device configuration requests.

    Firewall generic configuration driver for handling device
    configuration requests from Orchestrator.
    """

    def __init__(self):
        self.parse = data_parser.DataParser()

    def _parse_vm_context(self, context):
        try:
            username = str(context['service_vm_context'][
                           'vyos']['username'])
            password = str(context['service_vm_context'][
                           'vyos']['password'])
            headers = {'Content-Type': 'application/json',
                       'username': username,
                       'password': password}
            return headers
        except Exception as e:
            msg = ("Failed to get header from context. ERROR: %s" % e)
            LOG.error(msg)
            raise Exception(msg)

    def configure_healthmonitor(self, context, resource_data):
        vm_status = super(FwGenericConfigDriver, self).configure_healthmonitor(
                              context, resource_data)
        if resource_data['nfds'][0]['periodicity'] == gen_cfg_const.INITIAL:
            if vm_status == common_const.SUCCESS:
                try:
                    resp = self.configure_user(context, resource_data)
                    if resp != common_const.STATUS_SUCCESS:
                        return common_const.FAILURE
                except Exception as e:
                    msg = ("Failed to configure user. ERROR: %s" % e)
                    LOG.error(msg)
                    return common_const.FAILURE
            return vm_status

    def configure_user(self, context, resource_data):
        headers = self._parse_vm_context(context)
        resource_data = self.parse.parse_data(common_const.HEALTHMONITOR,
                                              resource_data)
        mgmt_ip = resource_data['mgmt_ip']
        url = const.request_url % (mgmt_ip,
                                   self.port,
                                   'change_auth')
        data = {}
        LOG.info(_LI("Initiating POST request to configure Authentication "
                     "service at mgmt ip:%(mgmt_ip)s"),
                 {'mgmt_ip': mgmt_ip})
        err_msg = ("Change Auth POST request to the VyOS firewall "
                   "service at %s failed. " % url)
        try:
            resp = self.rest_api.fire(url, data, common_const.POST, headers)
        except Exception as err:
            err_msg += ("Reason: %r" % str(err).capitalize())
            LOG.error(err_msg)
            return err_msg

        if resp is common_const.STATUS_SUCCESS:
            msg = ("Configured user authentication successfully"
                   " for vyos service at %r." % mgmt_ip)
            LOG.info(msg)
            return resp

        err_msg += (("Failed to change Authentication para Status code "
                     "Status code: %r, Reason: %r" %
                     (resp['status'], resp['reason']))
                    if type(resp) is dict
                    else ("Reason: " + resp))
        LOG.error(err_msg)
        return err_msg

    def _configure_static_ips(self, context, resource_data):
        """ Configure static IPs for provider and stitching interfaces
        of service VM.

        Issues REST call to service VM for configuration of static IPs.

        :param resource_data: a dictionary of firewall rules and objects
        send by neutron plugin

        Returns: SUCCESS/Failure message with reason.

        """
        headers = self._parse_vm_context(context)
        static_ips_info = dict(
            provider_ip=resource_data.get('provider_ip'),
            provider_cidr=resource_data.get('provider_cidr'),
            provider_mac=resource_data.get('provider_mac'),
            stitching_ip=resource_data.get('stitching_ip'),
            stitching_cidr=resource_data.get('stitching_cidr'),
            stitching_mac=resource_data.get('stitching_mac'))
        mgmt_ip = resource_data['mgmt_ip']

        url = const.request_url % (mgmt_ip,
                                   self.port,
                                   'add_static_ip')
        data = jsonutils.dumps(static_ips_info)

        LOG.info(_LI("Initiating POST request to add static IPs for primary "
                     "service at mgmt ip:%(mgmt_ip)s"),
                 {'mgmt_ip': mgmt_ip})
        err_msg = ("Static IP POST request to the VyOS firewall "
                   "service at %s failed. " % url)
        try:
            resp = self.rest_api.fire(url, data, common_const.POST, headers)
        except Exception as err:
            err_msg += ("Reason: %r" % str(err).capitalize())
            LOG.error(err_msg)
            return err_msg

        if resp is common_const.STATUS_SUCCESS:
            msg = ("Static IPs successfully added for service at %r." % url)
            LOG.info(msg)
            return resp

        err_msg += (("Status code: %r, Reason: %r" %
                     (resp['status'], resp['reason']))
                    if type(resp) is dict
                    else ("Reason: " + resp))
        LOG.error(err_msg)
        return err_msg

    def configure_interfaces(self, context, resource_data):
        """ Configure interfaces for the service VM.

        Calls static IP configuration function and implements
        persistent rule addition in the service VM.
        Issues REST call to service VM for configuration of interfaces.

        :param context: neutron context
        :param resource_data: a dictionary of firewall rules and objects
        send by neutron plugin

        Returns: SUCCESS/Failure message with reason.

        """
        headers = self._parse_vm_context(context)
        resource_data = self.parse.parse_data(common_const.INTERFACES,
                                              resource_data)
        mgmt_ip = resource_data['mgmt_ip']

        try:
            result_log_forward = self._configure_log_forwarding(
                const.request_url, mgmt_ip, self.port, headers)
        except Exception as err:
            msg = ("Failed to configure log forwarding for service at %s. "
                   "Error: %s" % (mgmt_ip, err))
            LOG.error(msg)
        else:
            if result_log_forward == common_const.UNHANDLED:
                pass
            elif result_log_forward != common_const.STATUS_SUCCESS:
                # Failure in log forward configuration won't break chain
                # creation. However, error will be logged for detecting
                # failure.
                msg = ("Failed to configure log forwarding for service at %s."
                       " Error: %s" % (mgmt_ip, result_log_forward))
                LOG.error(msg)

        try:
            result_static_ips = self._configure_static_ips(context,
                                                           resource_data)
        except Exception as err:
            msg = ("Failed to add static IPs. Error: %s" % err)
            LOG.error(msg)
            return msg
        else:
            if result_static_ips != common_const.STATUS_SUCCESS:
                return result_static_ips

        rule_info = dict(
            provider_mac=resource_data['provider_mac'],
            stitching_mac=resource_data['stitching_mac'])

        url = const.request_url % (mgmt_ip,
                                   self.port, 'add_rule')
        data = jsonutils.dumps(rule_info)
        LOG.info(_LI("Initiating POST request to add persistent rule to "
                     "primary service at mgmt ip: %(mgmt_ip)s"),
                 {'mgmt_ip': mgmt_ip})
        err_msg = ("Add persistent rule POST request to the VyOS firewall "
                   "service at %s failed. " % url)
        try:
            resp = self.rest_api.fire(url, data, common_const.POST, headers)
        except Exception as err:
            err_msg += ("Reason: %r" % str(err).capitalize())
            LOG.error(err_msg)
            return err_msg

        if resp is common_const.STATUS_SUCCESS:
            msg = ("Persistent rule successfully added for "
                   "service at %r." % url)
            LOG.info(msg)

            # wait for 10secs for the ip address to get configured. Sometimes
            # observed that 'set_routes' fail with 'ip not configured' error.
            time.sleep(10)
            return resp

        err_msg += (("Status code: %r" % resp['status'])
                    if type(resp) is dict
                    else ("Reason: " + resp))
        LOG.error(err_msg)
        return err_msg

    def _clear_static_ips(self, context, resource_data):
        """ Clear static IPs for provider and stitching
        interfaces of the service VM.

        Issues REST call to service VM for deletion of static IPs.

        :param resource_data: a dictionary of firewall rules and objects
        send by neutron plugin

        Returns: SUCCESS/Failure message with reason.

        """
        headers = self._parse_vm_context(context)
        static_ips_info = dict(
            provider_ip=resource_data.get('provider_ip'),
            provider_cidr=resource_data.get('provider_cidr'),
            provider_mac=resource_data.get('provider_mac'),
            stitching_ip=resource_data.get('stitching_ip'),
            stitching_cidr=resource_data.get('stitching_cidr'),
            stitching_mac=resource_data.get('stitching_mac'))
        mgmt_ip = resource_data['mgmt_ip']

        url = const.request_url % (mgmt_ip,
                                   self.port,
                                   'del_static_ip')
        data = jsonutils.dumps(static_ips_info)

        LOG.info(_LI("Initiating POST request to remove static IPs for "
                     "primary service at mgmt ip: %(mgmt_ip)s"),
                 {'mgmt_ip': mgmt_ip})

        err_msg = ("Static IP DELETE request to the VyOS firewall "
                   "service at %s failed. " % url)
        try:
            resp = self.rest_api.fire(url, data, common_const.DELETE, headers)
        except Exception as err:
            err_msg += ("Reason: %r" % str(err).capitalize())
            LOG.error(err_msg)
            return err_msg

        if resp is common_const.STATUS_SUCCESS:
            msg = ("Static IPs successfully removed for service at %r." % url)
            LOG.info(msg)
            return resp

        err_msg += (("Status code: %r, Reason: %r" %
                     (resp['status'], resp['reason']))
                    if type(resp) is dict
                    else ("Reason: " + resp))
        LOG.error(err_msg)
        return err_msg

    def clear_interfaces(self, context, resource_data):
        """ Clear interfaces for the service VM.

        Calls static IP clear function and implements
        persistent rule deletion in the service VM.
        Issues REST call to service VM for deletion of interfaces.

        :param context: neutron context
        :param resource_data: a dictionary of firewall rules and objects
        send by neutron plugin

        Returns: SUCCESS/Failure message with reason.

        """
        headers = self._parse_vm_context(context)
        resource_data = self.parse.parse_data(common_const.INTERFACES,
                                              resource_data)
        try:
            result_static_ips = self._clear_static_ips(context, resource_data)
        except Exception as err:
            msg = ("Failed to remove static IPs. Error: %s" % err)
            LOG.error(msg)
            return msg
        else:
            if result_static_ips != common_const.STATUS_SUCCESS:
                return result_static_ips
            else:
                LOG.info(_LI("Successfully removed static IPs. "
                             "Result: %(result_static_ips)s"),
                         {'result_static_ips': result_static_ips})

        rule_info = dict(
            provider_mac=resource_data['provider_mac'],
            stitching_mac=resource_data['stitching_mac'])

        mgmt_ip = resource_data['mgmt_ip']

        LOG.info(_LI("Initiating DELETE persistent rule for primary "
                     "service at mgmt ip: %(mgmt_ip)s"),
                 {'mgmt_ip': mgmt_ip})
        url = const.request_url % (mgmt_ip, self.port, 'delete_rule')
        data = jsonutils.dumps(rule_info)

        err_msg = ("Persistent rule DELETE request to the VyOS firewall "
                   "service at %s failed. " % url)
        try:
            resp = self.rest_api.fire(url, data, common_const.DELETE, headers)
        except Exception as err:
            err_msg += ("Reason: %r" % str(err).capitalize())
            LOG.error(err_msg)
            return err_msg

        if resp is common_const.STATUS_SUCCESS:
            msg = ("Persistent rules successfully deleted "
                   "for service at %r." % url)
            LOG.info(msg)
            return resp

        err_msg += (("Status code: %r." % resp['status'])
                    if type(resp) is dict
                    else ("Reason: " + resp))
        LOG.error(err_msg)
        return err_msg

    def configure_routes(self, context, resource_data):
        """ Configure routes for the service VM.

        Issues REST call to service VM for configuration of routes.

        :param context: neutron context
        :param resource_data: a dictionary of firewall rules and objects
        send by neutron plugin

        Returns: SUCCESS/Failure message with reason.

        """
        headers = self._parse_vm_context(context)
        forward_routes = resource_data.get('forward_route')
        resource_data = self.parse.parse_data(common_const.ROUTES,
                                              resource_data)
        mgmt_ip = resource_data.get('mgmt_ip')
        gateway_ip = resource_data.get('stitching_gw_ip')

        # checking whether VPN service is present in the chain
        # if yes, just configure the stitching pbr else
        # configure both stitching and provider pbrs.

        if not forward_routes:
            source_cidrs = [resource_data.get('stitching_cidr')]
        else:
            source_cidrs = [resource_data.get('provider_cidr'),
                            resource_data.get('stitching_cidr')]

        url = const.request_url % (mgmt_ip, self.port,
                                   'add-source-route')
        route_info = []
        for source_cidr in source_cidrs:
            route_info.append({'source_cidr': source_cidr,
                               'gateway_ip': gateway_ip})
        data = jsonutils.dumps(route_info)
        LOG.info(_LI("Initiating POST request to configure route of primary "
                     "service at mgmt ip: %(mgmt_ip)s"),
                 {'mgmt_ip': mgmt_ip})

        err_msg = ("Configure routes POST request to the VyOS firewall "
                   "service at %s failed. " % url)
        try:
            resp = self.rest_api.fire(url, data, common_const.POST, headers)
        except Exception as err:
            err_msg += ("Reason: %r" % str(err).capitalize())
            LOG.error(err_msg)
            return err_msg

        if resp is common_const.STATUS_SUCCESS:
            msg = ("Configured routes successfully for service at %r." % url)
            LOG.info(msg)
            return resp

        err_msg += (("Status code: %r, Reason: %r" %
                     (resp['status'], resp['reason']))
                    if type(resp) is dict
                    else ("Reason: " + resp))
        LOG.error(err_msg)
        return err_msg

    def clear_routes(self, context, resource_data):
        """ Clear routes for the service VM.

        Issues REST call to service VM for deletion of routes.

        :param context: neutron context
        :param resource_data: a dictionary of firewall rules and objects
        send by neutron plugin

        Returns: SUCCESS/Failure message with reason.

        """
        headers = self._parse_vm_context(context)
        resource_data = self.parse.parse_data(common_const.ROUTES,
                                              resource_data)
        mgmt_ip = resource_data.get('mgmt_ip')
        source_cidrs = [resource_data.get('provider_cidr'),
                        resource_data.get('stitching_cidr')]

        url = const.request_url % (mgmt_ip, self.port,
                                   'delete-source-route')
        route_info = []
        for source_cidr in source_cidrs:
            route_info.append({'source_cidr': source_cidr})
        data = jsonutils.dumps(route_info)
        LOG.info(_LI("Initiating Delete route to primary "
                     "service at mgmt ip: %(mgmt_ip)s"),
                 {'mgmt_ip': mgmt_ip})

        err_msg = ("Routes DELETE request to the VyOS firewall "
                   "service at %s failed. " % url)
        try:
            resp = self.rest_api.fire(url, data, common_const.DELETE, headers)
        except Exception as err:
            err_msg += ("Reason: %r" % str(err).capitalize())
            LOG.error(err_msg)
            return err_msg

        if resp is common_const.STATUS_SUCCESS:
            msg = ("Routes successfully removed for service at %r." % url)
            LOG.info(msg)
            return resp

        err_msg += (("Status code: %r, Reason: %r" %
                     (resp['status'], resp['reason']))
                    if type(resp) is dict
                    else ("Reason: " + resp))
        LOG.error(err_msg)
        return err_msg


@base_driver.set_class_attr(SERVICE_TYPE=fw_const.SERVICE_TYPE,
                            SERVICE_VENDOR=const.VYOS)
class FwaasDriver(FwGenericConfigDriver):
    """ Firewall as a service driver for handling firewall
    service configuration requests.

    We initialize service type in this class because agent loads
    class object only for those driver classes that have service type
    initialized. Also, only this driver class is exposed to the agent.

    """

    def __init__(self, conf):
        self.conf = conf
        self.timeout = const.REST_TIMEOUT
        self.rest_api = RestApi(self.timeout)
        self.host = self.conf.host
        self.port = const.CONFIGURATION_SERVER_PORT
        super(FwaasDriver, self).__init__()

    def create_firewall(self, context, firewall, host):
        """ Implements firewall creation

        Issues REST call to service VM for firewall creation

        :param context: Neutron context
        :param firewall: Firewall resource object from neutron fwaas plugin
        :param host: Name of the host machine

        Returns: SUCCESS/Failure message with reason.

        """
        headers = self._parse_vm_context(context['agent_info']['context'])
        resource_data = self.parse.parse_data(common_const.FIREWALL, context)

        LOG.info(_LI("Processing request 'Create Firewall'  in FWaaS Driver "
                     "for Firewall ID: %(f_id)s"),
                 {'f_id': firewall['id']})
        mgmt_ip = resource_data.get('mgmt_ip')
        url = const.request_url % (mgmt_ip,
                                   self.port,
                                   'configure-firewall-rule')
        msg = ("Initiating POST request for FIREWALL ID: %r Tenant ID:"
               " %r. URL: %s" % (firewall['id'], firewall['tenant_id'], url))
        LOG.debug(msg)
        data = jsonutils.dumps(firewall)

        err_msg = ("Configure firewall POST request to the VyOS "
                   "service at %s failed. " % url)
        try:
            resp = self.rest_api.fire(url, data, common_const.POST, headers)
        except Exception as err:
            err_msg += ("Reason: %r" % str(err).capitalize())
            LOG.error(err_msg)
            return common_const.STATUS_ERROR

        if resp is common_const.STATUS_SUCCESS:
            LOG.info(_LI("Configured firewall successfully at URL: %(url)s "),
                     {'url': url})
            return common_const.STATUS_ACTIVE

        err_msg += (("Reason: %r, Response Content: %r" %
                     (resp.pop('message'), resp))
                    if type(resp) is dict
                    else ("Reason: " + resp))
        LOG.error(err_msg)
        return common_const.STATUS_ERROR

    def update_firewall(self, context, firewall, host):
        """ Implements firewall updation

        Issues REST call to service VM for firewall updation

        :param context: Neutron context
        :param firewall: Firewall resource object from neutron fwaas plugin
        :param host: Name of the host machine

        Returns: SUCCESS/Failure message with reason.

        """
        headers = self._parse_vm_context(context['agent_info']['context'])
        LOG.info(_LI("Processing request 'Update Firewall' in FWaaS Driver "
                     "for Firewall ID:%(f_id)s"),
                 {'f_id': firewall['id']})
        resource_data = self.parse.parse_data(common_const.FIREWALL, context)
        mgmt_ip = resource_data.get('mgmt_ip')
        url = const.request_url % (mgmt_ip,
                                   self.port,
                                   'update-firewall-rule')
        msg = ("Initiating UPDATE request. URL: %s" % url)
        LOG.debug(msg)
        data = jsonutils.dumps(firewall)

        err_msg = ("Update firewall POST request to the VyOS "
                   "service at %s failed. " % url)
        try:
            resp = self.rest_api.fire(url, data, common_const.PUT, headers)
        except Exception as err:
            err_msg += ("Reason: %r" % str(err).capitalize())
            LOG.error(err_msg)
            return common_const.STATUS_ERROR

        if resp is common_const.STATUS_SUCCESS:
            msg = ("Updated firewall successfully for service at %r." % url)
            LOG.debug(msg)
            return common_const.STATUS_ACTIVE

        err_msg += (("Reason: %r, Response Content: %r" %
                     (resp.pop('message'), resp))
                    if type(resp) is dict
                    else ("Reason: " + resp))
        LOG.error(err_msg)
        return common_const.STATUS_ERROR

    def delete_firewall(self, context, firewall, host):
        """ Implements firewall deletion

        Issues REST call to service VM for firewall deletion

        :param context: Neutron context
        :param firewall: Firewall resource object from neutron fwaas plugin
        :param host: Name of the host machine

        Returns: SUCCESS/Failure message with reason.

        """
        headers = self._parse_vm_context(context['agent_info']['context'])
        LOG.info(_LI("Processing request 'Delete Firewall' in FWaaS Driver "
                     "for Firewall ID:%(f_id)s"),
                 {'f_id': firewall['id']})
        resource_data = self.parse.parse_data(common_const.FIREWALL, context)
        mgmt_ip = resource_data.get('mgmt_ip')
        url = const.request_url % (mgmt_ip,
                                   self.port,
                                   'delete-firewall-rule')
        msg = ("Initiating DELETE request. URL: %s" % url)
        LOG.info(msg)
        data = jsonutils.dumps(firewall)

        err_msg = ("Delete firewall POST request to the VyOS "
                   "service at %s failed. " % url)
        try:
            resp = self.rest_api.fire(url, data, common_const.DELETE, headers)
        except Exception as err:
            err_msg += ("Reason: %r" % str(err).capitalize())
            LOG.error(err_msg)
            return common_const.STATUS_SUCCESS

        if resp is common_const.STATUS_SUCCESS:
            msg = ("Deleted firewall successfully for service at %r." % url)
            LOG.info(msg)
            return common_const.STATUS_DELETED

        if type(resp) is dict:
            if not resp.get('delete_success') and (
                    resp.get('message') == const.INTERFACE_NOT_FOUND):
                err_msg += ("Firewall was not deleted as interface was not "
                            "available in the firewall. It might have got "
                            "detached. So marking this delete as SUCCESS. "
                            "URL: %r, Response Content: %r" %
                            (url, resp.content))
                LOG.error(err_msg)
                return common_const.STATUS_SUCCESS
            else:
                err_msg += ("Response Content: %r" % resp)
        else:
            err_msg += ("Reason: " + resp)
        LOG.error(err_msg)
        msg = ("Firewall deletion has failed, but still sending"
               "status as firewall deleted success from configurator")
        LOG.info(msg)
        return common_const.STATUS_DELETED
