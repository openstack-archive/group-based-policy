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


import exceptions

from gbpservice.nfp.common import constants as nfp_constants
from gbpservice.nfp.core import log as nfp_logging
from gbpservice.nfp.lib import rest_client_over_unix as unix_rc

from neutron.common import rpc as n_rpc
from neutron import context as n_context

from oslo_config import cfg
from oslo_config import cfg as oslo_config
import oslo_messaging as messaging
from oslo_serialization import jsonutils

import requests

LOG = nfp_logging.getLogger(__name__)
Version = 'v1'  # v1/v2/v3#

rest_opts = [
    cfg.StrOpt('rest_server_address',
               default='', help='Rest connection IpAddr'),
    cfg.IntOpt('rest_server_port',
               default=8080, help='Rest connection Port'),
]

rpc_opts = [
    cfg.StrOpt('topic',
               default='', help='Topic for rpc connection'),
]

oslo_config.CONF.register_opts(rest_opts, "REST")
oslo_config.CONF.register_opts(rpc_opts, "RPC")
n_rpc.init(cfg.CONF)

UNIX_REST = 'unix_rest'
TCP_REST = 'tcp_rest'

""" Common Class for restClient exceptions """


class RestClientException(exceptions.Exception):

    """ RestClient Exception """

""" Common Class to handle restclient request"""


class RestApi(object):

    def __init__(self, rest_server_address, rest_server_port):
        self.rest_server_address = rest_server_address
        self.rest_server_port = rest_server_port
        self.url = "http://%s:%s/v1/nfp/%s"

    def _response(self, resp, url):
        success_code = [200, 201, 202, 204]
        # Evaluate responses into success and failures.
        # Raise exception for failure cases which needs
        # to be handled in caller function.
        if success_code.__contains__(resp.status_code):
            return resp
        elif resp.status_code == 400:
            raise RestClientException("HTTPBadRequest: %s" % resp.reason)
        elif resp.status_code == 401:
            raise RestClientException("HTTPUnauthorized: %s" % resp.reason)
        elif resp.status_code == 403:
            raise RestClientException("HTTPForbidden: %s" % resp.reason)
        elif resp.status_code == 404:
            raise RestClientException("HttpNotFound: %s" % resp.reason)
        elif resp.status_code == 405:
            raise RestClientException(
                "HTTPMethodNotAllowed: %s" % resp.reason)
        elif resp.status_code == 406:
            raise RestClientException("HTTPNotAcceptable: %s" % resp.reason)
        elif resp.status_code == 408:
            raise RestClientException("HTTPRequestTimeout: %s" % resp.reason)
        elif resp.status_code == 409:
            raise RestClientException("HTTPConflict: %s" % resp.reason)
        elif resp.status_code == 415:
            raise RestClientException(
                "HTTPUnsupportedMediaType: %s" % resp.reason)
        elif resp.status_code == 417:
            raise RestClientException(
                "HTTPExpectationFailed: %s" % resp.reason)
        elif resp.status_code == 500:
            raise RestClientException("HTTPServerError: %s" % resp.reason)
        else:
            raise RestClientException('Unhandled Exception code: %s %s' %
                                      (resp.status_code, resp.reason))
        return resp

    def post(self, path, body, method_type):
        """Post restclient request handler
        Return:Http response
        """
        url = self.url % (
            self.rest_server_address,
            self.rest_server_port, path)
        data = jsonutils.dumps(body)
        try:
            # Method-Type needs to be added here,as DELETE/CREATE
            # both case are handled by post as delete also needs
            # to send data to the rest-server.
            headers = {"content-type": "application/json",
                       "method-type": method_type}
            resp = requests.post(url, data,
                                 headers=headers)
            message = "POST url %s %d" % (url, resp.status_code)
            LOG.info(message)
            return self._response(resp, url)
        except RestClientException as rce:
            message = "Rest API %s - Failed. Reason: %s" % (
                url, rce)
            LOG.error(message)

    def put(self, path, body):
        """Put restclient request handler
        Return:Http response
        """
        url = self.url % (
            self.rest_server_address,
            self.rest_server_port, path)
        data = jsonutils.dumps(body)
        try:
            headers = {"content-type": "application/json"}
            resp = requests.put(url, data,
                                headers=headers)
            message = "PUT url %s %d" % (url, resp.status_code)
            LOG.info(message)
            return self._response(resp, url)
        except RestClientException as rce:
            message = "Rest API %s - Failed. Reason: %s" % (
                url, rce)
            LOG.error(message)

    def get(self, path):
        """Get restclient request handler
        Return:Http response
        """
        url = self.url % (
            self.rest_server_address,
            self.rest_server_port, path)
        try:
            headers = {"content-type": "application/json"}
            resp = requests.get(url,
                                headers=headers)
            message = "GET url %s %d" % (url, resp.status_code)
            LOG.info(message)
            return self._response(resp, url)
        except RestClientException as rce:
            message = "Rest API %s - Failed. Reason: %s" % (
                url, rce)
            LOG.error(message)

""" Common Class to handle rpcclient request"""


class RPCClient(object):
    API_VERSION = '1.0'

    def __init__(self, topic):
        self.topic = topic
        target = messaging.Target(topic=self.topic,
                                  version=self.API_VERSION)
        self.client = n_rpc.get_client(target)
        self.cctxt = self.client.prepare(version=self.API_VERSION,
                                         topic=self.topic)


def send_request_to_configurator(conf, context, body,
                                 method_type, device_config=False,
                                 network_function_event=False):
    """Common function to handle (create, delete) request for configurator.
    Send create/delete to configurator rest-server.
    Return:Http Response
    """
    # This function reads configuration data and decides
    # method (tcp_rest/rpc) for sending request to configurator.
    if device_config:
        method_name = method_type.lower() + '_network_function_device_config'
        body['info']['context'].update({'neutron_context': context.to_dict()})
    elif network_function_event:
        method_name = 'network_function_event'
    else:
        if (body['config'][0]['resource'] in
                nfp_constants.CONFIG_TAG_RESOURCE_MAP.values()):
            body['config'][0]['resource_data'].update(
                {'neutron_context': context.to_dict()})
            body['info']['context'].update(
                {'neutron_context': context.to_dict()})
        method_name = method_type.lower() + '_network_function_config'

    if conf.backend == TCP_REST:
        try:
            rc = RestApi(conf.REST.rest_server_address,
                         conf.REST.rest_server_port)
            if method_type.lower() in [nfp_constants.CREATE,
                                       nfp_constants.DELETE]:
                resp = rc.post(method_name, body, method_type.upper())
                message = "%s -> POST response: (%s) body: %s " % (method_name,
                                                                   resp, body)
                LOG.debug(message)
            elif method_type.lower() in [nfp_constants.UPDATE]:
                resp = rc.put(method_name, body)
                message = "%s -> PUT response: (%s) body: %s " % (method_name,
                                                                  resp, body)
                LOG.debug(message)
            else:
                message = ("%s api not supported" % (method_name))
                LOG.error(message)
        except RestClientException as rce:
            message = "%s -> POST request failed.Reason: %s" % (
                method_name, rce)
            LOG.error(message)

    elif conf.backend == UNIX_REST:
        try:
            if method_type.lower() in [nfp_constants.CREATE,
                                       nfp_constants.DELETE]:
                resp, content = unix_rc.post(method_name,
                                             body=body)
                message = ("%s -> POST response: (%s) body : %s " %
                           (method_name, content, body))
                LOG.debug(message)
            elif method_type.lower() in [nfp_constants.UPDATE]:
                resp, content = unix_rc.put(method_name,
                                            body=body)
                message = ("%s -> PUT response: (%s) body : %s " %
                           (method_name, content, body))
                LOG.debug(message)
            else:
                message = ("%s api not supported" % (method_name))
                LOG.error(message)
        except unix_rc.RestClientException as rce:
            message = "%s -> request failed . Reason %s " % (
                method_name, rce)
            LOG.error(message)

    else:
        message = ("%s -> RPC request sent. " % (method_name))
        LOG.info(message)
        rpcClient = RPCClient(conf.RPC.topic)
        rpcClient.cctxt.cast(context, method_name,
                             body=body)


def get_response_from_configurator(conf):
    """Common function to handle get request for configurator.
    Get notification http response from configurator rest server.
    Return:Http Response
    response_data = [
            {'receiver': <neutron/device_orchestrator/service_orchestrator>,
             'resource': <firewall/vpn/loadbalancer/orchestrator>,
             'method': <notification method name>,
             'kwargs': <notification method arguments>
        },
    ]
    """
    # This function reads configuration data and decides
    # method (tcp_rest/ unix_rest/ rpc) for get response from configurator.
    if conf.backend == TCP_REST:
        try:
            rc = RestApi(conf.REST.rest_server_address,
                         conf.REST.rest_server_port)
            resp = rc.get('get_notifications')
            rpc_cbs_data = jsonutils.loads(resp.content)
            return rpc_cbs_data
        except RestClientException as rce:
            message = ("get_notification ->"
                       "GET request failed. Reason : %s" % (rce))
            LOG.error(message)
            return "get_notification -> GET request failed. Reason : %s" % (
                rce)
        except Exception as e:
            message = ("get_notification ->"
                       "GET request failed. Reason : %s" % (e))
            LOG.error(message)
            return "get_notification -> GET request failed. Reason : %s" % (
                e)

    elif conf.backend == UNIX_REST:
        try:
            resp, content = unix_rc.get('get_notifications')
            content = jsonutils.loads(content)
            if content:
                message = ("get_notification ->"
                           "GET response: (%s)" % (content))
                LOG.debug(message)
            return content
        except unix_rc.RestClientException as rce:
            message = ("get_notification ->"
                       "GET request failed. Reason : %s" % (
                           rce))
            LOG.error(message)
            return "get_notification -> GET request failed. Reason : %s" % (
                rce)
        except Exception as e:
            message = ("get_notification ->"
                       "GET request failed. Reason : %s" % (
                           e))
            LOG.error(message)
            return "get_notification -> GET request failed. Reason : %s" % (
                e)

    else:
        rpc_cbs_data = []
        try:
            rpcClient = RPCClient(conf.RPC.topic)
            context = n_context.Context(
                'config_agent_user', 'config_agent_tenant')
            rpc_cbs_data = rpcClient.cctxt.call(context,
                                                'get_notifications')
            return rpc_cbs_data
        except Exception as e:
            message = "Exception while processing %s" % e
            LOG.error(message)
            return "get_notification -> GET request failed. Reason : %s" % (
                e)


def parse_service_flavor_string(service_flavor_str):
    """Parse service_flavour string to service details dictionary.
        Return: Service Details Dictionary
    """
    service_details = {}
    if ',' not in service_flavor_str:
        service_details['device_type'] = 'nova'
        service_details['service_vendor'] = service_flavor_str
    else:
        service_flavor_dict = dict(item.split('=') for item
                                   in service_flavor_str.split(','))
        service_details = {key.strip(): value.strip() for key, value
                           in service_flavor_dict.iteritems()}
    return service_details
