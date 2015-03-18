# Copyright 2014 OneConvergence, Inc. All Rights Reserved.
#
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

import copy
import httplib
import requests
import urlparse

from oslo_config import cfg
from oslo_log import log as logging
from oslo_serialization import jsonutils

from gbpservice.neutron.services.grouppolicy.common import exceptions


SERVICE_CONTROLLER_OPTIONS = [
    cfg.StrOpt('service_controller_ip',
               help=_('One Convergence NVSD Service Controller IP Address')),
    cfg.StrOpt('service_controller_port',
               help=_('One Convergence NVSD Service Controller Port Number')),
    cfg.StrOpt('request_retries',
               help=_('One Convergence NVSD Service Controller API '
                      'request retries')),
    cfg.StrOpt('request_timeout',
               help=_('One Convergence NVSD Service Controller API '
                      'request timeout')),
    cfg.StrOpt('api_version',
               default='1.0',
               help=_('One Convergence NVSD Service Controller API Version')),
]

cfg.CONF.register_opts(SERVICE_CONTROLLER_OPTIONS, "NVSD_SERVICE_CONTROLLER")

LOG = logging.getLogger(__name__)

NVSD_ENDPOINT = "/nvsd_connectivity_port"
NVSD_ENDPOINT_GROUP = "/nvsd_connectivity_portgroup"
NVSD_CONTRACT = "/nvsd_connectivity_contract"
NVSD_POLICY = "/nvsd_connectivity_policy"
NVSD_POLICY_ACTION = "/nvsd_connectivity_action"
NVSD_POLICY_CLASSIFIER = "/nvsd_connectivity_classifier"
NVSD_POLICY_RULE = "/nvsd_connectivity_rule"
NVSD_SERVICE = "/service"

ADMIN_URL = "&is_admin=true"
API_TENANT_USER = "?tenant_id=%s&user_id=%s"


class GroupPolicyException(exceptions.GroupPolicyException):
    """Base for policy driver exceptions returned to user."""
    message = _("Unexpected response code %(status)s from NVSD "
                "Service Controller for %(method)s to %(url)s")


class NVSDServiceController(object):
    """Encapsulates the One Convergence NVSD Service Controller details.

    Uses python-requests library to perform API request to One Convergence
    NVSD Service Controller.
    """

    def __init__(self):

        self._host = cfg.CONF.NVSD_SERVICE_CONTROLLER.service_controller_ip
        self._port = cfg.CONF.NVSD_SERVICE_CONTROLLER.service_controller_port
        self._retries = cfg.CONF.NVSD_SERVICE_CONTROLLER.request_retries
        self._request_timeout = float(cfg.CONF.NVSD_SERVICE_CONTROLLER.
                                      request_timeout)
        self.service_api_url = 'http://' + self._host + ':' + str(self._port)
        self.pool = requests.Session()

    def do_request(self, method, url=None, headers=None, data=None,
                   timeout=10):
        response = self.pool.request(method, url=url,
                                     headers=headers, data=data,
                                     timeout=timeout)
        return response

    def request(self, method, uri, context, body="",
                content_type="application/json", filters={}):
        """Issue a request to NVSD Service Controller."""

        headers = {"Content-Type": content_type}
        api_version = "/v" + cfg.CONF.NVSD_SERVICE_CONTROLLER.api_version
        uri = api_version + uri
        if context.is_admin:
            uri = uri + ADMIN_URL
        if filters.get('tenant_id'):
            uri = uri + "&filter_tenant_id=%s" % filters.get('tenant_id')[0]

        url = urlparse.urljoin(self.service_api_url, uri)

        response = None

        try:
            response = self.do_request(method, url=url, headers=headers,
                                       data=body,
                                       timeout=self._request_timeout)

            LOG.debug("Request: %(method)s %(uri)s executed",
                      {'method': method, 'uri': self.service_api_url + uri})
        except httplib.IncompleteRead as err:
            response = err.partial
        except Exception as err:
            LOG.error(_("Request failed in NVSD Service Controller. "
                        "Error : %s"), err)

        if response is None:
            # Request was timed out.
            LOG.error(_("Response is Null, Request for method : %(method)s to "
                        "%(uri)s Timed out"), {'method': method, 'uri': uri})
            raise GroupPolicyException(status="TimedOut", method=method,
                                       url=self.service_api_url + uri)

        status = response.status_code
        #Not Found (404) is OK for DELETE. Ignore it here
        if method == 'DELETE' and status == 404:
            return
        elif status not in (requests.codes.ok, requests.codes.created,
                            requests.codes.no_content):
            LOG.error(_("Unexpected response code %(status)s from NVSD "
                        "Service Controller for %(method)s to %(url)s"),
                      {'status': status, 'method': method, 'url': url})
            raise GroupPolicyException(status=status, method=method,
                                       url=self.service_api_url + uri)
        else:
            LOG.debug("Success: %(method)s %(url)s status=%(status)s",
                      {'method': method, 'url': self.service_api_url + uri,
                       'status': status})
        response.body = response.content
        return response


class NVSDServiceApi(object):
    """Invokes One Convergence NVSD Service Controller API.

    Invokes the appropriate One Convergence NVSD Service Controller API for
    each of the Openstack Group Based Policy API operation. Maps the Openstack
    Group Policy parameters to One Convergence NVSD API parameters.
    """

    def __init__(self):
        self.nvsd_service_controller = NVSDServiceController()

    def create_policy_classifier(self, context, policy_classifier):
        body = copy.deepcopy(policy_classifier)
        body.update({"port": policy_classifier.get("port_range")})
        tenant_id = context.tenant_id
        uri = (NVSD_POLICY_CLASSIFIER + "?tenant_id=%s&user_id=%s" %
               (tenant_id, context.user))
        response = self.nvsd_service_controller.request("POST", uri, context,
                                                        jsonutils.dumps(body))
        return response.json()

    def get_policy_classifiers(self, context, tenant_id, filters={}):
        uri = (NVSD_POLICY_CLASSIFIER + "?tenant_id=%s&user_id=%s" %
               (tenant_id, context.user))
        response = self.nvsd_service_controller.request("GET", uri, context)
        return response.json()

    def get_policy_classifier(self, context, classifier_id):
        uri = (NVSD_POLICY_CLASSIFIER + "/%s?tenant_id=%s&user_id=%s" %
               (classifier_id, context.tenant_id, context.user))
        response = self.nvsd_service_controller.request("GET", uri, context)
        return response.json()

    def update_policy_classifier(self, context, classifier):
        tenant_id = context.tenant_id
        classifier_id = classifier.get('id')
        body = copy.deepcopy(classifier)
        body.update({"port": classifier.get("port_range")})
        uri = (NVSD_POLICY_CLASSIFIER + "/%s?tenant_id=%s&user_id=%s" %
               (classifier_id, tenant_id, context.user))
        response = self.nvsd_service_controller.request("PUT", uri, context,
                                                        jsonutils.dumps(body))
        return response.json()

    def delete_policy_classifier(self, context, classifier_id):
        tenant_id = context.tenant_id
        uri = (NVSD_POLICY_CLASSIFIER + "/%s?tenant_id=%s&user_id=%s" %
               (classifier_id, tenant_id, context.user))
        self.nvsd_service_controller.request("DELETE", uri, context)

    def create_policy_rule(self, context, rule):
        '''
        body = copy.deepcopy(rule)
        body.update({'classifier': rule.get('policy_classifier_id'),
                     'actions': rule.get('policy_actions', []),
                     'policies_attached': []})
        '''
        tenant_id = context.tenant_id
        uri = (NVSD_POLICY_RULE + "?tenant_id=%s&user_id=%s" %
               (tenant_id, context.user))
        response = self.nvsd_service_controller.request("POST", uri, context,
                                                        jsonutils.dumps(rule))
        return response.json()

    def update_policy_rule(self, context, rule):
        tenant_id = context.tenant_id
        rule_id = rule.get('id')
        body = copy.deepcopy(rule)
        body.update({'classifier': rule.get('policy_classifier_id'),
                     'actions': rule.get('policy_actions', [])})
        uri = (NVSD_POLICY_RULE + "/%s?tenant_id=%s&user_id=%s" %
               (rule_id, tenant_id, context.user))
        response = self.nvsd_service_controller.request("PUT", uri, context,
                                                        jsonutils.dumps(body))
        return response.json()

    def get_policy_rule(self, context, rule_id):
        uri = (NVSD_POLICY_RULE + "/%s?tenant_id=%s&user_id=%s" %
               (rule_id, context.tenant_id, context.user))
        response = self.nvsd_service_controller.request("GET", uri, context)
        return response.json()

    def get_policy_rules(self, context, tenant_id, filters={}):
        uri = (NVSD_POLICY_RULE + "?tenant_id=%s&user_id=%s" %
               (tenant_id, context.user))
        response = self.nvsd_service_controller.request("GET", uri, context)
        return response.json()

    def delete_policy_rule(self, context, rule_id):
        uri = (NVSD_POLICY_RULE + "/%s?tenant_id=%s&user_id=%s" %
               (rule_id, context.tenant_id, context.user))
        self.nvsd_service_controller.request("DELETE", uri, context)

    def create_policy_action(self, context, action):
        body = copy.deepcopy(action)
        action_type = action.get("action_type")
        if action_type.lower() == "redirect":
            body["action_type"] = "l2redirect"
        tenant_id = context.tenant_id
        uri = (NVSD_POLICY_ACTION + "?tenant_id=%s&user_id=%s" %
               (tenant_id, context.user))
        response = self.nvsd_service_controller.request("POST", uri, context,
                                                        jsonutils.dumps(body))
        return response.json()

    def update_policy_action(self, context, policy_action):
        tenant_id = context.tenant_id
        action_id = policy_action.get('id')
        body = copy.deepcopy(policy_action)
        action_type = policy_action.get("action_type")
        if action_type.lower() == "redirect":
            body["action_type"] = "l2redirect"
        uri = (NVSD_POLICY_ACTION + "/%s?tenant_id=%s&user_id=%s" %
               (action_id, tenant_id, context.user))
        response = self.nvsd_service_controller.request("PUT", uri, context,
                                                        jsonutils.dumps(body))
        return response.json()

    def get_policy_action(self, context, action_id):
        uri = (NVSD_POLICY_ACTION + "/%s?tenant_id=%s&user_id=%s" %
               (action_id, context.tenant_id, context.user))
        response = self.nvsd_service_controller.request("GET", uri)
        return response.json()

    def get_policy_actions(self, context, tenant_id, filters={}):
        uri = (NVSD_POLICY_ACTION + "?tenant_id=%s&user_id=%s" %
               (tenant_id, context.user))
        response = self.nvsd_service_controller.request("GET", uri, context)
        return response.json()

    def delete_policy_action(self, context, action_id):
        uri = (NVSD_POLICY_ACTION + "/%s?tenant_id=%s&user_id=%s" %
               (action_id, context.tenant_id, context.user))
        self.nvsd_service_controller.request("DELETE", uri, context)

    def create_endpointgroup(self, context, endpointgroup):
        uri = (NVSD_ENDPOINT_GROUP + "?tenant_id=%s&user_id=%s" %
               (context.tenant_id, context.user))
        response = self.nvsd_service_controller.request(
                            "POST", uri, context,
                            jsonutils.dumps(endpointgroup))

        return response.json()

    def get_endpointgroups(self, context, tenant_id, filters={}):
        uri = (NVSD_ENDPOINT_GROUP + "?tenant_id=%s&user_id=%s" %
               (tenant_id, context.user))
        response = self.nvsd_service_controller.request("GET", uri, context)
        return response.json()

    def get_endpointgroup(self, context, endpointgroup_id):
        uri = (NVSD_ENDPOINT_GROUP + "/%s?tenant_id=%s&user_id=%s" %
               (endpointgroup_id, context.tenant_id, context.user))
        response = self.nvsd_service_controller.request("GET", uri, context)
        return response.json()

    def update_endpointgroup(self, context, endpointgroup):
        tenant_id = context.tenant_id
        endpointgroup_id = endpointgroup.get('id')
        uri = (NVSD_ENDPOINT_GROUP + "/%s?tenant_id=%s&user_id=%s" %
               (endpointgroup_id, tenant_id, context.user))
        response = self.nvsd_service_controller.request(
                                "PUT", uri, context,
                                jsonutils.dumps(endpointgroup))
        return response.json()

    def delete_endpointgroup(self, context, endpointgroup_id):
        uri = (NVSD_ENDPOINT_GROUP + "/%s?tenant_id=%s&user_id=%s" %
               (endpointgroup_id, context.tenant_id, context.user))
        self.nvsd_service_controller.request("DELETE", uri, context)

    def create_endpoint(self, context, endpoint):
        body = copy.deepcopy(endpoint)
        body.update({'connectivity_portgroup_id':
                     endpoint.get('policy_target_group_id')})

        tenant_id = context.tenant_id
        uri = (NVSD_ENDPOINT + "?tenant_id=%s&user_id=%s" %
               (tenant_id, context.user))
        response = self.nvsd_service_controller.request("POST", uri, context,
                                                        jsonutils.dumps(body))
        return response.json()

    def update_endpoint(self, context, endpoint):
        tenant_id = context.tenant_id
        endpoint_id = endpoint.get('id')
        body = copy.deepcopy(endpoint)
        body.update({'connectivity_portgroup_id':
                     endpoint.get('policy_target_group_id')})

        uri = (NVSD_ENDPOINT + "/%s?tenant_id=%s&user_id=%s" %
               (endpoint_id, tenant_id, context.user))
        response = self.nvsd_service_controller.request("PUT", uri, context,
                                                        jsonutils.dumps(body))
        return response.json()

    def get_endpoint(self, context, endpoint_id):
        uri = (NVSD_ENDPOINT + "/%s?tenant_id=%s&user_id=%s" %
               (endpoint_id, context.tenant_id, context.user))
        response = self.nvsd_service_controller.request("GET", uri, context)
        return response.json()

    def get_endpoints(self, context, tenant_id, filters={}):
        uri = (NVSD_ENDPOINT + "?tenant_id=%s&user_id=%s" %
               (tenant_id, context.user))
        response = self.nvsd_service_controller.request("GET", uri, context)
        return response.json()

    def delete_endpoint(self, context, endpoint_id):
        uri = (NVSD_ENDPOINT + "/%s?tenant_id=%s&user_id=%s" %
               (endpoint_id, context.tenant_id, context.user))
        self.nvsd_service_controller.request("DELETE", uri, context)
        return

    def create_contract(self, context, contract):
        tenant_id = context.tenant_id
        uri = (NVSD_CONTRACT + "?tenant_id=%s&user_id=%s" %
               (tenant_id, context.user))
        response = self.nvsd_service_controller.request(
                            "POST", uri, context, jsonutils.dumps(contract))
        return response.json()

    def update_contract(self, context, contract):
        tenant_id = context.tenant_id
        contract_id = contract.get('id')
        uri = (NVSD_CONTRACT + "/%s?tenant_id=%s&user_id=%s" %
               (contract_id, tenant_id, context.user))
        response = self.nvsd_service_controller.request(
                                "PUT", uri, context, jsonutils.dumps(contract))
        return response.json()

    def get_contract(self, context, contract_id):
        uri = (NVSD_CONTRACT + "/%s?tenant_id=%s&user_id=%s" %
               (contract_id, context.tenant_id, context.user))
        response = self.nvsd_service_controller.request("GET", uri, context)
        return response.json()

    def get_contracts(self, context, tenant_id, filters={}):
        uri = (NVSD_CONTRACT + "?tenant_id=%s&user_id=%s" %
               (tenant_id, context.user))
        response = self.nvsd_service_controller.request("GET", uri, context)
        return response.json()

    def delete_contract(self, context, contract_id):
        uri = (NVSD_CONTRACT + "/%s?tenant_id=%s&user_id=%s" %
               (contract_id, context.tenant_id, context.user))
        self.nvsd_service_controller.request("DELETE", uri, context)

    def create_policy(self, context, policy):
        tenant_id = context.tenant_id
        uri = (NVSD_POLICY + "?tenant_id=%s&user_id=%s" %
               (tenant_id, context.user))
        response = self.nvsd_service_controller.request(
                                "POST", uri, context, jsonutils.dumps(policy))
        return response.json()

    def update_policy(self, context, policy):
        tenant_id = context.tenant_id
        policy_id = policy.get('id')
        uri = (NVSD_POLICY + "/%s?tenant_id=%s&user_id=%s" %
               (policy_id, tenant_id, context.user))
        response = self.nvsd_service_controller.request(
                                "PUT", uri, context, jsonutils.dumps(policy))
        return response.json()

    def get_policy(self, context, policy_id):
        uri = (NVSD_POLICY + "/%s?tenant_id=%s&user_id=%s" %
               (policy_id, context.tenant_id, context.user))
        response = self.nvsd_service_controller.request("GET", uri, context)
        return response.json()

    def get_policys(self, context, tenant_id, filters={}):
        uri = (NVSD_POLICY + "?tenant_id=%s&user_id=%s" %
               (tenant_id, context.user))
        response = self.nvsd_service_controller.request("GET", uri, context)
        return response.json()

    def delete_policy(self, context, policy_id):
        uri = (NVSD_POLICY + "/%s?tenant_id=%s&user_id=%s" %
               (policy_id, context.tenant_id, context.user))
        self.nvsd_service_controller.request("DELETE", uri, context)

    def get_nvsd_service(self, context, service_id):
        uri = (NVSD_SERVICE + "/%s?tenant_id=%s&user_id=%s" %
               (service_id, context.tenant_id, context.user))
        response = self.nvsd_service_controller.request("GET", uri, context)
        return response.json()
