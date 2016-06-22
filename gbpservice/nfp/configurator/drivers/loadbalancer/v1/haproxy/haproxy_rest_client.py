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

import httplib
import json as jsonutils
import requests
import urlparse

from gbpservice.nfp.core import log as nfp_logging

LOG = nfp_logging.getLogger(__name__)


class RestClientException(Exception):
    """Embeds the exceptions thrown by the REST Client."""

    def __init__(self, status, method, url):
        """RestClientException init

        :param status: HTTP Response code
        :param method: HTTP Request Method
        :param url: REST Server request url

        """
        msg = ("REST Request failed for URL: %s, Method: "
               "%s and Response Code: %s" % (url, method, status))
        LOG.error(msg)
        super(RestClientException, self).__init__(self, msg)
        self.status = status
        self.method = method
        self.url = url


class HttpRequests(object):
    """Encapsulates the Python requests module

    Uses python-requests library to perform API request to the REST server
    """

    def __init__(self, host, port, retries=0, request_timeout=30):

        self._host = host
        self._port = port
        self._retries = retries
        self._request_timeout = request_timeout
        self.rest_server_url = 'http://' + self._host + ':' + str(self._port)
        self.pool = requests.Session()

    def do_request(self, method, url=None, headers=None, data=None,
                   timeout=30):
        response = None
        try:
            response = self.pool.request(method, url=url,
                                         headers=headers, data=data,
                                         timeout=timeout)
        except Exception as err:
            msg = ("Failed in performing HTTP request. %s"
                   % str(err).capitalize())
            LOG.error(msg)
        return response

    def request(self, method, uri, body=None,
                content_type="application/json"):
        """Issue a request to REST API server."""

        headers = {"Content-Type": content_type}
        url = urlparse.urljoin(self.rest_server_url, uri)

        response = None

        try:
            response = self.do_request(method, url=url, headers=headers,
                                       data=body,
                                       timeout=self._request_timeout)

            msg = ("Request: %s, URI: %s executed."
                   % (method, (self.rest_server_url + uri)))
            LOG.debug(msg)
        except httplib.IncompleteRead as err:
            response = err.partial
            msg = ("Request failed in REST Api Server. %s"
                   % str(err).capitalize())
            LOG.error(msg)
        except Exception as err:
            msg = ("Request failed in REST Api Server. %s"
                   % str(err).capitalize())
            LOG.error(msg)

        if response is None:
            # Request was timed out.
            msg = ("Response is Null, Request for method: %s to "
                   "URI: %s timed out" % (method, uri))
            LOG.error(msg)
            # TODO(Magesh): Use constants defined in requests or httplib
            # for checking error codes
            raise RestClientException(status=408, method=method, url=url)

        status = response.status_code
        # Not Found (404) is OK for DELETE. Ignore it here
        if method == 'DELETE' and status == 404:
            return
        elif status not in (200, 201, 204):
            # requests.codes.ok = 200, requests.codes.created = 201,
            # requests.codes.no_content = 204
            msg = ("Unexpected response code %s from REST "
                   "API Server for %s to %s"
                   % (status, method, url))
            LOG.error(msg)
            raise RestClientException(status=status, method=method,
                                      url=self.rest_server_url + uri)
        else:
            msg = ("Success: %s, url: %s and status: %s"
                   % (method, (self.rest_server_url + uri), status))
            LOG.debug(msg)
        response.body = response.content
        return response

    def create_resource(self, resource_path, resource_data):
        response = self.request("POST", resource_path,
                                jsonutils.dumps(resource_data))
        return response.json()

    def update_resource(self, resource_path, resource_data):
        response = self.request("PUT", resource_path,
                                jsonutils.dumps(resource_data))
        return response.json()

    def delete_resource(self, resource_path):
        return self.request("DELETE", resource_path)

    def get_resource(self, resource_path):
        response = self.request("GET", resource_path)
        return response.json()

    def list_resources(self, resource_path):
        response = self.request("GET", resource_path)
        return response.json()

    def sync_config(self, resource_path, resource_data):
        response = self.request("POST", resource_path,
                                jsonutils.dumps(resource_data))
        return response.json()
