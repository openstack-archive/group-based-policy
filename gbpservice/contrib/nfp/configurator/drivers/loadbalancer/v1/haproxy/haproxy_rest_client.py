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

import json as jsonutils
import requests
import urlparse

from gbpservice.nfp.core import log as nfp_logging

LOG = nfp_logging.getLogger(__name__)


class HttpRequests(object):
    """Encapsulates Python requests module
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
        except Exception as e:
            msg = ("[Request:%s, URL:%s, Body:%s] Failed.Reason:%s"
                   % (method, url, data, e))
            LOG.error(msg)
            raise Exception(msg)
        return response

    def request(self, method, uri, body=None,
                content_type="application/json"):
        headers = {"Content-Type": content_type}
        url = urlparse.urljoin(self.rest_server_url, uri)

        response = self.do_request(method, url=url, headers=headers,
                                   data=body,
                                   timeout=self._request_timeout)
        if response is None:
            msg = ("[Request:%s, URL:%s, Body:%s] Failed.HTTP response is None"
                   ".Request timed out" % (method, url, body))
            LOG.error(msg)
            raise Exception(msg)

        status = response.status_code
        # Not Found (404) is OK for DELETE. Ignore it here
        if method == 'DELETE' and status == 404:
            return
        elif status not in (200, 201, 204):
            # requests.codes.ok = 200, requests.codes.created = 201,
            # requests.codes.no_content = 204
            msg = ("[Request:%s, URL:%s, Body:%s] Failed with status:%s"
                   % (method, url, body, status))
            LOG.error(msg)
            raise Exception(msg)
        else:
            msg = ("[Request:%s, URL:%s, Body:%s] executed successfully"
                   % (method, url, body))
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
