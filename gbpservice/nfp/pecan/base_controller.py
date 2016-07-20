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

from oslo_log import log as logging
import oslo_serialization.jsonutils as jsonutils

from pecan import hooks
from pecan import rest
import zlib

LOG = logging.getLogger(__name__)
HookController = hooks.HookController
PecanHook = hooks.PecanHook


class ZipperHook(PecanHook):

    def before(self, state):
        if state.request.method.upper() != 'GET':
            try:
                zippedBody = state.request.body
                body = zlib.decompress(zippedBody)
                body = jsonutils.loads(body)
                state.request.json_body = body
                state.request.content_type = "application/json"
            except Exception as e:
                msg = ("Failed to process data ,Reason: %s" % (e))
                LOG.error(msg)

    def after(self, state):
        data = state.response.body
        state.response.body = zlib.compress(data)
        state.response.content_type = "application/octet-stream"


class BaseController(rest.RestController, HookController):
    """This is root controller that forward the request to __init__.py
    file inside controller folder inside v1

    """
    __hooks__ = [ZipperHook()]
