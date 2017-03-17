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

import six
import sys

from oslo_config import cfg
from oslo_log import log as logging

from gbpservice._i18n import _
from gbpservice._i18n import _LE

LOG = logging.getLogger(__name__)

exc_log_opts = [
    cfg.BoolOpt('fatal_exception_format_errors',
                default=False,
                help='Make exception message format errors fatal.'),
]

CONF = cfg.CONF
CONF.register_opts(exc_log_opts)


class NFPException(Exception):
    """Base NFP Exception

    To correctly use this class, inherit from it and define
    a 'message' property. That message will get printf'd
    with the keyword arguments provided to the constructor.

    """
    message = _("An unknown exception occurred.")
    code = 500
    headers = {}
    safe = False

    def __init__(self, message=None, **kwargs):
        self.kwargs = kwargs
        self.kwargs['message'] = message

        if 'code' not in self.kwargs:
            try:
                self.kwargs['code'] = self.code
            except AttributeError:
                pass

        for k, v in self.kwargs.items():
            if isinstance(v, Exception):
                self.kwargs[k] = six.text_type(v)

        if self._should_format():
            try:
                message = self.message % kwargs

            except Exception:
                exc_info = sys.exc_info()
                # kwargs doesn't match a variable in the message
                # log the issue and the kwargs
                LOG.exception(_LE('Exception in string format operation'))
                for name, value in kwargs.items():
                    LOG.error(_LE("%(name)s: %(value)s"),
                              {'name': name, 'value': value})
                if CONF.fatal_exception_format_errors:
                    six.reraise(*exc_info)
                # at least get the core message out if something happened
                message = self.message
        elif isinstance(message, Exception):
            message = six.text_type(message)

        self.msg = message
        super(NFPException, self).__init__(message)

    def _should_format(self):
        return self.kwargs['message'] is None or '%(message)' in self.message

    def __unicode__(self):
        return six.text_type(self.msg)


class NotFound(NFPException):
    message = _("Resource could not be found.")
    code = 404
    safe = True


class NetworkFunctionNotFound(NotFound):
    message = _("NetworkFunction %(network_function_id)s could not be found")


class NetworkFunctionInstanceNotFound(NotFound):
    message = _("NetworkFunctionInstance %(network_function_instance_id)s "
                "could not be found")


class NetworkFunctionDeviceNotFound(NotFound):
    message = _("NetworkFunctionDevice %(network_function_device_id)s could "
                "not be found")


class NetworkFunctionDeviceInterfaceNotFound(NotFound):
    message = _("NetworkFunctionDeviceInterface "
                "%(network_function_device_interface_id)s could "
                "not be found")


class NFPPortNotFound(NotFound):
    message = _("NFP Port %(port_id)s could not be found")


class RequiredDataNotProvided(NFPException):
    message = _("The required data %(required_data)s is missing in "
                "%(request)s")


class IncompleteData(NFPException):
    message = _("Data passed is incomplete")


class NotSupported(NFPException):
    message = _("Feature is not supported")


class ComputePolicyNotSupported(NotSupported):
    message = _("Compute policy %(compute_policy)s is not supported")


class HotplugNotSupported(NotSupported):
    message = _("Vendor %(vendor)s doesn't support hotplug feature")
