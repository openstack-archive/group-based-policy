# Copyright 2011 VMware, Inc, 2014 A10 Networks
# All Rights Reserved.
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

"""
Octavia base exception handling.
"""

from oslo_utils import excutils
from webob import exc

from gbpservice.contrib.nfp.configurator.drivers.loadbalancer.v2.haproxy.octavia_lib.\
    i18n import _LE
from gbpservice.contrib.nfp.configurator.drivers.loadbalancer.v2.haproxy.octavia_lib.\
    i18n import _LI


class OctaviaException(Exception):
    """Base Octavia Exception.

    To correctly use this class, inherit from it and define
    a 'message' property. That message will get printf'd
    with the keyword arguments provided to the constructor.
    """
    message = _("An unknown exception occurred.")

    def __init__(self, *args, **kwargs):
        try:
            if len(args) > 0:
                self.message = args[0]
            super(OctaviaException, self).__init__(self.message % kwargs)
            self.msg = self.message % kwargs
        except Exception:
            with excutils.save_and_reraise_exception() as ctxt:
                if not self.use_fatal_exceptions():
                    ctxt.reraise = False
                    # at least get the core message out if something happened
                    super(OctaviaException, self).__init__(self.message)

    def __unicode__(self):
        return unicode(self.msg)

    @staticmethod
    def use_fatal_exceptions():
        return False


# NOTE(blogan) Using webob exceptions here because WSME exceptions a very
# limited at this point and they do not work well in _lookup methods in the
# controllers
class APIException(exc.HTTPClientError):
    msg = "Something unknown went wrong"
    code = 500

    def __init__(self, **kwargs):
        self.msg = self.msg % kwargs
        super(APIException, self).__init__(detail=self.msg)


class NotFound(APIException):
    msg = _('%(resource)s %(id)s not found.')
    code = 404


class NotAuthorized(APIException):
    msg = _("Not authorized.")
    code = 401


class InvalidOption(APIException):
    msg = _("%(value)s is not a valid option for %(option)s")
    code = 400


class L7RuleValidation(APIException):
    msg = _("Error parsing L7Rule: %(error)s")
    code = 400


class InvalidHMACException(OctaviaException):
    message = _("HMAC hashes didn't match")


class MissingArguments(OctaviaException):
    message = _("Missing arguments.")


class NetworkConfig(OctaviaException):
    message = _("Unable to allocate network resource from config")


class NeedsPassphrase(OctaviaException):
    message = _("Passphrase needed to decrypt key but client "
                "did not provide one.")


class UnreadableCert(OctaviaException):
    message = _("Could not read X509 from PEM")


class MisMatchedKey(OctaviaException):
    message = _("Key and x509 certificate do not match")


class CertificateStorageException(OctaviaException):
    message = _('Could not store certificate: %(msg)s')


class CertificateGenerationException(OctaviaException):
    message = _('Could not sign the certificate request: %(msg)s')


class DuplicateListenerEntry(APIException):
    msg = _("Another Listener on this Load Balancer "
            "is already using protocol_port %(port)d")
    code = 409


class DuplicateMemberEntry(APIException):
    msg = _("Another member on this pool is already using ip %(ip_address)s "
            "on protocol_port %(port)d")
    code = 409


class DuplicateHealthMonitor(APIException):
    msg = _("This pool already has a health monitor")
    code = 409


class DuplicatePoolEntry(APIException):
    msg = _("This listener already has a default pool")
    code = 409


class PoolInUseByL7Policy(APIException):
    msg = _("Pool %(id)s is in use by L7 policy %(l7policy_id)s")
    code = 409


class ImmutableObject(APIException):
    msg = _("%(resource)s %(id)s is immutable and cannot be updated.")
    code = 409


class TooManyL7RulesOnL7Policy(APIException):
    message = _("Too many rules on L7 policy %(id)s")
    code = 409


class ComputeBuildException(OctaviaException):
    message = _LE('Failed to build compute instance.')


class ComputeDeleteException(OctaviaException):
    message = _LE('Failed to delete compute instance.')


class ComputeGetException(OctaviaException):
    message = _LE('Failed to retrieve compute instance.')


class ComputeStatusException(OctaviaException):
    message = _LE('Failed to retrieve compute instance status.')


class ComputeGetInterfaceException(OctaviaException):
    message = _LE('Failed to retrieve compute virtual interfaces.')


class IDAlreadyExists(OctaviaException):
    message = _LE('Already an entity with that specified id.')
    code = 409


class NoReadyAmphoraeException(OctaviaException):
    message = _LE('There are not any READY amphora available.')


class GlanceNoTaggedImages(OctaviaException):
    message = _LE("No Glance images are tagged with %(tag)s tag.")


class NoSuitableAmphoraException(OctaviaException):
    message = _LE('Unable to allocate an amphora due to: %(msg)s')


# This is an internal use exception for the taskflow work flow
# and will not be exposed to the customer.  This means it is a
# normal part of operation while waiting for compute to go active
# on the instance
class ComputeWaitTimeoutException(OctaviaException):
    message = _LI('Waiting for compute to go active timeout.')


class InvalidTopology(OctaviaException):
    message = _LE('Invalid topology specified: %(topology)s')


# L7 policy and rule exceptions
class InvalidL7PolicyAction(APIException):
    message = _LE('Invalid L7 Policy action specified: %(action)s')
    code = 400


class InvalidL7PolicyArgs(APIException):
    message = _LE('Invalid L7 Policy arguments: %(msg)s')
    code = 400


class InvalidURL(OctaviaException):
    message = _LE('Not a valid URL: %(url)s')


class InvalidString(OctaviaException):
    message = _LE('Invalid characters in %(what)s')


class InvalidRegex(OctaviaException):
    message = _LE('Unable to parse regular expression: %(e)s')


class InvalidL7Rule(OctaviaException):
    message = _LE('Invalid L7 Rule: $(msg)s')


class ServerGroupObjectCreateException(OctaviaException):
    message = _LE('Failed to create server group object.')


class ServerGroupObjectDeleteException(OctaviaException):
    message = _LE('Failed to delete server group object.')
