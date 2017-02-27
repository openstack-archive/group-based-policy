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


import time

from gbpservice.nfp.core import log as nfp_logging
from gbpservice.nfp.lib import nfp_exceptions

LOG = nfp_logging.getLogger(__name__)

sql_lock_support = True


class ContextManager(object):

    def __init__(self, session=None, suppress=tuple()):
        # suppress tuple holds the kind of exceptions
        # the we don't have re-raise
        self.session = session
        self.suppress = suppress

    def __enter__(self):
        pass

    def __exit__(self, Exptype, expvalue, traceback):

        if self.suppress and Exptype:
            if Exptype in self.suppress:
                return False
            for exception in self.suppress:
                if isinstance(Exptype, exception):
                    return False
        if not self.suppress and traceback:
            return True
        else:
            return False

    def retry(self, method, *args, **kwargs):
        tries = kwargs.pop('tries', 1)
        delay = 2
        backoff = 2
        while tries > 1:
            # Loop for 'tries-1' times and
            # the last time without any try-catch
            try:
                return method(*args, **kwargs)
            except Exception:
                msg = " %s retrying in %s seconds " % (self.__class__, delay)
                LOG.error(msg)

            time.sleep(delay)
            tries -= 1
            delay *= backoff
        return method(*args, **kwargs)


class NfpDbContextManager(ContextManager):

    def new(self, **kwargs):
        return NfpDbContextManager(**kwargs)

    def lock(self, session, method, *args, **kwargs):
        if not sql_lock_support:
            return method(session, *args, **kwargs)
        with session.begin(subtransactions=True):
            session.execute("SELECT GET_LOCK('nfp_db_lock', -1)")
            ret = method(session, *args, **kwargs)
            session.execute("SELECT RELEASE_LOCK('nfp_db_lock')")
            return ret

    def __enter__(self):
        super(NfpDbContextManager, self).__enter__()
        return self

    def __exit__(self, Exptype, expvalue, traceback):
        if super(NfpDbContextManager, self).__exit__(
                Exptype, expvalue, traceback):
            raise nfp_exceptions.DbException(Exptype, str(expvalue), traceback)

        # By default exit method returns False, if False is returned
        # the with block re-raises the exception. To suppress that
        # True should be returned explicitly

        return True


class NfpNovaContextManager(ContextManager):

    def new(self, **kwargs):
        return NfpNovaContextManager(**kwargs)

    def __enter__(self):
        super(NfpNovaContextManager, self).__enter__()
        return self

    def __exit__(self, Exptype, expvalue, traceback):
        if super(NfpNovaContextManager, self).__exit__(
                Exptype, expvalue, traceback):
            raise nfp_exceptions.NovaException(
                Exptype, str(expvalue), traceback)

        # By default exit method returns False, if False is returned
        # the with block re-raises the exception. To suppress that
        # True should be returned explicitly

        return True


class NfpKeystoneContextManager(ContextManager):

    def new(self, **kwargs):
        return NfpKeystoneContextManager(**kwargs)

    def __enter__(self):
        super(NfpKeystoneContextManager, self).__enter__()
        return self

    def __exit__(self, Exptype, expvalue, traceback):
        if super(NfpKeystoneContextManager, self).__exit__(
                Exptype, expvalue, traceback):
            raise nfp_exceptions.KeystoneException(
                Exptype, str(expvalue), traceback)
        # By default exit method returns False, if False is returned
        # the with block re-raises the exception. To suppress that
        # True should be returned explicitly

        return True


class NfpNeutronContextManager(ContextManager):

    def new(self, **kwargs):
        return NfpNeutronContextManager(**kwargs)

    def __enter__(self):
        super(NfpNeutronContextManager, self).__enter__()
        return self

    def __exit__(self, Exptype, expvalue, traceback):
        if super(NfpNeutronContextManager, self).__exit__(
                Exptype, expvalue, traceback):
            raise nfp_exceptions.NeutronException(
                Exptype, str(expvalue), traceback)

        # By default exit method returns False, if False is returned
        # the with block re-raises the exception. To suppress that
        # True should be returned explicitly

        return True


class NfpHeatContextManager(ContextManager):

    def new(self, **kwargs):
        return NfpHeatContextManager(**kwargs)

    def __enter__(self):
        super(NfpHeatContextManager, self).__enter__()
        return self

    def __exit__(self, Exptype, expvalue, traceback):
        if super(NfpHeatContextManager, self).__exit__(
                Exptype, expvalue, traceback):
            raise nfp_exceptions.HeatException(
                Exptype, str(expvalue), traceback)

        # By default exit method returns False, if False is returned
        # the with block re-raises the exception. To suppress that
        # True should be returned explicitly

        return True


class NfpGBPContextManager(ContextManager):

    def new(self, **kwargs):
        return NfpGBPContextManager(**kwargs)

    def __enter__(self):
        super(NfpGBPContextManager, self).__enter__()
        return self

    def __exit__(self, Exptype, expvalue, traceback):
        if super(NfpGBPContextManager, self).__exit__(
                Exptype, expvalue, traceback):
            raise nfp_exceptions.GBPException(
                Exptype, str(expvalue), traceback)

        # By default exit method returns False, if False is returned
        # the with block re-raises the exception. To suppress that
        # True should be returned explicitly

        return True

# Create the respective instances once, so that no need
# to instantiate them again any where

DbContextManager = NfpDbContextManager()
NovaContextManager = NfpNovaContextManager()
KeystoneContextManager = NfpKeystoneContextManager()
NeutronContextManager = NfpNeutronContextManager()
HeatContextManager = NfpHeatContextManager()
GBPContextManager = NfpGBPContextManager()
