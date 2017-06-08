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

from neutron.common import exceptions as n_exc
from neutron.db import api as db_api
from oslo_db import api as oslo_db_api
from oslo_db import exception as db_exc
from oslo_log import log as logging
from sqlalchemy.orm import exc


LOG = logging.getLogger(__name__)


def patched_is_nested_instance(e, etypes):
    """Check if exception or its inner excepts are an instance of etypes."""
    LOG.debug("Using patched_is_nested_instance")
    if etypes != db_exc.DBError:
        etypes = etypes + (db_exc.DBDeadlock, exc.StaleDataError,
                           db_exc.DBConnectionError, db_exc.DBDuplicateEntry,
                           db_exc.RetryRequest, )
        etypes = tuple(set(etypes))

    return (isinstance(e, etypes) or
            isinstance(e, n_exc.MultipleExceptions) and
            any(patched_is_nested_instance(
                i, etypes) for i in e.inner_exceptions))


db_api.is_nested_instance = patched_is_nested_instance


# Use newton version on mitaka. No patch needed on newer branches.
def patched_is_retriable(e):
    LOG.debug("Using patched_is_retriable")
    if getattr(e, '_RETRY_EXCEEDED', False):
        return False
    if db_api._is_nested_instance(e, (db_exc.DBDeadlock, exc.StaleDataError,
                                      db_exc.DBConnectionError,
                                      db_exc.DBDuplicateEntry,
                                      db_exc.RetryRequest)):
        return True
    # looking savepoints mangled by deadlocks. see bug/1590298 for details.
    return patched_is_nested_instance(e, db_exc.DBError) and '1305' in str(e)


db_api.is_retriable = patched_is_retriable


db_api.retry_db_errors = oslo_db_api.wrap_db_retry(
    max_retries=10,
    retry_on_request=True,
    exception_checker=patched_is_retriable
)
