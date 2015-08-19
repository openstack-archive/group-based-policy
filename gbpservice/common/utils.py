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

import contextlib

from neutron.openstack.common import log as logging
from oslo.utils import importutils
from stevedore import driver

LOG = logging.getLogger(__name__)


@contextlib.contextmanager
def clean_session(session):
    # Cleans session by expunging persisted object. This avoids inconsistency
    # when multiple transactions are called with the same context.
    session.expunge_all()
    yield
    session.expunge_all()


def load_plugin(namespace, plugin):
    try:
        # Try to resolve plugin by name
        mgr = driver.DriverManager(namespace, plugin)
        plugin_class = mgr.driver
    except RuntimeError as e1:
        # fallback to class name
        try:
            plugin_class = importutils.import_class(plugin)
        except ImportError as e2:
            LOG.exception(_("Error loading plugin by name, %s"), e1)
            LOG.exception(_("Error loading plugin by class, %s"), e2)
            raise ImportError(_("Plugin not found."))
    return plugin_class()


class DictClass(dict):

    def __getattr__(self, item):
        return self[item]

    __setattr__ = dict.__setattr__
    __delattr__ = dict.__delattr__
