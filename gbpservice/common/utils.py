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
from oslo_utils import importutils
from stevedore import driver

LOG = logging.getLogger(__name__)


def load_driver(namespace, driver_name):
    try:
        # Try to resolve driver by name
        mgr = driver.DriverManager(namespace, driver_name)
        driver_class = mgr.driver
    except RuntimeError as e1:
        # fallback to class name
        try:
            driver_class = importutils.import_class(driver_name)
        except ImportError as e2:
            LOG.exception(_("Error loading driver by name, %s"), e1)
            LOG.exception(_("Error loading driver by class, %s"), e2)
            raise ImportError(_("Driver not found."))
    return driver_class()


def get_resource_plural(resource):
    if resource.endswith('y'):
        resource_plural = resource.replace('y', 'ies')
    else:
        resource_plural = resource + 's'

    return resource_plural


class DictClass(dict):

    def __getattr__(self, item):
        return self[item]

    __setattr__ = dict.__setattr__
    __delattr__ = dict.__delattr__
