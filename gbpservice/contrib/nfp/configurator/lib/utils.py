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

from gbpservice.nfp.core import log as nfp_logging
import inspect
import os
import sys

LOG = nfp_logging.getLogger(__name__)


class ConfiguratorUtils(object):
    """Utility class which provides common library functions for configurator.

       New common library functions, if needed, should be added in this class.
    """

    def __init__(self):
        pass

    def load_drivers(self, pkg):
        """Load all the driver class objects inside pkg. In each class in the
           pkg it will look for keywork 'service_type' or/and 'vendor' and
           select that class as driver class

        @param pkg : package
        e.g pkg = 'gbpservice.neutron.nsf.configurator.drivers.firewall'

        Returns: driver_objects dictionary
               e.g driver_objects = {'loadbalancer': <driver class object>}

        """
        driver_objects = {}

        base_driver = __import__(pkg,
                                 globals(), locals(), ['drivers'], -1)
        drivers_dir = base_driver.__path__[0]

        modules = []
        subdirectories = [x[0] for x in os.walk(drivers_dir)]
        for subd in subdirectories:
            syspath = sys.path
            sys.path = [subd] + syspath
            try:
                files = os.listdir(subd)
            except OSError:
                msg = ("Failed to read files from dir %s" % (subd))
                LOG.error(msg)
                files = []

            for fname in files:
                if fname.endswith(".py") and fname != '__init__.py':
                    modules += [__import__(fname[:-3])]
            sys.path = syspath

        for module in modules:
            for name, class_obj in inspect.getmembers(module):
                if inspect.isclass(class_obj):
                    key = ''
                    if hasattr(class_obj, 'service_type'):
                        key += class_obj.service_type
                    if hasattr(class_obj, 'service_vendor'):
                        key += class_obj.service_vendor
                    if key:
                        driver_objects[key] = class_obj

        return driver_objects

    def load_agents(self, pkg):
        """Load all the agents inside pkg.

        @param pkg : package
        e.g pkg = 'gbpservice.neutron.nsf.configurator.agents'

        Returns: imported_service_agents list

        """
        imported_service_agents = []
        base_agent = __import__(pkg,
                                globals(), locals(), ['agents'], -1)
        agents_dir = base_agent.__path__[0]
        syspath = sys.path
        sys.path = [agents_dir] + syspath
        try:
            files = os.listdir(agents_dir)
        except OSError:
            msg = ("Failed to read files from dir %s" % (agents_dir))
            LOG.error(msg)
            files = []

        for fname in files:
            if fname.endswith(".py") and fname != '__init__.py':
                agent = __import__(pkg, globals(),
                                   locals(), [fname[:-3]], -1)
                imported_service_agents += [
                                eval('agent.%s' % (fname[:-3]))]
                # modules += [__import__(fname[:-3])]
        sys.path = syspath
        return imported_service_agents
