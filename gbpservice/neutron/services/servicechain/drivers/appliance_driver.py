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

import ast
import time

from neutron.openstack.common import jsonutils
from neutron.openstack.common import log as logging
from neutron.plugins.common import constants as pconst


from gbpservice.neutron.services.servicechain.common import exceptions as exc
from gbpservice.neutron.services.servicechain.drivers import simplechain_driver


LOG = logging.getLogger(__name__)


class ChainWithTwoArmAppliance(simplechain_driver.SimpleChainDriver):


    def _fetch_template_and_params(self, context, sc_instance,
                                   sc_spec, sc_node):
        if sc_node['service_type'] == pconst.LOADBALANCER:
            return super(ChainWithTwoArmAppliance,
                         self)._fetch_template_and_params(context,
                                                          sc_instance,
                                                          sc_spec, sc_node)
        stack_template = sc_node.get('config')
        # TODO(Sumit):Raise an exception ??
        if not stack_template:
            LOG.error(_("Service Config is not defined for the service"
                        " chain Node"))
            return
        stack_template = jsonutils.loads(stack_template)
        config_param_values = sc_instance.get('config_param_values', {})
        stack_params = {}
        # config_param_values has the parameters for all Nodes. Only apply
        # the ones relevant for this Node
        if config_param_values:
            config_param_values = jsonutils.loads(config_param_values)
        config_param_names = sc_spec.get('config_param_names', [])
        if config_param_names:
            config_param_names = ast.literal_eval(config_param_names)

        provider_ptg_id = sc_instance.get("provider_ptg_id")
        consumer_ptg_id = sc_instance.get("consumer_ptg_id")
        for key in config_param_names or []:
            if "provider_ptg" in key:
                config_param_values[key] = provider_ptg_id
            elif key == "consumer_ptg":
                config_param_values[key] = consumer_ptg_id
        node_params = (stack_template.get('Parameters')
                       or stack_template.get('parameters'))
        if node_params:
            for parameter in config_param_values.keys():
                if parameter in node_params.keys():
                    stack_params[parameter] = config_param_values[parameter]
        return (stack_template, stack_params)
