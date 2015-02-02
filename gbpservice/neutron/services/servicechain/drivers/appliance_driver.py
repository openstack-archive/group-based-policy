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

from neutron.common import log
from neutron.openstack.common import jsonutils
from neutron.openstack.common import log as logging
from neutron.plugins.common import constants as pconst
from oslo.config import cfg

from gbpservice.neutron.services.servicechain.common import exceptions as exc
from gbpservice.neutron.services.servicechain.drivers import simplechain_driver


appliance_driver_opts = [
    cfg.StrOpt('management_ptg_name',
               default='Management PTG',
               help=_("Name of the PTG that is associated with the "
                      "management network")),
]

cfg.CONF.register_opts(appliance_driver_opts, "appliance_driver")

sc_supported_type = [pconst.LOADBALANCER, 'FIREWALL_TRANSPARENT', 'IDS']
TRANSPARENT_PT = "transparent"
SERVICE_PT = "service"
PROVIDER_PT_NAME = "chain_provider_%s_%s"
CONSUMER_PT_NAME = "chain_consumer_%s_%s"
SC_METADATA = '{"sc_instance":"%s", "order":"%s", "provider_ptg":"%s"}'
MANAGEMENT_PTG_NAME = cfg.CONF.appliance_driver.management_ptg_name

LOG = logging.getLogger(__name__)


class ChainWithTwoArmAppliance(simplechain_driver.SimpleChainDriver):

    @log.log
    def create_servicechain_node_precommit(self, context):
        if context.current['service_type'] not in sc_supported_type:
            raise exc.InvalidServiceTypeForReferenceDriver()

    def _fetch_template_and_params(self, context, sc_instance,
                                   sc_spec, sc_node, order):
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

        provider_ptg_id = sc_instance.get('provider_ptg_id')
        consumer_ptg_id = sc_instance.get('consumer_ptg_id')
        sc_instance_id = sc_instance['id']
        filters = {'name': [MANAGEMENT_PTG_NAME]}
        management_ptgs = self._grouppolicy_plugin.get_policy_target_groups(
            context._plugin_context, filters)
        pt_type = TRANSPARENT_PT

        if sc_node['service_type'] == pconst.LOADBALANCER:
            pt_type = SERVICE_PT
            member_ips = []

            if 'Subnet' in config_param_names:
                value = self._get_ptg_subnet(context, provider_ptg_id)
                config_param_values['Subnet'] = value

            if any('PoolMemberIP' in s for s in config_param_names):
                member_ips = self._get_member_ips(context, provider_ptg_id)

            member_count = 0
            for key in config_param_names or []:
                if 'PoolMemberIP' in key:
                    value = (member_ips[member_count]
                             if len(member_ips) > member_count else '0')
                    member_count += 1
                    config_param_values[key] = value

        if 'provider_ptg' in config_param_names:
            config_param_values['provider_ptg'] = provider_ptg_id
        if 'consumer_ptg' in config_param_names:
            config_param_values['consumer_ptg'] = consumer_ptg_id
        if 'provider_pt_name' in config_param_names:
            config_param_values['provider_pt_name'] = PROVIDER_PT_NAME % (
                order, pt_type)
        if 'consumer_pt_name' in config_param_names:
            config_param_values['consumer_pt_name'] = CONSUMER_PT_NAME % (
                order, pt_type)
        if 'service_chain_metadata' in config_param_names:
            config_param_values['service_chain_metadata'] = (
                SC_METADATA % (sc_instance_id, order, provider_ptg_id))
        if 'management_ptg' in config_param_names:
            config_param_values['management_ptg'] = management_ptgs[0]['id']

        node_params = (stack_template.get('Parameters')
                       or stack_template.get('parameters'))
        if node_params:
            for parameter in config_param_values.keys():
                if parameter in node_params.keys():
                    stack_params[parameter] = config_param_values[parameter]
        return (stack_template, stack_params)
