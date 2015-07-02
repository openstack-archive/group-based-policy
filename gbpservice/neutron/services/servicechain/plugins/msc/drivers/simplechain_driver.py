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

from heatclient import client as heat_client
from heatclient import exc as heat_exc
from neutron.common import log
from neutron.db import model_base
from neutron import manager
from neutron.openstack.common import jsonutils
from neutron.openstack.common import log as logging
from neutron.plugins.common import constants as pconst
from oslo.config import cfg
import sqlalchemy as sa


from gbpservice.neutron.services.servicechain.common import exceptions as exc


LOG = logging.getLogger(__name__)

service_chain_opts = [
    cfg.IntOpt('stack_delete_retries',
               default=5,
               help=_("Number of attempts to retry for stack deletion")),
    cfg.IntOpt('stack_delete_retry_wait',
               default=3,
               help=_("Wait time between two successive stack delete "
                      "retries")),
    cfg.StrOpt('heat_uri',
               default='http://localhost:8004/v1',
               help=_("Heat server address to create services "
                      "specified in the service chain.")),
    cfg.StrOpt('heat_ca_certificates_file', default=None,
               help=_('CA file for heatclient to verify server certificates')),
    cfg.BoolOpt('heat_api_insecure', default=False,
                help=_("If True, ignore any SSL validation issues")),
]


cfg.CONF.register_opts(service_chain_opts, "simplechain")

# Service chain API supported Values
sc_supported_type = [pconst.LOADBALANCER, pconst.FIREWALL]
STACK_DELETE_RETRIES = cfg.CONF.simplechain.stack_delete_retries
STACK_DELETE_RETRY_WAIT = cfg.CONF.simplechain.stack_delete_retry_wait


class ServiceChainInstanceStack(model_base.BASEV2):
    """ServiceChainInstance stacks owned by the servicechain driver."""

    __tablename__ = 'sc_instance_stacks'
    instance_id = sa.Column(sa.String(36),
                            nullable=False, primary_key=True)
    stack_id = sa.Column(sa.String(36),
                         nullable=False, primary_key=True)


class SimpleChainDriver(object):

    @log.log
    def initialize(self):
        pass

    @log.log
    def create_servicechain_node_precommit(self, context):
        if context.current['service_profile_id'] is None:
            if context.current['service_type'] not in sc_supported_type:
                raise exc.InvalidServiceTypeForReferenceDriver()
        elif context.current['service_type']:
            LOG.warn(_('Both service_profile_id and service_type are'
                       'specified, service_type will be ignored.'))

    @log.log
    def create_servicechain_node_postcommit(self, context):
        pass

    @log.log
    def update_servicechain_node_precommit(self, context):
        if (context.original['config'] != context.current['config']):
            filters = {'servicechain_spec': context.original[
                                                'servicechain_specs']}
            sc_instances = context._plugin.get_servicechain_instances(
                context._plugin_context, filters)
            if sc_instances:
                raise exc.NodeUpdateNotSupported()

    @log.log
    def update_servicechain_node_postcommit(self, context):
        pass

    @log.log
    def delete_servicechain_node_precommit(self, context):
        pass

    @log.log
    def delete_servicechain_node_postcommit(self, context):
        pass

    @log.log
    def create_servicechain_spec_precommit(self, context):
        pass

    @log.log
    def create_servicechain_spec_postcommit(self, context):
        pass

    @log.log
    def update_servicechain_spec_precommit(self, context):
        pass

    @log.log
    def update_servicechain_spec_postcommit(self, context):
        if context.original['nodes'] != context.current['nodes']:
            filters = {'servicechain_spec': [context.original['id']]}
            sc_instances = context._plugin.get_servicechain_instances(
                context._plugin_context, filters)
            for sc_instance in sc_instances:
                self._update_servicechain_instance(context,
                                                   sc_instance,
                                                   context._sc_spec)

    @log.log
    def delete_servicechain_spec_precommit(self, context):
        pass

    @log.log
    def delete_servicechain_spec_postcommit(self, context):
        pass

    @log.log
    def create_servicechain_instance_precommit(self, context):
        pass

    @log.log
    def create_servicechain_instance_postcommit(self, context):
        sc_instance = context.current
        sc_spec_ids = sc_instance.get('servicechain_specs')
        for sc_spec_id in sc_spec_ids:
            sc_spec = context._plugin.get_servicechain_spec(
                context._plugin_context, sc_spec_id)
            sc_node_ids = sc_spec.get('nodes')
            self._create_servicechain_instance_stacks(context, sc_node_ids,
                                                      sc_instance, sc_spec)

    @log.log
    def update_servicechain_instance_precommit(self, context):
        pass

    @log.log
    def update_servicechain_instance_postcommit(self, context):
        original_spec_ids = context.original.get('servicechain_specs')
        new_spec_ids = context.current.get('servicechain_specs')
        if set(original_spec_ids) != set(new_spec_ids):
            for new_spec_id in new_spec_ids:
                newspec = context._plugin.get_servicechain_spec(
                    context._plugin_context, new_spec_id)
                self._update_servicechain_instance(context, context.current,
                                                   newspec)

    @log.log
    def delete_servicechain_instance_precommit(self, context):
        pass

    @log.log
    def delete_servicechain_instance_postcommit(self, context):
        self._delete_servicechain_instance_stacks(context._plugin_context,
                                                  context.current['id'])

    @log.log
    def create_service_profile_precommit(self, context):
        if context.current['service_type'] not in sc_supported_type:
            raise exc.InvalidServiceTypeForReferenceDriver()

    @log.log
    def create_service_profile_postcommit(self, context):
        pass

    @log.log
    def update_service_profile_precommit(self, context):
        pass

    @log.log
    def update_service_profile_postcommit(self, context):
        pass

    @log.log
    def delete_service_profile_precommit(self, context):
        pass

    @log.log
    def delete_service_profile_postcommit(self, context):
        pass

    def _get_ptg(self, context, ptg_id):
        return self._get_resource(self._grouppolicy_plugin,
                                  context._plugin_context,
                                  'policy_target_group',
                                  ptg_id)

    def _get_pt(self, context, pt_id):
        return self._get_resource(self._grouppolicy_plugin,
                                  context._plugin_context,
                                  'policy_target',
                                  pt_id)

    def _get_port(self, context, port_id):
        return self._get_resource(self._core_plugin,
                                  context._plugin_context,
                                  'port',
                                  port_id)

    def _get_ptg_subnet(self, context, ptg_id):
        ptg = self._get_ptg(context, ptg_id)
        return ptg.get("subnets")[0]

    def _get_member_ips(self, context, ptg_id):
        ptg = self._get_ptg(context, ptg_id)
        pt_ids = ptg.get("policy_targets")
        member_addresses = []
        for pt_id in pt_ids:
            pt = self._get_pt(context, pt_id)
            port_id = pt.get("port_id")
            port = self._get_port(context, port_id)
            ipAddress = port.get('fixed_ips')[0].get("ip_address")
            member_addresses.append(ipAddress)
        return member_addresses

    def _fetch_template_and_params(self, context, sc_instance,
                                   sc_spec, sc_node):
        stack_template = sc_node.get('config')
        # TODO(magesh):Raise an exception ??
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

        # This service chain driver knows how to fill in two parameter values
        # for the template at present.
        # 1)Subnet -> Provider PTG subnet is used
        # 2)PoolMemberIPs -> List of IP Addresses of all PTs in Provider PTG

        # TODO(magesh):Process on the basis of ResourceType rather than Name
        # eg: Type: OS::Neutron::PoolMember
        # Variable number of pool members is not handled yet. We may have to
        # dynamically modify the template json to achieve that
        member_ips = []
        provider_ptg_id = sc_instance.get("provider_ptg_id")
        # If we have the key "PoolMemberIP*" in template input parameters,
        # fetch the list of IPs of all PTs in the PTG
        for key in config_param_names or []:
            if "PoolMemberIP" in key:
                member_ips = self._get_member_ips(context, provider_ptg_id)
                break

        member_count = 0
        for key in config_param_names or []:
            if "PoolMemberIP" in key:
                value = (member_ips[member_count]
                         if len(member_ips) > member_count else '0')
                member_count = member_count + 1
                config_param_values[key] = value
            elif key == "Subnet":
                value = self._get_ptg_subnet(context, provider_ptg_id)
                config_param_values[key] = value
        node_params = (stack_template.get('Parameters')
                       or stack_template.get('parameters'))
        if node_params:
            for parameter in config_param_values.keys():
                if parameter in node_params.keys():
                    stack_params[parameter] = config_param_values[parameter]
        return (stack_template, stack_params)

    def _create_servicechain_instance_stacks(self, context, sc_node_ids,
                                             sc_instance, sc_spec):
        heatclient = HeatClient(context._plugin_context)
        for sc_node_id in sc_node_ids:
            sc_node = context._plugin.get_servicechain_node(
                context._plugin_context, sc_node_id)

            stack_template, stack_params = self._fetch_template_and_params(
                context, sc_instance, sc_spec, sc_node)

            stack_name = ("stack_" + sc_instance['name'] + sc_node['name'] +
                          sc_instance['id'][:8])
            stack = heatclient.create(
                stack_name.replace(" ", ""), stack_template, stack_params)

            self._insert_chain_stack_db(
                context._plugin_context.session, sc_instance['id'],
                stack['stack']['id'])

    def _delete_servicechain_instance_stacks(self, context, instance_id):
        stack_ids = self._get_chain_stacks(context.session, instance_id)
        heatclient = HeatClient(context)
        for stack in stack_ids:
            heatclient.delete(stack.stack_id)
        for stack in stack_ids:
            self._wait_for_stack_delete(heatclient, stack.stack_id)
        self._delete_chain_stacks_db(context.session, instance_id)

    # Wait for the heat stack to be deleted for a maximum of 15 seconds
    # we check the status every 3 seconds and call sleep again
    # This is required because cleanup of subnet fails when the stack created
    # some ports on the subnet and the resource delete is not completed by
    # the time subnet delete is triggered by Resource Mapping driver
    def _wait_for_stack_delete(self, heatclient, stack_id):
        stack_delete_retries = STACK_DELETE_RETRIES
        while True:
            try:
                stack = heatclient.get(stack_id)
                if stack.stack_status == 'DELETE_COMPLETE':
                    return
                elif stack.stack_status == 'DELETE_FAILED':
                    heatclient.delete(stack_id)
            except Exception:
                LOG.exception(_("Service Chain Instance cleanup may not have "
                                "happened because Heat API request failed "
                                "while waiting for the stack %(stack)s to be "
                                "deleted"), {'stack': stack_id})
                return
            else:
                time.sleep(STACK_DELETE_RETRY_WAIT)
                stack_delete_retries = stack_delete_retries - 1
                if stack_delete_retries == 0:
                    LOG.warn(_("Resource cleanup for service chain instance is"
                               " not completed within %(wait)s seconds as "
                               "deletion of Stack %(stack)s is not completed"),
                             {'wait': (STACK_DELETE_RETRIES *
                                       STACK_DELETE_RETRY_WAIT),
                              'stack': stack_id})
                    return
                else:
                    continue

    def _get_instance_by_spec_id(self, context, spec_id):
        filters = {'servicechain_spec': [spec_id]}
        return context._plugin.get_servicechain_instances(
            context._plugin_context, filters)

    def _update_servicechain_instance(self, context, sc_instance, newspec):
        self._delete_servicechain_instance_stacks(context._plugin_context,
                                                  sc_instance['id'])
        sc_node_ids = newspec.get('nodes')
        self._create_servicechain_instance_stacks(context,
                                                  sc_node_ids,
                                                  sc_instance,
                                                  newspec)

    def _delete_chain_stacks_db(self, session, sc_instance_id):
        with session.begin(subtransactions=True):
            stacks = session.query(ServiceChainInstanceStack
                                   ).filter_by(instance_id=sc_instance_id
                                               ).all()
            for stack in stacks:
                session.delete(stack)

    def _insert_chain_stack_db(self, session, sc_instance_id, stack_id):
        with session.begin(subtransactions=True):
            chainstack = ServiceChainInstanceStack(
                instance_id=sc_instance_id,
                stack_id=stack_id)
            session.add(chainstack)

    def _get_chain_stacks(self, session, sc_instance_id):
        with session.begin(subtransactions=True):
            stack_ids = session.query(ServiceChainInstanceStack.stack_id
                                      ).filter_by(instance_id=sc_instance_id
                                                  ).all()
        return stack_ids

    def _get_resource(self, plugin, context, resource, resource_id):
        obj_getter = getattr(plugin, 'get_' + resource)
        obj = obj_getter(context, resource_id)
        return obj

    @property
    def _core_plugin(self):
        # REVISIT(Magesh): Need initialization method after all
        # plugins are loaded to grab and store plugin.
        return manager.NeutronManager.get_plugin()

    @property
    def _grouppolicy_plugin(self):
        # REVISIT(Magesh): Need initialization method after all
        # plugins are loaded to grab and store plugin.
        plugins = manager.NeutronManager.get_service_plugins()
        grouppolicy_plugin = plugins.get(pconst.GROUP_POLICY)
        if not grouppolicy_plugin:
            LOG.error(_("No Grouppolicy service plugin found."))
            raise exc.ServiceChainDeploymentError()
        return grouppolicy_plugin


class HeatClient:

    def __init__(self, context, password=None):
        api_version = "1"
        endpoint = "%s/%s" % (cfg.CONF.simplechain.heat_uri, context.tenant)
        kwargs = {
            'token': context.auth_token,
            'username': context.user_name,
            'password': password
        }
        self.client = heat_client.Client(api_version, endpoint, **kwargs)
        self.stacks = self.client.stacks

    def create(self, name, data, parameters=None):
        fields = {
            'stack_name': name,
            'timeout_mins': 10,
            'disable_rollback': True,
            'password': data.get('password')
        }
        fields['template'] = data
        fields['parameters'] = parameters
        return self.stacks.create(**fields)

    def delete(self, stack_id):
        try:
            self.stacks.delete(stack_id)
        except heat_exc.HTTPNotFound:
            LOG.warn(_("Stack %(stack)s created by service chain driver is "
                       "not found at cleanup"), {'stack': stack_id})

    def get(self, stack_id):
        return self.stacks.get(stack_id)
