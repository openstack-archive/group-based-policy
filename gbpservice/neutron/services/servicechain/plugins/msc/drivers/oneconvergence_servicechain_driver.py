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
import copy

import eventlet
from heatclient import client as heat_client
from neutron.api.v2 import attributes
from neutron.common import log
from neutron.db import model_base
from neutron.openstack.common import jsonutils
from neutron.openstack.common import log as logging
from oslo.config import cfg
import sqlalchemy as sa

from gbpservice.neutron.services.grouppolicy.drivers.oneconvergence import (
    nvsd_gbp_api as napi)
from gbpservice.neutron.services.servicechain.plugins.msc.drivers import (
    simplechain_driver as simplechain_driver)


eventlet.monkey_patch()

LOG = logging.getLogger(__name__)


class ServiceChainInstancePolicyMap(model_base.BASEV2):
    """NVSD Policy attached to the Service Chain Instance."""

    __tablename__ = 'nvsd_sc_instance_policies'
    instance_id = sa.Column(sa.String(36),
                            nullable=False, primary_key=True)
    policy_id = sa.Column(sa.String(36),
                          nullable=False, primary_key=True)


class ServiceChainInstanceVipEPMap(model_base.BASEV2):
    """NVSD Policy attached to the Service Chain Instance."""

    __tablename__ = 'nvsd_sc_instance_vip_eps'
    instance_id = sa.Column(sa.String(36),
                            nullable=False, primary_key=True)
    vip_port = sa.Column(sa.String(36),
                         nullable=False, primary_key=True)
    nvsd_ep_id = sa.Column(sa.String(36),
                          nullable=False, primary_key=True)


class PendingServiceChainInsertions(object):
    """Encapsulates a ServiceChain Insertion Operation"""

    def __init__(self, context, node_stacks, chain_instance_id,
                 provider_ptg_id, consumer_ptg_id, classifier_id):
        self.context = context
        self.node_stacks = node_stacks
        self.chain_instance_id = chain_instance_id
        self.provider_ptg_id = provider_ptg_id
        self.consumer_ptg_id = consumer_ptg_id
        self.classifier_id = classifier_id


class OneconvergenceServiceChainDriver(simplechain_driver.SimpleChainDriver):

    STATUSES = (CREATE_IN_PROGRESS, CREATE_FAILED, CREATE_COMPLETE
                ) = ('CREATE_IN_PROGRESS', 'CREATE_FAILED', 'CREATE_COMPLETE')

    def __init__(self):
        self.pending_chain_insertions = list()
        self.nvsd_api = napi.NVSDServiceApi()

    @log.log
    def create_servicechain_node_precommit(self, context):
        pass

    @log.log
    def create_servicechain_spec_precommit(self, context):
        super(OneconvergenceServiceChainDriver,
              self).create_servicechain_spec_precommit(context)

    @log.log
    def update_servicechain_spec_postcommit(self, context):
        filters = {'servicechain_spec': [context._original_sc_spec['id']]}
        sc_instances = context._plugin.get_servicechain_instances(
                                    context._plugin_context, filters)
        if sc_instances:
            self._update_servicechain_instance(context,
                                               sc_instances[0],
                                               context._sc_spec)

    @log.log
    def create_servicechain_instance_postcommit(self, context):
        self._create_servicechain_instance_postcommit(context)
        node_stacks = self._get_chain_stacks(context._plugin_context.session,
                                           context.current['id'])
        thread_context = copy.copy(context._plugin_context)
        pendinginsertion = PendingServiceChainInsertions(
                                    thread_context,
                                    node_stacks,
                                    context.current['id'],
                                    context.current['provider_ptg_id'],
                                    context.current['consumer_ptg_id'],
                                    context.current['classifier_id'])
        eventlet.spawn_n(self._process_chain_processing, pendinginsertion)

    @log.log
    def update_servicechain_instance_postcommit(self, context):
        original_spec_ids = context._original_sc_instance.get(
                                                    'servicechain_specs')
        new_spec_ids = context._sc_instance.get('servicechain_specs')
        if set(original_spec_ids) != set(new_spec_ids):
            for new_spec_id in new_spec_ids:
                newspec = context._plugin.get_servicechain_spec(
                    context._plugin_context, new_spec_id)
                self._update_servicechain_instance(context, context.current,
                                                   newspec)

    @log.log
    def delete_servicechain_instance_postcommit(self, context):
        self.delete_nvsd_policy(context, context.current['id'])
        self._delete_chain_policy_map(context._plugin_context.session,
                                      context.current['id'])
        self.delete_nvsd_ep(context, context.current['id'])
        super(OneconvergenceServiceChainDriver,
              self).delete_servicechain_instance_postcommit(context)

    def _get_l2p(self, context, l2p_id):
        return self._get_resource(self._grouppolicy_plugin,
                                  context._plugin_context,
                                  'l2_policy',
                                  l2p_id)

    def _get_member_ports(self, context, ptg_id):
        ptg = self._get_ptg(context, ptg_id)
        pt_ids = ptg.get("policy_targets")
        member_ports = []
        for pt_id in pt_ids:
            pt = self._get_pt(context, pt_id)
            port_id = pt.get("port_id")
            member_ports.append(port_id)
        return member_ports

    def _fetch_template_and_params(self, context, sc_instance,
                                   sc_spec, sc_node):
        stack_template = sc_node.get('config')
        if not stack_template:
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
        # TODO(magesh):Process on the basis of ResourceType rather than Name
        provider_ptg_id = sc_instance.get("provider_ptg_id")
        node_params = (stack_template.get('Parameters')
                       or stack_template.get('parameters'))
        if not node_params:
            return (stack_template, stack_params)
        for key in list(set(config_param_names) & set(node_params.keys())):
            if key == "PoolMemberIPs":
                value = self._get_member_ips(context, provider_ptg_id)
                # TODO(Magesh):Return one value for now
                value = value[0] if value else ""
                config_param_values[key] = value
            elif key == "pool_member_port":
                value = self._get_member_ports(context, provider_ptg_id)
                # TODO(Magesh):Return one value for now
                value = value[0] if value else ""
                config_param_values[key] = value
            elif key == "Subnet":
                value = self._get_ptg_subnet(context, provider_ptg_id)
                config_param_values[key] = value
            elif key == "vip_port":
                value = self._create_lb_service_port(context, provider_ptg_id)
                config_param_values[key] = value

        for parameter in list(set(config_param_values.keys()) &
                              set(node_params.keys())):
            if parameter in node_params.keys():
                stack_params[parameter] = config_param_values[parameter]
        return (stack_template, stack_params)

    def _create_servicechain_instance_stacks(self, context, sc_node_ids,
                                             sc_instance, sc_spec):
        for sc_node_id in sc_node_ids:
            sc_node = context._plugin.get_servicechain_node(
                context._plugin_context, sc_node_id)

            stack_template, stack_params = self._fetch_template_and_params(
                                context, sc_instance, sc_spec, sc_node)

            stack = HeatClient(context._plugin_context).create(
                "stack_" + sc_instance['name'] + sc_node['name']
                + sc_node['id'][:5],
                stack_template,
                stack_params)

            self._insert_chain_stack_db(context._plugin_context.session,
                                     sc_instance['id'], stack['stack']['id'])

    def _create_servicechain_instance_postcommit(self, context):
        sc_instance = context.current
        sc_spec_ids = sc_instance.get('servicechain_specs')
        for sc_spec_id in sc_spec_ids:
            sc_spec = context._plugin.get_servicechain_spec(
                context._plugin_context, sc_spec_id)
            sc_node_ids = sc_spec.get('nodes')
            self._create_servicechain_instance_stacks(context, sc_node_ids,
                                                      sc_instance, sc_spec)

    def _create_port(self, plugin_context, attrs):
        return self._create_resource(self._core_plugin, plugin_context, 'port',
                                     attrs)

    def _create_resource(self, plugin, context, resource, attrs):
        action = 'create_' + resource
        obj_creator = getattr(plugin, action)
        obj = obj_creator(context, {resource: attrs})
        return obj

    def _delete_resource(self, plugin, context, resource, resource_id):
        action = 'delete_' + resource
        obj_deleter = getattr(plugin, action)
        obj_deleter(context, resource_id)

    def _create_lb_service_port(self, context, ptg_id):
        ptg = self._get_ptg(context, ptg_id)
        subnet_id = ptg.get("subnets")[0]
        l2p_id = ptg['l2_policy_id']
        l2p = self._get_l2p(context, l2p_id)
        attrs = {'tenant_id': context.current['tenant_id'],
                 'name': 'ep_' + context.current['name'],
                 'network_id': l2p['network_id'],
                 'fixed_ips': [{"subnet_id": subnet_id}],
                 'mac_address': attributes.ATTR_NOT_SPECIFIED,
                 'device_id': '',
                 'device_owner': 'compute:service',
                 'port_security_enabled': False,
                 'security_groups': [],
                 'admin_state_up': True}
        port = self._create_port(context._plugin_context, attrs)
        port_id = port['id']
        body = {'tenant_id': context._plugin_context.tenant,
                'user_id': context._plugin_context.user,
                'policy_target_group_id': ptg_id,
                'port_id': port_id}
        nvsd_ep = self.nvsd_api.create_endpoint(context._plugin_context, body)
        ep_id = nvsd_ep['id']
        self._add_chain_nvsd_vip_ep_map(context._plugin_context.session,
                                    context.current['id'],
                                    ep_id,
                                    port_id)
        return port_id

    def _delete_port(self, plugin_context, port_id):
        self._delete_resource(self._core_plugin,
                              plugin_context, 'port', port_id)

    def delete_nvsd_ep(self, context, sc_instance_id):
        chain_nvsd_ep_map = self._get_chain_nvsd_ep_map(
                            context._plugin_context.session, sc_instance_id)
        if not chain_nvsd_ep_map:
            return
        nvsd_ep_id = chain_nvsd_ep_map.nvsd_ep_id
        vip_port = chain_nvsd_ep_map.vip_port
        self.nvsd_api.delete_endpoint(context._plugin_context,
                                      nvsd_ep_id)
        try:
            self._delete_port(context._plugin_context, vip_port)
        except Exception:
            pass
        self._delete_chain_nvsd_ep_map(context._plugin_context.session,
                                       sc_instance_id)

    def _update_servicechain_instance(self, context, sc_instance, newspec):
        self._delete_servicechain_instance_stacks(context._plugin_context,
                                                  sc_instance['id'])
        #Delete Policy and create new policy
        sc_node_ids = newspec.get('nodes')
        self._create_servicechain_instance_stacks(context,
                                                  sc_node_ids,
                                                  sc_instance)
        node_stacks = self._get_chain_stacks(context._plugin_context.session,
                                             context.current['id'])
        thread_context = copy.copy(context._plugin_context)
        pendinginsertion = PendingServiceChainInsertions(
                                           thread_context,
                                           node_stacks,
                                           context.current['id'],
                                           context.current['provider_ptg_id'],
                                           context.current['consumer_ptg_id'],
                                           context.current['classifier_id'])
        eventlet.spawn_n(self._process_chain_processing, pendinginsertion)

    def _delete_chain_policy_map(self, session, sc_instance_id):
        with session.begin(subtransactions=True):
            chain_policy_map = session.query(
                                    ServiceChainInstancePolicyMap).filter_by(
                                    instance_id=sc_instance_id).first()
            if chain_policy_map:
                session.delete(chain_policy_map)

    def _add_chain_policy_map(self, session, sc_instance_id, policy_id):
        with session.begin(subtransactions=True):
            chain_policy_map = ServiceChainInstancePolicyMap(
                                            instance_id=sc_instance_id,
                                            policy_id=policy_id)
            session.add(chain_policy_map)

    def _get_chain_policy_map(self, session, sc_instance_id):
        with session.begin(subtransactions=True):
            chain_policy_map = session.query(
                                ServiceChainInstancePolicyMap).filter_by(
                                    instance_id=sc_instance_id).first()
        return chain_policy_map

    def _delete_chain_nvsd_ep_map(self, session, sc_instance_id):
        with session.begin(subtransactions=True):
            chain_nvsd_ep_map = session.query(
                                    ServiceChainInstanceVipEPMap).filter_by(
                                    instance_id=sc_instance_id).first()
            if chain_nvsd_ep_map:
                session.delete(chain_nvsd_ep_map)

    def _add_chain_nvsd_vip_ep_map(self, session, sc_instance_id, nvsd_ep_id,
                                   port_id):
        with session.begin(subtransactions=True):
            chain_nvsd_ep_map = ServiceChainInstanceVipEPMap(
                                            instance_id=sc_instance_id,
                                            nvsd_ep_id=nvsd_ep_id,
                                            vip_port=port_id)
            session.add(chain_nvsd_ep_map)

    def _get_chain_nvsd_ep_map(self, session, sc_instance_id):
        with session.begin(subtransactions=True):
            chain_nvsd_ep_map = session.query(
                ServiceChainInstanceVipEPMap).filter_by(
                    instance_id=sc_instance_id).first()
        return chain_nvsd_ep_map

    def _process_chain_processing(self, pending_chain):
        while True:
            if self._perform_service_insertion(pending_chain):
                return

    def nvsd_get_service(self, context, service_id):
        return self.nvsd_api.get_nvsd_service(context,
                                              service_id)

    def create_nvsd_policy(self, context, left_group, right_group,
                           classifier_id, nvsd_action_list):
        #Create rule and policy in SC with the classifier and action list
        rule_ids = []
        for action in nvsd_action_list:
            body = {'tenant_id': context.tenant,
                    'user_id': context.user,
                    'classifier': classifier_id,
                    'actions': [action],
                    'policies_attached': []}
            rule = self.nvsd_api.create_policy_rule(context,
                                                    body)
            rule_ids.append(rule.get("id"))

        body = {'tenant_id': context.tenant,
                'user_id': context.user,
                'left_group': left_group,
                'right_group': right_group,
                'rules': rule_ids}
        nvsd_policy = self.nvsd_api.create_policy(context,
                                                  body)
        return nvsd_policy.get('id')

    def delete_nvsd_policy(self, context, sc_instance_id):
        chain_nvsd_policy_map = self._get_chain_policy_map(
                            context._plugin_context.session, sc_instance_id)
        if not chain_nvsd_policy_map:
            return
        nvsd_policy_id = chain_nvsd_policy_map.policy_id
        nvsd_policy = self.nvsd_api.get_policy(context._plugin_context,
                                               nvsd_policy_id)
        self.nvsd_api.delete_policy(context._plugin_context,
                                    nvsd_policy_id)
        for rule_id in nvsd_policy.get("rules"):
            rule = self.nvsd_api.get_policy_rule(context._plugin_context,
                                                 rule_id)
            self.nvsd_api.delete_policy_rule(context._plugin_context, rule_id)
            for action_id in rule.get("actions"):
                self.nvsd_api.delete_policy_action(context._plugin_context,
                                                   action_id)

    def checkStackStatus(self, context, node_stacks):
        for node_stack in node_stacks:
            stack = HeatClient(context).stacks.get(node_stack.stack_id)
            #CREATE_COMPLETE, CREATE_IN_PROGRESS, CREATE_FAILED
            if stack.stack_status == self.CREATE_IN_PROGRESS:
                return self.CREATE_IN_PROGRESS
            elif stack.stack_status == self.CREATE_FAILED:
                return self.CREATE_FAILED
            elif stack.stack_status != self.CREATE_COMPLETE:
                return self.CREATE_FAILED
        return self.CREATE_COMPLETE

    def _fetch_serviceids_from_stack(self, context, node_stacks,
                                     chain_instance_id):
        service_ids = []
        for node_stack in node_stacks:
            stack_resources = HeatClient(context).resources.list(
                                                    node_stack.stack_id)
            for resource in stack_resources:
                if resource.resource_type == "OC::ES::Service":
                    service_id = resource.physical_resource_id
                    service_ids.append(service_id)
                    break
        return service_ids

    def create_nvsd_action(self, context, action_body):
        return self.nvsd_api.create_policy_action(context, action_body)

    def _create_nvsd_services_action(self, context, service_ids):
        nvsd_action_list = []
        copy_action = None
        l2redirect_action = None
        for service_id in service_ids:
            service = self.nvsd_get_service(context, service_id)
            if service['insertion_mode'] == "L2":
                if not l2redirect_action:
                    l2redirect_action = {"action_type": "L2REDIRECT",
                                         'tenant_id': context.tenant,
                                         'user_id': context.user,
                                         "action_value": service_id}
                else:
                    if l2redirect_action.get("action_value"):
                        l2redirect_action['action_value_list'] = [{
                                            "service": l2redirect_action[
                                                            'action_value']}]
                        del l2redirect_action['action_value']
                    else:
                        l2redirect_action['action_value_list'].append({
                                                        "service": service_id})
            elif service['insertion_mode'] == "TAP":
                copy_action = {"action_type": "TAP",
                               'tenant_id': context.tenant,
                               'user_id': context.user,
                               "action_value": service_id}
        # Supporting only one TAP in a chain
        if copy_action:
            action = self.create_nvsd_action(context, copy_action)
            nvsd_action_list.append(action['id'])
        if l2redirect_action:
            action = self.create_nvsd_action(context, l2redirect_action)
            nvsd_action_list.append(action['id'])
        return nvsd_action_list

    def _perform_service_insertion(self, pending_chain):
        context = pending_chain.context
        node_stacks = pending_chain.node_stacks
        chain_instance_id = pending_chain.chain_instance_id

        status = self.checkStackStatus(context, node_stacks)
        if status == self.CREATE_IN_PROGRESS:
            return False
        elif status == self.CREATE_FAILED:
            # TODO(Magesh): Status has to be added to ServiceChainInstance
            # Update the Status to ERROR  at this point
            return True

        # Services are created by now. Determine Service IDs an setup
        # Traffic Steering.
        service_ids = self._fetch_serviceids_from_stack(context, node_stacks,
                                                        chain_instance_id)
        nvsd_action_list = self._create_nvsd_services_action(context,
                                                             service_ids)

        left_group = pending_chain.consumer_ptg_id
        right_group = pending_chain.provider_ptg_id
        classifier_id = pending_chain.classifier_id
        if nvsd_action_list:
            policy_id = self.create_nvsd_policy(context, left_group,
                                                right_group, classifier_id,
                                                nvsd_action_list)
            # TODO(Magesh): Need to store actions and rules also, because
            # cleanup will be missed if policy create failed
            self._add_chain_policy_map(
                    context.session, chain_instance_id, policy_id)
        return True


class HeatClient:
    def __init__(self, context, password=None):
        api_version = "1"
        endpoint = "%s/%s" % (cfg.CONF.servicechain.heat_uri, context.tenant)
        kwargs = {
            'token': context.auth_token,
            'username': context.user_name,
            'password': password
        }
        self.client = heat_client.Client(api_version, endpoint, **kwargs)
        self.stacks = self.client.stacks
        self.resources = self.client.resources

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

    def list(self, stack_id):
        return self.resources.list(stack_id)
