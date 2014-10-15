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
from heatclient import client as heat_client
from neutron.common import log
from neutron.db import model_base
from oslo.config import cfg
import sqlalchemy as sa


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
        pass

    @log.log
    def create_servicechain_node_postcommit(self, context):
        pass

    @log.log
    def update_servicechain_node_precommit(self, context):
        pass

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
        filters = {'servicechain_spec': [context.original['id']]}
        sc_instances = context._plugin.get_servicechain_instances(
                                    context._plugin_context, filters)
        if sc_instances:
            self._update_servicechain_instance(context,
                                               sc_instances[0],
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
        sc_spec_id = sc_instance.get('servicechain_spec')
        sc_spec = context._plugin.get_servicechain_spec(
            context._plugin_context, sc_spec_id)
        sc_node_ids = sc_spec.get('nodes')
        self._create_servicechain_instance_stacks(context, sc_node_ids,
                                                  sc_instance)

    @log.log
    def update_servicechain_instance_precommit(self, context):
        pass

    @log.log
    def update_servicechain_instance_postcommit(self, context):
        original_spec_id = context.original.get('servicechain_spec')
        new_spec_id = context.current.get('servicechain_spec')
        if original_spec_id != new_spec_id:
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

    def _create_servicechain_instance_stacks(self, context, sc_node_ids,
                                             sc_instance):
        heatclient = HeatClient(context._plugin_context)
        for sc_node_id in sc_node_ids:
            sc_node = context._plugin.get_servicechain_node(
                context._plugin_context, sc_node_id)
            stack_template = sc_node.get('config')
            if not stack_template:
                return
            stack_template = ast.literal_eval(stack_template)
            template_params = sc_instance.get('config_params', {})
            stack_param = {}
            #template_params has the parameters for all Nodes. Only apply
            #the ones relevant for this Node
            if template_params:
                instance_params = ast.literal_eval(template_params)
                stack_params = (stack_template.get('Parameters')
                                or stack_template.get('parameters'))
                if stack_params:
                    for parameter in (set(instance_params.keys()) &
                                      set(stack_params.keys())):
                        stack_param[parameter] = instance_params[parameter]

            stack = heatclient.create(
                "stack_" + sc_instance['name'] + sc_node['name']
                + sc_node['id'][:5],
                stack_template,
                stack_param)

            self._insert_chain_stack_db(context._plugin_context.session,
                                     sc_instance['id'], stack['stack']['id'])

    def _delete_servicechain_instance_stacks(self, context, instance_id):
        stack_ids = self._get_chain_stacks(context.session, instance_id)
        heatclient = HeatClient(context)
        for stack in stack_ids:
            heatclient.delete(stack.stack_id)
        self._delete_chain_stacks_db(context.session, instance_id)

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
                                                      sc_instance)

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

    def delete(self, id):
        return self.stacks.delete(id)
