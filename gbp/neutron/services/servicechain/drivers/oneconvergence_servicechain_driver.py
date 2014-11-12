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

import copy

import eventlet
from heatclient import client as heat_client
from neutron.common import log
from neutron.db import model_base
from neutron.openstack.common import log as logging
from oslo.config import cfg
import sqlalchemy as sa

from gbp.neutron.services.grouppolicy.drivers.oneconvergence import\
                                                         nvsd_gbp_api
from gbp.neutron.services.servicechain.drivers import simplechain_driver


eventlet.monkey_patch()

LOG = logging.getLogger(__name__)


class ServiceChainInstancePolicyMap(model_base.BASEV2):
    """NVSD Policy attached to the Service Chain Instance."""

    __tablename__ = 'nvsd_sc_instance_policies'
    instance_id = sa.Column(sa.String(36),
                            nullable=False, primary_key=True)
    policy_id = sa.Column(sa.String(36),
                          nullable=False, primary_key=True)


class PendingServiceChainInsertions(object):
    """Encapsulates a ServiceChain Insertion Operation"""

    def __init__(self, context, node_stacks, chain_instance_id,
                 provider_ptg, consumer_ptg, classifier):
        self.context = context
        self.node_stacks = node_stacks
        self.chain_instance_id = chain_instance_id
        self.provider_ptg = provider_ptg
        self.consumer_ptg = consumer_ptg
        self.classifier = classifier


class OneconvergenceServiceChainDriver(simplechain_driver.SimpleChainDriver):

    STATUSES = (CREATE_IN_PROGRESS, CREATE_FAILED, CREATE_COMPLETE
                ) = ('CREATE_IN_PROGRESS', 'CREATE_FAILED', 'CREATE_COMPLETE')

    def __init__(self):
        self.pending_chain_insertions = list()
        self.nvsd_api = nvsd_gbp_api.NVSDServiceApi()

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
        super(OneconvergenceServiceChainDriver,
              self).create_servicechain_instance_postcommit(context)
        node_stacks = self._get_chain_stacks(context._plugin_context.session,
                                           context.current['id'])
        thread_context = copy.copy(context._plugin_context)
        pendinginsertion = PendingServiceChainInsertions(
                                    thread_context,
                                    node_stacks,
                                    context.current['id'],
                                    context.current['provider_ptg'],
                                    context.current['consumer_ptg'],
                                    context.current['classifier'])
        eventlet.spawn_n(self._process_chain_processing, pendinginsertion)

    @log.log
    def update_servicechain_instance_postcommit(self, context):
        original_spec_id = context._original_sc_instance.get(
                                                    'servicechain_spec')
        new_spec_id = context._sc_instance.get('servicechain_spec')
        if original_spec_id != new_spec_id:
            newspec = context._plugin.get_servicechain_spec(
                                    context._plugin_context, new_spec_id)
            self._update_servicechain_instance(context, context._sc_instance,
                                               newspec)

    @log.log
    def delete_servicechain_instance_postcommit(self, context):
        self.delete_nvsd_policy(context, context.current['id'])
        self._delete_chain_policy_map(context._plugin_context.session,
                                      context.current['id'])
        super(OneconvergenceServiceChainDriver,
              self).delete_servicechain_instance_postcommit(context)

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
                                             context.current['provider_ptg'],
                                             context.current['consumer_ptg'],
                                             context.current['classifier'])
        eventlet.spawn_n(self._process_chain_processing, pendinginsertion)

    def _delete_chain_policy_map(self, session, sc_instance_id):
        with session.begin(subtransactions=True):
            policy_id = session.query(ServiceChainInstancePolicyMap).filter_by(
                                    instance_id=sc_instance_id).first()
            session.delete(policy_id)

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
        return self.nvsd_api.create_policy_action(context,
                                             action_body)

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
        #Supporting only one TAP in a chain
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
            #TODO(Magesh): Status has to be added to ServiceChainInstance
            #Update the Status to ERROR  at this point
            return True

        #Services are created by now. Determine Service IDs an setup
        #Traffic Steering.
        service_ids = self._fetch_serviceids_from_stack(context, node_stacks,
                                                        chain_instance_id)
        nvsd_action_list = self._create_nvsd_services_action(context,
                                                             service_ids)

        left_group = pending_chain.consumer_ptg
        right_group = pending_chain.provider_ptg
        classifier_id = pending_chain.classifier
        if nvsd_action_list:
            policy_id = self.create_nvsd_policy(context, left_group,
                                                right_group, classifier_id,
                                                nvsd_action_list)
            #TODO(Magesh): Need to store actions and rules also, because
            #cleanup will be missed if policy create failed
            self._add_chain_policy_map(context.session,
                                       chain_instance_id,
                                       policy_id)
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
