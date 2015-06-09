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

import time

from neutron.common import log
from neutron.db import model_base
from neutron.plugins.common import constants as pconst
from oslo_config import cfg
from oslo_log import log as logging
from oslo_serialization import jsonutils
import sqlalchemy as sa

from gbpservice.neutron.services.servicechain.plugins.ncp import (
                                                    exceptions as exc)
from gbpservice.neutron.services.servicechain.plugins.ncp import driver_base
from gbpservice.neutron.services.servicechain.plugins.ncp.node_drivers import (
                                openstack_heat_api_client as heat_api_client)

LOG = logging.getLogger(__name__)

service_chain_opts = [
    cfg.IntOpt('stack_action_wait_time',
               default=15,
               help=_("Seconds to wait for pending stack operation "
                      "to complete")),
    cfg.StrOpt('heat_uri',
               default='http://localhost:8004/v1',
               help=_("Heat API server address to instantiate services "
                      "specified in the service chain.")),
]

cfg.CONF.register_opts(service_chain_opts, "servicechain")
STACK_ACTION_WAIT_TIME = cfg.CONF.servicechain.stack_action_wait_time
STACK_ACTION_RETRY_WAIT = 5  # Retry after every 5 seconds


class ServiceNodeInstanceStack(model_base.BASEV2):
    """ServiceChainInstance stacks owned by the Node driver."""

    __tablename__ = 'node_instance_stacks'
    sc_instance_id = sa.Column(sa.String(36),
                               nullable=False, primary_key=True)
    sc_node_id = sa.Column(sa.String(36),
                           nullable=False, primary_key=True)
    stack_id = sa.Column(sa.String(36),
                         nullable=False, primary_key=True)


class InvalidServiceType(exc.NodeCompositionPluginBadRequest):
    message = _("The Template Node driver only supports the services "
                "Firewall and LB in a Service Chain")


class ProfileUpdateNotSupported(exc.NodeCompositionPluginBadRequest):
    message = _("The Template Node driver does not allow updating the "
                "service profile used by a Node")


class ServiceTypeUpdateNotSupported(exc.NodeCompositionPluginBadRequest):
    message = _("The Template Node driver does not allow updating the "
                "service type used by a Node")


class TemplateNodeDriver(driver_base.NodeDriverBase):

    sc_supported_type = [pconst.LOADBALANCER, pconst.FIREWALL]
    initialized = False

    @log.log
    def initialize(self, name):
        self.initialized = True
        self._name = name

    @log.log
    def get_plumbing_info(self, context):
        pass

    @log.log
    def validate_create(self, context):
        if context.current_node['service_profile_id'] is None:
            if (context.current_node['service_type'] not in
                self.sc_supported_type):
                raise InvalidServiceType()
        elif (context.current_profile['service_type'] not in
              self.sc_supported_type):
            raise InvalidServiceType()
        else:
            return True

    @log.log
    def validate_update(self, context):
        if context.current_profile != context.original_profile:
            raise ProfileUpdateNotSupported()
        if (context.current_node['service_type'] !=
            context.original_node['service_type']):
            raise ServiceTypeUpdateNotSupported()
        else:
            return True

    @log.log
    def create(self, context):
        heatclient = heat_api_client.HeatClient(
                            context.plugin_context,
                            cfg.CONF.servicechain.heat_uri)

        stack_template, stack_params = self._fetch_template_and_params(context)

        stack_name = ("stack_" + context.instance['name'] +
                      context.current_node['name'] +
                      context.instance['id'][:8] +
                      context.current_node['id'][:8])
        # Heat does not accept space in stack name
        stack_name = stack_name.replace(" ", "")
        stack = heatclient.create(stack_name, stack_template, stack_params)

        self._insert_node_instance_stack_in_db(
            context.plugin_session, context.current_node['id'],
            context.instance['id'], stack['stack']['id'])

    @log.log
    def delete(self, context):
        stack_ids = self._get_node_instance_stacks(context.plugin_session,
                                                   context.current_node['id'],
                                                   context.instance['id'])
        heatclient = heat_api_client.HeatClient(
                                context.plugin_context,
                                cfg.CONF.servicechain.heat_uri)
        for stack in stack_ids:
            heatclient.delete(stack.stack_id)
        for stack in stack_ids:
            self._wait_for_stack_operation_complete(
                                heatclient, stack.stack_id, 'delete')
        self._delete_node_instance_stack_in_db(context.plugin_session,
                                               context.current_node['id'],
                                               context.instance['id'])

    @log.log
    def update(self, context):
        heatclient = heat_api_client.HeatClient(
                            context.plugin_context,
                            cfg.CONF.servicechain.heat_uri)

        stack_template, stack_params = self._fetch_template_and_params(context)

        stack_ids = self._get_node_instance_stacks(context.plugin_session,
                                                   context.current_node['id'],
                                                   context.instance['id'])
        for stack_id in stack_ids:
            self._wait_for_stack_operation_complete(
                                heatclient, stack_id, 'update')
            heatclient.update(stack_id, stack_template, stack_params)

    @log.log
    def update_policy_target_added(self, context, policy_target):
        pass

    @log.log
    def update_policy_target_removed(self, context, policy_target):
        pass

    @property
    def name(self):
        return self._name

    def _fetch_template_and_params(self, context):
        sc_instance = context.instance
        sc_node = context.current_node
        provider_ptg = context.provider
        # TODO(Magesh): Handle multiple subnets
        provider_ptg_subnet_id = provider_ptg['subnets'][0]

        stack_template = sc_node.get('config')
        # TODO(magesh):Raise an exception
        if not stack_template:
            LOG.error(_("Service Config is not defined for the service"
                        " chain Node"))
            return

        stack_template = jsonutils.loads(stack_template)
        config_param_values = sc_instance.get('config_param_values', {})
        stack_params = {}

        if config_param_values:
            config_param_values = jsonutils.loads(config_param_values)

        node_params = (stack_template.get('Parameters')
                       or stack_template.get('parameters')
                       or [])
        for parameter in node_params:
            if parameter == "Subnet":
                stack_params[parameter] = provider_ptg_subnet_id
            elif parameter in config_param_values:
                stack_params[parameter] = config_param_values[parameter]
        return (stack_template, stack_params)

    def _wait_for_stack_operation_complete(self, heatclient, stack_id, action):
        time_waited = 0
        while True:
            try:
                stack = heatclient.get(stack_id)
                if stack.stack_status == 'DELETE_FAILED':
                    heatclient.delete(stack_id)
                elif stack.stack_status not in ['UPDATE_IN_PROGRESS',
                                                'PENDING_DELETE']:
                    return
            except Exception:
                LOG.exception(_("Retrieving the stack %(stack)s failed."),
                              {'stack': stack_id})
                return
            else:
                time.sleep(STACK_ACTION_RETRY_WAIT)
                time_waited = time_waited + STACK_ACTION_RETRY_WAIT
                if time_waited >= STACK_ACTION_WAIT_TIME:
                    LOG.error(_("Stack %(action)s not completed within "
                                "%(wait)s seconds"),
                              {'action': action,
                               'wait': STACK_ACTION_WAIT_TIME,
                               'stack': stack_id})
                    return

    def _delete_node_instance_stack_in_db(self, session, sc_node_id,
                                          sc_instance_id):
        with session.begin(subtransactions=True):
            stacks = (session.query(ServiceNodeInstanceStack).
                      filter_by(sc_node_id=sc_node_id).
                      filter_by(sc_instance_id=sc_instance_id).
                      all())
            for stack in stacks:
                session.delete(stack)

    def _insert_node_instance_stack_in_db(self, session, sc_node_id,
                                          sc_instance_id, stack_id):
        with session.begin(subtransactions=True):
            chainstack = ServiceNodeInstanceStack(
                sc_node_id=sc_node_id,
                sc_instance_id=sc_instance_id,
                stack_id=stack_id)
            session.add(chainstack)

    def _get_node_instance_stacks(self, session, sc_node_id=None,
                                  sc_instance_id=None):
        with session.begin(subtransactions=True):
            query = session.query(ServiceNodeInstanceStack)
            if sc_node_id:
                query = query.filter_by(sc_node_id=sc_node_id)
            if sc_instance_id:
                query = query.filter_by(sc_instance_id=sc_instance_id)
            return query.all()
