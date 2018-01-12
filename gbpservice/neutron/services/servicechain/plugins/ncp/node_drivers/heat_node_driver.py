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

from heatclient import exc as heat_exc
from neutron.db import api as db_api
from neutron.db import models_v2 as ndb
from neutron.plugins.common import constants as pconst
from neutron_lib.db import model_base
from oslo_config import cfg
from oslo_db import exception as db_exc
from oslo_log import helpers as log
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
    cfg.IntOpt('delete_vip_port_retries',
               default=10,
               help=_("Retries to check if LB VIP port is deleted")),
    cfg.StrOpt('heat_uri',
               default='http://localhost:8004/v1',
               help=_("Heat API server address to instantiate services "
                      "specified in the service chain.")),
    cfg.StrOpt('exclude_pool_member_tag',
               default='ExcludePoolMember',
               help=_("Policy Targets created for the LB Pool Members should "
                      "have this tag in their description")),
]

cfg.CONF.register_opts(service_chain_opts, "heat_node_driver")
EXCLUDE_POOL_MEMBER_TAG = cfg.CONF.heat_node_driver.exclude_pool_member_tag
STACK_ACTION_WAIT_TIME = cfg.CONF.heat_node_driver.stack_action_wait_time
STACK_ACTION_RETRY_WAIT = 5  # Retry after every 5 seconds
DELETE_VIP_PORT_RETRIES = cfg.CONF.heat_node_driver.delete_vip_port_retries


class ServiceNodeInstanceStack(model_base.BASEV2):
    """ServiceChainInstance stacks owned by the Node driver."""

    __tablename__ = 'ncp_node_instance_stacks'
    sc_instance_id = sa.Column(sa.String(36),
                               nullable=False, primary_key=True)
    sc_node_id = sa.Column(sa.String(36),
                           nullable=False, primary_key=True)
    stack_id = sa.Column(sa.String(36),
                         nullable=False, primary_key=True)


class InvalidServiceType(exc.NodeCompositionPluginBadRequest):
    message = _("The Heat Node driver only supports the services "
                "Firewall and LB in a Service Chain")


class ServiceProfileRequired(exc.NodeCompositionPluginBadRequest):
    message = _("A Service profile is required in Service node")


class NodeVendorMismatch(exc.NodeCompositionPluginBadRequest):
    message = _("The Heat Node driver only handles nodes which have service "
                "profile with vendor name %(vendor)s")


class ServiceConfigNotJsonString(exc.NodeCompositionPluginBadRequest):
    message = _("Service config should be a json string for the Heat Node "
                "driver")


class HeatTemplateVersionNotSupported(exc.NodeCompositionPluginBadRequest):
    message = _("The Heat Node driver only supports AWS and HOT template "
                "formats for service node config")


class ServiceResourceDefinitionsMissing(exc.NodeCompositionPluginBadRequest):
    message = _("The Service template does not have service resources defined")


class HeatResourceMissing(exc.NodeCompositionPluginBadRequest):
    message = _("The service template requires the Resource %(resource)s for "
                "service type %(servicetype)s")


class ProfileUpdateNotSupported(exc.NodeCompositionPluginBadRequest):
    message = _("The Heat Node driver does not allow updating the "
                "service profile used by a Node")


class ServiceTypeUpdateNotSupported(exc.NodeCompositionPluginBadRequest):
    message = _("The Heat Node driver does not allow updating the "
                "service type used by a Node")


class HeatNodeDriver(driver_base.NodeDriverBase):

    vendor_name = 'heat_based_node_driver'
    initialized = False
    sc_supported_type = [pconst.LOADBALANCERV2, pconst.FIREWALL]
    required_heat_resources = {
        pconst.LOADBALANCERV2: ['OS::Neutron::LBaaS::LoadBalancer',
                                'OS::Neutron::LBaaS::Listener',
                                'OS::Neutron::LBaaS::Pool'],
        pconst.FIREWALL: ['OS::Neutron::Firewall',
                          'OS::Neutron::FirewallPolicy'],
    }

    @log.log_method_call
    def initialize(self, name):
        self.initialized = True
        self._name = name

    @log.log_method_call
    def get_plumbing_info(self, context):
        pass

    @log.log_method_call
    def validate_create(self, context):
        if context.current_profile is None:
            raise ServiceProfileRequired()
        if context.current_profile['vendor'].lower() != (
            self.vendor_name.lower()):
            raise NodeVendorMismatch(vendor=self.vendor_name)
        service_type = context.current_profile['service_type']
        if service_type not in self.sc_supported_type:
            raise InvalidServiceType()

        self._validate_service_config(context.current_node['config'],
                                      service_type)

    @log.log_method_call
    def validate_update(self, context):
        if not context.original_node:  # PT create/delete notifications
            return
        if context.current_profile != context.original_profile:
            raise ProfileUpdateNotSupported()
        if (context.current_node['service_type'] !=
            context.original_node['service_type']):
            raise ServiceTypeUpdateNotSupported()
        else:
            service_type = context.current_profile['service_type']
            self._validate_service_config(context.current_node['config'],
                                          service_type)

    def _validate_service_config(self, service_template, service_type):
        if not service_template:
            raise ServiceResourceDefinitionsMissing()

        try:
            service_template = jsonutils.loads(service_template)
        except Exception:
            raise ServiceConfigNotJsonString()

        if (not service_template.get('AWSTemplateFormatVersion') and
                not service_template.get('heat_template_version')):
                raise HeatTemplateVersionNotSupported()
        is_template_aws_version = service_template.get(
                                        'AWSTemplateFormatVersion', False)
        resources_key = 'Resources' if is_template_aws_version else 'resources'
        if not service_template.get(resources_key):
            raise ServiceResourceDefinitionsMissing()

        for resource_name in self.required_heat_resources[service_type]:
            param_key = self._get_heat_resource_key(
                            service_template[resources_key],
                            is_template_aws_version,
                            resource_name)
            if not param_key:
                raise HeatResourceMissing(resource=resource_name,
                                          servicetype=service_type)

    @log.log_method_call
    def create(self, context):
        heatclient = self._get_heat_client(context.plugin_context)

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

    @log.log_method_call
    def delete(self, context):
        stack_ids = self._get_node_instance_stacks(context.plugin_session,
                                                   context.current_node['id'],
                                                   context.instance['id'])
        heatclient = self._get_heat_client(context.plugin_context)

        for stack in stack_ids:
            vip_port_id = None
            try:
                rstr = heatclient.client.resources.get(stack_ids[0].stack_id,
                    'loadbalancer')
                vip_port_id = rstr.attributes['vip_port_id']
            except heat_exc.HTTPNotFound:
                # stack not found, so no need to process any further
                pass
            heatclient.delete(stack.stack_id)
            if vip_port_id:
                for x in range(0, DELETE_VIP_PORT_RETRIES):
                    # We intentionally get a new session so as to be
                    # able to read the updated DB
                    session = db_api.get_reader_session()
                    vip_port = session.query(ndb.Port).filter_by(
                        id=vip_port_id).all()
                    if vip_port:
                        # heat stack delete is not finished yet, so try again
                        LOG.debug(("VIP port %s is not yet deleted"), vip_port)
                        LOG.debug(("Retry attempt; %s"), x + 1)
                        # Stack delete will at least take some minimal amount
                        # of time, hence we wait a little bit.
                        time.sleep(STACK_ACTION_WAIT_TIME)
                    else:
                        # we force a retry so that a new session can be
                        # used that will correctly reflect the VIP port as
                        # deleted and hence allow the subsequent policy driver
                        # to delete the VIP subnet
                        raise db_exc.RetryRequest(Exception)

        self._delete_node_instance_stack_in_db(context.plugin_session,
                                               context.current_node['id'],
                                               context.instance['id'])

    @log.log_method_call
    def update(self, context):
        heatclient = self._get_heat_client(context.plugin_context)

        stack_template, stack_params = self._fetch_template_and_params(context)

        stack_ids = self._get_node_instance_stacks(context.plugin_session,
                                                   context.current_node['id'],
                                                   context.instance['id'])
        for stack in stack_ids:
            self._wait_for_stack_operation_complete(
                                heatclient, stack.stack_id, 'update')
            heatclient.update(stack.stack_id, stack_template, stack_params)

    @log.log_method_call
    def update_policy_target_added(self, context, policy_target):
        if context.current_profile['service_type'] == pconst.LOADBALANCERV2:
            self.update(context)

    @log.log_method_call
    def update_policy_target_removed(self, context, policy_target):
        if context.current_profile['service_type'] == pconst.LOADBALANCERV2:
            self.update(context)

    @log.log_method_call
    def update_node_consumer_ptg_added(self, context, policy_target_group):
        pass

    @log.log_method_call
    def update_node_consumer_ptg_removed(self, context, policy_target_group):
        pass

    @log.log_method_call
    def notify_chain_parameters_updated(self, context):
        self.update(context)

    @log.log_method_call
    def policy_target_group_updated(self, context, old_policy_target_group,
                                    current_policy_target_group):
        pass

    def get_status(self, context):
        # TODO(Sumit): Needs to be implemented
        return {'status': '', 'status_details': ''}

    @property
    def name(self):
        return self._name

    def _get_heat_client(self, plugin_context):
        return heat_api_client.HeatClient(
                                plugin_context,
                                cfg.CONF.heat_node_driver.heat_uri)

    def _fetch_template_and_params(self, context):
        sc_instance = context.instance
        provider_ptg = context.provider
        # TODO(Magesh): Handle multiple subnets
        provider_ptg_subnet_id = provider_ptg['subnets'][0]
        consumer = context.consumer
        service_type = context.current_profile['service_type']

        stack_template = context.current_node.get('config')
        stack_template = jsonutils.loads(stack_template)
        config_param_values = sc_instance.get('config_param_values', {})
        stack_params = {}

        if config_param_values:
            config_param_values = jsonutils.loads(config_param_values)

        is_template_aws_version = stack_template.get(
                                        'AWSTemplateFormatVersion', False)

        if service_type == pconst.LOADBALANCERV2:
            self._generate_pool_members(context, stack_template,
                                        config_param_values,
                                        provider_ptg,
                                        is_template_aws_version)
        elif service_type == pconst.FIREWALL:
            provider_subnet = context.core_plugin.get_subnet(
                                context.plugin_context, provider_ptg_subnet_id)
            consumer_cidrs = []
            if consumer:
                if context.is_consumer_external:
                    # REVISIT(Magesh): Allowing the first destination which is
                    # 0/0 Validate and skip adding FW rule in case routes is
                    # not set
                    es = context.gbp_plugin.get_external_segment(
                        context.plugin_context,
                        consumer['external_segments'][0])
                    consumer_cidrs = [x['destination']
                                      for x in es['external_routes']]
                else:
                    consumer_subnet = context.core_plugin.get_subnet(
                        context._plugin_context, consumer['subnets'][0])
                    consumer_cidrs = [consumer_subnet['cidr']]
            provider_cidr = provider_subnet['cidr']
            self._update_template_with_firewall_rules(
                    context, provider_ptg, provider_cidr, consumer_cidrs,
                    stack_template, is_template_aws_version)

        node_params = (stack_template.get('Parameters')
                       or stack_template.get('parameters')
                       or [])
        for parameter in node_params:
            if parameter == "Subnet":
                stack_params[parameter] = provider_ptg_subnet_id
            elif parameter == "service_chain_metadata":
                stack_params[parameter] = sc_instance['id']
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
                                                'DELETE_IN_PROGRESS']:
                    return
            except Exception:
                LOG.exception("Retrieving the stack %(stack)s failed.",
                              {'stack': stack_id})
                return
            else:
                time.sleep(STACK_ACTION_RETRY_WAIT)
                time_waited = time_waited + STACK_ACTION_RETRY_WAIT
                if time_waited >= STACK_ACTION_WAIT_TIME:
                    LOG.error("Stack %(action)s not completed within "
                              "%(wait)s seconds",
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

    def _update_template_with_firewall_rules(self, context, provider_ptg,
                                             provider_cidr, consumer_cidrs,
                                             stack_template,
                                             is_template_aws_version):
        resources_key = ('Resources' if is_template_aws_version
                         else 'resources')
        properties_key = ('Properties' if is_template_aws_version
                          else 'properties')
        ref_key = 'Ref' if is_template_aws_version else 'get_resource'

        rule_num = 1
        rule_list = []
        for consumer_cidr in consumer_cidrs:
            rule_name = "Rule_" + str(rule_num)
            rule_num = rule_num + 1
            stack_template[resources_key][rule_name] = (
                self._generate_firewall_rule(
                    is_template_aws_version, context.classifier["protocol"],
                    context.classifier["port_range"],
                    provider_cidr, consumer_cidr))
            rule_list.append({ref_key: rule_name})

        resource_name = 'OS::Neutron::FirewallPolicy'
        fw_policy_key = self._get_heat_resource_key(
                            stack_template[resources_key],
                            is_template_aws_version,
                            resource_name)

        stack_template[resources_key][fw_policy_key][properties_key][
            'firewall_rules'] = rule_list

    def _generate_firewall_rule(self, is_template_aws_version, protocol,
                                destination_port, destination_cidr,
                                source_cidr):
        type_key = 'Type' if is_template_aws_version else 'type'
        properties_key = ('Properties' if is_template_aws_version
                          else 'properties')
        return {type_key: "OS::Neutron::FirewallRule",
                properties_key: {
                    "protocol": protocol,
                    "enabled": True,
                    "destination_port": destination_port,
                    "action": "allow",
                    "destination_ip_address": destination_cidr,
                    "source_ip_address": source_cidr}}

    def _generate_pool_members(self, context, stack_template,
                               config_param_values, provider_ptg,
                               is_template_aws_version):
        resources_key = 'Resources' if is_template_aws_version else 'resources'
        type_key = 'Type' if is_template_aws_version else 'type'
        member_ips = self._get_member_ips(context, provider_ptg)
        if not member_ips:
            return

        pool_res_name = None
        for resource in stack_template[resources_key]:
            if stack_template[resources_key][resource][type_key] == (
                    'OS::Neutron::LBaaS::Pool'):
                pool_res_name = resource
                break

        for member_ip in member_ips:
            member_name = 'mem-' + member_ip
            stack_template[resources_key][member_name] = (
                self._generate_pool_member_template(
                    context, is_template_aws_version,
                    pool_res_name, member_ip))

    def _generate_pool_member_template(self, context,
                                       is_template_aws_version,
                                       pool_res_name, member_ip):
        type_key = 'Type' if is_template_aws_version else 'type'
        properties_key = ('Properties' if is_template_aws_version
                          else 'properties')
        res_key = 'Ref' if is_template_aws_version else 'get_resource'
        return {type_key: "OS::Neutron::LBaaS::PoolMember",
                properties_key: {
                    "address": member_ip,
                    "admin_state_up": True,
                    "pool": {res_key: pool_res_name},
                    "protocol_port": {'get_param': 'app_port'},
                    "subnet": {'get_param': 'Subnet'},
                    "weight": 1}}

    def _get_member_ips(self, context, ptg):
        member_addresses = []
        policy_target_groups = context.gbp_plugin.get_policy_targets(
                context.plugin_context,
                filters={'id': ptg.get("policy_targets")})
        for policy_target in policy_target_groups:
            if EXCLUDE_POOL_MEMBER_TAG not in policy_target['description']:
                port_id = policy_target.get("port_id")
                if port_id:
                    port = context.core_plugin.get_port(
                                        context._plugin_context, port_id)
                    ip = port.get('fixed_ips')[0].get("ip_address")
                    member_addresses.append(ip)
        return member_addresses

    def _get_heat_resource_key(self, template_resource_dict,
                               is_template_aws_version, resource_name):
        type_key = 'Type' if is_template_aws_version else 'type'
        for key in template_resource_dict:
            if template_resource_dict[key].get(type_key) == resource_name:
                return key
