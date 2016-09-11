# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import copy
import time

from heatclient import exc as heat_exc
from keystoneclient import exceptions as k_exceptions
from neutron._i18n import _LE
from neutron._i18n import _LI
from neutron._i18n import _LW
from neutron.db import api as db_api
from neutron.plugins.common import constants as pconst
from oslo_config import cfg
from oslo_serialization import jsonutils
from oslo_utils import excutils
import yaml

from gbpservice.neutron.services.grouppolicy.common import constants as gconst
from gbpservice.neutron.services.servicechain.plugins.ncp import plumber_base
from gbpservice.nfp.common import constants as nfp_constants
from gbpservice.nfp.core import log as nfp_logging
from gbpservice.nfp.lib import transport
from gbpservice.nfp.orchestrator.config_drivers.heat_client import HeatClient
from gbpservice.nfp.orchestrator.db import nfp_db as nfp_db
from gbpservice.nfp.orchestrator.openstack.openstack_driver import (
        KeystoneClient)
from gbpservice.nfp.orchestrator.openstack.openstack_driver import (
        NeutronClient)
from gbpservice.nfp.orchestrator.openstack.openstack_driver import GBPClient


HEAT_DRIVER_OPTS = [
    cfg.StrOpt('svc_management_ptg_name',
               default='svc_management_ptg',
               help=_("Name of the PTG that is associated with the "
                      "service management network")),
    cfg.StrOpt('remote_vpn_client_pool_cidr',
               default='192.168.254.0/24',
               help=_("CIDR pool for remote vpn clients")),
    cfg.StrOpt('heat_uri',
               default='http://localhost:8004/v1',
               help=_("Heat API server address to instantiate services "
                      "specified in the service chain.")),
    cfg.IntOpt('stack_action_wait_time',
               default=120,
               help=_("Seconds to wait for pending stack operation "
                      "to complete")),
    cfg.BoolOpt('is_service_admin_owned',
                help=_("Parameter to indicate whether the Service VM has to "
                       "to be owned by the Admin"),
                default=True),
    cfg.StrOpt('keystone_version',
               default='v3',
               help=_("Parameter to indicate version of keystone "
                       "used by heat_driver")),
]

cfg.CONF.register_opts(HEAT_DRIVER_OPTS,
                       "heat_driver")

SC_METADATA = ('{"sc_instance":"%s", "floating_ip": "%s", '
               '"provider_interface_mac": "%s", '
               '"standby_provider_interface_mac": "%s",'
               '"network_function_id": "%s",'
               '"service_vendor": "%s"}')

SVC_MGMT_PTG_NAME = (
    cfg.CONF.heat_driver.svc_management_ptg_name)

STACK_ACTION_WAIT_TIME = (
    cfg.CONF.heat_driver.stack_action_wait_time)
STACK_ACTION_RETRY_WAIT = 5  # Retry after every 5 seconds
APIC_OWNED_RES = 'apic_owned_res_'

LOG = nfp_logging.getLogger(__name__)


class HeatDriver(object):

    def __init__(self, config):
        self.keystoneclient = KeystoneClient(config)
        self.gbp_client = GBPClient(config)
        self.neutron_client = NeutronClient(config)

        self.keystone_conf = config.keystone_authtoken
        keystone_version = self.keystone_conf.auth_version
        self.v2client = self.keystoneclient._get_v2_keystone_admin_client()
        self.admin_id = self.v2client.users.find(
            name=self.keystone_conf.admin_user).id
        self.admin_role = self._get_role_by_name(
            self.v2client, "admin", keystone_version)
        self.heat_role = self._get_role_by_name(
            self.v2client, "heat_stack_owner", keystone_version)

    def _resource_owner_tenant_id(self):
        auth_token = self.keystoneclient.get_scoped_keystone_token(
            self.keystone_conf.admin_user,
            self.keystone_conf.admin_password,
            self.keystone_conf.admin_tenant_name)
        try:
            tenant_id = self.keystoneclient.get_tenant_id(
                auth_token, self.keystone_conf.admin_tenant_name)
            return tenant_id
        except k_exceptions.NotFound:
            with excutils.save_and_reraise_exception(reraise=True):
                LOG.error(_LE('No tenant with name %s exists.'),
                          self.keystone_conf.admin_tenant_name)
        except k_exceptions.NoUniqueMatch:
            with excutils.save_and_reraise_exception(reraise=True):
                LOG.error(
                    _LE('Multiple tenants matches found for %s'),
                    self.keystone_conf.admin_tenant_name)

    def _get_resource_owner_context(self):
        if cfg.CONF.heat_driver.is_service_admin_owned:
            tenant_id = self._resource_owner_tenant_id()
            auth_token = self.keystoneclient.get_scoped_keystone_token(
                self.keystone_conf.admin_user,
                self.keystone_conf.admin_password,
                self.keystone_conf.admin_tenant_name,
                tenant_id)
        return auth_token, tenant_id

    def _get_role_by_name(self, keystone_client, name, keystone_version):
        if keystone_version == 'v2.0':
            roles = keystone_client.roles.list()
            if roles:
                for role in roles:
                    if name in role.name:
                        return role
        else:
            role = keystone_client.roles.list(name=name)
            if role:
                return role[0]

    def get_allocated_roles(self, v2client, user, tenant_id=None):
        allocated_role_names = []
        allocated_roles = v2client.roles.roles_for_user(user, tenant=tenant_id)
        if allocated_roles:
            for role in allocated_roles:
                allocated_role_names.append(role.name)
        return allocated_role_names

    def _assign_admin_user_to_project_v2_keystone(self, project_id):
        allocated_role_names = self.get_allocated_roles(
            self.v2client, self.admin_id, project_id)
        if self.admin_role:
            if self.admin_role.name not in allocated_role_names:
                self.v2client.roles.add_user_role(
                    self.admin_id, self.admin_role.id, tenant=project_id)
        if self.heat_role:
            if self.heat_role.name not in allocated_role_names:
                self.v2client.roles.add_user_role(self.admin_id,
                                                  self.heat_role.id,
                                                  tenant=project_id)

    def _assign_admin_user_to_project(self, project_id):
        keystone_version = self.keystone_conf.auth_version

        if keystone_version == 'v2.0':
            return self._assign_admin_user_to_project_v2_keystone(project_id)
        else:
            v3client = self.keystoneclient._get_v3_keystone_admin_client()
            admin_id = v3client.users.find(
                name=self.keystone_conf.admin_user).id
            admin_role = self._get_role_by_name(v3client, "admin",
                                                keystone_version)
            if admin_role:
                v3client.roles.grant(admin_role.id, user=admin_id,
                                     project=project_id)
            heat_role = self._get_role_by_name(v3client, "heat_stack_owner",
                                               keystone_version)
            if heat_role:
                v3client.roles.grant(heat_role.id, user=admin_id,
                                     project=project_id)

    def keystone(self, user, pwd, tenant_name, tenant_id=None):
        if tenant_id:
            return self.keystoneclient.get_scoped_keystone_token(
                user, pwd, tenant_name, tenant_id)
        else:
            return self.keystoneclient.get_scoped_keystone_token(
                user, pwd, tenant_name)

    def _get_heat_client(self, tenant_id, assign_admin=False):
        # REVISIT(Akash) Need to discuss use cases why it is needed,
        # since user can do it from ui also. hence, commenting it for now
        '''
        if assign_admin:
            try:
                self._assign_admin_user_to_project(tenant_id)
            except Exception:
                LOG.exception(_LE("Failed to assign admin user to project"))
                return None
        '''
        logging_context = nfp_logging.get_logging_context()
        auth_token = logging_context['auth_token']

        timeout_mins, timeout_seconds = divmod(STACK_ACTION_WAIT_TIME, 60)
        if timeout_seconds:
            timeout_mins = timeout_mins + 1
        try:
            heat_client = HeatClient(
                self.keystone_conf.admin_user,
                tenant_id,
                cfg.CONF.heat_driver.heat_uri,
                self.keystone_conf.admin_password,
                auth_token=auth_token,
                timeout_mins=timeout_mins)
        except Exception:
            LOG.exception(_LE("Failed to create heatclient object"))
            return None

        return heat_client

    def _get_tenant_context(self, tenant_id):
        auth_token = self.keystone(
            self.keystone_conf.admin_user,
            self.keystone_conf.admin_password,
            self.keystone_conf.admin_tenant_name,
            tenant_id=tenant_id)
        return auth_token, tenant_id

    def loadbalancer_post_stack_create(self, network_function_details):
        db_handler = nfp_db.NFPDbBase()
        db_session = db_api.get_session()
        service_details = self.get_service_details(network_function_details)
        service_profile = service_details['service_profile']
        if service_profile['service_type'] in [pconst.LOADBALANCER,
                                               pconst.LOADBALANCERV2]:
            network_function_instance = network_function_details.get(
                'network_function_instance')
            if network_function_instance:
                for port in network_function_instance.get('port_info'):
                    port_info = db_handler.get_port_info(db_session, port)
                    if port_info['port_model'] != nfp_constants.GBP_PORT:
                        return

    def _post_stack_create(self, nfp_context):
        service_details = self.get_service_details_from_nfp_context(
            nfp_context)
        service_type = service_details['service_details']['service_type']

        if service_type in [pconst.LOADBALANCER]:
            logging_context = nfp_logging.get_logging_context()
            auth_token = logging_context['auth_token']
            provider_tenant_id = nfp_context['tenant_id']
            provider = service_details['provider_ptg']
            self._create_policy_target_for_vip(
                auth_token, provider_tenant_id, provider)

    def _get_provider_ptg_info(self, auth_token, sci_id):
        servicechain_instance = self.gbp_client.get_servicechain_instance(
            auth_token, sci_id)
        provider_ptg_id = servicechain_instance['provider_ptg_id']
        provider_ptg = self.gbp_client.get_policy_target_group(
            auth_token, provider_ptg_id)
        return provider_ptg

    def _pre_stack_cleanup(self, network_function):
        logging_context = nfp_logging.get_logging_context()
        auth_token = logging_context['auth_token']
        service_profile = self.gbp_client.get_service_profile(
            auth_token, network_function['service_profile_id'])
        service_type = service_profile['service_type']
        if service_type in [pconst.LOADBALANCER]:
            provider = self._get_provider_ptg_info(auth_token,
                    network_function['service_chain_id'])
            provider_tenant_id = provider['tenant_id']
            self._update_policy_targets_for_vip(
                auth_token, provider_tenant_id, provider)

    def _post_stack_cleanup(self, network_function):
        #TODO(ashu): In post stack cleanup, need to delete vip pt, currently
        # we dont have any way to identify vip pt, so skipping this, but need
        # to fix it.
        return

    def _get_vip_pt(self, auth_token, vip_port_id):
        vip_pt = None
        filters = {'port_id': vip_port_id}
        policy_targets = self.gbp_client.get_policy_targets(
            auth_token,
            filters=filters)
        if policy_targets:
            vip_pt = policy_targets[0]

        return vip_pt

    def _get_lb_vip(self, auth_token, provider):
        provider_subnet = None
        lb_vip = None
        lb_vip_name = None

        provider_l2p_subnets = self.neutron_client.get_subnets(
            auth_token,
            filters={'id': provider['subnets']})
        for subnet in provider_l2p_subnets:
            if not subnet['name'].startswith(APIC_OWNED_RES):
                provider_subnet = subnet
                break
        if provider_subnet:
            lb_pool_ids = self.neutron_client.get_pools(
                auth_token,
                filters={'subnet_id': [provider_subnet['id']]})
            if lb_pool_ids and lb_pool_ids[0]['vip_id']:
                lb_vip = self.neutron_client.get_vip(
                    auth_token, lb_pool_ids[0]['vip_id'])['vip']
                lb_vip_name = ("service_target_vip_pt" +
                        lb_pool_ids[0]['vip_id'])
        return lb_vip, lb_vip_name

    def _create_policy_target_for_vip(self, auth_token,
                                      provider_tenant_id, provider):
        provider_pt_id = ''
        admin_token = self.keystoneclient.get_admin_token()
        lb_vip, vip_name = self._get_lb_vip(auth_token, provider)
        provider_pt = self._get_provider_pt(admin_token, provider)
        if provider_pt:
            provider_pt_id = provider_pt['id']

        vip_pt = self.gbp_client.create_policy_target(
            auth_token, provider_tenant_id, provider['id'],
            vip_name, lb_vip['port_id'])

        policy_target_info = {'cluster_id': vip_pt['id']}
        self.gbp_client.update_policy_target(auth_token, vip_pt['id'],
                policy_target_info)

        self.gbp_client.update_policy_target(admin_token, provider_pt_id,
                policy_target_info)

    def _update_policy_targets_for_vip(self, auth_token,
                                      provider_tenant_id, provider):
        provider_pt_id = ''
        admin_token = self.keystoneclient.get_admin_token()
        lb_vip, vip_name = self._get_lb_vip(auth_token, provider)
        provider_pt = self._get_provider_pt(admin_token, provider)
        if provider_pt:
            provider_pt_id = provider_pt['id']

        policy_target_info = {'cluster_id': ''}
        vip_pt = self._get_vip_pt(auth_token, lb_vip['port_id'])
        if vip_pt:
            self.gbp_client.update_policy_target(auth_token, vip_pt['id'],
                    policy_target_info)

        self.gbp_client.update_policy_target(admin_token, provider_pt_id,
                policy_target_info)

    def _get_provider_pt(self, auth_token, provider):
        if provider.get("policy_targets"):
            filters = {'id': provider.get("policy_targets")}
        else:
            filters = {'policy_target_group': provider['id']}
        policy_targets = self.gbp_client.get_policy_targets(
                auth_token,
                filters=filters)
        for policy_target in policy_targets:
            if ('endpoint' in policy_target['name'] and
                    self._is_service_target(policy_target)):
                return policy_target
        return None

    def _is_service_target(self, policy_target):
        if policy_target['name'] and (policy_target['name'].startswith(
                plumber_base.SERVICE_TARGET_NAME_PREFIX) or
                policy_target['name'].startswith('tscp_endpoint_service') or
                policy_target['name'].startswith('vip_pt')):
            return True
        else:
            return False

    def _get_member_ips(self, auth_token, ptg):
        member_addresses = []
        if ptg.get("policy_targets"):
            policy_targets = self.gbp_client.get_policy_targets(
                auth_token,
                filters={'id': ptg.get("policy_targets")})
        else:
            return member_addresses
        for policy_target in policy_targets:
            if not self._is_service_target(policy_target):
                port_id = policy_target.get("port_id")
                if port_id:
                    port = self.neutron_client.get_port(
                        auth_token, port_id)['port']
                    ip_address = port.get('fixed_ips')[0].get("ip_address")
                    member_addresses.append(ip_address)
        return member_addresses

    def _generate_lb_member_template(self, is_template_aws_version,
                                     pool_res_name, member_ip, stack_template):
        type_key = 'Type' if is_template_aws_version else 'type'
        properties_key = ('Properties' if is_template_aws_version
                          else 'properties')
        resources_key = 'Resources' if is_template_aws_version else 'resources'
        res_key = 'Ref' if is_template_aws_version else 'get_resource'

        lbaas_pool_key = self._get_heat_resource_key(
            stack_template[resources_key],
            is_template_aws_version,
            "OS::Neutron::Pool")
        lbaas_vip_key = self._get_heat_resource_key(
            stack_template[resources_key],
            is_template_aws_version,
            "OS::Neutron::LoadBalancer")
        vip_port = stack_template[resources_key][lbaas_pool_key][
            properties_key]['vip']['protocol_port']
        member_port = stack_template[resources_key][lbaas_vip_key][
            properties_key].get('protocol_port')
        protocol_port = member_port if member_port else vip_port

        return {type_key: "OS::Neutron::PoolMember",
                properties_key: {
                    "address": member_ip,
                    "admin_state_up": True,
                    "pool_id": {res_key: pool_res_name},
                    "protocol_port": protocol_port,
                    "weight": 1}}

    def _modify_lb_resources_name(self, stack_template, provider_ptg,
                                  is_template_aws_version):
        resources_key = 'Resources' if is_template_aws_version else 'resources'
        type_key = 'Type' if is_template_aws_version else 'type'
        properties_key = ('Properties' if is_template_aws_version
                          else 'properties')

        for resource in stack_template[resources_key]:
            if stack_template[resources_key][resource][type_key] == (
                    'OS::Neutron::Pool'):
                # Include provider name in Pool, VIP name.
                ptg_name = '-' + provider_ptg['name']
                stack_template[resources_key][resource][
                    properties_key]['name'] += ptg_name
                stack_template[resources_key][resource][
                    properties_key]['vip']['name'] += ptg_name

    def _generate_lbv2_member_template(self, is_template_aws_version,
                                       member_ip, stack_template):
        type_key = 'Type' if is_template_aws_version else 'type'
        properties_key = ('Properties' if is_template_aws_version
                          else 'properties')
        resources_key = 'Resources' if is_template_aws_version else 'resources'
        res_key = 'Ref' if is_template_aws_version else 'get_resource'

        lbaas_loadbalancer_key = self._get_heat_resource_key(
            stack_template[resources_key],
            is_template_aws_version,
            "OS::Neutron::LBaaS::LoadBalancer")
        subnet = stack_template[resources_key][lbaas_loadbalancer_key][
            properties_key]['vip_subnet']

        return {type_key: "OS::Neutron::LBaaS::PoolMember",
                properties_key: {
                    "pool": {res_key: "pool"},
                    "address": member_ip,
                    "protocol_port": {"get_param": "app_port"},
                    "subnet": subnet,
                    "weight": 1}}

    def _modify_lbv2_resources_name(self, stack_template, provider_ptg,
                                    is_template_aws_version):
        pass

    def _generate_lbaasv2_pool_members(self, auth_token, stack_template,
                                       config_param_values, provider_ptg,
                                       is_template_aws_version):
        resources_key = 'Resources' if is_template_aws_version else 'resources'
        self._modify_lbv2_resources_name(
            stack_template, provider_ptg, is_template_aws_version)
        member_ips = self._get_member_ips(auth_token, provider_ptg)
        if not member_ips:
            return
        for member_ip in member_ips:
            member_name = 'mem-' + member_ip
            stack_template[resources_key][member_name] = (
                self._generate_lbv2_member_template(
                    is_template_aws_version,
                    member_ip, stack_template))

    def _generate_pool_members(self, auth_token, stack_template,
                               config_param_values, provider_ptg,
                               is_template_aws_version):
        resources_key = 'Resources' if is_template_aws_version else 'resources'
        self._modify_lb_resources_name(
            stack_template, provider_ptg, is_template_aws_version)
        member_ips = self._get_member_ips(auth_token, provider_ptg)
        if not member_ips:
            return
        pool_res_name = self._get_heat_resource_key(
            stack_template[resources_key],
            is_template_aws_version,
            "OS::Neutron::Pool")
        for member_ip in member_ips:
            member_name = 'mem-' + member_ip
            stack_template[resources_key][member_name] = (
                self._generate_lb_member_template(
                    is_template_aws_version, pool_res_name,
                    member_ip, stack_template))

    def _get_consumers_for_chain(self, auth_token, provider):
        filters = {'id': provider['provided_policy_rule_sets']}
        provided_prs = self.gbp_client.get_policy_rule_sets(
            auth_token, filters=filters)
        redirect_prs = None
        for prs in provided_prs:
            filters = {'id': prs['policy_rules']}
            policy_rules = self.gbp_client.get_policy_rules(
                auth_token, filters=filters)
            for policy_rule in policy_rules:
                filters = {'id': policy_rule['policy_actions'],
                           'action_type': [gconst.GP_ACTION_REDIRECT]}
                policy_actions = self.gbp_client.get_policy_actions(
                    auth_token, filters=filters)
                if policy_actions:
                    redirect_prs = prs
                    break

        if not redirect_prs:
            LOG.error(_LE("Redirect rule doesn't exist in policy target rule "
                          " set"))
            return None, None
        return (redirect_prs['consuming_policy_target_groups'],
                redirect_prs['consuming_external_policies'])

    def _append_firewall_rule(self, stack_template, provider_cidr,
                              consumer_cidr, fw_template_properties,
                              consumer_id):
        resources_key = fw_template_properties['resources_key']
        properties_key = fw_template_properties['properties_key']
        fw_rule_keys = fw_template_properties['fw_rule_keys']
        rule_name = "%s_%s" % ("node_driver_rule", consumer_id[:16])
        fw_policy_key = fw_template_properties['fw_policy_key']
        i = 1
        for fw_rule_key in fw_rule_keys:
            fw_rule_name = (rule_name + '_' + str(i))
            stack_template[resources_key][fw_rule_name] = (
                copy.deepcopy(stack_template[resources_key][fw_rule_key]))
            stack_template[resources_key][fw_rule_name][
                properties_key]['destination_ip_address'] = provider_cidr
            # Use user provided Source for N-S
            if consumer_cidr != "0.0.0.0/0":
                stack_template[resources_key][fw_rule_name][
                    properties_key]['source_ip_address'] = consumer_cidr

            if stack_template[resources_key][fw_policy_key][
                    properties_key].get('firewall_rules'):
                stack_template[resources_key][fw_policy_key][
                    properties_key]['firewall_rules'].append({
                        'get_resource': fw_rule_name})
            i += 1

    def _get_heat_resource_key(self, template_resource_dict,
                               is_template_aws_version, resource_name):
        type_key = 'Type' if is_template_aws_version else 'type'
        for key in template_resource_dict:
            if template_resource_dict[key].get(type_key) == resource_name:
                return key

    def _get_all_heat_resource_keys(self, template_resource_dict,
                                    is_template_aws_version, resource_name):
        type_key = 'Type' if is_template_aws_version else 'type'
        resource_keys = []
        for key in template_resource_dict:
            if template_resource_dict[key].get(type_key) == resource_name:
                resource_keys.append(key)
        return resource_keys

    def _create_firewall_template(self, auth_token,
                                  service_details, stack_template):

        consuming_ptgs_details = service_details['consuming_ptgs_details']
        consumer_eps = service_details['consuming_external_policies']

        # Handle a case where a chain is provided first and then consumed
        # if (not consuming_ptgs_details) and (not consumer_eps):
        #    return None

        is_template_aws_version = stack_template.get(
            'AWSTemplateFormatVersion', False)
        resources_key = 'Resources' if is_template_aws_version else 'resources'
        properties_key = ('Properties' if is_template_aws_version
                          else 'properties')
        fw_rule_keys = self._get_all_heat_resource_keys(
            stack_template[resources_key], is_template_aws_version,
            'OS::Neutron::FirewallRule')
        fw_policy_key = self._get_all_heat_resource_keys(
            stack_template['resources'], is_template_aws_version,
            'OS::Neutron::FirewallPolicy')[0]

        provider_subnet = service_details['provider_subnet']
        provider_cidr = provider_subnet['cidr']

        fw_template_properties = dict(
            resources_key=resources_key, properties_key=properties_key,
            is_template_aws_version=is_template_aws_version,
            fw_rule_keys=fw_rule_keys,
            fw_policy_key=fw_policy_key)

        for consumer in consuming_ptgs_details:
            ptg = consumer['ptg']
            subnets = consumer['subnets']

            # Skip the stitching PTG
            if ptg['proxied_group_id']:
                continue

            fw_template_properties.update({'name': ptg['id'][:3]})
            for subnet in subnets:
                if subnet['name'].startswith(APIC_OWNED_RES):
                    continue

                consumer_cidr = subnet['cidr']
                self._append_firewall_rule(stack_template,
                                           provider_cidr, consumer_cidr,
                                           fw_template_properties, ptg['id'])

        for consumer_ep in consumer_eps:
            fw_template_properties.update({'name': consumer_ep['id'][:3]})
            self._append_firewall_rule(stack_template, provider_cidr,
                                       "0.0.0.0/0", fw_template_properties,
                                       consumer_ep['id'])

        for rule_key in fw_rule_keys:
            del stack_template[resources_key][rule_key]
            stack_template[resources_key][fw_policy_key][
                properties_key]['firewall_rules'].remove(
                    {'get_resource': rule_key})

        return stack_template

    def _update_firewall_template(self, auth_token, provider, stack_template):
        consumer_ptgs, consumer_eps = self._get_consumers_for_chain(
            auth_token, provider)
        if (consumer_ptgs is None) and (consumer_eps is None):
            return None
        is_template_aws_version = stack_template.get(
            'AWSTemplateFormatVersion', False)
        resources_key = 'Resources' if is_template_aws_version else 'resources'
        properties_key = ('Properties' if is_template_aws_version
                          else 'properties')
        fw_rule_keys = self._get_all_heat_resource_keys(
            stack_template[resources_key], is_template_aws_version,
            'OS::Neutron::FirewallRule')
        fw_policy_key = self._get_all_heat_resource_keys(
            stack_template['resources'], is_template_aws_version,
            'OS::Neutron::FirewallPolicy')[0]

        provider_l2p_subnets = self.neutron_client.get_subnets(
            auth_token,
            filters={'id': provider['subnets']})
        for subnet in provider_l2p_subnets:
            if not subnet['name'].startswith(APIC_OWNED_RES):
                provider_cidr = subnet['cidr']
                break
        if not provider_cidr:
            LOG.error(_LE("Unable to get provider cidr for provider "
                          "policy target group %(provider_ptg)s") %
                      {"provider_ptg": provider})
            return None

        fw_template_properties = dict(
            resources_key=resources_key, properties_key=properties_key,
            is_template_aws_version=is_template_aws_version,
            fw_rule_keys=fw_rule_keys,
            fw_policy_key=fw_policy_key)

        if consumer_ptgs:
            filters = {'id': consumer_ptgs}
            consumer_ptgs_details = self.gbp_client.get_policy_target_groups(
                auth_token, filters)

            # Revisit(Magesh): What is the name updated below ?? FW or Rule?
            # This seems to have no effect in UTs
            for consumer in consumer_ptgs_details:
                if consumer['proxied_group_id']:
                    continue
                fw_template_properties.update({'name': consumer['id'][:3]})
                for subnet_id in consumer['subnets']:
                    subnet = self.neutron_client.get_subnet(
                        auth_token, subnet_id)['subnet']
                    if subnet['name'].startswith(APIC_OWNED_RES):
                        continue

                    consumer_cidr = subnet['cidr']
                    self._append_firewall_rule(
                        stack_template, provider_cidr, consumer_cidr,
                        fw_template_properties, consumer['id'])

        if consumer_eps:
            filters = {'id': consumer_eps}
            consumer_eps_details = self.gbp_client.get_external_policies(
                auth_token, filters)
            for consumer_ep in consumer_eps_details:
                fw_template_properties.update({'name': consumer_ep['id'][:3]})
                self._append_firewall_rule(stack_template, provider_cidr,
                                           "0.0.0.0/0", fw_template_properties,
                                           consumer_ep['id'])

        for rule_key in fw_rule_keys:
            del stack_template[resources_key][rule_key]
            stack_template[resources_key][fw_policy_key][
                properties_key]['firewall_rules'].remove(
                    {'get_resource': rule_key})

        return stack_template

    def _modify_fw_resources_name(self, stack_template, provider_ptg,
                                  is_template_aws_version):
        resources_key = 'Resources' if is_template_aws_version else 'resources'
        properties_key = ('Properties' if is_template_aws_version
                          else 'properties')
        resource_name = 'OS::Neutron::FirewallPolicy'
        fw_policy_key = self._get_heat_resource_key(
            stack_template[resources_key],
            is_template_aws_version,
            resource_name)
        fw_resource_name = 'OS::Neutron::Firewall'
        fw_key = self._get_heat_resource_key(
            stack_template[resources_key],
            is_template_aws_version,
            fw_resource_name)
        # Include provider name in firewall, firewall policy.
        ptg_name = '-' + provider_ptg['name']
        stack_template[resources_key][fw_policy_key][
            properties_key]['name'] += ptg_name
        stack_template[resources_key][fw_key][
            properties_key]['name'] += ptg_name

    def _get_rvpn_l3_policy(self, auth_token, provider, node_update):
        # For remote vpn - we need to create a implicit l3 policy
        # for client pool cidr, to avoid this cidr being reused.
        # Check for this tenant if this l3 policy is defined.
        # 1) If yes, get the cidr
        # 2) Else Create one for this tenant with the user provided cidr
        rvpn_l3policy_filter = {
            'tenant_id': [provider['tenant_id']],
            'name': ["remote-vpn-client-pool-cidr-l3policy"]}
        rvpn_l3_policy = self.gbp_client.get_l3_policies(
            auth_token,
            rvpn_l3policy_filter)

        if node_update and not rvpn_l3_policy:
            LOG.error(_LE("Unable to get L3 policy for remote VPN "
                          "while updating node"))
            return None

        if not rvpn_l3_policy:
            remote_vpn_client_pool_cidr = (
                cfg.CONF.heat_driver.
                remote_vpn_client_pool_cidr)
            rvpn_l3_policy = {
                'l3_policy': {
                    'name': "remote-vpn-client-pool-cidr-l3policy",
                    'description': ("L3 Policy for remote vpn "
                                    "client pool cidr"),
                    'ip_pool': remote_vpn_client_pool_cidr,
                    'ip_version': 4,
                    'subnet_prefix_length': 24,
                    'proxy_ip_pool': remote_vpn_client_pool_cidr,
                    'proxy_subnet_prefix_length': 24,
                    'external_segments': {},
                    'tenant_id': provider['tenant_id']}}
            rvpn_l3_policy = self.gbp_client.create_l3_policy(
                auth_token, rvpn_l3_policy)
        else:
            rvpn_l3_policy = rvpn_l3_policy[0]
        return rvpn_l3_policy

    def _get_management_gw_ip(self, auth_token):
        filters = {'name': [SVC_MGMT_PTG_NAME]}
        svc_mgmt_ptgs = self.gbp_client.get_policy_target_groups(
            auth_token, filters)
        if not svc_mgmt_ptgs:
            LOG.error(_LE("Service Management Group is not created by Admin"))
            return None
        else:
            mgmt_subnet_id = svc_mgmt_ptgs[0]['subnets'][0]
            mgmt_subnet = self.neutron_client.get_subnet(
                auth_token, mgmt_subnet_id)['subnet']
            mgmt_gw_ip = mgmt_subnet['gateway_ip']
            return mgmt_gw_ip

    def _get_site_conn_keys(self, template_resource_dict,
                            is_template_aws_version, resource_name):
        keys = []
        type_key = 'Type' if is_template_aws_version else 'type'
        for key in template_resource_dict:
            if template_resource_dict[key].get(type_key) == resource_name:
                keys.append(key)
        return keys

    def _create_node_config_data(self, auth_token, tenant_id,
                                 service_chain_node, service_chain_instance,
                                 provider, provider_port, consumer,
                                 consumer_port, network_function,
                                 mgmt_ip, service_details):

        nf_desc = None
        common_desc = {'network_function_id': network_function['id']}

        service_type = service_details['service_details']['service_type']
        service_vendor = service_details['service_details']['service_vendor']
        device_type = service_details['service_details']['device_type']
        base_mode_support = (True if device_type == 'None'
                             else False)

        _, stack_template_str = self.parse_template_config_string(
            service_chain_node.get('config'))
        try:
            stack_template = (jsonutils.loads(stack_template_str) if
                              stack_template_str.startswith('{') else
                              yaml.load(stack_template_str))
        except Exception:
            LOG.error(_LE(
                "Unable to load stack template for service chain "
                "node:  %(node_id)s") % {'node_id': service_chain_node})
            return None, None
        config_param_values = service_chain_instance.get(
            'config_param_values', '{}')
        stack_params = {}
        try:
            config_param_values = jsonutils.loads(config_param_values)
        except Exception:
            LOG.error(_LE("Unable to load config parameters"))
            return None, None

        is_template_aws_version = stack_template.get(
            'AWSTemplateFormatVersion', False)
        resources_key = ('Resources' if is_template_aws_version
                         else 'resources')
        parameters_key = ('Parameters' if is_template_aws_version
                          else 'parameters')
        properties_key = ('Properties' if is_template_aws_version
                          else 'properties')

        if not base_mode_support:
            provider_port_mac = provider_port['mac_address']
            provider_cidr = service_details['provider_subnet']['cidr']
            provider_subnet = service_details['provider_subnet']
        else:
            provider_port_mac = ''
            provider_cidr = ''
        standby_provider_port_mac = None

        if service_type == pconst.LOADBALANCER:
            self._generate_pool_members(
                auth_token, stack_template, config_param_values,
                provider, is_template_aws_version)
            config_param_values['Subnet'] = provider_subnet['id']
            config_param_values['service_chain_metadata'] = ""
            if not base_mode_support:
                config_param_values[
                    'service_chain_metadata'] = str(common_desc)
                nf_desc = str((SC_METADATA % (service_chain_instance['id'],
                                              mgmt_ip,
                                              provider_port_mac,
                                              standby_provider_port_mac,
                                              network_function['id'],
                                              service_vendor)))

                lb_pool_key = self._get_heat_resource_key(
                    stack_template[resources_key],
                    is_template_aws_version,
                    'OS::Neutron::Pool')
                stack_template[resources_key][lb_pool_key][properties_key][
                    'description'] = str(common_desc)

        elif service_type == pconst.LOADBALANCERV2:
            self._generate_lbaasv2_pool_members(
                auth_token, stack_template, config_param_values,
                provider, is_template_aws_version)
            config_param_values['Subnet'] = provider_subnet['id']
            config_param_values['service_chain_metadata'] = ""
            if not base_mode_support:
                config_param_values[
                    'service_chain_metadata'] = str(common_desc)
                nf_desc = str((SC_METADATA % (service_chain_instance['id'],
                                              mgmt_ip,
                                              provider_port_mac,
                                              standby_provider_port_mac,
                                              network_function['id'],
                                              service_vendor)))

            lb_loadbalancer_key = self._get_heat_resource_key(
                stack_template[resources_key],
                is_template_aws_version,
                'OS::Neutron::LBaaS::LoadBalancer')
            stack_template[resources_key][lb_loadbalancer_key][
                properties_key]['description'] = str(common_desc)

        elif service_type == pconst.FIREWALL:
            stack_template = self._create_firewall_template(
                auth_token, service_details, stack_template)

            if not stack_template:
                return None, None
            self._modify_fw_resources_name(
                stack_template, provider, is_template_aws_version)
            if not base_mode_support:
                firewall_desc = {'vm_management_ip': mgmt_ip,
                                 'provider_ptg_info': [provider_port_mac],
                                 'provider_cidr': provider_cidr,
                                 'service_vendor': service_vendor,
                                 'network_function_id': network_function[
                                     'id']}

                fw_key = self._get_heat_resource_key(
                    stack_template[resources_key],
                    is_template_aws_version,
                    'OS::Neutron::Firewall')
                stack_template[resources_key][fw_key][properties_key][
                    'description'] = str(common_desc)

                nf_desc = str(firewall_desc)
        elif service_type == pconst.VPN:
            config_param_values['Subnet'] = (
                consumer_port['fixed_ips'][0]['subnet_id']
                if consumer_port else None)
            l2p = self.gbp_client.get_l2_policy(
                auth_token, provider['l2_policy_id'])
            l3p = self.gbp_client.get_l3_policy(
                auth_token, l2p['l3_policy_id'])
            config_param_values['RouterId'] = l3p['routers'][0]
            stitching_cidr = service_details['consumer_subnet']['cidr']
            mgmt_gw_ip = self._get_management_gw_ip(auth_token)
            if not mgmt_gw_ip:
                return None, None

            services_nsp = self.gbp_client.get_network_service_policies(
                auth_token,
                filters={'name': ['nfp_services_nsp']})
            if not services_nsp:
                fip_nsp = {
                    'network_service_policy': {
                        'name': 'nfp_services_nsp',
                        'description': 'nfp_implicit_resource',
                        'shared': False,
                        'tenant_id': tenant_id,
                        'network_service_params': [
                            {"type": "ip_pool", "value": "nat_pool",
                             "name": "vpn_svc_external_access"}]
                    }
                }
                nsp = self.gbp_client.create_network_service_policy(
                    auth_token, fip_nsp)
            else:
                nsp = services_nsp[0]
            if not base_mode_support:
                stitching_pts = self.gbp_client.get_policy_targets(
                    auth_token,
                    filters={'port_id': [consumer_port['id']]})
                if not stitching_pts:
                    LOG.error(_LE("Policy target is not created for the "
                                  "stitching port"))
                    return None, None
                stitching_ptg_id = (
                    stitching_pts[0]['policy_target_group_id'])
            else:
                stitching_ptg_id = consumer['id']
            self.gbp_client.update_policy_target_group(
                auth_token, stitching_ptg_id,
                {'policy_target_group': {
                    'network_service_policy_id': nsp['id']}})
            stitching_port_fip = ""

            if not base_mode_support:
                floatingips = (
                    self.neutron_client.get_floating_ips(auth_token))
                if not floatingips:
                    LOG.error(_LE("Floating IP for VPN Service has been "
                                  "disassociated Manually"))
                    return None, None

                for fip in floatingips:
                    if consumer_port['id'] == fip['port_id']:
                        stitching_port_fip = fip['floating_ip_address']
                        break
                if not stitching_port_fip:
                    LOG.error(_LE("Floatingip retrival has failed."))
                    return None, None

                try:
                    desc = ('fip=' + mgmt_ip +
                            ";tunnel_local_cidr=" +
                            provider_cidr + ";user_access_ip=" +
                            stitching_port_fip + ";fixed_ip=" +
                            consumer_port['fixed_ips'][0]['ip_address'] +
                            ';service_vendor=' + service_vendor +
                            ';stitching_cidr=' + stitching_cidr +
                            ';stitching_gateway=' + service_details[
                                'consumer_subnet']['gateway_ip'] +
                            ';mgmt_gw_ip=' + mgmt_gw_ip +
                            ';network_function_id=' + network_function['id'])
                except Exception:
                    LOG.error(_LE("Problem in preparing description, some of "
                                  "the fields might not have initialized"))
                    return None, None
                stack_params['ServiceDescription'] = desc
                siteconn_keys = self._get_site_conn_keys(
                    stack_template[resources_key],
                    is_template_aws_version,
                    'OS::Neutron::IPsecSiteConnection')
                for siteconn_key in siteconn_keys:
                    stack_template[resources_key][siteconn_key][
                        properties_key]['description'] = str(common_desc)

                vpnservice_key = self._get_heat_resource_key(
                    stack_template[resources_key],
                    is_template_aws_version,
                    'OS::Neutron::VPNService')
                stack_template[resources_key][vpnservice_key][properties_key][
                    'description'] = str(common_desc)

                nf_desc = str(desc)

        if nf_desc:
            network_function['description'] = network_function[
                'description'] + '\n' + nf_desc

        for parameter in stack_template.get(parameters_key) or []:
            if parameter in config_param_values:
                stack_params[parameter] = config_param_values[parameter]

        LOG.info(_LI('Final stack_template : %(stack_data)s, '
                     'stack_params : %(params)s') %
                 {'stack_data': stack_template, 'params': stack_params})
        return (stack_template, stack_params)

    def _update_node_config(self, auth_token, tenant_id, service_profile,
                            service_chain_node, service_chain_instance,
                            provider, consumer_port, network_function,
                            provider_port, update=False, mgmt_ip=None,
                            consumer=None):
        nf_desc = None
        common_desc = {'network_function_id': str(network_function['id'])}
        provider_cidr = provider_subnet = None
        provider_l2p_subnets = self.neutron_client.get_subnets(
            auth_token, filters={'id': provider['subnets']})
        for subnet in provider_l2p_subnets:
            if not subnet['name'].startswith(APIC_OWNED_RES):
                provider_cidr = subnet['cidr']
                provider_subnet = subnet
                break
        if not provider_cidr:
            LOG.error(_LE("No provider cidr availabale"))
            return None, None
        service_type = service_profile['service_type']
        service_details = transport.parse_service_flavor_string(
            service_profile['service_flavor'])
        base_mode_support = (True if service_details['device_type'] == 'None'
                             else False)

        _, stack_template_str = self.parse_template_config_string(
            service_chain_node.get('config'))
        try:
            stack_template = (jsonutils.loads(stack_template_str) if
                              stack_template_str.startswith('{') else
                              yaml.load(stack_template_str))
        except Exception:
            LOG.error(_LE(
                "Unable to load stack template for service chain "
                "node:  %(node_id)s"), {'node_id': service_chain_node})
            return None, None
        config_param_values = service_chain_instance.get(
            'config_param_values', '{}')
        stack_params = {}
        try:
            config_param_values = jsonutils.loads(config_param_values)
        except Exception:
            LOG.error(_LE("Unable to load config parameters"))
            return None, None

        is_template_aws_version = stack_template.get(
            'AWSTemplateFormatVersion', False)
        resources_key = ('Resources' if is_template_aws_version
                         else 'resources')
        parameters_key = ('Parameters' if is_template_aws_version
                          else 'parameters')
        properties_key = ('Properties' if is_template_aws_version
                          else 'properties')

        if not base_mode_support:
            provider_port_mac = provider_port['mac_address']
            provider_cidr = self.neutron_client.get_subnet(
                auth_token, provider_port['fixed_ips'][0][
                    'subnet_id'])['subnet']['cidr']
        else:
            provider_port_mac = ''
            provider_cidr = ''
        standby_provider_port_mac = None

        service_vendor = service_details['service_vendor']
        if service_type == pconst.LOADBALANCER:
            self._generate_pool_members(
                auth_token, stack_template, config_param_values,
                provider, is_template_aws_version)
            config_param_values['Subnet'] = provider_subnet['id']
            config_param_values['service_chain_metadata'] = ""
            if not base_mode_support:
                config_param_values[
                    'service_chain_metadata'] = str(common_desc)
                nf_desc = str((SC_METADATA % (service_chain_instance['id'],
                                              mgmt_ip,
                                              provider_port_mac,
                                              standby_provider_port_mac,
                                              network_function['id'],
                                              service_vendor)))

                lb_pool_key = self._get_heat_resource_key(
                    stack_template[resources_key],
                    is_template_aws_version,
                    'OS::Neutron::Pool')
                stack_template[resources_key][lb_pool_key][properties_key][
                    'description'] = str(common_desc)

        elif service_type == pconst.LOADBALANCERV2:
            self._generate_lbaasv2_pool_members(
                auth_token, stack_template, config_param_values,
                provider, is_template_aws_version)
            config_param_values['Subnet'] = provider_subnet['id']
            config_param_values['service_chain_metadata'] = ""
            if not base_mode_support:
                config_param_values[
                    'service_chain_metadata'] = str(common_desc)
                nf_desc = str((SC_METADATA % (service_chain_instance['id'],
                                              mgmt_ip,
                                              provider_port_mac,
                                              standby_provider_port_mac,
                                              network_function['id'],
                                              service_vendor)))

            lb_loadbalancer_key = self._get_heat_resource_key(
                stack_template[resources_key],
                is_template_aws_version,
                'OS::Neutron::LBaaS::LoadBalancer')
            stack_template[resources_key][lb_loadbalancer_key][
                properties_key]['description'] = str(common_desc)

        elif service_type == pconst.FIREWALL:
            stack_template = self._update_firewall_template(
                auth_token, provider, stack_template)
            if not stack_template:
                return None, None
            self._modify_fw_resources_name(
                stack_template, provider, is_template_aws_version)
            if not base_mode_support:
                firewall_desc = {'vm_management_ip': mgmt_ip,
                                 'provider_ptg_info': [provider_port_mac],
                                 'provider_cidr': provider_cidr,
                                 'service_vendor': service_vendor,
                                 'network_function_id': network_function[
                                     'id']}

                fw_key = self._get_heat_resource_key(
                    stack_template[resources_key],
                    is_template_aws_version,
                    'OS::Neutron::Firewall')
                stack_template[resources_key][fw_key][properties_key][
                    'description'] = str(common_desc)

                nf_desc = str(firewall_desc)
        elif service_type == pconst.VPN:
            config_param_values['Subnet'] = (
                consumer_port['fixed_ips'][0]['subnet_id']
                if consumer_port else None)
            l2p = self.gbp_client.get_l2_policy(
                auth_token, provider['l2_policy_id'])
            l3p = self.gbp_client.get_l3_policy(
                auth_token, l2p['l3_policy_id'])
            config_param_values['RouterId'] = l3p['routers'][0]
            stitching_subnet = self.neutron_client.get_subnet(
                auth_token,
                consumer['subnets'][0])['subnet']
            stitching_cidr = stitching_subnet['cidr']
            mgmt_gw_ip = self._get_management_gw_ip(auth_token)
            if not mgmt_gw_ip:
                return None, None
            if not update:
                services_nsp = self.gbp_client.get_network_service_policies(
                    auth_token,
                    filters={'name': ['nfp_services_nsp']})
                if not services_nsp:
                    fip_nsp = {
                        'network_service_policy': {
                            'name': 'nfp_services_nsp',
                            'description': 'nfp_implicit_resource',
                            'shared': False,
                            'tenant_id': tenant_id,
                            'network_service_params': [
                                {"type": "ip_pool", "value": "nat_pool",
                                 "name": "vpn_svc_external_access"}]
                        }
                    }
                    nsp = self.gbp_client.create_network_service_policy(
                        auth_token, fip_nsp)
                else:
                    nsp = services_nsp[0]
                if not base_mode_support:
                    stitching_pts = self.gbp_client.get_policy_targets(
                        auth_token,
                        filters={'port_id': [consumer_port['id']]})
                    if not stitching_pts:
                        LOG.error(_LE("Policy target is not created for the "
                                      "stitching port"))
                        return None, None
                    stitching_ptg_id = (
                        stitching_pts[0]['policy_target_group_id'])
                else:
                    stitching_ptg_id = consumer['id']
                self.gbp_client.update_policy_target_group(
                    auth_token, stitching_ptg_id,
                    {'policy_target_group': {
                        'network_service_policy_id': nsp['id']}})
            if not base_mode_support:
                floatingips = self.neutron_client.get_floating_ips(
                    auth_token, consumer_port['id'])
                if not floatingips:
                    LOG.error(_LE("Floating IP for VPN Service has been "
                                  "disassociated Manually"))
                    return None, None
                for fip in floatingips:
                    if consumer_port['fixed_ips'][0]['ip_address'] == fip[
                            'fixed_ip_address']:
                        stitching_port_fip = fip['floating_ip_address']

                try:
                    desc = ('fip=' + mgmt_ip +
                            ";tunnel_local_cidr=" +
                            provider_cidr + ";user_access_ip=" +
                            stitching_port_fip + ";fixed_ip=" +
                            consumer_port['fixed_ips'][0]['ip_address'] +
                            ';service_vendor=' + service_details[
                                'service_vendor'] +
                            ';stitching_cidr=' + stitching_cidr +
                            ';stitching_gateway=' + stitching_subnet[
                                'gateway_ip'] +
                            ';mgmt_gw_ip=' + mgmt_gw_ip +
                            ';network_function_id=' + network_function['id'])
                except Exception:
                    LOG.error(_LE("Problem in preparing description, some of "
                                  "the fields might not have initialized"))
                    return None, None
                stack_params['ServiceDescription'] = desc
                siteconn_keys = self._get_site_conn_keys(
                    stack_template[resources_key],
                    is_template_aws_version,
                    'OS::Neutron::IPsecSiteConnection')
                for siteconn_key in siteconn_keys:
                    stack_template[resources_key][siteconn_key][
                        properties_key]['description'] = str(common_desc)

                vpnservice_key = self._get_heat_resource_key(
                    stack_template[resources_key],
                    is_template_aws_version,
                    'OS::Neutron::VPNService')
                stack_template[resources_key][vpnservice_key][properties_key][
                    'description'] = str(common_desc)

                nf_desc = str(desc)

        if nf_desc:
            network_function['description'] = network_function[
                'description'] + '\n' + nf_desc

        for parameter in stack_template.get(parameters_key) or []:
            if parameter in config_param_values:
                stack_params[parameter] = config_param_values[parameter]

        LOG.info(_LI('Final stack_template : %(stack_data)s, '
                     'stack_params : %(params)s') %
                 {'stack_data': stack_template, 'params': stack_params})
        return (stack_template, stack_params)

    def parse_template_config_string(self, config_str):
        service_config = tag_str = ''
        for tag_str in [nfp_constants.HEAT_CONFIG_TAG,
                        nfp_constants.CONFIG_INIT_TAG,
                        nfp_constants.ANSIBLE_TAG,
                        nfp_constants.CUSTOM_JSON]:
            try:
                service_config = config_str.split(tag_str + ':')[1]
                break
            except IndexError:
                # Try for next tag
                pass
            except Exception:
                return None, None
        if not service_config:
            service_config = config_str
            tag_str = nfp_constants.HEAT_CONFIG_TAG
        return tag_str, service_config

    def get_service_details(self, network_function_details):
        db_handler = nfp_db.NFPDbBase()
        db_session = db_api.get_session()
        network_function = network_function_details['network_function']
        network_function_instance = network_function_details.get(
            'network_function_instance')
        service_profile_id = network_function['service_profile_id']
        admin_token = self.keystoneclient.get_admin_token()
        service_profile = self.gbp_client.get_service_profile(
            admin_token, service_profile_id)

        service_details = transport.parse_service_flavor_string(
            service_profile['service_flavor'])
        if service_details['device_type'] != 'None':
            network_function_device = network_function_details[
                'network_function_device']
            mgmt_ip = network_function_device['mgmt_ip_address']
        else:
            mgmt_ip = None

        heat_stack_id = network_function['heat_stack_id']
        service_id = network_function['service_id']
        servicechain_node = self.gbp_client.get_servicechain_node(admin_token,
                                                                  service_id)
        service_chain_id = network_function['service_chain_id']
        servicechain_instance = self.gbp_client.get_servicechain_instance(
            admin_token,
            service_chain_id)
        provider_ptg_id = servicechain_instance['provider_ptg_id']
        consumer_ptg_id = servicechain_instance['consumer_ptg_id']
        provider_ptg = self.gbp_client.get_policy_target_group(
            admin_token,
            provider_ptg_id)
        consumer_ptg = None
        if consumer_ptg_id and consumer_ptg_id != 'N/A':
            consumer_ptg = self.gbp_client.get_policy_target_group(
                admin_token,
                consumer_ptg_id)

        consumer_port = None
        provider_port = None
        consumer_policy_target_group = None
        provider_policy_target_group = None
        policy_target = None
        if network_function_instance:
            for port in network_function_instance.get('port_info'):
                port_info = db_handler.get_port_info(db_session, port)
                port_classification = port_info['port_classification']
                if port_info['port_model'] == nfp_constants.GBP_PORT:
                    policy_target_id = port_info['id']
                    port_id = self.gbp_client.get_policy_targets(
                        admin_token,
                        filters={'id': policy_target_id})[0]['port_id']
                    policy_target = self.gbp_client.get_policy_target(
                        admin_token, policy_target_id)
                else:
                    port_id = port_info['id']

                if port_classification == nfp_constants.CONSUMER:
                    consumer_port = self.neutron_client.get_port(
                        admin_token, port_id)['port']
                    if policy_target:
                        consumer_policy_target_group = (
                            self.gbp_client.get_policy_target_group(
                                admin_token,
                                policy_target['policy_target_group_id']))
                elif port_classification == nfp_constants.PROVIDER:
                    LOG.info(_LI("provider info: %s") % (port_id))
                    provider_port = self.neutron_client.get_port(
                        admin_token, port_id)['port']
                    if policy_target:
                        provider_policy_target_group = (
                            self.gbp_client.get_policy_target_group(
                                admin_token,
                                policy_target['policy_target_group_id']))

        service_details = {
            'service_profile': service_profile,
            'servicechain_node': servicechain_node,
            'servicechain_instance': servicechain_instance,
            'consumer_port': consumer_port,
            'provider_port': provider_port,
            'mgmt_ip': mgmt_ip,
            'policy_target_group': provider_policy_target_group,
            'heat_stack_id': heat_stack_id,
            'provider_ptg': provider_ptg,
            'consumer_ptg': consumer_ptg or consumer_policy_target_group
        }

        return service_details

    def _wait_for_stack_operation_complete(self, heatclient, stack_id, action,
                                           ignore_error=False):
        time_waited = 0
        operation_failed = False
        timeout_mins, timeout_seconds = divmod(STACK_ACTION_WAIT_TIME, 60)
        if timeout_seconds:
            timeout_mins = timeout_mins + 1
        # Heat timeout is in order of minutes. Allow Node driver to wait a
        # little longer than heat timeout
        wait_timeout = timeout_mins * 60 + 30
        while True:
            try:
                stack = heatclient.get(stack_id)
                if stack.stack_status == 'DELETE_FAILED':
                    heatclient.delete(stack_id)
                elif stack.stack_status == 'CREATE_COMPLETE':
                    return
                elif stack.stack_status == 'DELETE_COMPLETE':
                    LOG.info(_LI("Stack %(stack)s is deleted"),
                             {'stack': stack_id})
                    if action == "delete":
                        return
                    else:
                        operation_failed = True
                elif stack.stack_status == 'CREATE_FAILED':
                    operation_failed = True
                elif stack.stack_status == 'UPDATE_FAILED':
                    operation_failed = True
                elif stack.stack_status not in [
                        'UPDATE_IN_PROGRESS', 'CREATE_IN_PROGRESS',
                        'DELETE_IN_PROGRESS']:
                    return
            except heat_exc.HTTPNotFound:
                LOG.warning(_LW(
                    "Stack %(stack)s created by service chain "
                    "driver is not found while waiting for %(action)s "
                    "to complete"),
                    {'stack': stack_id, 'action': action})
                if action == "create" or action == "update":
                    operation_failed = True
                else:
                    return
            except Exception:
                LOG.exception(_LE("Retrieving the stack %(stack)s failed."),
                              {'stack': stack_id})
                if action == "create" or action == "update":
                    operation_failed = True
                else:
                    return

            if operation_failed:
                if ignore_error:
                    return
                else:
                    LOG.error(_LE("Stack %(stack_name)s %(action)s failed for "
                                  "tenant %(stack_owner)s"),
                              {'stack_name': stack.stack_name,
                               'stack_owner': stack.stack_owner,
                               'action': action})
                    return None
            else:
                time.sleep(STACK_ACTION_RETRY_WAIT)
                time_waited = time_waited + STACK_ACTION_RETRY_WAIT
                if time_waited >= wait_timeout:
                    LOG.error(_LE("Stack %(action)s not completed within "
                                  "%(wait)s seconds"),
                              {'action': action,
                               'wait': wait_timeout,
                               'stack': stack_id})
                    # Some times, a second delete request succeeds in cleaning
                    # up the stack when the first request is stuck forever in
                    # Pending state
                    if action == 'delete':
                        try:
                            heatclient.delete(stack_id)
                        except Exception:
                            pass
                        return
                    else:
                        LOG.error(_LE(
                            "Stack %(stack_name)s %(action)s not "
                            "completed within %(time)s seconds where "
                            "stack owner is %(stack_owner)s") %
                            {'stack_name': stack.stack_name,
                             'action': action,
                             'time': wait_timeout,
                             'stack_owner': stack.stack_owner})
                        return None

    def is_config_complete(self, stack_id, tenant_id,
                           network_function_details):
        success_status = "COMPLETED"
        failure_status = "ERROR"
        intermediate_status = "IN_PROGRESS"
        _, resource_owner_tenant_id = (
            self._get_resource_owner_context())
        heatclient = self._get_heat_client(tenant_id)
        if not heatclient:
            return failure_status
        try:
            stack = heatclient.get(stack_id)
            if stack.stack_status == 'DELETE_FAILED':
                return failure_status
            elif stack.stack_status == 'CREATE_COMPLETE':
                self.loadbalancer_post_stack_create(network_function_details)
                return success_status
            elif stack.stack_status == 'UPDATE_COMPLETE':
                return success_status
            elif stack.stack_status == 'DELETE_COMPLETE':
                LOG.info(_LI("Stack %(stack)s is deleted"),
                         {'stack': stack_id})
                return failure_status
            elif stack.stack_status == 'CREATE_FAILED':
                return failure_status
            elif stack.stack_status == 'UPDATE_FAILED':
                return failure_status
            elif stack.stack_status not in [
                    'UPDATE_IN_PROGRESS', 'CREATE_IN_PROGRESS',
                    'DELETE_IN_PROGRESS']:
                return intermediate_status
        except Exception:
            LOG.exception(_LE("Retrieving the stack %(stack)s failed."),
                          {'stack': stack_id})
            return failure_status

    def check_config_complete(self, nfp_context):
        success_status = "COMPLETED"
        failure_status = "ERROR"
        intermediate_status = "IN_PROGRESS"

        provider_tenant_id = nfp_context['tenant_id']
        stack_id = nfp_context['heat_stack_id']

        heatclient = self._get_heat_client(provider_tenant_id)
        if not heatclient:
            return failure_status
        try:
            stack = heatclient.get(stack_id)
            if stack.stack_status == 'DELETE_FAILED':
                return failure_status
            elif stack.stack_status == 'CREATE_COMPLETE':
                self._post_stack_create(nfp_context)
                return success_status
            elif stack.stack_status == 'UPDATE_COMPLETE':
                return success_status
            elif stack.stack_status == 'DELETE_COMPLETE':
                LOG.info(_LI("Stack %(stack)s is deleted"),
                         {'stack': stack_id})
                return failure_status
            elif stack.stack_status == 'CREATE_FAILED':
                return failure_status
            elif stack.stack_status == 'UPDATE_FAILED':
                return failure_status
            elif stack.stack_status not in [
                    'UPDATE_IN_PROGRESS', 'CREATE_IN_PROGRESS',
                    'DELETE_IN_PROGRESS']:
                return intermediate_status
        except Exception:
            LOG.exception(_LE("Retrieving the stack %(stack)s failed."),
                          {'stack': stack_id})
            return failure_status

    def is_config_delete_complete(self, stack_id, tenant_id,
            network_function=None):
        success_status = "COMPLETED"
        failure_status = "ERROR"
        intermediate_status = "IN_PROGRESS"
        _, resource_owner_tenant_id = (
            self._get_resource_owner_context())
        heatclient = self._get_heat_client(tenant_id)
        if not heatclient:
            return failure_status
        try:
            stack = heatclient.get(stack_id)
            if stack.stack_status == 'DELETE_FAILED':
                return failure_status
            elif stack.stack_status == 'CREATE_COMPLETE':
                return failure_status
            elif stack.stack_status == 'DELETE_COMPLETE':
                LOG.info(_LI("Stack %(stack)s is deleted"),
                         {'stack': stack_id})
                if network_function:
                    self._post_stack_cleanup(network_function)
                return success_status
            elif stack.stack_status == 'CREATE_FAILED':
                return failure_status
            elif stack.stack_status == 'UPDATE_FAILED':
                return failure_status
            elif stack.stack_status not in [
                    'UPDATE_IN_PROGRESS', 'CREATE_IN_PROGRESS',
                    'DELETE_IN_PROGRESS']:
                return intermediate_status
        except Exception:
            LOG.exception(_LE("Retrieving the stack %(stack)s failed."),
                          {'stack': stack_id})
            return failure_status

    def get_service_details_from_nfp_context(self, nfp_context):
        network_function = nfp_context['network_function']
        # network_function_instance = nfp_context['network_function_instance']
        service_details = nfp_context['service_details']
        mgmt_ip = nfp_context['management']['port']['ip_address']
        heat_stack_id = network_function['heat_stack_id']
        # service_id = network_function['service_id']
        # service_chain_id = network_function['service_chain_id']
        servicechain_instance = nfp_context['service_chain_instance']
        servicechain_node = nfp_context['service_chain_node']

        consumer_policy_target_group = nfp_context['consumer']['ptg']
        provider_policy_target_group = nfp_context['provider']['ptg']
        provider_port = nfp_context['provider']['port']
        provider_subnet = nfp_context['provider']['subnet']
        consumer_port = nfp_context['consumer']['port']
        consumer_subnet = nfp_context['consumer']['subnet']
        service_details['consuming_external_policies'] = nfp_context[
            'consuming_eps_details']
        service_details['consuming_ptgs_details'] = nfp_context[
            'consuming_ptgs_details']

        return {
            'service_profile': None,
            'service_details': service_details,
            'servicechain_node': servicechain_node,
            'servicechain_instance': servicechain_instance,
            'consumer_port': consumer_port,
            'consumer_subnet': consumer_subnet,
            'provider_port': provider_port,
            'provider_subnet': provider_subnet,
            'mgmt_ip': mgmt_ip,
            'heat_stack_id': heat_stack_id,
            'provider_ptg': provider_policy_target_group,
            'consumer_ptg': consumer_policy_target_group,
            'consuming_external_policies':
            service_details['consuming_external_policies'],
            'consuming_ptgs_details':
            service_details['consuming_ptgs_details']
        }

    def apply_config(self, network_function_details):
        service_details = self.get_service_details(network_function_details)
        service_profile = service_details['service_profile']
        service_chain_node = service_details['servicechain_node']
        service_chain_instance = service_details['servicechain_instance']
        provider = service_details['provider_ptg']
        consumer = service_details['consumer_ptg']
        consumer_port = service_details['consumer_port']
        provider_port = service_details['provider_port']
        mgmt_ip = service_details['mgmt_ip']

        service_details = transport.parse_service_flavor_string(
            service_profile['service_flavor'])

        auth_token, resource_owner_tenant_id = (
            self._get_resource_owner_context())
        provider_tenant_id = provider['tenant_id']
        heatclient = self._get_heat_client(provider_tenant_id)
        if not heatclient:
            return None
        stack_name = ("stack_" + service_chain_instance['name'] +
                      service_chain_node['name'] +
                      service_chain_instance['id'][:8] +
                      service_chain_node['id'][:8] + '-' +
                      time.strftime("%Y%m%d%H%M%S"))
        # Heat does not accept space in stack name
        stack_name = stack_name.replace(" ", "")
        stack_template, stack_params = self._update_node_config(
            auth_token, provider_tenant_id, service_profile,
            service_chain_node, service_chain_instance, provider,
            consumer_port, network_function_details['network_function'],
            provider_port, mgmt_ip=mgmt_ip, consumer=consumer)

        if not stack_template and not stack_params:
            return None

        try:
            stack = heatclient.create(stack_name, stack_template, stack_params)
        except Exception as err:
            LOG.error(_LE("Heat stack creation failed for template : "
                          "%(template)s and stack parameters : %(params)s "
                          "with Error: %(error)s") %
                      {'template': stack_template, 'params': stack_params,
                       'error': err})
            return None

        stack_id = stack['stack']['id']
        LOG.info(_LI("Created stack with ID %(stack_id)s and "
                     "name %(stack_name)s for provider PTG %(provider)s"),
                 {'stack_id': stack_id, 'stack_name': stack_name,
                  'provider': provider['id']})

        return stack_id

    def apply_heat_config(self, nfp_context):
        service_details = self.get_service_details_from_nfp_context(
            nfp_context)

        network_function = nfp_context['network_function']
        # service_profile = service_details['service_profile']
        service_chain_node = service_details['servicechain_node']
        service_chain_instance = service_details['servicechain_instance']
        provider = service_details['provider_ptg']
        consumer = service_details['consumer_ptg']
        consumer_port = service_details['consumer_port']
        provider_port = service_details['provider_port']
        mgmt_ip = service_details['mgmt_ip']

        auth_token = nfp_context['resource_owner_context']['admin_token']
        provider_tenant_id = nfp_context['tenant_id']
        heatclient = self._get_heat_client(provider_tenant_id,
                                           assign_admin=True)
        if not heatclient:
            return None

        stack_template, stack_params = self._create_node_config_data(
            auth_token, provider_tenant_id,
            service_chain_node, service_chain_instance,
            provider, provider_port, consumer, consumer_port,
            network_function, mgmt_ip, service_details)

        if not stack_template and not stack_params:
            return None

        if not heatclient:
            return None

        stack_name = ("stack_" + service_chain_instance['name'] +
                      service_chain_node['name'] +
                      service_chain_instance['id'][:8] +
                      service_chain_node['id'][:8] + '-' +
                      time.strftime("%Y%m%d%H%M%S"))
        # Heat does not accept space in stack name
        stack_name = stack_name.replace(" ", "")

        try:
            stack = heatclient.create(stack_name, stack_template, stack_params)
        except Exception as err:
            LOG.error(_LE("Heat stack creation failed for template : "
                          "%(template)s and stack parameters : %(params)s "
                          "with Error: %(error)s") %
                      {'template': stack_template, 'params': stack_params,
                       'error': err})
            return None

        stack_id = stack['stack']['id']
        LOG.info(_LI("Created stack with ID %(stack_id)s and "
                     "name %(stack_name)s for provider PTG %(provider)s"),
                 {'stack_id': stack_id, 'stack_name': stack_name,
                  'provider': provider['id']})

        return stack_id

    def delete_config(self, stack_id, tenant_id, network_function=None):
        _, resource_owner_tenant_id = (
            self._get_resource_owner_context())

        try:
            heatclient = self._get_heat_client(tenant_id)
            if not heatclient:
                return None
            if network_function:
                self._pre_stack_cleanup(network_function)
            heatclient.delete(stack_id)
        except Exception as err:
            # Log the error and continue with VM delete in case of *aas
            # cleanup failure
            LOG.exception(_LE("Cleaning up the service chain stack failed "
                              "with Error: %(error)s"), {'error': err})
            return None
        return stack_id

    def is_update_config_supported(self, service_type):
        return (
            False
            if (service_type == pconst.VPN or
                service_type == pconst.FIREWALL)
            else True
        )

    def _update(self, auth_token, resource_owner_tenant_id, service_profile,
                service_chain_node, service_chain_instance, provider,
                consumer_port, network_function, provider_port, stack_id,
                consumer=None, mgmt_ip=None, pt_added_or_removed=False):
        # If it is not a Node config update or PT change for LB, no op
        service_type = service_profile['service_type']
        service_details = transport.parse_service_flavor_string(
            service_profile['service_flavor'])
        base_mode_support = (True if service_details['device_type'] == 'None'
                             else False)
        provider_tenant_id = provider['tenant_id']
        heatclient = self._get_heat_client(provider_tenant_id)
        if not heatclient:
            return None

        if not base_mode_support and not mgmt_ip:
            LOG.error(_LE("Service information is not available with Service "
                          "Orchestrator on node update"))
            return None

        stack_template, stack_params = self._update_node_config(
            auth_token, provider_tenant_id, service_profile,
            service_chain_node, service_chain_instance, provider,
            consumer_port, network_function, provider_port,
            update=True, mgmt_ip=mgmt_ip, consumer=consumer)
        if not stack_template and not stack_params:
            return None

        if stack_id:
            if service_type == pconst.VPN or service_type == pconst.FIREWALL:
                stack_name = ("stack_" + service_chain_instance['name'] +
                              service_chain_node['name'] +
                              service_chain_instance['id'][:8] +
                              service_chain_node['id'][:8] + '-' +
                              time.strftime("%Y%m%d%H%M%S"))
                try:
                    stack = heatclient.create(stack_name, stack_template,
                                              stack_params)
                except Exception as err:
                    msg = ('Fatal error. Heat Stack creation failed while '
                           'update of node. To recover,please delete the '
                           'associated provider of Tenant ID -  %r . Details '
                           '- %r' % (provider_tenant_id, str(err)))
                    LOG.exception(_LE('%(msg)s') % {'msg': msg})
                    return None
                stack_id = stack["stack"]["id"]
            else:
                try:
                    heatclient.update(stack_id, stack_template, stack_params)
                except Exception as err:
                    msg = ('Node update failed. There can be a chance if the '
                           'service is LOADBALANCER, the related '
                           'configuration would have been lost. Please check '
                           'with the ADMIN for issue of failure and '
                           're-initiate the update node once again.')
                    LOG.exception(_LE('%(msg)s NODE-ID: %(node_id)s '
                                      'INSTANCE-ID: %(instance_id)s '
                                      'TenantID: %(tenant_id)s . '
                                      'ERROR: %(err)s') %
                                  {'msg': msg,
                                   'node_id': service_chain_node['id'],
                                   'instance_id': service_chain_instance['id'],
                                   'tenant_id': provider_tenant_id,
                                   'err': str(err)})
                    return None
        if not stack_id:
            stack_name = ("stack_" + service_chain_instance['name'] +
                          service_chain_node['name'] +
                          service_chain_instance['id'][:8] +
                          service_chain_node['id'][:8] + '-' +
                          time.strftime("%Y%m%d%H%M%S"))
            try:
                stack = heatclient.create(stack_name, stack_template,
                                          stack_params)
            except Exception as err:
                msg = ('Fatal error. Heat Stack creation failed while '
                       'update of node. To recover,please delete the '
                       'associated provider of Tenant ID -  %r . Details '
                       '- %r' % (provider_tenant_id, str(err)))
                LOG.exception(_LE('%(msg)s') % {'msg': msg})
                return None
            stack_id = stack["stack"]["id"]
        return stack_id

    def update_config(self, network_function_details, stack_id):
        service_details = self.get_service_details(network_function_details)
        service_profile = service_details['service_profile']
        service_chain_node = service_details['servicechain_node']
        service_chain_instance = service_details['servicechain_instance']
        provider = service_details['provider_ptg']
        consumer = service_details['consumer_ptg']
        consumer_port = service_details['consumer_port']
        provider_port = service_details['provider_port']
        mgmt_ip = service_details['mgmt_ip']

        auth_token, resource_owner_tenant_id = (
            self._get_resource_owner_context())
        stack_id = self._update(auth_token, resource_owner_tenant_id,
                                service_profile, service_chain_node,
                                service_chain_instance, provider,
                                consumer_port, network_function_details[
                                    'network_function'],
                                provider_port,
                                stack_id, consumer=consumer, mgmt_ip=mgmt_ip)

        if not stack_id:
            return None
        return stack_id

    def handle_policy_target_operations(self, network_function_details,
                                        policy_target, operation):
        service_details = self.get_service_details(network_function_details)
        service_profile = service_details['service_profile']
        service_chain_node = service_details['servicechain_node']
        service_chain_instance = service_details['servicechain_instance']
        provider = service_details['provider_ptg']
        consumer_port = service_details['consumer_port']
        provider_port = service_details['provider_port']
        mgmt_ip = service_details['mgmt_ip']
        stack_id = service_details['heat_stack_id']

        if service_profile['service_type'] in [pconst.LOADBALANCER,
                                               pconst.LOADBALANCERV2]:
            if self._is_service_target(policy_target):
                return
            auth_token, resource_owner_tenant_id = (
                self._get_resource_owner_context())
            try:
                stack_id = self._update(auth_token, resource_owner_tenant_id,
                                        service_profile, service_chain_node,
                                        service_chain_instance, provider,
                                        consumer_port,
                                        network_function_details[
                                            'network_function'],
                                        provider_port, stack_id,
                                        mgmt_ip=mgmt_ip,
                                        pt_added_or_removed=True)
                return stack_id
            except Exception:
                LOG.exception(_LE("Processing policy target %(operation)s "
                                  " failed") % {'operation': operation})
                return None

    def notify_chain_parameters_updated(self, network_function_details):
        pass  # We are not using the classifier specified in redirect Rule

    def handle_consumer_ptg_operations(self, network_function_details,
                                       policy_target_group, operation):
        service_details = self.get_service_details(network_function_details)
        service_profile = service_details['service_profile']
        service_chain_node = service_details['servicechain_node']
        service_chain_instance = service_details['servicechain_instance']
        provider = service_details['provider_ptg']
        consumer_port = service_details['consumer_port']
        provider_port = service_details['provider_port']
        mgmt_ip = service_details['mgmt_ip']
        stack_id = service_details['heat_stack_id']

        if service_profile['service_type'] == pconst.FIREWALL:
            auth_token, resource_owner_tenant_id = (
                self._get_resource_owner_context())
            try:
                stack_id = self._update(auth_token, resource_owner_tenant_id,
                                        service_profile, service_chain_node,
                                        service_chain_instance, provider,
                                        consumer_port,
                                        network_function_details[
                                            'network_function'],
                                        provider_port, stack_id,
                                        mgmt_ip=mgmt_ip)

                if not stack_id:
                    return None
                return stack_id
            except Exception:
                LOG.exception(_LE(
                    "Processing policy target group "
                    "%(operation)s failed") % {'operation': operation})
                return None
