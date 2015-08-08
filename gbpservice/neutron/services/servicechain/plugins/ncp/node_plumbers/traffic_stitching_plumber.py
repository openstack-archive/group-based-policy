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

from neutron.api.v2 import attributes as attr
from neutron import manager
from neutron.openstack.common import log as logging
from oslo.config import cfg

from gbpservice.neutron.extensions import driver_proxy_group as pg_ext
from gbpservice.neutron.extensions import group_policy
from gbpservice.neutron.services.grouppolicy.common import exceptions as exc
from gbpservice.neutron.services.servicechain.plugins.ncp import plumber_base
from gbpservice.neutron.services.servicechain.plugins.ncp.node_plumbers import(
    common as common)

LOG = logging.getLogger(__name__)
TSCP_RESOURCE_PREFIX = 'tscp_'


class TrafficStitchingPlumber(plumber_base.NodePlumberBase):
    """Traffic Stitching Plumber (TScP).

    uses the GBP underlying constructs in order to guarantee a correct traffic
    flow across services from their provider to the consumer and vice versa.
    The output of the plumbing operations will be either the creation or
    deletion of a set of Service Targets, which effectively result in creation
    of Policy Targets exposed to the specific Node Driver for its own use.
    In addition to that, TScP will create a set of L2Ps and/or PTGs that are
    "stitched" together and host the actual service PTs. The proxy_group
    extension is a requirement for this plumber to work.
    """
    def initialize(self):
        self._gbp_plugin = None
        self._sc_plugin = None

        # Verify that proxy_group extension is loaded
        if pg_ext.PROXY_GROUP not in cfg.CONF.group_policy.extension_drivers:
            LOG.error(_("proxy_group GBP driver extension is mandatory for "
                        "traffic stitching plumber."))
            raise exc.GroupPolicyDeploymentError()

    @property
    def gbp_plugin(self):
        if not self._gbp_plugin:
            self._gbp_plugin = (manager.NeutronManager.get_service_plugins()
                                .get("GROUP_POLICY"))
        return self._gbp_plugin

    @property
    def sc_plugin(self):
        if not self._sc_plugin:
            self._sc_plugin = (manager.NeutronManager.get_service_plugins()
                               .get("SERVICECHAIN"))
        return self._sc_plugin

    def plug_services(self, context, deployment):
        if deployment:
            provider = deployment[0]['context'].provider
            management = deployment[0]['context'].management
            # Sorted from provider (N) to consumer (0)
            # TODO(ivar): validate number of interfaces per service per service
            # type is as expected
            self._sort_deployment(deployment)
            for part in deployment:
                info = part['plumbing_info']
                if not info:
                    return
                part_context = part['context']
                # Management PT can be created immediately
                self._create_service_target(
                    context, part_context, info.get('management', []),
                    management, 'management')
                # Create proper PTs based on the service type
                jump_ptg = None
                LOG.info(_("Plumbing service of type '%s'"),
                         info['plumbing_type'])
                if info['plumbing_type'] == common.PLUMBING_TYPE_ENDPOINT:
                    # No stitching needed, only provider side PT is created.
                    # overriding PT name in order to keep port security up
                    # for this kind of service.
                    info['provider'][0]['name'] = "tscp_endpoint_service_"
                    self._create_service_target(
                        context, part_context, info.get('provider', []),
                        provider, 'provider')

                elif info['plumbing_type'] == common.PLUMBING_TYPE_GATEWAY:
                    # L3 stitching needed, provider and consumer side PTs are
                    # created. One proxy_gateway is needed in consumer side
                    jump_ptg = self._create_l3_jump_group(
                        context, provider, part['context'].current_position)
                    # On provider side, this service is the default gateway
                    info['provider'][0]['group_default_gateway'] = True
                    self._create_service_target(
                        context, part_context, info['provider'],
                        provider, 'provider')
                    # On consumer side, this service is the proxy gateway
                    info['consumer'][0]['proxy_gateway'] = True
                    self._create_service_target(
                        context, part_context, info['consumer'], jump_ptg,
                        'consumer')
                elif info['plumbing_type'] == common.PLUMBING_TYPE_TRANSPARENT:
                    # L2 stitching needed, provider and consumer side PTs are
                    # created
                    self._create_service_target(
                        context, part_context, info.get('provider', []),
                        provider, 'provider')
                    jump_ptg = self._create_l2_jump_group(
                        context, provider, part['context'].current_position)
                    self._create_service_target(
                        context, part_context, info['consumer'],
                        jump_ptg, 'consumer')
                else:
                    LOG.warn(_("Unsupported plumbing type %s"),
                             info['plumbing_type'])
                # Replace current "provider" with jump ptg if needed
                provider = jump_ptg or provider

    def unplug_services(self, context, deployment):
        # Sorted from provider (0) to consumer (N)
        if not deployment:
            return
        self._sort_deployment(deployment)
        provider = deployment[0]['context'].provider

        for part in deployment:
            self._delete_service_targets(context, part)

        # Delete jump PTGs
        jump_ptgs = []
        while provider['proxy_group_id']:
            try:
                proxy = self.gbp_plugin.get_policy_target_group(
                    context, provider['proxy_group_id'])
                jump_ptgs.append(proxy)
            except group_policy.PolicyTargetGroupNotFound as ex:
                LOG.info(ex.message)
                # If this proxy doesn't exist, then subsequent ones won't too
                break
            provider = proxy

        for jump_ptg in reversed(jump_ptgs):
            try:
                self.gbp_plugin.delete_policy_target_group(
                    context, jump_ptg['id'])
            except group_policy.PolicyTargetGroupNotFound as ex:
                LOG.info(ex.message)

    def _create_l3_jump_group(self, context, proxied, position):
        return self._create_jump_group(
            context, proxied, position, pg_ext.PROXY_TYPE_L3)

    def _create_l2_jump_group(self, context, proxied, position):
        return self._create_jump_group(
            context, proxied, position, pg_ext.PROXY_TYPE_L2)

    def _create_jump_group(self, context, proxied, position, type):
        data = {
            "name": (TSCP_RESOURCE_PREFIX + str(position) + "_" +
                     proxied['name']),
            "description": "Implicitly created stitching group",
            "l2_policy_id": None,
            "proxied_group_id": proxied['id'],
            "proxy_type": type,
            "proxy_group_id": attr.ATTR_NOT_SPECIFIED,
            "network_service_policy_id": None,
            "service_management": False
        }
        return self.gbp_plugin.create_policy_target_group(
            context, {'policy_target_group': data})

    def _create_service_target(self, *args, **kwargs):
        kwargs['extra_data'] = {'proxy_gateway': False,
                                'group_default_gateway': False}
        super(TrafficStitchingPlumber, self)._create_service_target(
            *args, **kwargs)
