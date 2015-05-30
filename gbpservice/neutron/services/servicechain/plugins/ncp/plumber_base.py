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

import abc
import six

from neutron.openstack.common import log as logging

from gbpservice.neutron.extensions import group_policy
from gbpservice.neutron.services.servicechain.plugins.ncp import exceptions
from gbpservice.neutron.services.servicechain.plugins.ncp import model

TARGET_DESCRIPTION = "%s facing Service Target for node %s in instance %s"
LOG = logging.getLogger(__name__)


@six.add_metaclass(abc.ABCMeta)
class NodePlumberBase(object):
    """Node Plumber base Class

    The node plumber is an entity which takes care of plumbing nodes in a
    chain. By node plumbing is intended the creation/disruption of the
    appropriate Neutron and GBP constructs (typically Ports and Policy Targets)
    based on the specific Node needs, taking into account the whole service
    chain in the process. Ideally, this module will ensure that the traffic
    flows as expected according to the user intent.
    """

    @abc.abstractmethod
    def initialize(self):
        """Perform plumber initialization.

        No abstract methods defined below will be called prior to this method
        being called.
        """

    @abc.abstractmethod
    def plug_services(self, context, deployment):
        """Plug services

        Given a deployment, this method is expected to create all the needed
        policy targets / neutron ports placed where needed based on the whole
        chain configuration.
        The expectation is that this method ultimately creates ServiceTarget
        object that will be retrieved by the node drivers at the right time.

        A deployment is a list composed as follows:
        [{'context': node_context,
          'driver': deploying_driver,
          'plumbing_info': node_plumbing_needs},
          ...]
        No assumptions should be made on the order of the nodes as received in
        the deployment, but it can be retrieved by calling
        node_context.current_position
        """

    @abc.abstractmethod
    def unplug_services(self, context, deployment):
        """Plug services

        Given a deployment, this method is expected to destroy all the
        policy targets / neutron ports previously created for this chain
        configuration.
        The expectation is that this method ultimately removes all the
        ServiceTarget related to this particular chain.

        A deployment is a list composed as follows:
        [{'context': node_context,
          'driver': deploying_driver,
          'plumbing_info': node_plumbing_needs},
          ...]
        No assumptions should be made on the order of the nodes as received in
        the deployment, but it can be retrieved by calling
        node_context.current_position
        """

    def _create_service_targets(self, context, part):
        info = part['plumbing_info']
        if not info:
            return
        part_context = part['context']
        provider = part_context.provider
        consumer = part_context.consumer
        management = part_context.management

        self._create_service_target(context, part_context,
                                    info.get('provider', []),
                                    provider, 'provider')
        self._create_service_target(context, part_context,
                                    info.get('consumer', []),
                                    consumer, 'consumer')
        self._create_service_target(context, part_context,
                                    info.get('management', []),
                                    management, 'management')

    def _delete_service_targets(self, context, part):
        part_context = part['context']
        node = part_context.current_node
        instance = part_context.instance
        gbp_plugin = part_context.gbp_plugin
        pts = model.get_service_targets(
            context.session, servicechain_instance_id=instance['id'],
            servicechain_node_id=node['id'])

        for pt in pts:
            try:
                gbp_plugin.delete_policy_target(context, pt.policy_target_id,
                                                notify_sc=False)
            except group_policy.PolicyTargetNotFound as ex:
                LOG.debug(ex.message)

    def _create_service_target(self, context, part_context, targets, group,
                               relationship):
        instance = part_context.instance
        node = part_context.current_node
        gbp_plugin = part_context.gbp_plugin
        for target in targets:
            if not group:
                exceptions.NotAvailablePTGForTargetRequest(
                    ptg_type=relationship, instance=instance['id'],
                    node=node['id'])
            data = {'policy_target_group_id': group['id'],
                    'description': TARGET_DESCRIPTION % (relationship,
                                                         node['id'],
                                                         instance['id']),
                    'name': '', 'port_id': None}
            data.update(target)
            pt = gbp_plugin.create_policy_target(context,
                                                 {'policy_target': data},
                                                 notify_sc=False)
            model.set_service_target(part_context, pt['id'], relationship)

    def _sort_deployment(self, deployment):
        deployment.sort(key=lambda x: x['context'].current_position)