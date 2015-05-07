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

from oslo_log import log as logging
from oslo_utils import excutils

from gbpservice.neutron.db import servicechain_db
from gbpservice.neutron.services.servicechain.plugins.ncp import (
    context as ctx)
from gbpservice.neutron.services.servicechain.plugins.ncp import (
    exceptions as exc)
from gbpservice.neutron.services.servicechain.plugins.ncp import (
    node_driver_manager as manager)
from gbpservice.neutron.services.servicechain.plugins.ncp import model


LOG = logging.getLogger(__name__)


class NodeCompositionPlugin(servicechain_db.ServiceChainDbPlugin):

    """Implementation of the Service Chain Plugin.

    """
    supported_extension_aliases = ["servicechain"]

    def __init__(self):
        self.driver_manager = manager.NodeDriverManager()
        super(NodeCompositionPlugin, self).__init__()
        self.driver_manager.initialize()

    def create_servicechain_instance(self, context, servicechain_instance):
        """Instance created.

        When a Servicechain Instance is created, all its nodes need to be
        instantiated.
        """
        session = context.session
        deployers = {}
        with session.begin(subtransactions=True):
            instance = super(NodeCompositionPlugin,
                             self).create_servicechain_instance(
                                 context, servicechain_instance)
            if len(instance['servicechain_specs']) > 1:
                raise exc.OneSpecPerInstanceAllowed()
            deployers = self._get_scheduled_drivers(context, instance,
                                                    'deploy')

        # Actual node deploy
        try:
            for node_id in deployers:
                for deployer in deployers[node_id]['drivers']:
                    try:
                        # TODO(ivar): Service plumbing
                        deployer.create(deployers[node_id]['context'])
                        model.set_node_ownership(deployers[node_id]['context'],
                                                 deployer.name)
                        break
                    except exc.NodeDriverError:
                        with excutils.save_and_reraise_exception() as ctxt:
                            LOG.warning(_("Deploy failed, deleting node "
                                          "instance."), instance['id'])
                            try:
                                deployer.destroy(deployers[node_id]['context'])
                            finally:
                                # TODO(ivar): PT Cleanup
                                pass
                            if deployer != deployers[node_id]['drivers'][-1]:
                                ctxt.reraise = False
        except Exception:
            # Some node could not be deployed
            with excutils.save_and_reraise_exception():
                LOG.error(_("Node deployment failed, "
                            "deleting servicechain_instance %s"),
                          instance['id'])
                self.delete_servicechain_instance(context, instance['id'])
        return instance

    def delete_servicechain_instance(self, context, servicechain_instance_id):
        """Instance deleted.

        When a Servicechain Instance is deleted, all its nodes need to be
        destroyed.
        """
        session = context.session
        with session.begin(subtransactions=True):
            instance = self.get_servicechain_instance(context,
                                                      servicechain_instance_id)
            destroyers = self._get_scheduled_drivers(context, instance,
                                                     'destroy')
            super(NodeCompositionPlugin, self).delete_servicechain_instance(
                context, servicechain_instance_id)
        # Actual node disruption
        for node_id in destroyers:
            for destroyer in destroyers[node_id]['drivers']:
                try:
                    destroyer.delete(destroyer[node_id]['context'])
                except exc.NodeDriverError:
                    LOG.error(_("Node destroy failed, for node %s "), node_id)
                except Exception as e:
                    LOG.exception(e)
                finally:
                    # TODO(ivar): PT Cleanup
                    pass

    def update_servicechain_instance(self, context, servicechain_instance_id,
                                     servicechain_instance):
        # TODO(ivar): look at all the possible updates for SCI
        return super(NodeCompositionPlugin, self).update_servicechain_instance(
            context, servicechain_instance_id, servicechain_instance)
        pass

    def update_servicechain_node(self, context, servicechain_node_id,
                                 servicechain_node):
        """Node Update.

        When a Servicechain Node is updated, all the corresponding instances
        need to be updated as well. This usually results in a node
        reconfiguration.
        """
        session = context.session
        updaters = {}
        with session.begin(subtransactions=True):
            original_sc_node = self.get_servicechain_node(
                context, servicechain_node_id)
            updated_sc_node = super(NodeCompositionPlugin,
                                    self).update_servicechain_node(
                                        context, servicechain_node_id,
                                        servicechain_node)
            instances = self._get_node_instances(context, updated_sc_node)
            for instance in instances:
                node_context = ctx.get_node_driver_context(
                    self, context, instance, updated_sc_node, original_sc_node)
                drivers = self.driver_manager.schedule_update(node_context)
                if not drivers:
                    raise exc.NoDriverAvailableForAction(
                        action='update', node_id=original_sc_node['id'])
                if not instance['id'] in updaters:
                    updaters[instance['id']] = {}
                    updaters[instance['id']]['context'] = node_context
                    updaters[instance['id']]['drivers'] = []
                updaters[instance['id']]['drivers'].extend(drivers)
        # Update the nodes
        for update in updaters.values():
            for updater in update['drivers']:
                try:
                    updater.update(update['context'])
                    break
                except exc.NodeDriverError as ex:
                    LOG.error(_("Node Update failed, %s"),
                              ex.message)

        return updated_sc_node

    def _get_instance_nodes(self, context, instance):
        if not instance['servicechain_specs']:
            return []
        specs = self.get_servicechain_spec(
            context, instance['servicechain_specs'][0])
        return self.get_servicechain_nodes(context, {'id': specs['nodes']})

    def _get_node_instances(self, context, node):
        specs = self.get_servicechain_specs(
            context, {'id': node['servicechain_specs']})
        result = []
        for spec in specs:
            result.extend(self.get_servicechain_instances(
                context, {'id': spec['instances']}))
        return result

    def _get_scheduled_drivers(self, context, instance, action):
        nodes = self._get_instance_nodes(context, instance)
        result = {}
        func = getattr(self.driver_manager, 'schedule_' + action)
        for node in nodes:
            node_context = ctx.get_node_driver_context(
                self, context, instance, node)
            drivers = func(node_context)
            if not drivers:
                raise exc.NoDriverAvailableForAction(action=action,
                                                     node_id=node['id'])
            if node['id'] not in result:
                result[node['id']] = {}
                result[node['id']]['drivers'] = []
                result[node['id']]['context'] = node_context
            result[node['id']]['drivers'].extend(drivers)
        return result