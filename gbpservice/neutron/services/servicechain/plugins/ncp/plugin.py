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

from neutron.common import log
from neutron.openstack.common import excutils
from neutron.openstack.common import log as logging
from oslo.config import cfg

from gbpservice.common import utils
from gbpservice.neutron.db import servicechain_db
from gbpservice.neutron.services.servicechain.plugins.ncp import (
    context as ctx)
from gbpservice.neutron.services.servicechain.plugins.ncp import (
    exceptions as exc)
from gbpservice.neutron.services.servicechain.plugins.ncp import (
    node_driver_manager as manager)
from gbpservice.neutron.services.servicechain.plugins import sharing

LOG = logging.getLogger(__name__)

PLUMBER_NAMESPACE = 'gbpservice.neutron.servicechain.ncp_plumbers'


class NodeCompositionPlugin(servicechain_db.ServiceChainDbPlugin,
                            sharing.SharingMixin):

    """Implementation of the Service Chain Plugin.

    """
    supported_extension_aliases = ["servicechain"]

    def __init__(self):
        self.driver_manager = manager.NodeDriverManager()
        super(NodeCompositionPlugin, self).__init__()
        self.driver_manager.initialize()
        self.plumber = utils.load_plugin(
            PLUMBER_NAMESPACE, cfg.CONF.node_composition_plugin.node_plumber)
        self.plumber.initialize()

    @log.log
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
            self._deploy_servicechain_nodes(context, deployers)
        except Exception:
            # Some node could not be deployed
            with excutils.save_and_reraise_exception():
                LOG.error(_("Node deployment failed, "
                            "deleting servicechain_instance %s"),
                          instance['id'])
                self.delete_servicechain_instance(context, instance['id'])

        return instance

    @log.log
    def update_servicechain_instance(self, context, servicechain_instance_id,
                                     servicechain_instance):
        """Instance updated.

        When a Servicechain Instance is updated and the spec changed, all the
        nodes of the previous spec should be destroyed and the newer ones
        created.
        """
        session = context.session
        deployers = {}
        updaters = {}
        destroyers = {}
        with session.begin(subtransactions=True):
            original_instance = self.get_servicechain_instance(
                context, servicechain_instance_id)
            updated_instance = super(
                NodeCompositionPlugin, self).update_servicechain_instance(
                context, servicechain_instance_id, servicechain_instance)

            if (original_instance['servicechain_specs'] !=
                    updated_instance['servicechain_specs']):
                if len(updated_instance['servicechain_specs']) > 1:
                    raise exc.OneSpecPerInstanceAllowed()
                destroyers = self._get_scheduled_drivers(
                    context, original_instance, 'destroy')
            else:  # Could be classifier update
                updaters = self._get_scheduled_drivers(
                    context, original_instance, 'update')

        if (original_instance['servicechain_specs'] !=
            updated_instance['servicechain_specs']):
            self._destroy_servicechain_nodes(context, destroyers)
            deployers = self._get_scheduled_drivers(
                        context, updated_instance, 'deploy')
            self._deploy_servicechain_nodes(context, deployers)
        else:
            self._update_servicechain_nodes(context, updaters)
        return updated_instance

    @log.log
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
        self._destroy_servicechain_nodes(context, destroyers)

        with session.begin(subtransactions=True):
            super(NodeCompositionPlugin, self).delete_servicechain_instance(
                context, servicechain_instance_id)

    @log.log
    def create_servicechain_node(self, context, servicechain_node):
        session = context.session
        with session.begin(subtransactions=True):
            result = super(NodeCompositionPlugin,
                           self).create_servicechain_node(context,
                                                          servicechain_node)
            self._validate_shared_create(context, result, 'servicechain_node')
        return result

    @log.log
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
            self._validate_shared_update(context, original_sc_node,
                                         updated_sc_node, 'servicechain_node')
            instances = self._get_node_instances(context, updated_sc_node)
            for instance in instances:
                node_context = ctx.get_node_driver_context(
                    self, context, instance, updated_sc_node, original_sc_node)
                # TODO(ivar): Validate that the node driver understands the
                # update.
                driver = self.driver_manager.schedule_update(node_context)
                if not driver:
                    raise exc.NoDriverAvailableForAction(
                        action='update', node_id=original_sc_node['id'])
                updaters[instance['id']] = {}
                updaters[instance['id']]['context'] = node_context
                updaters[instance['id']]['driver'] = driver
                updaters[instance['id']]['plumbing_info'] = (
                    driver.get_plumbing_info(node_context))
        # Update the nodes
        for update in updaters.values():
            try:
                update['driver'].update(update['context'])
            except exc.NodeDriverError as ex:
                LOG.error(_("Node Update failed, %s"),
                          ex.message)

        return updated_sc_node

    @log.log
    def create_servicechain_spec(self, context, servicechain_spec):
        session = context.session
        with session.begin(subtransactions=True):
            result = super(
                NodeCompositionPlugin, self).create_servicechain_spec(
                    context, servicechain_spec, set_params=False)
            self._validate_shared_create(context, result, 'servicechain_spec')
        return result

    @log.log
    def update_servicechain_spec(self, context, servicechain_spec_id,
                                 servicechain_spec):
        session = context.session
        with session.begin(subtransactions=True):
            original_sc_spec = self.get_servicechain_spec(
                                         context, servicechain_spec_id)
            updated_sc_spec = super(NodeCompositionPlugin,
                                    self).update_servicechain_spec(
                                        context, servicechain_spec_id,
                                        servicechain_spec, set_params=False)
            self._validate_shared_update(context, original_sc_spec,
                                         updated_sc_spec, 'servicechain_spec')

        # Remove the deleted node instances and add any new ones added
        # REVISIT(Magesh): Invoke a validate update in Node plumber
        # and reject the update in case the plumber does not support node
        # reordering in the spec. For now reordering is a NOOP
        if original_sc_spec['nodes'] != updated_sc_spec['nodes']:
            instances = original_sc_spec['instances']
            instances = self.get_servicechain_instances(
                context, filters={'id': instances})
            for instance in instances:
                removed_nodes = (set(original_sc_spec['nodes']) -
                                 set(updated_sc_spec['nodes']))
                added_nodes = (set(updated_sc_spec['nodes']) -
                               set(original_sc_spec['nodes']))
                removed_nodes = self.get_servicechain_nodes(
                        context, filters={'id': removed_nodes})
                added_nodes = self.get_servicechain_nodes(
                        context, filters={'id': added_nodes})
                destroyers = self._get_scheduled_drivers(
                        context, instance, 'destroy', nodes=removed_nodes)
                deployers = self._get_scheduled_drivers(
                        context, instance, 'deploy', nodes=added_nodes)
                self._destroy_servicechain_nodes(context, destroyers)
                self._deploy_servicechain_nodes(context, deployers)

        return updated_sc_spec

    @log.log
    def create_service_profile(self, context, service_profile):
        session = context.session
        with session.begin(subtransactions=True):
            result = super(
                NodeCompositionPlugin, self).create_service_profile(
                    context, service_profile)
            self._validate_shared_create(context, result, 'service_profile')
        return result

    @log.log
    def update_service_profile(self, context, service_profile_id,
                               service_profile):
        session = context.session
        with session.begin(subtransactions=True):
            original_profile = self.get_service_profile(
                context, service_profile_id)
            updated_profile = super(NodeCompositionPlugin,
                                    self).update_service_profile(
                                        context, service_profile_id,
                                        service_profile)
            self._validate_profile_update(context, original_profile,
                                          updated_profile)
        return updated_profile

    def update_chains_pt_added(self, context, policy_target):
        """ Auto scaling function.

        Notify the correct set of node drivers that a new policy target has
        been added to a relevant PTG.
        """
        self._update_chains_pt_modified(context, policy_target, 'added')

    def update_chains_pt_removed(self, context, policy_target):
        """ Auto scaling function.

        Notify the correct set of node drivers that a new policy target has
        been removed from a relevant PTG.
        """
        self._update_chains_pt_modified(context, policy_target, 'removed')

    def _update_chains_pt_modified(self, context, policy_target, action):
        scis = self._get_instances_from_policy_target(context, policy_target)

        for sci in scis:
            updaters = self._get_scheduled_drivers(context, sci, 'update')
            for update in updaters.values():
                try:
                    getattr(update['driver'],
                            'update_policy_target_' + action)(
                                update['context'], policy_target)
                except exc.NodeDriverError as ex:
                    LOG.error(_("Node Update on policy target modification "
                                "failed, %s"), ex.message)

    def notify_chain_parameters_updated(self, context,
                                        servicechain_instance_id):
        """Hook for GBP drivers to inform about any updates that affect the SCI

        Notify the correct set of node drivers that some parameter that affects
        the service chain is updated. The updates could be something like
        adding or removing an Allow Rule to the ruleset and may have to be
        enforced in the Firewall Service VM, or it could simply be a
        classifier update.
        """
        sci = self.get_servicechain_instance(context, servicechain_instance_id)
        updaters = self._get_scheduled_drivers(context, sci, 'update')
        for update in updaters.values():
            try:
                getattr(update['driver'],
                        'notify_chain_parameters_updated')(update['context'])
            except exc.NodeDriverError as ex:
                LOG.error(_("Node Update on GBP parameter update "
                            "failed, %s"), ex.message)

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

    def _get_scheduled_drivers(self, context, instance, action, nodes=None):
        if nodes is None:
            nodes = self._get_instance_nodes(context, instance)
        result = {}
        func = getattr(self.driver_manager, 'schedule_' + action)
        for node in nodes or []:
            node_context = ctx.get_node_driver_context(
                self, context, instance, node)
            driver = func(node_context)
            if not driver:
                raise exc.NoDriverAvailableForAction(action=action,
                                                     node_id=node['id'])
            result[node['id']] = {}
            result[node['id']]['driver'] = driver
            result[node['id']]['context'] = node_context
            result[node['id']]['plumbing_info'] = driver.get_plumbing_info(
                node_context)
        return result

    def _deploy_servicechain_nodes(self, context, deployers):
        self.plumber.plug_services(context, deployers.values())
        for deploy in deployers.values():
            driver = deploy['driver']
            driver.create(deploy['context'])

    def _update_servicechain_nodes(self, context, updaters):
        for update in updaters.values():
            driver = update['driver']
            driver.update(update['context'])

    def _destroy_servicechain_nodes(self, context, destroyers):
        # Actual node disruption
        try:
            for destroy in destroyers.values():
                driver = destroy['driver']
                try:
                    driver.delete(destroy['context'])
                except exc.NodeDriverError:
                    LOG.error(_("Node destroy failed, for node %s "),
                              driver['context'].current_node['id'])
                except Exception as e:
                    LOG.exception(e)
                finally:
                    self.driver_manager.clear_node_owner(destroy['context'])
        finally:
            self.plumber.unplug_services(context, destroyers.values())

    def _validate_profile_update(self, context, original, updated):
        # Raise if the profile is in use by any instance
        # Ugly one shot query to verify whether the profile is in use
        db = servicechain_db
        query = context.session.query(db.ServiceChainInstance)
        query = query.join(db.InstanceSpecAssociation)
        query = query.join(db.ServiceChainSpec)
        query = query.join(db.SpecNodeAssociation)
        query = query.join(db.ServiceChainNode)
        instance = query.filter(
            db.ServiceChainNode.service_profile_id == original['id']).first()
        if instance:
            raise exc.ServiceProfileInUseByAnInstance(
                profile_id=original['id'], instance_id=instance.id)
        self._validate_shared_update(context, original, updated,
                                     'service_profile')
