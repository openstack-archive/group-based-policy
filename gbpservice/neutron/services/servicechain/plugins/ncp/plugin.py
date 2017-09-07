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

from neutron.db import api as db_api
from neutron.plugins.common import constants as pconst
from neutron.quota import resource_registry
from oslo_config import cfg
from oslo_log import helpers as log
from oslo_log import log as logging
from oslo_utils import excutils

from gbpservice._i18n import _LE
from gbpservice._i18n import _LI
from gbpservice._i18n import _LW
from gbpservice.common import utils
from gbpservice.neutron.db import servicechain_db
from gbpservice.neutron.services.grouppolicy.common import constants as gp_cts
from gbpservice.neutron.services.grouppolicy.common import utils as gutils
from gbpservice.neutron.services.servicechain.plugins.ncp import (
    context as ctx)
from gbpservice.neutron.services.servicechain.plugins.ncp import (
    exceptions as exc)
from gbpservice.neutron.services.servicechain.plugins.ncp import (
    node_driver_manager as manager)
from gbpservice.neutron.services.servicechain.plugins import sharing

LOG = logging.getLogger(__name__)

PLUMBER_NAMESPACE = 'gbpservice.neutron.servicechain.ncp_plumbers'
cfg.CONF.import_opt('policy_drivers',
                    'gbpservice.neutron.services.grouppolicy.config',
                    group='group_policy')
STATUS = 'status'
STATUS_DETAILS = 'status_details'
STATUS_SET = set([STATUS, STATUS_DETAILS])


class NodeCompositionPlugin(servicechain_db.ServiceChainDbPlugin,
                            sharing.SharingMixin):

    """Implementation of the Service Chain Plugin.

    """
    supported_extension_aliases = ["servicechain"]
    path_prefix = gp_cts.GBP_PREFIXES[pconst.SERVICECHAIN]

    @resource_registry.tracked_resources(
        servicechain_node=servicechain_db.ServiceChainNode,
        servicechain_spec=servicechain_db.ServiceChainSpec,
        servicechain_instance=servicechain_db.ServiceChainInstance,
        service_profile=servicechain_db.ServiceProfile)
    def __init__(self):
        self.driver_manager = manager.NodeDriverManager()
        super(NodeCompositionPlugin, self).__init__()
        self.driver_manager.initialize()
        plumber_klass = cfg.CONF.node_composition_plugin.node_plumber
        self.plumber = utils.load_plugin(
            PLUMBER_NAMESPACE, plumber_klass)
        self.plumber.initialize()
        LOG.info(_LI("Initialized node plumber '%s'"), plumber_klass)

    @log.log_method_call
    def create_servicechain_instance(self, context, servicechain_instance):
        """Instance created.

        When a Servicechain Instance is created, all its nodes need to be
        instantiated.
        """
        instance = self._process_commit_phase(context)
        if instance:
            return instance

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
        if not gutils.is_precommit_policy_driver_configured():
            # Actual node deploy
            try:
                self._deploy_servicechain_nodes(context, deployers)
            except Exception:
                # Some node could not be deployed
                with excutils.save_and_reraise_exception():
                    LOG.error(_LE("Node deployment failed, "
                                  "deleting servicechain_instance %s"),
                              instance['id'])
                    self.delete_servicechain_instance(context, instance['id'])

        return instance

    def _process_commit_phase(self, context):
        if hasattr(context, 'commit_phase'):
            if not gutils.is_precommit_policy_driver_configured() and (
                context.commit_phase == gp_cts.PRE_COMMIT):
                # The following is a bit of a hack to no-op
                # the call from the postcommit policy driver
                # during the pre-commit phase.
                return True
            if gutils.is_precommit_policy_driver_configured() and (
                context.commit_phase == gp_cts.POST_COMMIT):
                instance = self.get_servicechain_instance(
                    context, context.servicechain_instance['id'])
                self._call_deploy_sc_node(context, instance)
                return instance

    def _call_deploy_sc_node(self, context, instance):
        # Actual node deploy
        try:
            deployers = self._get_scheduled_drivers(
                context, instance, 'deploy')
            self._deploy_servicechain_nodes(context, deployers)
        except Exception:
            # Some node could not be deployed
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("Node deployment failed, "
                              "servicechain_instance %s is in ERROR state"),
                          instance['id'])

    @log.log_method_call
    def get_servicechain_instance(self, context,
                                  servicechain_instance_id, fields=None):
        """Instance retrieved.

        While get Servicechain Instance details, get all nodes details.
        """
        return self._get_resource(context, 'servicechain_instance',
                                  servicechain_instance_id, fields)

    @log.log_method_call
    def update_servicechain_instance(self, context, servicechain_instance_id,
                                     servicechain_instance):
        """Instance updated.

        When a Servicechain Instance is updated and the spec changed, all the
        nodes of the previous spec should be destroyed and the newer ones
        created.
        """
        instance = self._process_commit_phase(context)
        if instance:
            return instance

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
            context.deployers = deployers
            context.servicechain_instance = updated_instance
            if not gutils.is_precommit_policy_driver_configured():
                self._deploy_servicechain_nodes(context, deployers)
        else:
            self._update_servicechain_nodes(context, updaters)
        return updated_instance

    @log.log_method_call
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

    @log.log_method_call
    def create_servicechain_node(self, context, servicechain_node):
        session = context.session
        with session.begin(subtransactions=True):
            result = super(NodeCompositionPlugin,
                           self).create_servicechain_node(context,
                                                          servicechain_node)
            self._validate_shared_create(context, result, 'servicechain_node')
        return result

    @log.log_method_call
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
                LOG.error(_LE("Node Update failed, %s"),
                          ex.message)

        return updated_sc_node

    @log.log_method_call
    def get_servicechain_node(self, context, servicechain_node_id,
                              fields = None):
        return self._get_resource(context, 'servicechain_node',
                                  servicechain_node_id, fields)

    @log.log_method_call
    def create_servicechain_spec(self, context, servicechain_spec):
        session = context.session
        with session.begin(subtransactions=True):
            result = super(
                NodeCompositionPlugin, self).create_servicechain_spec(
                    context, servicechain_spec, set_params=False)
            self._validate_shared_create(context, result, 'servicechain_spec')
        return result

    @log.log_method_call
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
            # The reference plumber does not support modifying or reordering of
            # nodes in a service chain spec. Disallow update for now
            if (original_sc_spec['nodes'] != updated_sc_spec['nodes'] and
                original_sc_spec['instances']):
                raise exc.InuseSpecNodeUpdateNotAllowed()

        return updated_sc_spec

    @log.log_method_call
    def get_servicechain_spec(self, context,
                              servicechain_spec_id, fields = None):
        return self._get_resource(context, 'servicechain_spec',
                                  servicechain_spec_id, fields)

    @log.log_method_call
    def create_service_profile(self, context, service_profile):
        session = context.session
        with session.begin(subtransactions=True):
            result = super(
                NodeCompositionPlugin, self).create_service_profile(
                    context, service_profile)
            self._validate_shared_create(context, result, 'service_profile')
        return result

    @log.log_method_call
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

    @log.log_method_call
    def get_service_profile(self, context, service_profile_id, fields = None):
        return self._get_resource(context, 'service_profile',
                                  service_profile_id, fields)

    def update_chains_pt_added(self, context, policy_target, instance_id):
        """ Auto scaling function.

        Notify the correct set of node drivers that a new policy target has
        been added to a relevant PTG.
        """
        self._update_chains_pt_modified(context, policy_target, instance_id,
                                        'added')

    def update_chains_pt_removed(self, context, policy_target, instance_id):
        """ Auto scaling function.

        Notify the correct set of node drivers that a new policy target has
        been removed from a relevant PTG.
        """
        self._update_chains_pt_modified(context, policy_target, instance_id,
                                        'removed')

    def update_chains_consumer_added(self, context, policy_target_group,
                                     instance_id):
        """ Auto scaling function.

        Override this method to react to policy target group addition as
        a consumer of a chain.
        """
        self._update_chains_consumer_modified(context, policy_target_group,
                                              instance_id, 'added')

    def policy_target_group_updated(self, context, old_policy_target_group,
                                    current_policy_target_group,
                                    instance_id):
        """ Utility function.
        Override this method to react to policy target group update
        """
        self._policy_target_group_updated(context,
                                          old_policy_target_group,
                                          current_policy_target_group,
                                          instance_id)

    def update_chains_consumer_removed(self, context, policy_target_group,
                                       instance_id):
        """ Auto scaling function.

        Override this method to react to policy target group removed as a
        consumer of a chain
        """
        self._update_chains_consumer_modified(context, policy_target_group,
                                              instance_id, 'removed')

    def _policy_target_group_updated(self, context, old_policy_target_group,
                                     current_policy_target_group,
                                     instance_id):
        updaters = self._get_scheduled_drivers(
                context,
                self.get_servicechain_instance(context, instance_id),
                'update')
        for update in updaters.values():
            try:
                update['driver'].policy_target_group_updated(
                        update['context'],
                        old_policy_target_group,
                        current_policy_target_group)
            except exc.NodeDriverError as ex:
                LOG.error(_LE("Node Update on policy target group modification"
                              " failed, %s"), ex.message)

    def _update_chains_pt_modified(self, context, policy_target, instance_id,
                                   action):
        updaters = self._get_scheduled_drivers(
            context, self.get_servicechain_instance(context, instance_id),
            'update')
        for update in updaters.values():
            try:
                getattr(update['driver'],
                        'update_policy_target_' + action)(
                            update['context'], policy_target)
            except exc.NodeDriverError as ex:
                LOG.error(_LE("Node Update on policy target modification "
                              "failed, %s"), ex.message)

    def _update_chains_consumer_modified(self, context, policy_target_group,
                                         instance_id, action):
        updaters = self._get_scheduled_drivers(
            context, self.get_servicechain_instance(context, instance_id),
            'update')
        for update in updaters.values():
            try:
                getattr(update['driver'],
                        'update_node_consumer_ptg_' + action)(
                            update['context'], policy_target_group)
            except exc.NodeDriverError as ex:
                LOG.error(_LE(
                    "Node Update on policy target group modification "
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
                LOG.error(_LE("Node Update on GBP parameter update "
                              "failed, %s"), ex.message)

    def _get_instance_nodes(self, context, instance):
        context = utils.admin_context(context)
        if not instance['servicechain_specs']:
            return []
        specs = self.get_servicechain_spec(
            context, instance['servicechain_specs'][0])
        return self.get_servicechain_nodes(context, {'id': specs['nodes']})

    def _get_node_instances(self, context, node):
        context = utils.admin_context(context)
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

    def _get_resource(self, context, resource_name, resource_id, fields=None):
        session = context.session
        deployers = {}
        with session.begin(subtransactions=True):
            resource = getattr(super(NodeCompositionPlugin,
                self), 'get_' + resource_name)(context, resource_id)
            if resource_name == 'servicechain_instance':
                if len(resource['servicechain_specs']) > 1:
                    raise exc.OneSpecPerInstanceAllowed()
                try:
                    deployers = self._get_scheduled_drivers(context, resource,
                                                        'get')
                except Exception:
                    LOG.warning(_LW("Failed to get node driver"))

        # Invoke drivers only if status attributes are requested
        if not fields or STATUS_SET.intersection(set(fields)):
            _resource = self._get_resource_status(context, resource_name,
                                                  deployers)
            if _resource:
                updated_status = _resource['status']
                updated_status_details = _resource['status_details']
                if resource['status'] != updated_status or (
                    resource['status_details'] != updated_status_details):
                    new_status = {resource_name:
                              {'status': updated_status,
                               'status_details': updated_status_details}}
                    session = context.session
                    with session.begin(subtransactions=True):
                        getattr(super(NodeCompositionPlugin, self),
                            'update_' + resource_name)(
                             context, resource['id'], new_status)
                    resource['status'] = updated_status
                    resource['status_details'] = updated_status_details
        return self._fields(resource, fields)

    def _get_resource_status(self, context, resource_name, deployers=None):
        """
        Invoke node drivers only for servicechain_instance.
        Node driver should implement get_status api to return status
        and status_details of servicechain_instance
        """
        if resource_name == 'servicechain_instance':
            nodes_status = []
            result = {'status': 'BUILD',
                      'status_details': 'node deployment in progress'}
            if deployers:
                try:
                    for deploy in deployers.values():
                        driver = deploy['driver']
                        nodes_status.append(driver.get_status(
                            deploy['context']))
                    node_status = [node['status'] for node in nodes_status]
                    if 'ERROR' in node_status:
                        result['status'] = 'ERROR'
                        result['status_details'] = 'node deployment failed'
                    elif node_status.count('ACTIVE') == len(
                            deployers.values()):
                        result['status'] = 'ACTIVE'
                        result['status_details'] = 'node deployment completed'
                except Exception as exc:
                    LOG.error(_LE("Failed to get servicechain instance status "
                        "from node driver, Error: %(exc)s"), {'exc': exc})
                    return
                return result
        result = {'status': 'ACTIVE', 'status_details': ''}
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
                    LOG.error(_LE("Node destroy failed, for node %s "),
                              driver['context'].current_node['id'])
                except Exception as e:
                    if db_api.is_retriable(e):
                        with excutils.save_and_reraise_exception():
                            LOG.debug(
                                "Node driver '%(name)s' failed in"
                                " %(method)s, operation will be retried",
                                {'name': driver._name, 'method': 'delete'}
                            )
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
