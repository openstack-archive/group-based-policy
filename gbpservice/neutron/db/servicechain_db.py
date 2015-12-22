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
import sqlalchemy as sa
from sqlalchemy.ext.orderinglist import ordering_list
from sqlalchemy import orm
from sqlalchemy.orm import exc

from neutron.common import log
from neutron.db import common_db_mixin
from neutron.db import model_base
from neutron.db import models_v2
from neutron import manager
from neutron.openstack.common import jsonutils
from neutron.openstack.common import log as logging
from neutron.openstack.common import uuidutils
from neutron.plugins.common import constants as pconst

from gbpservice.neutron.db import gbp_quota_db as gquota
from gbpservice.neutron.extensions import servicechain as schain
from gbpservice.neutron.services.servicechain.common import exceptions as s_exc

LOG = logging.getLogger(__name__)
MAX_IPV4_SUBNET_PREFIX_LENGTH = 31
MAX_IPV6_SUBNET_PREFIX_LENGTH = 127


class SpecNodeAssociation(model_base.BASEV2):
    """Models one to many providing relation between Specs and Nodes."""
    __tablename__ = 'sc_spec_node_associations'
    servicechain_spec_id = sa.Column(
        sa.String(36), sa.ForeignKey('sc_specs.id'), primary_key=True)
    node_id = sa.Column(sa.String(36),
                        sa.ForeignKey('sc_nodes.id'),
                        primary_key=True)
    position = sa.Column(sa.Integer)


class InstanceSpecAssociation(model_base.BASEV2):
    """Models  one to many providing relation between Instance and Specs."""
    __tablename__ = 'sc_instance_spec_mappings'
    servicechain_instance_id = sa.Column(
        sa.String(36), sa.ForeignKey('sc_instances.id'), primary_key=True)
    servicechain_spec_id = sa.Column(sa.String(36),
                                     sa.ForeignKey('sc_specs.id'),
                                     primary_key=True)
    position = sa.Column(sa.Integer)


class ServiceChainNode(gquota.GBPQuotaBase, model_base.BASEV2, models_v2.HasId,
                       models_v2.HasTenant):
    """ServiceChain Node"""
    __tablename__ = 'sc_nodes'
    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(255))
    config = sa.Column(sa.TEXT)
    specs = orm.relationship(SpecNodeAssociation,
                             backref="nodes",
                             cascade='all, delete, delete-orphan')
    shared = sa.Column(sa.Boolean)
    service_type = sa.Column(sa.String(50), nullable=True)
    service_profile_id = sa.Column(
        sa.String(36), sa.ForeignKey('service_profiles.id'),
        nullable=True)


class ServiceChainInstance(gquota.GBPQuotaBase, model_base.BASEV2,
                           models_v2.HasId, models_v2.HasTenant):
    """Service chain instances"""
    __tablename__ = 'sc_instances'
    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(255))
    config_param_values = sa.Column(sa.String(4096))
    specs = orm.relationship(
        InstanceSpecAssociation,
        backref='instances',
        cascade='all,delete, delete-orphan',
        order_by='InstanceSpecAssociation.position',
        collection_class=ordering_list('position', count_from=1))
    provider_ptg_id = sa.Column(sa.String(36),
                             # FixMe(Magesh) Issue with cascade on Delete
                             # sa.ForeignKey('gp_policy_target_groups.id'),
                             nullable=True)
    consumer_ptg_id = sa.Column(sa.String(36),
                             # sa.ForeignKey('gp_policy_target_groups.id'),
                             nullable=True)
    management_ptg_id = sa.Column(sa.String(36),
                                  # sa.ForeignKey('gp_policy_target_groups.id'),
                                  nullable=True)
    classifier_id = sa.Column(sa.String(36),
                              # sa.ForeignKey('gp_policy_classifiers.id'),
                              nullable=True)


class ServiceChainSpec(gquota.GBPQuotaBase, model_base.BASEV2, models_v2.HasId,
                       models_v2.HasTenant):
    """ ServiceChain Spec
    """
    __tablename__ = 'sc_specs'
    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(255))
    nodes = orm.relationship(
        SpecNodeAssociation,
        backref='specs', cascade='all, delete, delete-orphan',
        order_by='SpecNodeAssociation.position',
        collection_class=ordering_list('position', count_from=1))
    config_param_names = sa.Column(sa.String(4096))
    instances = orm.relationship(InstanceSpecAssociation,
                                 backref="specs",
                                 cascade='all, delete, delete-orphan')
    shared = sa.Column(sa.Boolean)


class ServiceProfile(gquota.GBPQuotaBase, model_base.BASEV2, models_v2.HasId,
                     models_v2.HasTenant):
    """ Service Profile
    """
    __tablename__ = 'service_profiles'
    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(255))
    vendor = sa.Column(sa.String(50))
    shared = sa.Column(sa.Boolean)
    # Not using ENUM for less painful upgrades. Validation will happen at the
    # API level
    insertion_mode = sa.Column(sa.String(50))
    service_type = sa.Column(sa.String(50))
    service_flavor = sa.Column(sa.String(1024))
    nodes = orm.relationship(ServiceChainNode, backref="service_profile")


gquota.DB_CLASS_TO_RESOURCE_NAMES[ServiceChainNode.__name__] = (
    'servicechain_node')
gquota.DB_CLASS_TO_RESOURCE_NAMES[ServiceChainSpec.__name__] = (
    'servicechain_spec')
gquota.DB_CLASS_TO_RESOURCE_NAMES[ServiceChainInstance.__name__] = (
    'servicechain_instance')
gquota.DB_CLASS_TO_RESOURCE_NAMES[ServiceProfile.__name__] = (
    'service_profile')


class ServiceChainDbPlugin(schain.ServiceChainPluginBase,
                           common_db_mixin.CommonDbMixin):
    """ServiceChain plugin interface implementation using SQLAlchemy models."""

    # TODO(osms69): native bulk support
    __native_bulk_support = False
    __native_pagination_support = True
    __native_sorting_support = True

    def __init__(self, *args, **kwargs):
        super(ServiceChainDbPlugin, self).__init__(*args, **kwargs)

    @property
    def _grouppolicy_plugin(self):
        # REVISIT(Magesh): Need initialization method after all
        # plugins are loaded to grab and store plugin.
        plugins = manager.NeutronManager.get_service_plugins()
        grouppolicy_plugin = plugins.get(pconst.GROUP_POLICY)
        if not grouppolicy_plugin:
            LOG.error(_("No Grouppolicy service plugin found."))
            raise s_exc.ServiceChainDeploymentError()
        return grouppolicy_plugin

    def _get_servicechain_node(self, context, node_id):
        try:
            return self._get_by_id(context, ServiceChainNode, node_id)
        except exc.NoResultFound:
            raise schain.ServiceChainNodeNotFound(sc_node_id=node_id)

    def _get_servicechain_spec(self, context, spec_id):
        try:
            return self._get_by_id(context, ServiceChainSpec, spec_id)
        except exc.NoResultFound:
            raise schain.ServiceChainSpecNotFound(sc_spec_id=spec_id)

    def _get_servicechain_instance(self, context, instance_id):
        try:
            return self._get_by_id(context, ServiceChainInstance, instance_id)
        except exc.NoResultFound:
            raise schain.ServiceChainInstanceNotFound(
                sc_instance_id=instance_id)

    def _get_service_profile(self, context, profile_id):
        try:
            return self._get_by_id(context, ServiceProfile, profile_id)
        except exc.NoResultFound:
            raise schain.ServiceProfileNotFound(
                profile_id=profile_id)

    def _make_sc_node_dict(self, sc_node, fields=None):
        res = {'id': sc_node['id'],
               'tenant_id': sc_node['tenant_id'],
               'name': sc_node['name'],
               'description': sc_node['description'],
               'service_profile_id': sc_node['service_profile_id'],
               'service_type': sc_node['service_type'],
               'config': sc_node['config'],
               'shared': sc_node['shared']}
        res['servicechain_specs'] = [sc_spec['servicechain_spec_id']
                                     for sc_spec in sc_node['specs']]
        return self._fields(res, fields)

    def _make_sc_spec_dict(self, spec, fields=None):
        res = {'id': spec['id'],
               'tenant_id': spec['tenant_id'],
               'name': spec['name'],
               'description': spec['description'],
               'config_param_names': spec.get('config_param_names'),
               'shared': spec['shared']}
        res['nodes'] = [sc_node['node_id'] for sc_node in spec['nodes']]
        res['instances'] = [x['servicechain_instance_id'] for x in
                            spec['instances']]
        return self._fields(res, fields)

    def _make_sc_instance_dict(self, instance, fields=None):
        res = {'id': instance['id'],
               'tenant_id': instance['tenant_id'],
               'name': instance['name'],
               'description': instance['description'],
               'config_param_values': instance['config_param_values'],
               'provider_ptg_id': instance['provider_ptg_id'],
               'consumer_ptg_id': instance['consumer_ptg_id'],
               'management_ptg_id': instance['management_ptg_id'],
               'classifier_id': instance['classifier_id']}
        res['servicechain_specs'] = [sc_spec['servicechain_spec_id']
                                    for sc_spec in instance['specs']]
        return self._fields(res, fields)

    def _make_service_profile_dict(self, profile, fields=None):
        res = {'id': profile['id'],
               'tenant_id': profile['tenant_id'],
               'name': profile['name'],
               'description': profile['description'],
               'shared': profile['shared'],
               'service_type': profile['service_type'],
               'service_flavor': profile['service_flavor'],
               'vendor': profile['vendor'],
               'insertion_mode': profile['insertion_mode']}
        res['nodes'] = [node['id'] for node in profile['nodes']]
        return self._fields(res, fields)

    @staticmethod
    def validate_service_type(service_type):
        if service_type not in schain.sc_supported_type:
            raise schain.ServiceTypeNotSupported(sc_service_type=service_type)

    @log.log
    def create_servicechain_node(self, context, servicechain_node):
        node = servicechain_node['servicechain_node']
        tenant_id = self._get_tenant_id_for_create(context, node)
        with context.session.begin(subtransactions=True):
            node_db = ServiceChainNode(
                id=uuidutils.generate_uuid(), tenant_id=tenant_id,
                name=node['name'], description=node['description'],
                service_profile_id=node['service_profile_id'],
                service_type=node['service_type'],
                config=node['config'], shared=node['shared'])
            context.session.add(node_db)
        return self._make_sc_node_dict(node_db)

    @log.log
    def update_servicechain_node(self, context, servicechain_node_id,
                                 servicechain_node, set_params=False):
        node = servicechain_node['servicechain_node']
        with context.session.begin(subtransactions=True):
            node_db = self._get_servicechain_node(context,
                                                  servicechain_node_id)
            node_db.update(node)
            # Update the config param names derived for the associated specs
            spec_node_associations = node_db.specs
            for node_spec in spec_node_associations:
                spec_id = node_spec.servicechain_spec_id
                spec_db = self._get_servicechain_spec(context, spec_id)
                self._process_nodes_for_spec(
                    context, spec_db, self._make_sc_spec_dict(spec_db),
                    set_params=set_params)
        return self._make_sc_node_dict(node_db)

    @log.log
    def delete_servicechain_node(self, context, servicechain_node_id):
        with context.session.begin(subtransactions=True):
            node_db = self._get_servicechain_node(context,
                                                  servicechain_node_id)
            if node_db.specs:
                raise schain.ServiceChainNodeInUse(
                                    node_id=servicechain_node_id)
            context.session.delete(node_db)

    @log.log
    def get_servicechain_node(self, context, servicechain_node_id,
                              fields=None):
        node = self._get_servicechain_node(context, servicechain_node_id)
        return self._make_sc_node_dict(node, fields)

    @log.log
    def get_servicechain_nodes(self, context, filters=None, fields=None,
                               sorts=None, limit=None, marker=None,
                               page_reverse=False):
        marker_obj = self._get_marker_obj(context, 'servicechain_node', limit,
                                          marker)
        return self._get_collection(context, ServiceChainNode,
                                    self._make_sc_node_dict,
                                    filters=filters, fields=fields,
                                    sorts=sorts, limit=limit,
                                    marker_obj=marker_obj,
                                    page_reverse=page_reverse)

    @log.log
    def get_servicechain_nodes_count(self, context, filters=None):
        return self._get_collection_count(context, ServiceChainNode,
                                          filters=filters)

    def _process_nodes_for_spec(self, context, spec_db, spec,
                                set_params=True):
        if 'nodes' in spec:
            self._set_nodes_for_spec(context, spec_db, spec['nodes'],
                                     set_params=set_params)
            del spec['nodes']
        return spec

    def _set_nodes_for_spec(self, context, spec_db, nodes_id_list,
                            set_params=True):
        if not nodes_id_list:
            spec_db.nodes = []
            spec_db.config_param_names = '[]'
            return
        with context.session.begin(subtransactions=True):
            # We will first check if the new list of nodes is valid
            filters = {'id': [n_id for n_id in nodes_id_list]}
            nodes_in_db = self._get_collection_query(context, ServiceChainNode,
                                                     filters=filters)
            nodes_list = [n_db['id'] for n_db in nodes_in_db]
            for node_id in nodes_id_list:
                if node_id not in nodes_list:
                    # If we find an invalid node id in the list we
                    # do not perform the update
                    raise schain.ServiceChainNodeNotFound(sc_node_id=node_id)
            # New list of nodes is valid so we will first reset the
            #  existing list and then add each node in order.
            # Note that the list could be empty in which case we interpret
            # it as clearing existing nodes.
            spec_db.nodes = []
            if set_params:
                spec_db.config_param_names = '[]'
            for node_id in nodes_id_list:
                if set_params:
                    sc_node = self.get_servicechain_node(context, node_id)
                    node_dict = jsonutils.loads(sc_node['config'])
                    config_params = (node_dict.get('parameters') or
                                     node_dict.get('Parameters'))
                    if config_params:
                        if not spec_db.config_param_names:
                            spec_db.config_param_names = str(
                                config_params.keys())
                        else:
                            config_param_names = ast.literal_eval(
                                spec_db.config_param_names)
                            config_param_names.extend(config_params.keys())
                            spec_db.config_param_names = str(
                                config_param_names)

                assoc = SpecNodeAssociation(servicechain_spec_id=spec_db.id,
                                            node_id=node_id)
                spec_db.nodes.append(assoc)

    def _process_specs_for_instance(self, context, instance_db, instance):
        if 'servicechain_specs' in instance:
            self._set_specs_for_instance(context, instance_db,
                                         instance['servicechain_specs'])
            del instance['servicechain_specs']
        return instance

    def _set_specs_for_instance(self, context, instance_db, spec_id_list):
        if not spec_id_list:
            instance_db.spec_ids = []
            return
        with context.session.begin(subtransactions=True):
            filters = {'id': spec_id_list}
            specs_in_db = self._get_collection_query(context, ServiceChainSpec,
                                                     filters=filters)
            specs_list = set(spec_db['id'] for spec_db in specs_in_db)
            for spec_id in spec_id_list:
                if spec_id not in specs_list:
                    # Do not update if spec ID is invalid
                    raise schain.ServiceChainSpecNotFound(sc_spec_id=spec_id)
            # Reset the existing list and then add each spec in order. The list
            # could be empty in which case we clear the existing specs.
            instance_db.specs = []
            for spec_id in spec_id_list:
                assoc = InstanceSpecAssociation(
                                    servicechain_instance_id=instance_db.id,
                                    servicechain_spec_id=spec_id)
                instance_db.specs.append(assoc)

    def _get_instances_from_policy_target(self, context, policy_target):
        with context.session.begin(subtransactions=True):
            ptg_id = policy_target['policy_target_group_id']
            scis_p = self.get_servicechain_instances(
                context, {'provider_ptg_id': [ptg_id]})
            scis_c = self.get_servicechain_instances(
                context, {'consumer_ptg_id': [ptg_id]})
            # Don't return duplicates
            result = []
            seen = set()
            for sci in scis_p + scis_c:
                if sci['id'] not in seen:
                    seen.add(sci['id'])
                    result.append(sci)
            return result

    @log.log
    def create_servicechain_spec(self, context, servicechain_spec,
                                 set_params=True):
        spec = servicechain_spec['servicechain_spec']
        tenant_id = self._get_tenant_id_for_create(context, spec)
        with context.session.begin(subtransactions=True):
            spec_db = ServiceChainSpec(id=uuidutils.generate_uuid(),
                                       tenant_id=tenant_id,
                                       name=spec['name'],
                                       description=spec['description'],
                                       shared=spec['shared'])
            self._process_nodes_for_spec(context, spec_db, spec,
                                         set_params=set_params)
            context.session.add(spec_db)
        return self._make_sc_spec_dict(spec_db)

    @log.log
    def update_servicechain_spec(self, context, spec_id,
                                 servicechain_spec, set_params=True):
        spec = servicechain_spec['servicechain_spec']
        with context.session.begin(subtransactions=True):
            spec_db = self._get_servicechain_spec(context,
                                                  spec_id)
            spec = self._process_nodes_for_spec(context, spec_db, spec,
                                                set_params=set_params)
            spec_db.update(spec)
        return self._make_sc_spec_dict(spec_db)

    @log.log
    def delete_servicechain_spec(self, context, spec_id):
        policy_actions = self._grouppolicy_plugin.get_policy_actions(
                                context, filters={"action_value": [spec_id]})
        if policy_actions:
            raise schain.ServiceChainSpecInUse(spec_id=spec_id)
        with context.session.begin(subtransactions=True):
            spec_db = self._get_servicechain_spec(context,
                                                  spec_id)
            if spec_db.instances:
                raise schain.ServiceChainSpecInUse(spec_id=spec_id)
            context.session.delete(spec_db)

    @log.log
    def get_servicechain_spec(self, context, spec_id,
                              fields=None):
        spec = self._get_servicechain_spec(context, spec_id)
        return self._make_sc_spec_dict(spec, fields)

    @log.log
    def get_servicechain_specs(self, context, filters=None, fields=None,
                               sorts=None, limit=None, marker=None,
                               page_reverse=False):
        marker_obj = self._get_marker_obj(context, 'servicechain_spec', limit,
                                          marker)
        return self._get_collection(context, ServiceChainSpec,
                                    self._make_sc_spec_dict,
                                    filters=filters, fields=fields,
                                    sorts=sorts, limit=limit,
                                    marker_obj=marker_obj,
                                    page_reverse=page_reverse)

    @log.log
    def get_servicechain_specs_count(self, context, filters=None):
        return self._get_collection_count(context, ServiceChainSpec,
                                          filters=filters)

    @log.log
    def create_servicechain_instance(self, context, servicechain_instance):
        instance = servicechain_instance['servicechain_instance']
        tenant_id = self._get_tenant_id_for_create(context, instance)
        with context.session.begin(subtransactions=True):
            if not instance['management_ptg_id']:
                management_groups = (
                    self._grouppolicy_plugin.get_policy_target_groups(
                        context, {'service_management': [True],
                                  'tenant_id': [instance['tenant_id']]}))
                if not management_groups:
                    # Fall back on shared service management
                    management_groups = (
                        self._grouppolicy_plugin.get_policy_target_groups(
                            context, {'service_management': [True]}))
                if management_groups:
                    instance['management_ptg_id'] = management_groups[0]['id']
            instance_db = ServiceChainInstance(
                id=uuidutils.generate_uuid(),
                tenant_id=tenant_id, name=instance['name'],
                description=instance['description'],
                config_param_values=instance['config_param_values'],
                provider_ptg_id=instance['provider_ptg_id'],
                consumer_ptg_id=instance['consumer_ptg_id'],
                management_ptg_id=instance['management_ptg_id'],
                classifier_id=instance['classifier_id'])
            self._process_specs_for_instance(context, instance_db, instance)
            context.session.add(instance_db)
        return self._make_sc_instance_dict(instance_db)

    @log.log
    def update_servicechain_instance(self, context, servicechain_instance_id,
                                     servicechain_instance):
        instance = servicechain_instance['servicechain_instance']
        with context.session.begin(subtransactions=True):
            instance_db = self._get_servicechain_instance(
                context, servicechain_instance_id)
            instance = self._process_specs_for_instance(context, instance_db,
                                                        instance)
            instance_db.update(instance)
        return self._make_sc_instance_dict(instance_db)

    @log.log
    def delete_servicechain_instance(self, context, servicechain_instance_id):
        with context.session.begin(subtransactions=True):
            instance_db = self._get_servicechain_instance(
                context, servicechain_instance_id)
            context.session.delete(instance_db)

    @log.log
    def get_servicechain_instance(self, context, sc_instance_id, fields=None):
        instance_db = self._get_servicechain_instance(context, sc_instance_id)
        return self._make_sc_instance_dict(instance_db, fields)

    @log.log
    def get_servicechain_instances(self, context, filters=None, fields=None,
                                   sorts=None, limit=None, marker=None,
                                   page_reverse=False):
        marker_obj = self._get_marker_obj(context, 'servicechain_instance',
                                          limit, marker)
        return self._get_collection(context, ServiceChainInstance,
                                    self._make_sc_instance_dict,
                                    filters=filters, fields=fields,
                                    sorts=sorts, limit=limit,
                                    marker_obj=marker_obj,
                                    page_reverse=page_reverse)

    @log.log
    def get_servicechain_instances_count(self, context, filters=None):
        return self._get_collection_count(context, ServiceChainInstance,
                                          filters=filters)

    @log.log
    def get_service_profiles_count(self, context, filters=None):
        return self._get_collection_count(context, ServiceProfile,
                                          filters=filters)

    @log.log
    def create_service_profile(self, context, service_profile):
        profile = service_profile['service_profile']
        tenant_id = self._get_tenant_id_for_create(context, profile)
        with context.session.begin(subtransactions=True):
            profile_db = ServiceProfile(
                id=uuidutils.generate_uuid(), tenant_id=tenant_id,
                name=profile['name'], description=profile['description'],
                service_type=profile['service_type'],
                insertion_mode=profile['insertion_mode'],
                vendor=profile['vendor'],
                service_flavor=profile['service_flavor'],
                shared=profile['shared'])
            context.session.add(profile_db)
        return self._make_service_profile_dict(profile_db)

    @log.log
    def update_service_profile(self, context, service_profile_id,
                               service_profile):
        profile = service_profile['service_profile']
        with context.session.begin(subtransactions=True):
            profile_db = self._get_service_profile(context,
                                                   service_profile_id)
            profile_db.update(profile)
        return self._make_service_profile_dict(profile_db)

    @log.log
    def delete_service_profile(self, context, service_profile_id):
        with context.session.begin(subtransactions=True):
            profile_db = self._get_service_profile(context,
                                                   service_profile_id)
            if profile_db.nodes:
                raise schain.ServiceProfileInUse(
                    profile_id=service_profile_id)
            context.session.delete(profile_db)

    @log.log
    def get_service_profile(self, context, service_profile_id, fields=None):
        profile_db = self._get_service_profile(
            context, service_profile_id)
        return self._make_service_profile_dict(profile_db, fields)

    @log.log
    def get_service_profiles(self, context, filters=None, fields=None,
                             sorts=None, limit=None, marker=None,
                             page_reverse=False):
        marker_obj = self._get_marker_obj(context, 'service_profile',
                                          limit, marker)
        return self._get_collection(context, ServiceProfile,
                                    self._make_service_profile_dict,
                                    filters=filters, fields=fields,
                                    sorts=sorts, limit=limit,
                                    marker_obj=marker_obj,
                                    page_reverse=page_reverse)
