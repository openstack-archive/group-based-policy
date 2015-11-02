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
from neutron.plugins.common import constants as pconst
from oslo_log import log as logging
from oslo_utils import excutils

import gbpservice.neutron.db.servicechain_db as servicechain_db
from gbpservice.neutron.services.grouppolicy.common import constants as gp_cts
from gbpservice.neutron.services.servicechain.plugins.msc import (
    context as servicechain_context)
from gbpservice.neutron.services.servicechain.plugins.msc import (
    driver_manager as manager)
from gbpservice.neutron.services.servicechain.plugins import sharing


LOG = logging.getLogger(__name__)


class ServiceChainPlugin(servicechain_db.ServiceChainDbPlugin,
                         sharing.SharingMixin):

    """Implementation of the Service Chain Plugin.

    """
    supported_extension_aliases = ["servicechain"]
    path_prefix = gp_cts.GBP_PREFIXES[pconst.SERVICECHAIN]

    def __init__(self):
        self.driver_manager = manager.DriverManager()
        super(ServiceChainPlugin, self).__init__()
        self.driver_manager.initialize()

    @log.log
    def create_servicechain_node(self, context, servicechain_node):
        session = context.session
        with session.begin(subtransactions=True):
            result = super(ServiceChainPlugin, self).create_servicechain_node(
                context, servicechain_node)
            self._validate_shared_create(context, result, 'servicechain_node')
            sc_context = servicechain_context.ServiceChainNodeContext(
                self, context, result)
            self.driver_manager.create_servicechain_node_precommit(
                sc_context)

        try:
            self.driver_manager.create_servicechain_node_postcommit(
                sc_context)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.error(_("driver_manager.create_servicechain_postcommit "
                            "failed, deleting servicechain_node %s"),
                          result['id'])
                self.delete_servicechain_node(context, result['id'])

        return result

    @log.log
    def update_servicechain_node(self, context, servicechain_node_id,
                                 servicechain_node):
        session = context.session
        with session.begin(subtransactions=True):
            original_sc_node = self.get_servicechain_node(
                                         context, servicechain_node_id)
            updated_sc_node = super(ServiceChainPlugin,
                                    self).update_servicechain_node(
                                        context, servicechain_node_id,
                                        servicechain_node,
                                        set_params=True)
            self._validate_shared_update(context, original_sc_node,
                                         updated_sc_node, 'servicechain_node')
            sc_context = servicechain_context.ServiceChainNodeContext(
                self, context, updated_sc_node,
                original_sc_node=original_sc_node)
            self.driver_manager.update_servicechain_node_precommit(
                sc_context)

        self.driver_manager.update_servicechain_node_postcommit(sc_context)

        return updated_sc_node

    @log.log
    def delete_servicechain_node(self, context, servicechain_node_id):
        session = context.session
        with session.begin(subtransactions=True):
            sc_node = self.get_servicechain_node(context,
                                                 servicechain_node_id)
            sc_context = servicechain_context.ServiceChainNodeContext(
                self, context, sc_node)
            self.driver_manager.delete_servicechain_node_precommit(
                sc_context)
            super(ServiceChainPlugin, self).delete_servicechain_node(
                context, servicechain_node_id)

        try:
            self.driver_manager.delete_servicechain_node_postcommit(
                sc_context)
        except Exception:
            LOG.exception(_("delete_servicechain_node_postcommit failed "
                            "for servicechain_node %s"),
                          servicechain_node_id)

    @log.log
    def create_servicechain_spec(self, context, servicechain_spec):
        session = context.session
        with session.begin(subtransactions=True):
            result = super(ServiceChainPlugin, self).create_servicechain_spec(
                context, servicechain_spec)
            self._validate_shared_create(context, result, 'servicechain_spec')
            sc_context = servicechain_context.ServiceChainSpecContext(
                self, context, result)
            self.driver_manager.create_servicechain_spec_precommit(
                sc_context)

        try:
            self.driver_manager.create_servicechain_spec_postcommit(sc_context)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.error(_("driver_manager.create_servicechain_postcommit "
                            "failed, deleting servicechain_spec %s"),
                          result['id'])
                self.delete_servicechain_spec(context, result['id'])

        return result

    @log.log
    def update_servicechain_spec(self, context, servicechain_spec_id,
                                 servicechain_spec):
        session = context.session
        with session.begin(subtransactions=True):
            original_sc_spec = self.get_servicechain_spec(
                                         context, servicechain_spec_id)
            updated_sc_spec = super(ServiceChainPlugin,
                                    self).update_servicechain_spec(
                                        context, servicechain_spec_id,
                                        servicechain_spec)
            self._validate_shared_update(context, original_sc_spec,
                                         updated_sc_spec, 'servicechain_spec')
            sc_context = servicechain_context.ServiceChainSpecContext(
                self, context, updated_sc_spec,
                original_sc_spec=original_sc_spec)
            self.driver_manager.update_servicechain_spec_precommit(
                sc_context)

        self.driver_manager.update_servicechain_spec_postcommit(sc_context)

        return updated_sc_spec

    @log.log
    def delete_servicechain_spec(self, context, servicechain_spec_id):
        session = context.session
        with session.begin(subtransactions=True):
            sc_spec = self.get_servicechain_spec(context,
                                                 servicechain_spec_id)
            sc_context = servicechain_context.ServiceChainSpecContext(
                self, context, sc_spec)
            self.driver_manager.delete_servicechain_spec_precommit(
                sc_context)
            super(ServiceChainPlugin, self).delete_servicechain_spec(
                context, servicechain_spec_id)

        try:
            self.driver_manager.delete_servicechain_spec_postcommit(sc_context)
        except Exception:
            LOG.exception(_("delete_servicechain_spec_postcommit failed "
                            "for servicechain_spec %s"),
                          servicechain_spec_id)

    @log.log
    def create_servicechain_instance(self, context, servicechain_instance):
        session = context.session
        with session.begin(subtransactions=True):
            result = super(ServiceChainPlugin,
                           self).create_servicechain_instance(
                               context, servicechain_instance)
            sc_context = servicechain_context.ServiceChainInstanceContext(
                self, context, result)
            self.driver_manager.create_servicechain_instance_precommit(
                sc_context)

        try:
            self.driver_manager.create_servicechain_instance_postcommit(
                sc_context)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.error(_(
                    "driver_manager.create_servicechain_instance_postcommit "
                    "failed, deleting servicechain_instance %s"),
                          result['id'])
                self.delete_servicechain_instance(context, result['id'])

        return result

    @log.log
    def update_servicechain_instance(self, context,
                                     servicechain_instance_id,
                                     servicechain_instance):
        session = context.session
        with session.begin(subtransactions=True):
            original_sc_instance = self.get_servicechain_instance(
                                         context, servicechain_instance_id)
            updated_sc_instance = super(ServiceChainPlugin,
                                    self).update_servicechain_instance(
                                        context, servicechain_instance_id,
                                        servicechain_instance)
            sc_context = servicechain_context.ServiceChainInstanceContext(
                self, context, updated_sc_instance,
                original_sc_instance=original_sc_instance)
            self.driver_manager.update_servicechain_instance_precommit(
                sc_context)

        self.driver_manager.update_servicechain_instance_postcommit(
            sc_context)
        return updated_sc_instance

    @log.log
    def delete_servicechain_instance(self, context, servicechain_instance_id):
        session = context.session
        with session.begin(subtransactions=True):
            sc_instance = self.get_servicechain_instance(
                                                context,
                                                servicechain_instance_id)
            sc_context = servicechain_context.ServiceChainInstanceContext(
                self, context, sc_instance)
            self.driver_manager.delete_servicechain_instance_precommit(
                sc_context)
            super(ServiceChainPlugin, self).delete_servicechain_instance(
                context, servicechain_instance_id)

        try:
            self.driver_manager.delete_servicechain_instance_postcommit(
                sc_context)
        except Exception:
            LOG.exception(_("delete_servicechain_instance_postcommit failed "
                            "for servicechain_instance %s"),
                          servicechain_instance_id)

    @log.log
    def create_service_profile(self, context, service_profile):
        session = context.session
        with session.begin(subtransactions=True):
            result = super(ServiceChainPlugin,
                           self).create_service_profile(
                               context, service_profile)
            self._validate_shared_create(context, result, 'service_profile')
            sc_context = servicechain_context.ServiceProfileContext(
                self, context, result)
            self.driver_manager.create_service_profile_precommit(
                sc_context)

        try:
            self.driver_manager.create_service_profile_postcommit(
                sc_context)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.error(_(
                    "driver_manager.create_service_profile_postcommit "
                    "failed, deleting service_profile %s"),
                          result['id'])
                self.delete_service_profile(context, result['id'])

        return result

    @log.log
    def update_service_profile(self, context, service_profile_id,
                               service_profile):
        session = context.session
        with session.begin(subtransactions=True):
            original_profile = self.get_service_profile(
                context, service_profile_id)
            updated_profile = super(ServiceChainPlugin,
                                    self).update_service_profile(
                context, service_profile_id, service_profile)
            self._validate_shared_update(context, original_profile,
                                         updated_profile, 'service_profile')
            sc_context = servicechain_context.ServiceProfileContext(
                self, context, updated_profile,
                original_profile=original_profile)
            self.driver_manager.update_service_profile_precommit(
                sc_context)

        self.driver_manager.update_service_profile_postcommit(
            sc_context)
        return updated_profile

    @log.log
    def delete_service_profile(self, context, service_profile_id):
        session = context.session
        with session.begin(subtransactions=True):
            profile = self.get_service_profile(
                context, service_profile_id)
            sc_context = servicechain_context.ServiceProfileContext(
                self, context, profile)
            self.driver_manager.delete_service_profile_precommit(
                sc_context)
            super(ServiceChainPlugin, self).delete_service_profile(
                context, service_profile_id)

        try:
            self.driver_manager.delete_service_profile_postcommit(
                sc_context)
        except Exception:
            LOG.exception(_("delete_service_profile_postcommit failed "
                            "for service_profile %s"),
                          service_profile_id)
