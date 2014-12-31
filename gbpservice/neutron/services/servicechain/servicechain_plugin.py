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

import gbpservice.neutron.db.servicechain_db as servicechain_db
from gbpservice.neutron.services.servicechain import (
    driver_manager as manager)
from gbpservice.neutron.services.servicechain import (
    servicechain_context as servicechain_context)
from gbpservice.neutron.services.servicechain.common import (
    exceptions as sc_exc)

LOG = logging.getLogger(__name__)


class ServiceChainPlugin(servicechain_db.ServiceChainDbPlugin):

    """Implementation of the Service Chain Plugin.

    """
    supported_extension_aliases = ["servicechain"]

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
            sc_context = servicechain_context.ServiceChainNodeContext(
                self, context, result)
            self.driver_manager.create_servicechain_node_precommit(
                sc_context)

        try:
            self.driver_manager.create_servicechain_node_postcommit(
                sc_context)
        except sc_exc.ServiceChainDriverError:
            with excutils.save_and_reraise_exception():
                LOG.error(_("driver_manager.create_servicechain_postcommit "
                            "failed, deleting servicechain_node '%s'"),
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
                                        servicechain_node)
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
        except sc_exc.ServiceChainDriverError:
            with excutils.save_and_reraise_exception():
                LOG.error(_(
                    "driver_manager.delete_servicechain_node_postcommit "
                    "failed, deleting servicechain_node '%s'"),
                    servicechain_node_id)

    @log.log
    def create_servicechain_spec(self, context, servicechain_spec):
        session = context.session
        with session.begin(subtransactions=True):
            result = super(ServiceChainPlugin, self).create_servicechain_spec(
                context, servicechain_spec)
            sc_context = servicechain_context.ServiceChainSpecContext(
                self, context, result)
            self.driver_manager.create_servicechain_spec_precommit(
                sc_context)

        try:
            self.driver_manager.create_servicechain_spec_postcommit(sc_context)
        except sc_exc.ServiceChainDriverError:
            with excutils.save_and_reraise_exception():
                LOG.error(_("driver_manager.create_servicechain_postcommit "
                            "failed, deleting servicechain_spec '%s'"),
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
        except sc_exc.ServiceChainDriverError:
            with excutils.save_and_reraise_exception():
                LOG.error(_(
                    "driver_manager.delete_servicechain_spec_postcommit "
                    "failed, deleting servicechain_spec '%s'"),
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
        except sc_exc.ServiceChainDriverError:
            with excutils.save_and_reraise_exception():
                LOG.error(_(
                    "driver_manager.create_servicechain_instance_postcommit "
                    "failed, deleting servicechain_instance '%s'"),
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
        except sc_exc.ServiceChainDriverError:
            with excutils.save_and_reraise_exception():
                LOG.error(_(
                    "driver_manager.delete_servicechain_instance_postcommit "
                    "failed, deleting servicechain_instance '%s'"),
                          servicechain_instance_id)
