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

from networking_sfc.extensions import flowclassifier as flowc_ext
from networking_sfc.db import flowclassifier_db as flowc_db
from networking_sfc.services.flowclassifier.drivers import base
from neutron.callbacks import events
from neutron.callbacks import registry
from neutron.callbacks import resources
from neutron_lib import constants as n_constants
from neutron_lib.plugins import directory

from gbpservice.neutron.services.sfc.aim import constants as sfc_cts
from gbpservice.neutron.services.sfc.aim import exceptions as exc

# Patch flow classifier supported L7 Params
flowc_ext.SUPPORTED_L7_PARAMETERS = {
    'router_id': {
        'allow_post': True, 'allow_put': True, 'is_visible': True,
        'validate': {'type:uuid': None}}
}


class FlowclassifierAIMDriver(base.FlowClassifierDriverBase):
    """SFC Driver mapping for AIM."""

    def initialize(self):
        self._core_plugin = None
        self._flowc_plugin = None
        super(FlowclassifierAIMDriver, self).initialize()
        registry.subscribe(self._handle_router_deletion,
                           resources.ROUTER, events.PRECOMMIT_DELETE)

    @property
    def l3_plugin(self):
        if not self._l3_plugin:
            self._l3_plugin = directory.get_plugin(n_constants.L3)
        return self._l3_plugin

    @property
    def flowc_plugin(self):
        if not self._flowc_plugin:
            self._flowc_plugin = directory.get_plugin(
                flowc_ext.FLOW_CLASSIFIER_EXT)
        return self._flowc_plugin

    def create_flow_classifier_precommit(self, context):
        self._validate_flow_classifier(context)
        registry.notify(sfc_cts.GBP_FLOW_CLASSIFIER, events.PRECOMMIT_CREATE,
                        self, driver_context=context)

    def update_flow_classifier_precommit(self, context):
        self._validate_flow_classifier(context)
        registry.notify(sfc_cts.GBP_FLOW_CLASSIFIER, events.PRECOMMIT_UPDATE,
                        self, driver_context=context)

    def delete_flow_classifier_precommit(self, context):
        registry.notify(sfc_cts.GBP_FLOW_CLASSIFIER, events.PRECOMMIT_DELETE,
                        self, driver_context=context)

    def _validate_flow_classifier(self, context):
        fc = context.current
        # Check router exists
        r_id = fc.get('l7_parameters', {}).get('router_id', None)
        if r_id:
            # Raises RouterNotFound if doesn't exist
            self.l3_plugin.get_router(context._plugin_context, r_id)
            # Only one classifier per router_id allowed
            for classifier in self._get_classifiers_by_router_id(
                    context._plugin_context, r_id):
                if classifier['id'] != fc['id']:
                    raise exc.OnlyOneFlowClassifierPerRouterIDAllowed(
                        current=fc['id'], conflicting=classifier['id'])

        # TODO(ivar): Any other parameter is unsupported, for now just
        # unenforced.

    def _get_classifiers_by_router_id(self, plugin_context, router_id):
        context = plugin_context
        with context.session.begin(subtransactions=True):
            flowc_ids = [x.classifier_id for x in context.session.query(
                flowc_db.L7Parameter).filter_by(keyword='router_id').filter_by(
                value=router_id).all()]
            return self.flowc_plugin.get_flow_classifiers(
                plugin_context, filters={'id': flowc_ids})

    def _handle_router_deletion(self, rtype, event, trigger, context,
                                router_db, router_id, **kwargs):
        flowcs = self._get_classifiers_by_router_id(context, router_id)
        if flowcs:
            raise exc.RouterIDInUseByFlowClassifier(router_id=router_id,
                                                    flowc_id=flowcs[0]['id'])
