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


class FlowclassifierAIMDriver(base.FlowClassifierDriverBase):
    """SFC Driver mapping for AIM."""

    def initialize(self):
        self._core_plugin = None
        self._flowc_plugin = None
        super(FlowclassifierAIMDriver, self).initialize()

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
        self._map_flow_classifier(context, context.current)
        registry.notify(sfc_cts.GBP_FLOW_CLASSIFIER, events.PRECOMMIT_CREATE,
                        self, driver_context=context)

    def update_flow_classifier_precommit(self, context):
        self._validate_flow_classifier(context)
        if self._should_regenerate_fc(context):
            # Regenerate Flow Classifier Model
            self._delete_flow_classifier_mapping(context._plugin_context,
                                                 context.original)
            self._map_flow_classifier(context._plugin_context, context.current)
        registry.notify(sfc_cts.GBP_FLOW_CLASSIFIER, events.PRECOMMIT_UPDATE,
                        self, driver_context=context)

    def delete_flow_classifier_precommit(self, context):
        self._delete_flow_classifier_mapping(context._plugin_context,
                                             context.current)
        registry.notify(sfc_cts.GBP_FLOW_CLASSIFIER, events.PRECOMMIT_DELETE,
                        self, driver_context=context)

    def _validate_flow_classifier(self, context):
        fc = context.current
        for classification in sfc_cts.SUPPORTED_FC_PARAMS:
            if not fc[classification]:
                raise exc.BadFlowClassifier(params=sfc_cts.SUPPORTED_FC_PARAMS)
        # TODO(ivar): if source/destination ports are not external ports,
        # then the source/destination ip prefixes have to match their
        # subnet exactly.

        # TODO(ivar): Any other parameter is unsupported, for now just
        # unenforced.

    def _map_flow_classifier(self, plugin_context, flowc):
        """Map flowclassifier to AIM model

        If source/destination ports are plugged to an external network, create
        AIM external EPGs in the proper L3Outs and set the corresponding
        source/destination ip prefix.

        :param context:
        :return:
        """

    def _delete_flow_classifier_mapping(self, plugin_context, flowc):
        pass

    def _should_regenerate_fc(self, context):
        return True
