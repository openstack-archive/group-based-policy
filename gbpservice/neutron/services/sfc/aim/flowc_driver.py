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

from networking_sfc.services.flowclassifier.drivers import base
from neutron.callbacks import events
from neutron.callbacks import registry

from gbpservice.neutron.services.sfc.aim import constants as sfc_cts
from gbpservice.neutron.services.sfc.aim import exceptions as exc


class FlowclassifierAIMDriverBase(base.FlowClassifierDriverBase):
    def create_flow_classifier_precommit(self, context):
        pass

    def create_flow_classifier(self, context):
        pass

    def update_flow_classifier(self, context):
        pass

    def delete_flow_classifier(self, context):
        pass


class FlowclassifierAIMDriver(FlowclassifierAIMDriverBase):
    """SFC Driver mapping for AIM."""

    def initialize(self):
        pass

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
        for classification in sfc_cts.SUPPORTED_FC_PARAMS:
            if not fc[classification]:
                raise exc.BadFlowClassifier(params=sfc_cts.SUPPORTED_FC_PARAMS)
        # TODO(ivar): if source/destination ports are not external ports,
        # then the source/destination ip prefixes have to match their
        # subnet exactly.

        # TODO(ivar): Any other parameter is unsupported, for now just
        # unenforced.

        # TODO(ivar): What if source and dest network/port are the same?
        # TODO(ivar): if source and destination ports are to a private network
        # source/destination CIDRs are not required

    def _should_regenerate_fc(self, context):
        return True
