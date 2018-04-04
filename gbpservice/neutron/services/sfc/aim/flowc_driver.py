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

from networking_sfc.db import flowclassifier_db as flc_db
from networking_sfc.extensions import flowclassifier
from networking_sfc.services.flowclassifier.drivers import base
from neutron.callbacks import events
from neutron.callbacks import registry
from neutron.callbacks import resources
from neutron_lib.api import validators
from neutron_lib.plugins import directory
from oslo_log import log as logging

from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import constants
from gbpservice.neutron.services.grouppolicy.common import exceptions as exc
from gbpservice.neutron.services.sfc.aim import constants as sfc_cts
from gbpservice.neutron.services.sfc.aim import exceptions as sfc_exc

LOG = logging.getLogger(__name__)
flowclassifier.SUPPORTED_L7_PARAMETERS.update(sfc_cts.AIM_FLC_L7_PARAMS)


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
        registry.subscribe(self._handle_network_delete, resources.NETWORK,
                           events.PRECOMMIT_DELETE)
        self._core_plugin = None

    @property
    def plugin(self):
        if not self._core_plugin:
            self._core_plugin = directory.get_plugin()
            if not self._core_plugin:
                LOG.error("No Core plugin found.")
                raise exc.GroupPolicyDeploymentError()
        return self._core_plugin

    def create_flow_classifier_precommit(self, context):
        self._validate_flow_classifier(context)
        registry.notify(constants.GBP_FLOW_CLASSIFIER, events.PRECOMMIT_CREATE,
                        self, driver_context=context)

    def update_flow_classifier_precommit(self, context):
        self._validate_flow_classifier(context)
        registry.notify(constants.GBP_FLOW_CLASSIFIER, events.PRECOMMIT_UPDATE,
                        self, driver_context=context)

    def delete_flow_classifier_precommit(self, context):
        registry.notify(constants.GBP_FLOW_CLASSIFIER, events.PRECOMMIT_DELETE,
                        self, driver_context=context)

    def _validate_flow_classifier(self, context):
        fc = context.current
        # Verify L7 params are set
        l7_p = fc['l7_parameters']
        if any(x for x in sfc_cts.AIM_FLC_L7_PARAMS.keys()
               if not validators.is_attr_set(l7_p.get(x))):
            raise sfc_exc.BadFlowClassifier(
                params=sfc_cts.AIM_FLC_L7_PARAMS.keys())
        # Verify standard params are set
        # TODO(ivar): src and dst prefix are needed only for SVI networks
        if any(x for x in sfc_cts.AIM_FLC_PARAMS
               if not validators.is_attr_set(fc.get(x))):
            raise sfc_exc.BadFlowClassifier(params=sfc_cts.AIM_FLC_PARAMS)
        # Verify networks exist
        src_net = self.plugin.get_network(
            context._plugin_context, l7_p[sfc_cts.LOGICAL_SRC_NET])
        if l7_p[sfc_cts.LOGICAL_SRC_NET] != l7_p[sfc_cts.LOGICAL_DST_NET]:
            # Verify dst existence
            self.plugin.get_network(context._plugin_context,
                                    l7_p[sfc_cts.LOGICAL_DST_NET])
        elif src_net.get('apic:svi') is False:
            # Same network, not SVI
            raise sfc_exc.FlowClassifierSameSrcDstNetworks()

        if validators.is_attr_set(fc.get('source_ip_prefix')) and (
                fc.get('source_ip_prefix') == fc.get('destination_ip_prefix')):
            # Same subnet for source and dst is not allowed. For overlapping
            # (but not same) subnets LPM will be applied.
            raise sfc_exc.FlowClassifierSameSubnet()

        # TODO(ivar): Any other parameter is unsupported, for now just
        # unenforced.

        # TODO(ivar): if source and destination ports are to a private network
        # source/destination CIDRs are not required

        # TODO(ivar): only one classifier can be provider (destination) if
        # the network is not SVI.

    def _get_classifiers_by_network_id(self, plugin_context, network_id):
        context = plugin_context
        with context.session.begin(subtransactions=True):
            classifier_ids = []
            for keyword in [sfc_cts.LOGICAL_SRC_NET, sfc_cts.LOGICAL_DST_NET]:
                classifier_ids.extend(
                    [x.classifier_id for x in context.session.query(
                        flc_db.L7Parameter).filter_by(
                        keyword=keyword).filter_by(value=network_id).all()])
            return classifier_ids

    def _handle_network_delete(self, rtype, event, trigger, context,
                               network_id, **kwargs):
        flc_ids = self._get_classifiers_by_network_id(context, network_id)
        if flc_ids:
            # TODO(ivar): instead of raising, we could try deleting the flow
            # classifier, which would fail (and rollback the transaction) if
            # in use.
            raise sfc_exc.NetworkInUseByFlowClassifiers(ids=flc_ids)
