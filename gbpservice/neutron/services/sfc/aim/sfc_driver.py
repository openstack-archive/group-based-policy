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

from networking_sfc.db import sfc_db
from networking_sfc.extensions import flowclassifier as flowc_ext
from networking_sfc.extensions import sfc as sfc_ext
from networking_sfc.services.sfc.common import context as sfc_ctx
from networking_sfc.services.sfc.drivers import base
from neutron.callbacks import events
from neutron.callbacks import registry
from neutron_lib import constants as n_constants
from neutron_lib.plugins import directory

from gbpservice.neutron.services.sfc.aim import constants as sfc_cts
from gbpservice.neutron.services.sfc.aim import exceptions


class SfcAIMDriver(base.SfcDriverBase):
    """SFC Driver mapping for AIM."""

    def initialize(self):
        self._core_plugin = None
        self._flowc_plugin = None
        self._l3_plugin = None
        self._sfc_plugin = None
        super(SfcAIMDriver, self).initialize()
        # We don't care about deletion, that is managed by the database layer
        # (can't delete a flowclassifier if in use.
        for event in [events.PRECOMMIT_UPDATE, events.PRECOMMIT_CREATE]:
            registry.subscribe(self._handle_flow_classifier,
                               sfc_cts.GBP_FLOW_CLASSIFIER, event)


    @property
    def plugin(self):
        if not self._core_plugin:
            self._core_plugin = directory.get_plugin()
        return self._core_plugin

    @property
    def flowc_plugin(self):
        if not self._flowc_plugin:
            self._flowc_plugin = directory.get_plugin(
                flowc_ext.FLOW_CLASSIFIER_EXT)
        return self._flowc_plugin

    @property
    def l3_plugin(self):
        if not self._l3_plugin:
            self._l3_plugin = directory.get_plugin(n_constants.L3)
        return self._l3_plugin

    @property
    def sfc_plugin(self):
        if not self._sfc_plugin:
            self._sfc_plugin = directory.get_plugin(sfc_ext.SFC_EXT)
        return self._sfc_plugin

    def create_port_pair_precommit(self, context):
        """Map Port Pair to AIM model

        A Port Pair by itself doesn't need to generate AIM model at least
        until added to a Port Pair Group.
        :param context:
        :return:
        """
        self._validate_port_pair(context)
        super(SfcAIMDriver, self).create_port_pair_precommit(context)

    def update_port_pair_precommit(self, context):
        self._validate_port_pair(context)
        super(SfcAIMDriver, self).update_port_pair_precommit(context)

    def delete_port_pair_precommit(self, context):
        # NOTE(ivar): The SFC plugin prevents port pair deletion when
        # belonging to a port pair group.
        pass

    def create_port_pair_group_precommit(self, context):
        """Map port pair group to AIM model

        A Port Pair Group is the equivalent of a Logical Device in AIM.
        :param context:
        :return:
        """
        # TODO(ivar): Some ports in the port pair group might not be bound.
        # we need to intercept binding events and modify the AIM model
        # accordingly
        self._validate_port_pair_group(context)
        self._map_port_pair_group(context._plugin_context, context.current)

    def update_port_pair_group_precommit(self, context):
        self._validate_port_pair_group(context)
        # Regenerate Port Pair Group Model
        # NOTE(ivar): this doesn't imply any datapth disruption if not
        # needed. By regenerating the AIM model in a single transaction,
        # we modify the hashtree by the same much as we would by only
        # adding the configuration difference. This is certainly slower though,
        # as we need to run more queries and compute more events on the
        # hashtree, so it should be improved to regenerate the model only
        # when necessary
        if self._should_regenerate_ppg(context):
            self._delete_port_pair_group_mapping(context._plugin_context,
                                                 context.original)
            self._map_port_pair_group(context._plugin_context, context.current)

    def delete_port_pair_group_precommit(self, context):
        self._delete_port_pair_group_mapping(context._plugin_context,
                                             context.current)

    def create_port_chain_precommit(self, context):
        self._validate_port_chain(context)
        self._map_port_chain(context._plugin_context, context.current)

    def update_port_chain_precommit(self, context):
        self._validate_port_chain(context)
        # Regenerate Port Chain Model
        if self._should_regenerate_pc(context):
            self._delete_port_chain_mapping(context._plugin_context,
                                            context.original)
            self._map_port_chain(context._plugin_context, context.current)

    def delete_port_chain_precommit(self, context):
        self._delete_port_chain_mapping(context._plugin_context,
                                        context.current)

    def _validate_port_pair(self, context):
        # Disallow service_function_parameters
        if context.current['service_function_parameters']:
            raise exceptions.UnsupportedConfiguration(
                conf='service_function_parameters', type='port_pair')
        # Ports need to belong to distinct networks
        ingress_net = self._get_port_network_id(context._plugin_context,
                                                context.current[0]['ingress'])
        egress_net = self._get_port_network_id(context._plugin_context,
                                               context.current[0]['egress'])
        if ingress_net == egress_net:
            raise exceptions.PortPairsSameNetwork(id=context.current['id'])

    def _validate_port_pair_group(self, context):
        # Disallow port_pair_group_parameters
        if context.current['port_pair_group_parameters']:
            raise exceptions.UnsupportedConfiguration(
                conf='port_pair_group_parameters', type='port_pair_group')
        # Verify all ports are in the same network for each side of the
        # connection
        port_pairs = context._plugin.get_port_pair_groups(
            context._plugin_context,
            filters={'id': context.current['port_pairs']})
        if port_pairs:
            ingress_net = self._get_port_network_id(
                context._plugin_context, port_pairs[0]['ingress'])
            egress_net = self._get_port_network_id(
                context._plugin_context, port_pairs[0]['egress'])
            if any(x for x in port_pairs[1:] if ((ingress_net, egress_net) != (
                    self._get_port_network_id(context._plugin_context, y)
                    for y in [x['ingress'], x['egress']]))):
                raise exceptions.PortPairsDifferentNetworkInGroup(
                    id=context.current['id'])

    def _validate_port_chain(self, context):
        # Disallow service_function_parameters
        if context.current['chain_parameters']:
            raise exceptions.UnsupportedConfiguration(
                conf='chain_parameters', type='port_chain')
        # Disallow multiple chains with same flow classifier.
        for flowc_id in context.current['flow_classifiers']:
            for chain in self._get_chains_by_classifier_id(
                    context._plugin_context, flowc_id):
                if chain['id'] != context.current['id']:
                    raise exceptions.OnlyOneChainPerFlowClassifierAllowed(
                        current=context.current['id'], conflicting=chain['id'])

    def _map_port_pair_group(self, plugin_context, ppg):
        pass

    def _delete_port_pair_group_mapping(self, plugin_context, ppg):
        pass

    def _map_port_chain(self, plugin_context, pc):
        pass

    def _delete_port_chain_mapping(self, plugin_context, pc):
        pass

    def _get_port_network_id(self, plugin_context, port_id):
        port = self.plugin.get_port(plugin_context, port_id)
        return port['network_id']

    def _get_chains_by_classifier_id(self, plugin_context, flowc_id):
        context = plugin_context
        with context.session.begin(subtransactions=True):
            chain_ids = [x.portchain_id for x in context.session.query(
                sfc_db.ChainClassifierAssoc).filter_by(
                flowclassifier_id=flowc_id).all()]
            return self.sfc_plugin.get_port_chains(plugin_context,
                                                   filters={'id': chain_ids})

    def _should_regenerate_ppg(self, context):
        return True

    def _should_regenerate_pc(self, context):
        return True

    def _handle_flow_classifier(self, rtype, event, trigger, driver_context,
                                **kwargs):
        if event == events.PRECOMMIT_UPDATE:
            current = driver_context.current
            original = driver_context.original
            pctx = driver_context._plugin_context
            if any(current[x] != original[x] for x in
                   sfc_cts.SUPPORTED_FC_PARAMS):
                # reject if in use
                for chain in self._get_chains_by_classifier_id(pctx,
                                                               current['id']):
                    raise exceptions.FlowClassifierInUseByAChain(
                        fields=sfc_cts.SUPPORTED_FC_PARAMS, pc_id=chain['id'])
