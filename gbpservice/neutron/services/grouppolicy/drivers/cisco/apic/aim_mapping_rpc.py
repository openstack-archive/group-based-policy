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

from collections import namedtuple
import sqlalchemy as sa
from sqlalchemy.ext import baked

from apic_ml2.neutron.db import port_ha_ipaddress_binding as ha_ip_db

from gbpservice.neutron.db.grouppolicy.extensions import (
    apic_auto_ptg_db as auto_ptg_db)
from gbpservice.neutron.db.grouppolicy.extensions import (
    apic_segmentation_label_db as seg_label_db)
from gbpservice.neutron.db.grouppolicy import group_policy_mapping_db as gpmdb
from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import (
    constants as md_const)

BAKERY = baked.bakery()

EndpointPtInfo = namedtuple(
    'EndpointPtInfo',
    ['pt_id',
     'ptg_id',
     'apg_id',
     'inject_default_route',
     'l3p_project_id',
     'is_auto_ptg'])


class AIMMappingRPCMixin(ha_ip_db.HAIPOwnerDbMixin):
    # The query_endpoint_rpc_info and update_endpoint_rpc_details
    # methods below are called by the apic_aim mechanism driver while
    # handling the request_endpoint_details (aka get_gbp_details) RPC
    # from the agent.

    def query_endpoint_rpc_info(self, session, info):
        # This method is called within a transaction from the apic_aim
        # MD's request_endpoint_details RPC handler to retrieve GBP
        # state needed to build the RPC response, after the info param
        # has already been populated with the data available within
        # Neutron itself.

        # Query for all needed scalar (non-list) state for the
        # policies associated with the port, and make sure the port is
        # owned by a policy target before continuing.
        pt_infos = self._query_pt_info(
            session, info['port_info'].port_id)
        if not pt_infos:
            return

        # A list was returned by the PT info query, like all the other
        # endpoint RPC queries, here and in the mechanism
        # driver. Currently, there will be at most a single item in
        # this list, but a join may later be added to this query in
        # order to eliminate another query's round-trip to the DB
        # server, resulting in multiple rows being returned. For now,
        # we just need that single row.
        pt_info = pt_infos[0]
        info['gbp_pt_info'] = pt_info

        # Query for policy target's segmentation labels.
        info['gbp_segmentation_labels'] = self._query_segmentation_labels(
            session, pt_info.pt_id)

    def _query_pt_info(self, session, port_id):
        query = BAKERY(lambda s: s.query(
            gpmdb.PolicyTargetMapping.id,
            gpmdb.PolicyTargetMapping.policy_target_group_id,
            gpmdb.PolicyTargetGroupMapping.application_policy_group_id,
            gpmdb.L2PolicyMapping.inject_default_route,
            gpmdb.L3PolicyMapping.project_id,
            auto_ptg_db.ApicAutoPtgDB.is_auto_ptg,
        ))
        query += lambda q: q.join(
            gpmdb.PolicyTargetGroupMapping,
            gpmdb.PolicyTargetGroupMapping.id ==
            gpmdb.PolicyTargetMapping.policy_target_group_id)
        query += lambda q: q.join(
            gpmdb.L2PolicyMapping,
            gpmdb.L2PolicyMapping.id ==
            gpmdb.PolicyTargetGroupMapping.l2_policy_id)
        query += lambda q: q.join(
            gpmdb.L3PolicyMapping,
            gpmdb.L3PolicyMapping.id ==
            gpmdb.L2PolicyMapping.l3_policy_id)
        query += lambda q: q.outerjoin(
            auto_ptg_db.ApicAutoPtgDB,
            auto_ptg_db.ApicAutoPtgDB.policy_target_group_id ==
            gpmdb.PolicyTargetMapping.policy_target_group_id)
        query += lambda q: q.filter(
            gpmdb.PolicyTargetMapping.port_id == sa.bindparam('port_id'))
        return [EndpointPtInfo._make(row) for row in
                query(session).params(
                    port_id=port_id)]

    def _query_segmentation_labels(self, session, pt_id):
        query = BAKERY(lambda s: s.query(
            seg_label_db.ApicSegmentationLabelDB.segmentation_label))
        query += lambda q: q.filter(
            seg_label_db.ApicSegmentationLabelDB.policy_target_id ==
            sa.bindparam('pt_id'))
        return [x for x, in query(session).params(
            pt_id=pt_id)]

    def update_endpoint_rpc_details(self, info, details):
        # This method is called outside a transaction from the
        # apic_aim MD's request_endpoint_details RPC handler to add or
        # update details within the RPC response, using data stored in
        # info by query_endpoint_rpc_info.

        # First, make sure the port is owned by a PolicyTarget before
        # continuing.
        pt_info = info.get('gbp_pt_info')
        if not pt_info:
            return
        gbp_details = details['gbp_details']

        # Replace EPG identity if not auto_ptg.
        if not pt_info.is_auto_ptg:
            gbp_details['app_profile_name'] = (
                self.name_mapper.application_policy_group(
                    None, pt_info.apg_id) if pt_info.apg_id
                else self.aim_mech_driver.ap_name)
            gbp_details['endpoint_group_name'] = pt_info.ptg_id
            gbp_details['ptg_tenant'] = (
                self.name_mapper.project(None, pt_info.l3p_project_id))

        # Update subnet gateway_ip and default_routes if needed.
        if not pt_info.inject_default_route:
            for subnet in gbp_details['subnets']:
                del subnet['gateway_ip']
                subnet['host_routes'] = [
                    r for r in subnet['host_routes']
                    if r['destination'] not in
                    [md_const.IPV4_ANY_CIDR, md_const.IPV4_METADATA_CIDR]]

        # Add segmentation labels.
        gbp_details['segmentation_labels'] = (
            info.get('gbp_segmentation_labels'))

        # REVISIT: If/when support for the proxy_group extension is
        # added to the aim_mapping PD, update promiscuous_mode to True
        # if this PT has a cluster_id that identifies a different PT
        # whose group_default_gateway set.
