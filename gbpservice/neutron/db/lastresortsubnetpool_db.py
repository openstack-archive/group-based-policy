# Copyright 2013 VMware, Inc.  All rights reserved.
#
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
#

import sqlalchemy as sa

from sqlalchemy import orm
from sqlalchemy import sql
from sqlalchemy.sql import expression as expr

from neutron.api.v2 import attributes as attr
from neutron.db import db_base_plugin_v2
from neutron.db import model_base
from neutron.db import models_v2


class LastResortSubnetpool(model_base.BASEV2):
    __tablename__ = "last_resort_subnetpools"
    subnetpool_id = sa.Column(sa.String(36),
                              sa.ForeignKey('subnetpools.id',
                                            ondelete="CASCADE"),
                              primary_key=True)
    is_last_resort = sa.Column(sa.Boolean, nullable=False,
                               server_default=sql.false())
    subnetpool = orm.relationship(
        models_v2.SubnetPool,
        backref=orm.backref("last_resort",
                            lazy="joined", cascade="delete"))


class LastResortSubnetpoolMixin(object):
    """Mixin class for last resort subnetpool."""

    def get_subnetpool_of_last_resort(self, context, tenant=None):
        pools = self._get_subnetpools_of_last_resort(context, tenant=tenant)
        return pools[0] if pools else None

    def _get_subnetpools_of_last_resort(self, context, tenant=None):
        filters = {"is_last_resort": [True]}
        if tenant:
            filters["tenant_id"] = [tenant]
        else:
            filters["shared"] = [True]
        with context.session.begin(subtransactions=True):
            return self.get_subnetpools(context, filters)

    def _get_last_resort_subnetpool(self, context, subnetpool_id):
        return (context.session.query(LastResortSubnetpool).
                filter_by(subnetpool_id=subnetpool_id)).first()

    def _subnetpool_model_hook(self, context, original_model, query):
        query = query.outerjoin(LastResortSubnetpool,
                                (original_model.id ==
                                 LastResortSubnetpool.subnetpool_id))
        return query

    def _subnetpool_filter_hook(self, context, original_model, conditions):
        return conditions

    def _subnetpool_result_filter_hook(self, query, filters):
        vals = filters and filters.get('is_last_resort', [])
        if not vals:
            return query
        return query.filter(
            (LastResortSubnetpool.is_last_resort.in_(vals)))

    db_base_plugin_v2.NeutronDbPluginV2.register_model_query_hook(
        models_v2.SubnetPool,
        "last_resort_subnetpool",
        '_subnetpool_model_hook',
        '_subnetpool_filter_hook',
        '_subnetpool_result_filter_hook')

    def _extend_port_dict_last_resort_subnetpool(self, subnetpool_res,
                                                 subnetpool_db):
        try:
            subnetpool_res["is_last_resort"] = (
                subnetpool_db.last_resort[0].is_last_resort)
        except (IndexError, AttributeError):
            # is_last_resort is not created yet when subnetpool is first added
            # to the database
            pass
        return subnetpool_res

    # Register dict extend functions for ports
    db_base_plugin_v2.NeutronDbPluginV2.register_dict_extend_funcs(
        attr.SUBNETPOOLS, ['_extend_port_dict_last_resort_subnetpool'])

    def update_last_resort_subnetpool(self, context, subnetpool):
        is_last_resort = False
        if attr.is_attr_set(subnetpool.get('is_last_resort')):
            is_last_resort = subnetpool['is_last_resort']
        with context.session.begin(subtransactions=True):
            if is_last_resort:
                # Verify feasibility. Only one last resort SP must exist per
                # tenant (or global)
                current_last_resort_sp = self._get_subnetpools_of_last_resort(
                    context, tenant=subnetpool['tenant_id'])
                if len(current_last_resort_sp) > 1:
                    raise
                if subnetpool['shared']:
                    # Check globally too
                    current_last_resort_sp = (
                        self._get_subnetpools_of_last_resort(context))
                    if len(current_last_resort_sp) > 1:
                        raise

            db_obj = self._get_last_resort_subnetpool(
                context, subnetpool['id'])
            if db_obj:
                db_obj.is_last_resort = is_last_resort
            db_obj = db_obj or LastResortSubnetpool(
                subnetpool_id=subnetpool['id'],
                is_last_resort=is_last_resort)
            context.session.add(db_obj)
        return is_last_resort
