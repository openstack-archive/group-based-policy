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

from neutron.api.v2 import attributes as attr
from neutron.common import exceptions as n_exc
from neutron.db import db_base_plugin_v2
from neutron.db import model_base
from neutron.db import models_v2


class ImplicitSubnetpool(model_base.BASEV2):
    __tablename__ = "implicit_subnetpools"
    subnetpool_id = sa.Column(sa.String(36),
                              sa.ForeignKey('subnetpools.id',
                                            ondelete="CASCADE"),
                              primary_key=True)
    is_implicit = sa.Column(sa.Boolean, nullable=False,
                            server_default=sql.false())
    subnetpool = orm.relationship(
        models_v2.SubnetPool,
        backref=orm.backref("implicit",
                            lazy="joined", cascade="delete"))


class ImplicitSubnetpoolMixin(object):
    """Mixin class for implicit subnetpool."""

    def get_implicit_subnetpool_id(self, context, tenant=None, ip_version="4"):
        pool = self.get_implicit_subnetpool(context, tenant=tenant,
                                            ip_version=ip_version)
        return pool['id'] if pool else None

    def get_implicit_subnetpool(self, context, tenant=None, ip_version="4"):
        pools = self._get_implicit_subnetpools(context, tenant=tenant,
                                               ip_version=ip_version)
        return pools[0] if pools else None

    def _get_implicit_subnetpools(self, context, tenant=None, ip_version="4"):
        admin_context = context.elevated()
        filters = {"is_implicit": [True],
                   "ip_version": [ip_version]}
        if tenant:
            filters["tenant_id"] = [tenant]
        else:
            filters["shared"] = [True]
        with context.session.begin(subtransactions=True):
            return self.get_subnetpools(admin_context, filters)

    def _get_implicit_subnetpool(self, context, subnetpool_id):
        return (context.session.query(ImplicitSubnetpool).
                filter_by(subnetpool_id=subnetpool_id)).first()

    def _subnetpool_model_hook(self, context, original_model, query):
        query = query.outerjoin(ImplicitSubnetpool,
                                (original_model.id ==
                                 ImplicitSubnetpool.subnetpool_id))
        return query

    def _subnetpool_filter_hook(self, context, original_model, conditions):
        return conditions

    def _subnetpool_result_filter_hook(self, query, filters):
        vals = filters and filters.get('is_implicit', [])
        if not vals:
            return query
        return query.filter(
            (ImplicitSubnetpool.is_implicit.in_(vals)))

    db_base_plugin_v2.NeutronDbPluginV2.register_model_query_hook(
        models_v2.SubnetPool,
        "implicit_subnetpool",
        '_subnetpool_model_hook',
        '_subnetpool_filter_hook',
        '_subnetpool_result_filter_hook')

    def _extend_subnetpool_dict_implicit(self, subnetpool_res,
                                         subnetpool_db):
        try:
            subnetpool_res["is_implicit"] = (
                subnetpool_db.implicit[0].is_implicit)
        except (IndexError, AttributeError):
            # is_implicit is not created yet when subnetpool is first added
            # to the database
            pass
        return subnetpool_res

    # Register dict extend functions for ports
    db_base_plugin_v2.NeutronDbPluginV2.register_dict_extend_funcs(
        attr.SUBNETPOOLS, ['_extend_subnetpool_dict_implicit'])

    def update_implicit_subnetpool(self, context, subnetpool):
        is_implicit = False
        if attr.is_attr_set(subnetpool.get('is_implicit')):
            is_implicit = subnetpool['is_implicit']
        with context.session.begin(subtransactions=True):
            if is_implicit:
                # Verify feasibility. Only one implicit SP must exist per
                # tenant (or global)
                msg = _('There can be at most one implicit '
                        'subnetpool per address family per tenant.')
                self._validate_implicit_subnetpool(
                    context, subnetpool['id'], tenant=subnetpool['tenant_id'],
                    msg=msg, ip_version=subnetpool['ip_version'])
                if subnetpool['shared']:
                    # Check globally too
                    msg = _('There can be at most one global implicit '
                            'subnetpool per address family.')
                    self._validate_implicit_subnetpool(
                        context, subnetpool['id'],
                        tenant=None,
                        msg=msg, ip_version=subnetpool['ip_version'])
            db_obj = self._get_implicit_subnetpool(
                context, subnetpool['id'])
            if db_obj:
                db_obj.is_implicit = is_implicit
            db_obj = db_obj or ImplicitSubnetpool(
                subnetpool_id=subnetpool['id'],
                is_implicit=is_implicit)
            context.session.add(db_obj)
        return is_implicit

    def _validate_implicit_subnetpool(self, context, subnetpool_id,
                                      tenant=None, msg=None, ip_version="4"):
        current_implicit_sp = self._get_implicit_subnetpools(
            context, tenant=tenant, ip_version=ip_version)
        if len(current_implicit_sp) > 1:
            raise n_exc.BadRequest(resource='subnetpools', msg=msg)
        if (len(current_implicit_sp) == 1 and
                current_implicit_sp[0]['id'] != subnetpool_id):
            raise n_exc.BadRequest(resource='subnetpools', msg=msg)
