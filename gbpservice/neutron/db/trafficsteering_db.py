# Copyright 2015, Instituto de Telecomunicacoes - Polo de Aveiro - ATNoG.
# All rights reserved.
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


import sqlalchemy as sa
from sqlalchemy.ext.orderinglist import ordering_list
from sqlalchemy import orm
from sqlalchemy.orm import exc

from neutron.common import log
from neutron.db import api as db
from neutron.db import db_base_plugin_v2 as base_db
from neutron.db import model_base
from neutron.db import models_v2
from neutron.openstack.common import uuidutils
from oslo_log import log as logging
from oslo_serialization import jsonutils

from gbpservice.neutron.extensions import trafficsteering as ts


LOG = logging.getLogger(__name__)


class PortChainSCIAssociation(model_base.BASEV2):
    """Models 1 to many relations between Port Chains and each SC Instance."""
    __tablename__ = 'sc_portchain_sci_mappings'
    servicechain_instance_id = sa.Column(sa.String(36),
                                         sa.ForeignKey('sc_instances.id'),
                                         primary_key=True)
    portchain_id = sa.Column(sa.String(36),
                             sa.ForeignKey('port_chains.id'),
                             primary_key=True)
    position = sa.Column(sa.Integer)


class PortChain(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Represents a Port Chain resource."""
    __tablename__ = 'ts_port_chains'
    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(1024))
    ports = sa.Column(sa.String(4096))
    sc_instances = orm.relationship(
        PortChainSCIAssociation,
        backref='portchains',
        cascade='all,delete, delete-orphan',
        order_by='PortChainSCIAssociation.position',
        collection_class=ordering_list('position', count_from=1))


class TrafficSteeringDbMixin(ts.TrafficSteeringPluginBase,
                             base_db.CommonDbMixin):
    """Mixin class for Traffic Steering DB implementation."""

    __native_bulk_support = False
    __native_pagination_support = True
    __native_sorting_support = True

    def __init__(self, *args, **kwargs):
        db.configure_db()
        super(TrafficSteeringDbMixin, self).__init__(*args, **kwargs)

    def _get_port_chain(self, context, id):
        try:
            return self._get_by_id(context, PortChain, id)
        except exc.NoResultFound:
            raise ts.PortChainNotFound(port_chain_id=id)

    def _get_min_max_ports_from_range(self, port_range):
        if not port_range:
            return [None, None]
        min_port, sep, max_port = port_range.partition(":")
        if not max_port:
            max_port = min_port
        return [int(min_port), int(max_port)]

    def _get_port_range_from_min_max_ports(self, min_port, max_port):
        if not min_port:
            return None
        if min_port == max_port:
            return str(min_port)
        else:
            return '%d:%d' % (min_port, max_port)

    def _make_port_chain_dict(self, c, fields=None):
        res = {'id': c['id'],
               'tenant_id': c['tenant_id'],
               'name': c['name'],
               'description': c['description'],
               'ports': jsonutils.loads(c['ports']),
               }
        res['steering_classifiers'] = [sc['steering_classifier_id']
                                       for sc in c['steering_classifiers']]
        return self._fields(res, fields)

    @log.log
    def create_port_chain(self, context, port_chain):
        c = port_chain['port_chain']
        tenant_id = self._get_tenant_id_for_create(context, c)
        with context.session.begin(subtransactions=True):
            chain_db = PortChain(id=uuidutils.generate_uuid(),
                                 tenant_id=tenant_id,
                                 name=c['name'],
                                 description=c['description'],
                                 ports=jsonutils.dumps(c['ports']))
            self._set_classifiers_for_port_chain(context, chain_db,
                                                 c['steering_classifiers'])
            context.session.add(chain_db)
        return self._make_port_chain_dict(chain_db)

    @log.log
    def update_port_chain(self, context, id, port_chain):
        pc = port_chain['port_chain']

        with context.session.begin(subtransactions=True):
            query = context.session.query(PortChain)
            chain_db = query.filter_by(id=id).first()

            chain_db.update(pc)

        return self._make_port_chain_dict(chain_db)

    @log.log
    def delete_port_chain(self, context, id):
        with context.session.begin(subtransactions=True):
            c_db = context.session.query(PortChain).filter_by(id=id).first()
            context.session.delete(c_db)

    @log.log
    def get_port_chain(self, context, id, fields=None):
        c_db = self._get_port_chain(context, id)
        return self._make_port_chain_dict(c_db, fields)

    @log.log
    def get_port_chains(self, context, filters=None, fields=None):
        return self._get_collection(context, PortChain,
                                    self._make_port_chain_dict,
                                    filters=filters, fields=fields)