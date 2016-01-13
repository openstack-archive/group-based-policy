# Copyright (c) 2016 OpenStack Foundation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from oslo_db.sqlalchemy import models
from oslo_utils import uuidutils
import sqlalchemy as sa
from sqlalchemy.ext import declarative
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import orm


TENANT_ID_MAX_LEN = 255
DESCRIPTION_MAX_LEN = 255


class HasTenant(object):
    """Tenant mixin, add to subclasses that have a tenant."""

    tenant_id = sa.Column(sa.String(TENANT_ID_MAX_LEN), index=True)


class HasId(object):
    """id mixin, add to subclasses that have an id."""

    id = sa.Column(sa.String(36),
                   primary_key=True,
                   default=uuidutils.generate_uuid)


class HasStatus(object):
    """status mixin, add to subclasses that have a status."""

    status = sa.Column(sa.String(16), nullable=False, index=True)


class HasStatusDescription(HasStatus):
    """Status with description mixin."""

    status_description = sa.Column(sa.String(DESCRIPTION_MAX_LEN))


# Do we need anything to be overridden from modelBase ??
class ServiceManagerBase(models.ModelBase):
    """Base class for NSF Models."""

    __table_args__ = {'mysql_engine': 'InnoDB'}

    def __iter__(self):
        self._i = iter(orm.object_mapper(self).columns)
        return self

    def next(self):
        n = next(self._i).name
        return n, getattr(self, n)

    __next__ = next

    def __repr__(self):
        """sqlalchemy based automatic __repr__ method."""
        items = ['%s=%r' % (col.name, getattr(self, col.name))
                 for col in self.__table__.columns]
        return "<%s.%s[object at %x] {%s}>" % (self.__class__.__module__,
                                               self.__class__.__name__,
                                               id(self), ', '.join(items))

    @declarative.declared_attr
    def __tablename__(cls):
        return cls.__name__.lower() + 's'


BASE = declarative_base(cls=ServiceManagerBase)


class PortInfo(BASE, HasId, HasTenant):
    """Represents the Port Information"""
    __tablename__ = 'port_infos'

    port_policy = sa.Column(sa.String(36))  # neutron_port, gbp_policy_target
    port_classification = sa.Column(sa.String(36))  # provider/consumer
    port_type = sa.Column(sa.String(36))  # active/standby/master


class NetworkInfo(BASE, HasId, HasTenant):
    """Represents the Network Service Instance"""
    __tablename__ = 'network_infos'

    network_policy = sa.Column(sa.String(36))  # neutron_network, gbp_group


class NSIPortAssociation(BASE):
    """One to many relation between NSIs and DataPorts."""
    __tablename__ = 'nsi_dataport_associations'

    network_service_instance_id = sa.Column(
        sa.String(36),
        sa.ForeignKey('network_service_instances.id'), primary_key=True)
    data_port_id = sa.Column(sa.String(36),
                             sa.ForeignKey('port_infos.id'), primary_key=True)


class NSDPortAssociation(BASE):
    """One to many relation between NSDs and DataPorts."""
    __tablename__ = 'nsd_dataport_associations'

    network_service_device_id = sa.Column(
        sa.String(36),
        sa.ForeignKey('network_service_devices.id'), primary_key=True)
    data_port_id = sa.Column(sa.String(36),
                             sa.ForeignKey('port_infos.id'),
                             primary_key=True)


class NSDNetworkAssociation(BASE):
    """One to many relation between NSDs and DataNetworks."""
    __tablename__ = 'nsd_datanetwork_associations'

    network_service_device_id = sa.Column(
        sa.String(36),
        sa.ForeignKey('network_service_devices.id'), primary_key=True)
    data_network_id = sa.Column(sa.String(36),
                                sa.ForeignKey('network_infos.id'),
                                primary_key=True)


class NetworkServiceInstance(BASE, HasId, HasTenant, HasStatusDescription):
    """Represents the Network Service Instance"""
    __tablename__ = 'network_service_instances'

    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(255))
    ha_state = sa.Column(sa.String(255))
    network_service_id = sa.Column(
        sa.String(36),
        sa.ForeignKey('network_services.id', ondelete="SET NULL"),
        nullable=True)
    network_service_device_id = sa.Column(
        sa.String(36),
        sa.ForeignKey('network_service_devices.id', ondelete="SET NULL"),
        nullable=True)
    port_info = orm.relationship(
        NSIPortAssociation,
        backref='network_service_instance', cascade='all, delete-orphan')


class NetworkService(BASE, HasId, HasTenant, HasStatusDescription):
    """Represents the Network Service object"""
    __tablename__ = 'network_services'

    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(255))
    service_id = sa.Column(sa.String(36), nullable=False)
    service_chain_id = sa.Column(sa.String(36), nullable=True)
    service_profile_id = sa.Column(sa.String(36), nullable=False)
    service_config = sa.Column(sa.TEXT)
    heat_stack_id = sa.Column(sa.String(36), nullable=True)
    network_service_instances = orm.relationship(
        NetworkServiceInstance,
        backref='network_service_instance')


class NetworkServiceDevice(BASE, HasId, HasTenant, HasStatusDescription):
    """Represents the Network Service Device"""
    __tablename__ = 'network_service_devices'

    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(255))
    cluster_id = sa.Column(sa.String(36), nullable=True)
    mgmt_ip_address = sa.Column(sa.String(36), nullable=True)
    mgmt_data_ports = orm.relationship(
        NSDPortAssociation,
        backref='network_service_device_mgmt_ports',
        cascade='all, delete-orphan')
    ha_monitoring_data_port = sa.Column(sa.String(36),
                                        sa.ForeignKey('port_infos.id'),
                                        nullable=True)
    ha_monitoring_data_network = sa.Column(sa.String(36),
                                           sa.ForeignKey('network_infos.id'),
                                           nullable=True)
    service_vendor = sa.Column(sa.String(36), nullable=False, index=True)
    max_interfaces = sa.Column(sa.Integer(), nullable=False)
    reference_count = sa.Column(sa.Integer(), nullable=False)
    interfaces_in_use = sa.Column(sa.Integer(), nullable=False)
