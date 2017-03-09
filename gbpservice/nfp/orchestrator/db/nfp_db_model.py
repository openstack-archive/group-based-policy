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

from neutron_lib.db import model_base
import sqlalchemy as sa
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import orm

from gbpservice.nfp.common import constants as nfp_constants

TENANT_ID_MAX_LEN = 255
DESCRIPTION_MAX_LEN = 4096


class HasStatus(object):
    """status mixin, add to subclasses that have a status."""

    status = sa.Column(sa.String(16), nullable=False, index=True)


class HasStatusDescription(HasStatus):
    """Status with description mixin."""

    status_description = sa.Column(sa.String(DESCRIPTION_MAX_LEN))


BASE = declarative_base(cls=model_base.NeutronBaseV2)


class PortInfo(BASE, model_base.HasId, model_base.HasProject):
    """Represents the Port Information"""
    __tablename__ = 'nfp_port_infos'

    port_model = sa.Column(sa.Enum(nfp_constants.NEUTRON_PORT,
                                   nfp_constants.GBP_PORT,
                                   name='port_model'))
    port_classification = sa.Column(sa.Enum(nfp_constants.PROVIDER,
                                            nfp_constants.CONSUMER,
                                            nfp_constants.MANAGEMENT,
                                            nfp_constants.MONITOR,
                                            name='port_classification'))
    port_role = sa.Column(sa.Enum(nfp_constants.ACTIVE_PORT,
                                  nfp_constants.STANDBY_PORT,
                                  nfp_constants.MASTER_PORT,
                                  name='port_role'),
                          nullable=True)


class NetworkInfo(BASE, model_base.HasId, model_base.HasProject):
    """Represents the Network Service Instance"""
    __tablename__ = 'nfp_network_infos'

    network_model = sa.Column(sa.Enum(nfp_constants.NEUTRON_NETWORK,
                                      nfp_constants.GBP_NETWORK,
                                      name='network_model'),
                              nullable=False)


class NSIPortAssociation(BASE):
    """One to many relation between NSIs and DataPorts."""
    __tablename__ = 'nfp_nfi_dataport_associations'

    network_function_instance_id = sa.Column(
        sa.String(36),
        sa.ForeignKey('nfp_network_function_instances.id'), primary_key=True)
    data_port_id = sa.Column(sa.String(36),
                             sa.ForeignKey('nfp_port_infos.id',
                                           ondelete='CASCADE'),
                             primary_key=True)


class NetworkFunctionInstance(BASE, model_base.HasId, model_base.HasProject,
                              HasStatusDescription):
    """Represents the Network Function Instance"""
    __tablename__ = 'nfp_network_function_instances'

    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(255))
    ha_state = sa.Column(sa.String(255))
    network_function_id = sa.Column(
        sa.String(36),
        sa.ForeignKey('nfp_network_functions.id', ondelete="SET NULL"),
        nullable=True)
    network_function_device_id = sa.Column(
        sa.String(36),
        sa.ForeignKey('nfp_network_function_devices.id', ondelete="SET NULL"),
        nullable=True)
    port_info = orm.relationship(
        NSIPortAssociation,
        cascade='all, delete-orphan')


class NetworkFunction(BASE, model_base.HasId, model_base.HasProject,
                      HasStatusDescription):
    """Represents the Network Function object"""
    __tablename__ = 'nfp_network_functions'

    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(1024))
    service_id = sa.Column(sa.String(36), nullable=False)
    service_chain_id = sa.Column(sa.String(36), nullable=True)
    service_profile_id = sa.Column(sa.String(36), nullable=False)
    service_config = sa.Column(sa.TEXT)
    config_policy_id = sa.Column(sa.String(36), nullable=True)
    network_function_instances = orm.relationship(
        NetworkFunctionInstance,
        backref='network_function')


class NetworkFunctionDevice(BASE, model_base.HasId, model_base.HasProject,
                            HasStatusDescription):
    """Represents the Network Function Device"""
    __tablename__ = 'nfp_network_function_devices'

    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(255))
    mgmt_ip_address = sa.Column(sa.String(36), nullable=True)
    mgmt_port_id = sa.Column(sa.String(36),
                             sa.ForeignKey('nfp_port_infos.id',
                                           ondelete='SET NULL'),
                             nullable=True)
    monitoring_port_id = sa.Column(sa.String(36),
                                   sa.ForeignKey('nfp_port_infos.id',
                                                 ondelete='SET NULL'),
                                   nullable=True)
    monitoring_port_network = sa.Column(sa.String(36),
                                        sa.ForeignKey('nfp_network_infos.id',
                                                      ondelete='SET NULL'),
                                        nullable=True)
    service_vendor = sa.Column(sa.String(36), nullable=False, index=True)
    max_interfaces = sa.Column(sa.Integer(), nullable=False)
    reference_count = sa.Column(sa.Integer(), nullable=False)
    interfaces_in_use = sa.Column(sa.Integer(), nullable=False)
    provider_metadata = sa.Column(sa.String(1024), nullable=True)
    gateway_port = sa.Column(sa.String(36), nullable=True)


class ClusterInfo(BASE, model_base.HasId, model_base.HasProject):
    """
    This table contains info about the ports participating in
    cluster and optional.
    """
    __tablename__ = 'nfd_cluster_mapping_info'
    network_function_device_id = sa.Column(sa.String(36), nullable=False)
    cluster_group = sa.Column(sa.Integer(), nullable=True)
    virtual_ip = sa.Column(sa.String(36), nullable=True)
    multicast_ip = sa.Column(sa.String(36), nullable=True)
    cluster_name = sa.Column(sa.String(36), nullable=True)


class ServiceGatewayDetails(BASE, model_base.HasId):
    __tablename__ = 'nfp_service_gateway_info'
    network_function_id = sa.Column(sa.String(36), sa.ForeignKey(
        'nfp_network_functions.id', ondelete='CASCADE'), nullable=False,
        primary_key=True)
    gateway_ptg = sa.Column(sa.String(36), nullable=False)
    primary_instance_gw_pt = sa.Column(sa.String(36), nullable=True)
    secondary_instance_gw_pt = sa.Column(sa.String(36), nullable=True)
    primary_gw_vip_pt = sa.Column(sa.String(36), nullable=True)
    secondary_gw_vip_pt = sa.Column(sa.String(36), nullable=True)


class ServiceNodeInstanceNetworkFunctionMapping(BASE, model_base.BASEV2):
    """ServiceChainInstance to NFP network function mapping."""

    __tablename__ = 'ncp_node_instance_network_function_mappings'
    sc_instance_id = sa.Column(sa.String(36),
                               nullable=False, primary_key=True)
    sc_node_id = sa.Column(sa.String(36),
                           nullable=False, primary_key=True)
    network_function_id = sa.Column(sa.String(36), nullable=True)
    status = sa.Column(sa.String(50), nullable=True)
    status_details = sa.Column(sa.String(4096), nullable=True)
