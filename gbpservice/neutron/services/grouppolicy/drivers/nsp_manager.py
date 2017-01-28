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

from neutron_lib.db import model_base
import sqlalchemy as sa


class ServicePolicyPTGIpAddressMapping(model_base.BASEV2):
    """Service Policy to IP Address mapping DB."""

    __tablename__ = 'gpm_service_policy_ipaddress_mappings'
    service_policy_id = sa.Column(
        sa.String(36), sa.ForeignKey('gp_network_service_policies.id'),
        nullable=False, primary_key=True)
    policy_target_group = sa.Column(
        sa.String(36), sa.ForeignKey('gp_policy_target_groups.id'),
        nullable=False, primary_key=True)
    ipaddress = sa.Column(sa.String(36))


class ServicePolicyPTGFipMapping(model_base.BASEV2):
    """Service Policy to FIP Address mapping DB."""

    __tablename__ = 'gpm_service_policy_fip_mappings'
    service_policy_id = sa.Column(
        sa.String(36), sa.ForeignKey('gp_network_service_policies.id',
                                     ondelete='CASCADE'),
        nullable=False, primary_key=True)
    policy_target_group_id = sa.Column(
        sa.String(36), sa.ForeignKey('gp_policy_target_groups.id',
                                     ondelete='CASCADE'),
        nullable=False, primary_key=True)
    floatingip_id = sa.Column(sa.String(36),
                              sa.ForeignKey('floatingips.id',
                                     ondelete='CASCADE'),
                              nullable=False,
                              primary_key=True)


class PolicyTargetFloatingIPMapping(model_base.BASEV2):
    """Mapping of PolicyTarget to Floating IP."""
    __tablename__ = 'gpm_pt_floatingip_mappings'
    policy_target_id = sa.Column(
        sa.String(36), sa.ForeignKey('gp_policy_targets.id',
                                     ondelete='CASCADE'),
        nullable=False, primary_key=True)
    floatingip_id = sa.Column(sa.String(36),
                              sa.ForeignKey('floatingips.id',
                                            ondelete='CASCADE'),
                              nullable=False,
                              primary_key=True)


class ServicePolicyQosPolicyMapping(model_base.BASEV2):
    """Mapping of a NSP to a Neutron QoS Policy."""
    __tablename__ = 'gpm_qos_policy_mappings'
    service_policy_id = sa.Column(
        sa.String(36),
        sa.ForeignKey('gp_network_service_policies.id',
                      ondelete='CASCADE'),
        nullable=False,
        primary_key=True
    )
    qos_policy_id = sa.Column(
        sa.String(36),
        sa.ForeignKey('qos_policies.id',
                      ondelete='RESTRICT'),
        nullable=False
    )


class NetworkServicePolicyMappingMixin(object):

    def _set_policy_ipaddress_mapping(self, session, service_policy_id,
                                      policy_target_group, ipaddress):
        with session.begin(subtransactions=True):
            mapping = ServicePolicyPTGIpAddressMapping(
                service_policy_id=service_policy_id,
                policy_target_group=policy_target_group, ipaddress=ipaddress)
            session.add(mapping)

    def _get_ptg_policy_ipaddress_mapping(self, session, policy_target_group):
        with session.begin(subtransactions=True):
            return (session.query(ServicePolicyPTGIpAddressMapping).
                    filter_by(policy_target_group=policy_target_group).first())

    def _delete_policy_ipaddress_mapping(self, session, policy_target_group):
        with session.begin(subtransactions=True):
            ip_mapping = session.query(
                ServicePolicyPTGIpAddressMapping).filter_by(
                    policy_target_group=policy_target_group).first()
            if ip_mapping:
                session.delete(ip_mapping)

    def _set_ptg_policy_fip_mapping(self, session, service_policy_id,
                                policy_target_group_id, fip_id):
        with session.begin(subtransactions=True):
            mapping = ServicePolicyPTGFipMapping(
                service_policy_id=service_policy_id,
                policy_target_group_id=policy_target_group_id,
                floatingip_id=fip_id)
            session.add(mapping)

    def _get_ptg_policy_fip_mapping(self, session, policy_target_group_id):
        with session.begin(subtransactions=True):
            return (session.query(ServicePolicyPTGFipMapping).
                    filter_by(policy_target_group_id=policy_target_group_id).
                    all())

    def _delete_ptg_policy_fip_mapping(self, session, policy_target_group_id):
        with session.begin(subtransactions=True):
            mappings = session.query(
                ServicePolicyPTGFipMapping).filter_by(
                    policy_target_group_id=policy_target_group_id).all()
            for mapping in mappings:
                session.delete(mapping)

    def _set_pt_floating_ips_mapping(self, session, policy_target_id, fip_ids):
        with session.begin(subtransactions=True):
            for fip_id in fip_ids:
                mapping = PolicyTargetFloatingIPMapping(
                    policy_target_id=policy_target_id, floatingip_id=fip_id)
                session.add(mapping)

    def _set_pts_floating_ips_mapping(self, session, pt_fip_map):
        with session.begin(subtransactions=True):
            for policy_target_id in pt_fip_map:
                self._set_pt_floating_ips_mapping(
                    session, policy_target_id,
                    pt_fip_map[policy_target_id])

    def _get_pt_floating_ip_mapping(self, session, policy_target_id):
        with session.begin(subtransactions=True):
            return (session.query(PolicyTargetFloatingIPMapping).
                    filter_by(policy_target_id=policy_target_id).all())

    def _delete_pt_floating_ip_mapping(self, session, policy_target_id):
        with session.begin(subtransactions=True):
            fip_mappings = session.query(
                PolicyTargetFloatingIPMapping).filter_by(
                    policy_target_id=policy_target_id).all()
            for fip_mapping in fip_mappings:
                session.delete(fip_mapping)

    def _get_nsp_qos_mapping(self, session, service_policy_id):
        with session.begin(subtransactions=True):
            return (session.query(ServicePolicyQosPolicyMapping).
                    filter_by(service_policy_id=service_policy_id).first())

    def _set_nsp_qos_mapping(self, session, service_policy_id, qos_policy_id):
        with session.begin(subtransactions=True):
            mapping = ServicePolicyQosPolicyMapping(
                service_policy_id=service_policy_id,
                qos_policy_id=qos_policy_id)
            session.add(mapping)

    def _delete_nsp_qos_mapping(self, session, mapping):
        if mapping:
            with session.begin(subtransactions=True):
                session.delete(mapping)
