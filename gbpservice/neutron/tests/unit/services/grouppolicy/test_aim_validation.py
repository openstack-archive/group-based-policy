# Copyright (c) 2017 Cisco Systems Inc.
# All Rights Reserved.
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

import copy

from aim.aim_lib.db import model as aim_lib_model
from aim.api import infra as aim_infra
from aim.api import resource as aim_resource
from aim import context as aim_context
from neutron import context as n_context
from neutron.db import segments_db as segment
from neutron.plugins.ml2 import models as ml2_models
from neutron.tests.unit.extensions import test_securitygroup
from neutron_lib import constants as n_constants
from oslo_config import cfg
import webob.exc

from gbpservice.neutron.db.grouppolicy import group_policy_db as gpdb
from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import (
    extension_db as ext_db)
from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import db
from gbpservice.neutron.services.grouppolicy import (
    group_policy_driver_api as api)
from gbpservice.neutron.services.grouppolicy.drivers.cisco.apic import (
    aim_validation as av)
from gbpservice.neutron.tests.unit.services.grouppolicy import (
    test_aim_mapping_driver)
from gbpservice.neutron.tests.unit.services.sfc import test_aim_sfc_driver


class AimValidationTestMixin(object):

    def _validate(self):
        # Validate should pass.
        self.assertEqual(api.VALIDATION_PASSED, self.av_mgr.validate())

    def _validate_repair_validate(self):
        # Validate should fail.
        self.assertEqual(
            api.VALIDATION_FAILED_REPAIRABLE, self.av_mgr.validate())

        # Repair.
        self.assertEqual(
            api.VALIDATION_REPAIRED, self.av_mgr.validate(repair=True))

        # Validate should pass.
        self.assertEqual(api.VALIDATION_PASSED, self.av_mgr.validate())

    def _validate_unrepairable(self):
        # Repair should fail.
        self.assertEqual(
            api.VALIDATION_FAILED_UNREPAIRABLE,
            self.av_mgr.validate(repair=True))

    def _validate_fails_binding_ports(self):
        # Repair should fail.
        self.assertEqual(
            api.VALIDATION_FAILED_BINDING_PORTS,
            self.av_mgr.validate(repair=True))

    def _test_aim_resource(self, resource, unexpected_attr_name='name',
                           unexpected_attr_value='unexpected',
                           test_unexpected_monitored=True):
        resource = copy.copy(resource)

        # Make sure the AIM resource exists.
        actual_resource = self.aim_mgr.get(self.aim_ctx, resource)
        self.assertIsNotNone(actual_resource)

        # Only test deleting and modifying if not monitored.
        if not actual_resource.monitored:
            # Delete the AIM resource and test.
            self.aim_mgr.delete(self.aim_ctx, resource)
            self._validate_repair_validate()
            self.assertTrue(
                actual_resource.user_equal(
                    self.aim_mgr.get(self.aim_ctx, resource)))

            # Modify the AIM resource and test.
            self.aim_mgr.update(
                self.aim_ctx, resource, display_name='not what it was')
            self._validate_repair_validate()
            self.assertTrue(
                actual_resource.user_equal(
                    self.aim_mgr.get(self.aim_ctx, resource)))

        # Add unexpected AIM resource and test.
        setattr(resource, unexpected_attr_name, unexpected_attr_value)
        self.aim_mgr.create(self.aim_ctx, resource)
        self._validate_repair_validate()

        if test_unexpected_monitored:
            # Add unexpected monitored AIM resource and test.
            resource.monitored = True
            self.aim_mgr.create(self.aim_ctx, resource)
            self._validate()

            # Delete unexpected monitored AIM resource.
            self.aim_mgr.delete(self.aim_ctx, resource)


class AimValidationTestCase(test_aim_mapping_driver.AIMBaseTestCase,
                            test_securitygroup.SecurityGroupsTestCase,
                            AimValidationTestMixin):

    def setUp(self):
        super(AimValidationTestCase, self).setUp()
        self.av_mgr = av.ValidationManager()
        self.aim_ctx = aim_context.AimContext(self.db_session)


class TestNeutronMapping(AimValidationTestCase):

    def setUp(self):
        super(TestNeutronMapping, self).setUp()

    def _test_routed_subnet(self, subnet_id, gw_ip):
        # Get the AIM Subnet.
        subnet = self._show('subnets', subnet_id)['subnet']
        sn_dn = subnet['apic:distinguished_names'][gw_ip]
        sn = aim_resource.Subnet.from_dn(sn_dn)

        # Test the AIM Subnet.
        self._test_aim_resource(sn, 'gw_ip_mask', '4.3.2.1/24')

    def _test_unscoped_vrf(self, router_id):
        # Get the router's unscoped AIM VRF.
        router = self._show('routers', router_id)['router']
        vrf_dn = router['apic:distinguished_names']['no_scope-VRF']
        vrf = aim_resource.VRF.from_dn(vrf_dn)

        # Test the AIM VRF.
        self._test_aim_resource(vrf)

    def test_static_resources(self):
        # Validate with initial static resources.
        self._validate()

        # Delete the common Tenant and test.
        tenant = aim_resource.Tenant(name='common')
        self.aim_mgr.delete(self.aim_ctx, tenant)
        self._validate_repair_validate()

        # Test unrouted AIM VRF.
        vrf = aim_resource.VRF(
            name=self.driver.aim_mech_driver.apic_system_id + '_UnroutedVRF',
            tenant_name='common')
        self._test_aim_resource(vrf)

        # Test the any Filter.
        filter_name = (self.driver.aim_mech_driver.apic_system_id +
                       '_AnyFilter')
        filter = aim_resource.Filter(
            name=filter_name,
            tenant_name='common')
        self._test_aim_resource(filter)

        # Test the any FilterEntry.
        entry = aim_resource.FilterEntry(
            name='AnyFilterEntry',
            filter_name=filter_name,
            tenant_name='common')
        self._test_aim_resource(entry)

        # Test the default SecurityGroup.
        sg_name = (self.driver.aim_mech_driver.apic_system_id +
                   '_DefaultSecurityGroup')
        sg = aim_resource.SecurityGroup(
            name=sg_name,
            tenant_name='common')
        self._test_aim_resource(sg)

        # Test the default SecurityGroupSubject.
        sg_subject = aim_resource.SecurityGroupSubject(
            name='default',
            security_group_name=sg_name,
            tenant_name='common')
        self._test_aim_resource(sg_subject)

        # Test one default SecurityGroupRule.
        sg_rule = aim_resource.SecurityGroupRule(
            name='arp_egress',
            security_group_subject_name='default',
            security_group_name=sg_name,
            tenant_name='common')
        self._test_aim_resource(sg_rule)

    def _test_project_resources(self, project_id):
        # Validate with initial project resources.
        self._validate()

        # Test AIM Tenant.
        tenant_name = self.driver.aim_mech_driver.name_mapper.project(
            None, project_id)
        tenant = aim_resource.Tenant(name=tenant_name)
        self._test_aim_resource(tenant)

        # Test AIM ApplicationProfile.
        ap = aim_resource.ApplicationProfile(
            tenant_name=tenant_name, name='OpenStack')
        self._test_aim_resource(ap)

    def test_project_resources(self):
        # REVISIT: Currently, a project's AIM Tenant and
        # ApplicationProfile are created in ensure_tenant just before
        # any Neutron/GBP resource is created using that project, and
        # are not cleaned up when the last Neutron/GBP resource
        # needing them is deleted. Instead, they are cleaned up when a
        # notification is received from Keystone that the project has
        # been deleted. We should consider managing these AIM
        # resources more dynamically. If we do, this test will need to
        # be reworked.

        # Test address scope.
        scope = self._make_address_scope(
            self.fmt, 4, name='as1', tenant_id='as_proj')['address_scope']
        self._test_project_resources(scope['project_id'])

        # Test network.
        net_resp = self._make_network(
            self.fmt, 'net1', True, tenant_id='net_proj')
        net = net_resp['network']
        self._test_project_resources(net['project_id'])

        # Test subnet.
        subnet = self._make_subnet(
            self.fmt, net_resp, '10.0.1.1', '10.0.1.0/24',
            tenant_id='subnet_proj')['subnet']
        self._test_project_resources(subnet['project_id'])

        # Test port. Since Neutron creates the default SG for the
        # port's project even when security_groups=[] is passed, we
        # need to delete the default SG to ensure the port is the only
        # resource owned by port_prog.
        port = self._make_port(
            self.fmt, net['id'], security_groups=[],
            tenant_id='port_proj')['port']
        sgs = self._list(
            'security-groups',
            query_params='project_id=port_proj')['security_groups']
        self.assertEqual(1, len(sgs))
        self._delete('security-groups', sgs[0]['id'])
        self._test_project_resources(port['project_id'])

        # Test security group.
        sg = self._make_security_group(
            self.fmt, 'sg1', 'desc1', tenant_id='sg_proj')['security_group']
        self._test_project_resources(sg['project_id'])

        # Test subnetpool.
        sp = self._make_subnetpool(
            self.fmt, ['10.0.0.0/8'], name='sp1', tenant_id='sp_proj',
            default_prefixlen=24)['subnetpool']
        self._test_project_resources(sp['project_id'])

        # Test router.
        router = self._make_router(
            self.fmt, 'router_proj', 'router1')['router']
        self._test_project_resources(router['project_id'])

        # Test floatingip.
        kwargs = {'router:external': True}
        ext_net_resp = self._make_network(
            self.fmt, 'ext_net', True, arg_list=self.extension_attributes,
            **kwargs)
        ext_net = ext_net_resp['network']
        self._make_subnet(
            self.fmt, ext_net_resp, '100.100.100.1', '100.100.100.0/24')
        fip = self._make_floatingip(
            self.fmt, ext_net['id'], tenant_id='fip_proj')['floatingip']
        self._test_project_resources(fip['project_id'])

    def test_address_scope(self):
        # Create address scope.
        scope4 = self._make_address_scope(
            self.fmt, 4, name='as4')['address_scope']
        scope4_id = scope4['id']
        vrf_dn = scope4['apic:distinguished_names']['VRF']
        self._validate()

        # Delete the address scope's mapping record and test.
        (self.db_session.query(db.AddressScopeMapping).
         filter_by(scope_id=scope4_id).
         delete())
        self._validate_repair_validate()

        # Test AIM VRF.
        vrf = aim_resource.VRF.from_dn(vrf_dn)
        self._test_aim_resource(vrf)

        # Create isomorphic v6 address scope.
        scope6 = self._make_address_scope_for_vrf(
            vrf_dn, n_constants.IP_VERSION_6, name='as6')['address_scope']
        scope6_id = scope6['id']
        self.assertEqual(vrf_dn, scope6['apic:distinguished_names']['VRF'])
        self._validate()

        # Test AIM VRF.
        self._test_aim_resource(vrf)

        # Delete the initial address scope's mapping record and test.
        (self.db_session.query(db.AddressScopeMapping).
         filter_by(scope_id=scope4_id).
         delete())
        self._validate_repair_validate()
        scope4 = self._show('address-scopes', scope4_id)['address_scope']
        self.assertEqual(vrf_dn, scope4['apic:distinguished_names']['VRF'])
        scope6 = self._show('address-scopes', scope6_id)['address_scope']
        self.assertEqual(vrf_dn, scope6['apic:distinguished_names']['VRF'])

        # Test AIM VRF.
        self._test_aim_resource(vrf)

        # Delete the 2nd address scope's mapping record and
        # test. Without this record, there is no way to know that the
        # scopes were previously isomorphic, so they no longer will
        # be isomorphic after repair.
        (self.db_session.query(db.AddressScopeMapping).
         filter_by(scope_id=scope6_id).
         delete())
        self._validate_repair_validate()
        scope4 = self._show('address-scopes', scope4_id)['address_scope']
        self.assertEqual(vrf_dn, scope4['apic:distinguished_names']['VRF'])
        scope6 = self._show('address-scopes', scope6_id)['address_scope']
        scope6_vrf_dn = scope6['apic:distinguished_names']['VRF']
        self.assertNotEqual(vrf_dn, scope6_vrf_dn)

        # Test both AIM VRFs.
        self._test_aim_resource(vrf)
        scope6_vrf = aim_resource.VRF.from_dn(scope6_vrf_dn)
        self._test_aim_resource(scope6_vrf)

    def _test_network_attrs(self, original):
        current = self._show('networks', original['id'])['network']
        self.assertDictEqual(original, current)

    def _test_network_resources(self, net_resp):
        net = net_resp['network']
        net_id = net['id']
        bd_dn = net['apic:distinguished_names']['BridgeDomain']
        epg_dn = net['apic:distinguished_names']['EndpointGroup']

        # Create unrouted subnet.
        subnet = self._make_subnet(
            self.fmt, net_resp, '10.0.2.1', '10.0.2.0/24')['subnet']
        subnet_id = subnet['id']
        self._validate()
        net = self._show('networks', net['id'])['network']

        # Delete the network's mapping record and test.
        (self.db_session.query(db.NetworkMapping).
         filter_by(network_id=net_id).
         delete())
        self._validate_repair_validate()
        self._test_network_attrs(net)

        # Corrupt the network's mapping record's BD and test.
        with self.db_session.begin():
            mapping = (self.db_session.query(db.NetworkMapping).
                       filter_by(network_id=net_id).
                       one())
            mapping.bd_tenant_name = 'bad_bd_tenant_name'
        self._validate_repair_validate()
        self._test_network_attrs(net)

        # Corrupt the network's mapping record's EPG and test.
        with self.db_session.begin():
            mapping = (self.db_session.query(db.NetworkMapping).
                       filter_by(network_id=net_id).
                       one())
            mapping.epg_app_profile_name = 'bad_epg_app_profilename'
        self._validate_repair_validate()
        self._test_network_attrs(net)

        # Corrupt the network's mapping record's VRF and test.
        with self.db_session.begin():
            mapping = (self.db_session.query(db.NetworkMapping).
                       filter_by(network_id=net_id).
                       one())
            mapping.vrf_name = 'bad_vrf_name'
        self._validate_repair_validate()
        self._test_network_attrs(net)

        # Test AIM BridgeDomain.
        bd = aim_resource.BridgeDomain.from_dn(bd_dn)
        self._test_aim_resource(bd)

        # Test AIM EndpointGroup.
        epg = aim_resource.EndpointGroup.from_dn(epg_dn)
        self._test_aim_resource(epg)

        # Test AIM Subnet.
        if not net['router:external']:
            # Add unexpect AIM Subnet if not external.
            sn = self.driver.aim_mech_driver._map_subnet(
                subnet, '10.0.2.1', bd)
            self.aim_mgr.create(self.aim_ctx, sn)
            self._validate_repair_validate()
        else:
            # Test AIM Subnet if external.
            #
            # REVISIT: If Subnet DN were included in
            # apic:distinguished_names, which it should be, could just
            # use _test_routed_subnet().
            #
            sn = aim_resource.Subnet(
                tenant_name = bd.tenant_name,
                bd_name = bd.name,
                gw_ip_mask='10.0.2.1/24')
            self._test_aim_resource(sn, 'gw_ip_mask', '10.0.3.1/24')

        # Delete subnet extension data and test migration use case.
        (self.db_session.query(ext_db.SubnetExtensionDb).
         filter_by(subnet_id=subnet_id).
         delete())
        self._validate_repair_validate()

        return net

    def test_unrouted_network(self):
        # Create network.
        net_resp = self._make_network(self.fmt, 'net1', True)
        net = net_resp['network']
        net_id = net['id']
        self._validate()

        # Test AIM resources.
        net = self._test_network_resources(net_resp)

        # Delete network extension data and test migration use case.
        (self.db_session.query(ext_db.NetworkExtensionDb).
         filter_by(network_id=net_id).
         delete())
        self._validate_repair_validate()
        self._test_network_attrs(net)

    def _test_external_network(self, vrf_name='openstack_EXT-l1'):
        # Create AIM HostDomainMappingV2.
        hd_mapping = aim_infra.HostDomainMappingV2(
            host_name='*', domain_name='vm2', domain_type='OpenStack')
        self.aim_mgr.create(self.aim_ctx, hd_mapping)

        # Create external network.
        kwargs = {'router:external': True,
                  'apic:distinguished_names':
                  {'ExternalNetwork': 'uni/tn-common/out-l1/instP-n1'}}
        net_resp = self._make_network(
            self.fmt, 'ext_net', True, arg_list=self.extension_attributes,
            **kwargs)
        net = net_resp['network']
        self._validate()

        # Test standard network AIM resources.
        net = self._test_network_resources(net_resp)

        # Test AIM L3Outside.
        l3out = aim_resource.L3Outside(tenant_name='common', name='l1')
        self._test_aim_resource(l3out)
        self._test_network_attrs(net)

        # Test AIM ExternalNetwork.
        en = aim_resource.ExternalNetwork(
            tenant_name='common', l3out_name='l1', name='n1')
        self._test_aim_resource(en)
        self._test_network_attrs(net)

        # Test AIM ExternalSubnet. Note that the NAT strategy code
        # will try to delete unexpected ExternalSubnets even if they
        # are monitored, so we skip that test.
        esn = aim_resource.ExternalSubnet(
            tenant_name='common', l3out_name='l1', external_network_name='n1',
            cidr='0.0.0.0/0')
        self._test_aim_resource(esn, 'cidr', '1.2.3.4/0', False)
        self._test_network_attrs(net)

        # Test AIM VRF.
        vrf = aim_resource.VRF(tenant_name='common', name=vrf_name)
        self._test_aim_resource(vrf)
        self._test_network_attrs(net)

        # Test AIM ApplicationProfile.
        ap = aim_resource.ApplicationProfile(
            tenant_name='common', name='openstack_OpenStack')
        self._test_aim_resource(ap)

        # Test AIM Contract.
        contract = aim_resource.Contract(
            tenant_name='common', name='openstack_EXT-l1')
        self._test_aim_resource(contract)

        # Test AIM ContractSubject.
        subject = aim_resource.ContractSubject(
            tenant_name='common', contract_name='openstack_EXT-l1',
            name='Allow')
        self._test_aim_resource(subject)

        # Test AIM Filter.
        filter = aim_resource.Filter(
            tenant_name='common', name='openstack_EXT-l1')
        self._test_aim_resource(filter)

        # Test AIM FilterEntry.
        entry = aim_resource.FilterEntry(
            tenant_name='common', filter_name='openstack_EXT-l1', name='Any')
        self._test_aim_resource(entry)

        return net

    def test_external_network(self):
        self._test_external_network()

    def test_preexisting_external_network(self):
        # Create pre-existing AIM VRF.
        vrf = aim_resource.VRF(tenant_name='common', name='v1', monitored=True)
        self.aim_mgr.create(self.aim_ctx, vrf)

        # Create pre-existing AIM L3Outside.
        l3out = aim_resource.L3Outside(
            tenant_name='common', name='l1', vrf_name='v1', monitored=True)
        self.aim_mgr.create(self.aim_ctx, l3out)

        # Create pre-existing AIM ExternalNetwork.
        ext_net = aim_resource.ExternalNetwork(
            tenant_name='common', l3out_name='l1', name='n1', monitored=True)
        self.aim_mgr.create(self.aim_ctx, ext_net)

        # Create pre-existing AIM ExternalSubnet.
        ext_sn = aim_resource.ExternalSubnet(
            tenant_name='common', l3out_name='l1', external_network_name='n1',
            cidr='0.0.0.0/0', monitored=True)
        self.aim_mgr.create(self.aim_ctx, ext_sn)

        # Run tests.
        net = self._test_external_network(vrf_name='v1')
        net_id = net['id']

        # Delete network extension data and clear ExternalNetwork
        # contracts to test migration use case.
        (self.db_session.query(ext_db.NetworkExtensionDb).
         filter_by(network_id=net_id).
         delete())
        (self.db_session.query(ext_db.NetworkExtensionCidrDb).
         filter_by(network_id=net_id).
         delete())
        self.aim_mgr.update(
            self.aim_ctx, ext_net,
            provided_contract_names=[],
            consumed_contract_names=[])

        # Test without DN for migration.
        self._validate_unrepairable()

        # Configure invalid DN for migration and test.
        cfg.CONF.set_override(
            'migrate_ext_net_dns', {net_id: 'abcdef'}, group='ml2_apic_aim')
        self._validate_unrepairable()

        # Configure non-existent DN for migration and test.
        cfg.CONF.set_override(
            'migrate_ext_net_dns', {net_id: 'uni/tn-common/out-l9/instP-n1'},
            group='ml2_apic_aim')
        self._validate_unrepairable()

        # Configure correct DN for migration and test.
        cfg.CONF.set_override(
            'migrate_ext_net_dns', {net_id: 'uni/tn-common/out-l1/instP-n1'},
            group='ml2_apic_aim')
        self._validate_repair_validate()
        self._test_network_attrs(net)

    def test_svi_network(self):
        # REVISIT: Test validation of actual mapping once implemented.

        # Create SVI network.
        kwargs = {'apic:svi': 'True'}
        self._make_network(
            self.fmt, 'net', True, arg_list=self.extension_attributes,
            **kwargs)

        # Test that validation fails.
        self._validate_unrepairable()

    def test_router(self):
        # Create router.
        router = self._make_router(
            self.fmt, self._tenant_id, 'router1')['router']
        contract_dn = router['apic:distinguished_names']['Contract']
        subject_dn = router['apic:distinguished_names']['ContractSubject']
        self._validate()

        # Test AIM Contract.
        contract = aim_resource.Contract.from_dn(contract_dn)
        self._test_aim_resource(contract)

        # Test AIM ContractSubject.
        subject = aim_resource.ContractSubject.from_dn(subject_dn)
        self._test_aim_resource(subject)

    def test_scoped_routing(self):
        # Create shared address scope and subnetpool as tenant_1.
        scope = self._make_address_scope(
            self.fmt, 4, admin=True, name='as1', tenant_id='tenant_1',
            shared=True)['address_scope']
        pool = self._make_subnetpool(
            self.fmt, ['10.0.0.0/8'], admin=True, name='sp1',
            tenant_id='tenant_1', address_scope_id=scope['id'],
            default_prefixlen=24, shared=True)['subnetpool']
        pool_id = pool['id']

        # Create network and subnet as tenant_2.
        net_resp = self._make_network(
            self.fmt, 'net1', True, tenant_id='tenant_2')
        subnet = self._make_subnet(
            self.fmt, net_resp, '10.0.1.1', '10.0.1.0/24',
            subnetpool_id=pool_id, tenant_id='tenant_2')['subnet']
        subnet_id = subnet['id']

        # Create extra unrouted subnet.
        self._make_subnet(
            self.fmt, net_resp, '10.0.2.1', '10.0.2.0/24',
            subnetpool_id=pool_id, tenant_id='tenant_2')

        # Create external network.
        kwargs = {'router:external': True,
                  'apic:distinguished_names':
                  {'ExternalNetwork': 'uni/tn-common/out-l1/instP-n1'}}
        ext_net = self._make_network(
            self.fmt, 'ext_net', True, arg_list=self.extension_attributes,
            **kwargs)['network']

        # Create extra external network to test CloneL3Out record below.
        kwargs = {'router:external': True,
                  'apic:distinguished_names':
                  {'ExternalNetwork': 'uni/tn-common/out-l2/instP-n2'}}
        self._make_network(
            self.fmt, 'extra_ext_net', True,
            arg_list=self.extension_attributes, **kwargs)

        # Create router as tenant_2.
        kwargs = {'apic:external_provided_contracts': ['p1', 'p2'],
                  'apic:external_consumed_contracts': ['c1', 'c2'],
                  'external_gateway_info': {'network_id': ext_net['id']}}
        router = self._make_router(
            self.fmt, 'tenant_2', 'router1',
            arg_list=self.extension_attributes, **kwargs)['router']
        router_id = router['id']

        # Validate before adding subnet to router.
        self._validate()

        # Add subnet to router.
        self.l3_plugin.add_router_interface(
            n_context.get_admin_context(), router_id,
            {'subnet_id': subnet_id})
        self._validate()

        # Test AIM Subnet.
        self._test_routed_subnet(subnet_id, '10.0.1.1')

        # Determine clone L3Outside identity based on VRF.
        vrf_dn = scope['apic:distinguished_names']['VRF']
        vrf = aim_resource.VRF.from_dn(vrf_dn)
        tenant_name = vrf.tenant_name
        l3out_name = 'l1-%s' % vrf.name

        # Test AIM L3Outside.
        l3out = aim_resource.L3Outside(
            tenant_name=tenant_name, name=l3out_name)
        self._test_aim_resource(l3out)

        # Test AIM ExternalNetwork.
        en = aim_resource.ExternalNetwork(
            tenant_name=tenant_name, l3out_name=l3out_name, name='n1')
        self._test_aim_resource(en)

        # Test AIM ExternalSubnet.
        esn = aim_resource.ExternalSubnet(
            tenant_name=tenant_name, l3out_name=l3out_name,
            external_network_name='n1', cidr='0.0.0.0/0')
        self._test_aim_resource(esn, 'cidr', '1.2.3.4/0')

        # Delete the CloneL3Out record and test.
        (self.db_session.query(aim_lib_model.CloneL3Out).
         filter_by(tenant_name=tenant_name, name=l3out_name).
         delete())
        self._validate_repair_validate()

        # Corrupt the CloneL3Out record and test.
        with self.db_session.begin():
            record = (self.db_session.query(aim_lib_model.CloneL3Out).
                      filter_by(tenant_name=tenant_name, name=l3out_name).
                      one())
            record.source_name = 'l2'
        self._validate_repair_validate()

        # Add monitored L3Out and unexpected CloneL3Out record and test.
        with self.db_session.begin():
            unexpected_l3out_name = 'l2-%s' % vrf.name
            unexpected_l3out = aim_resource.L3Outside(
                tenant_name=tenant_name, name=unexpected_l3out_name,
                monitored=True)
            self.aim_mgr.create(self.aim_ctx, unexpected_l3out)
            record = aim_lib_model.CloneL3Out(
                source_tenant_name='common', source_name='l2',
                name=unexpected_l3out_name, tenant_name=tenant_name)
            self.db_session.add(record)
        self._validate_repair_validate()

    def test_unscoped_routing(self):
        # Create shared network and unscoped subnet as tenant_1.
        net_resp = self._make_network(
            self.fmt, 'net1', True, tenant_id='tenant_1', shared=True)
        subnet = self._make_subnet(
            self.fmt, net_resp, '10.0.1.1', '10.0.1.0/24',
            tenant_id='tenant_1')['subnet']
        subnet1_id = subnet['id']

        # Create unshared network and unscoped subnet as tenant_2.
        net_resp = self._make_network(
            self.fmt, 'net2', True, tenant_id='tenant_2')
        subnet = self._make_subnet(
            self.fmt, net_resp, '10.0.2.1', '10.0.2.0/24',
            tenant_id='tenant_2')['subnet']
        subnet2_id = subnet['id']

        # Create extra unrouted subnet.
        self._make_subnet(
            self.fmt, net_resp, '10.0.3.1', '10.0.3.0/24',
            tenant_id='tenant_2')

        # Create external network.
        kwargs = {'router:external': True,
                  'apic:distinguished_names':
                  {'ExternalNetwork': 'uni/tn-common/out-l1/instP-n1'}}
        ext_net = self._make_network(
            self.fmt, 'ext_net', True, arg_list=self.extension_attributes,
            **kwargs)['network']

        # Create router as tenant_2.
        kwargs = {'apic:external_provided_contracts': ['p1', 'p2'],
                  'apic:external_consumed_contracts': ['c1', 'c2'],
                  'external_gateway_info': {'network_id': ext_net['id']}}
        router = self._make_router(
            self.fmt, 'tenant_2', 'router1',
            arg_list=self.extension_attributes, **kwargs)['router']
        router_id = router['id']

        # Validate before adding subnet to router.
        self._validate()

        # Add unshared subnet to router.
        self.l3_plugin.add_router_interface(
            n_context.get_admin_context(), router_id,
            {'subnet_id': subnet2_id})
        self._validate()

        # Test AIM Subnet and VRF.
        self._test_routed_subnet(subnet2_id, '10.0.2.1')
        self._test_unscoped_vrf(router_id)

        # Add shared subnet to router.
        self.l3_plugin.add_router_interface(
            n_context.get_admin_context(), router_id,
            {'subnet_id': subnet1_id})
        self._validate()

        # Test AIM Subnets and VRF.
        self._test_routed_subnet(subnet2_id, '10.0.2.1')
        self._test_routed_subnet(subnet1_id, '10.0.1.1')
        self._test_unscoped_vrf(router_id)

    def test_security_group(self):
        # Create security group with a rule.
        sg = self._make_security_group(
            self.fmt, 'sg1', 'security group 1')['security_group']
        rule1 = self._build_security_group_rule(
            sg['id'], 'ingress', 'tcp', '22', '23')
        rules = {'security_group_rules': [rule1['security_group_rule']]}
        sg_rule = self._make_security_group_rule(
            self.fmt, rules)['security_group_rules'][0]
        self._validate()

        # Test the AIM SecurityGroup.
        tenant_name = self.driver.aim_mech_driver.name_mapper.project(
            None, sg['project_id'])
        sg_name = sg['id']
        aim_sg = aim_resource.SecurityGroup(
            name=sg_name, tenant_name=tenant_name)
        self._test_aim_resource(aim_sg)

        # Test the AIM SecurityGroupSubject.
        aim_subject = aim_resource.SecurityGroupSubject(
            name='default', security_group_name=sg_name,
            tenant_name=tenant_name)
        self._test_aim_resource(aim_subject)

        # Test the AIM SecurityGroupRule.
        aim_rule = aim_resource.SecurityGroupRule(
            name=sg_rule['id'],
            security_group_subject_name='default',
            security_group_name=sg_name,
            tenant_name=tenant_name)
        self._test_aim_resource(aim_rule)

    def test_network_segment(self):
        # REVISIT: Test repair when migration from other types to
        # 'opflex' is supported.

        # Create network.
        net = self._make_network(self.fmt, 'net1', True)['network']

        # Change network's segment to an unknown type.
        self.db_session.query(segment.NetworkSegment).filter_by(
            network_id=net['id']).update({'network_type': 'xxx'})

        # Test that validation fails.
        self._validate_unrepairable()

    def test_port_binding(self):
        # Create network, subnet, and bound port.
        net_resp = self._make_network(self.fmt, 'net1', True)
        net = net_resp['network']
        subnet = self._make_subnet(
            self.fmt, net_resp, None, '10.0.0.0/24')['subnet']
        fixed_ips = [{'subnet_id': subnet['id'], 'ip_address': '10.0.0.100'}]
        port = self._make_port(
            self.fmt, net['id'], fixed_ips=fixed_ips)['port']
        port = self._bind_port_to_host(port['id'], 'host1')['port']
        self._validate()

        # Change port binding level to unknown mechanism driver and
        # test.
        self.db_session.query(ml2_models.PortBindingLevel).filter_by(
            port_id=port['id'], level=0).update({'driver': 'xxx'})
        self._validate_repair_validate()

        # Change port binding level to incorrect host and test.
        self.db_session.query(ml2_models.PortBindingLevel).filter_by(
            port_id=port['id'], level=0).update({'host': 'yyy'})
        self._validate_repair_validate()

        # Change port binding level to null segment ID and test.
        self.db_session.query(ml2_models.PortBindingLevel).filter_by(
            port_id=port['id'], level=0).update({'segment_id': None})
        self._validate_repair_validate()

        # Change port binding level to unknown mechanism driver, set
        # bad host, and test that repair fails.
        #
        # REVISIT: The apic_aim MD currently tries to allocate a
        # dynamic segment whenever there is no agent on the port's
        # host, which is probably wrong, but it does fail to bind, so
        # this test succeeds.
        self.db_session.query(ml2_models.PortBindingLevel).filter_by(
            port_id=port['id'], level=0).update({'driver': 'xxx',
                                                 'host': 'yyy'})
        self.db_session.query(ml2_models.PortBinding).filter_by(
            port_id=port['id']).update({'host': 'yyy'})
        self._validate_fails_binding_ports()

    def test_legacy_cleanup(self):
        # Create pre-existing AIM VRF.
        vrf = aim_resource.VRF(tenant_name='common', name='v1', monitored=True)
        self.aim_mgr.create(self.aim_ctx, vrf)

        # Create pre-existing AIM L3Outside.
        l3out = aim_resource.L3Outside(
            tenant_name='common', name='l1', vrf_name='v1', monitored=True)
        self.aim_mgr.create(self.aim_ctx, l3out)

        # Create pre-existing AIM ExternalNetwork.
        ext_net = aim_resource.ExternalNetwork(
            tenant_name='common', l3out_name='l1', name='n1', monitored=True)
        self.aim_mgr.create(self.aim_ctx, ext_net)

        # Create external network.
        kwargs = {'router:external': True,
                  'apic:distinguished_names':
                  {'ExternalNetwork': 'uni/tn-common/out-l1/instP-n1'}}
        ext_net = self._make_network(
            self.fmt, 'ext_net', True, tenant_id='tenant_1',
            arg_list=self.extension_attributes, **kwargs)['network']
        ext_net_id = ext_net['id']

        # Create router using external network.
        kwargs = {'external_gateway_info': {'network_id': ext_net_id}}
        router = self._make_router(
            self.fmt, self._tenant_id, 'router1',
            arg_list=self.extension_attributes, **kwargs)['router']
        router_id = router['id']

        # Create internal network and subnet.
        int_net_resp = self._make_network(self.fmt, 'net1', True)
        int_net = int_net_resp['network']
        int_net_id = int_net['id']
        int_subnet = self._make_subnet(
            self.fmt, int_net_resp, '10.0.1.1', '10.0.1.0/24')['subnet']
        int_subnet_id = int_subnet['id']

        # Add internal subnet to router.
        self.l3_plugin.add_router_interface(
            n_context.get_admin_context(), router_id,
            {'subnet_id': int_subnet_id})

        # Validate just to make sure everything is OK before creating
        # legacy plugin's SNAT-related resources.
        self._validate()

        # Create legacy plugin's SNAT-related Neutron network.
        leg_net_resp = self._make_network(
            self.fmt,
            'host-snat-network-for-internal-use-' + ext_net_id, False)
        leg_net = leg_net_resp['network']
        leg_net_id = leg_net['id']

        # Create legacy plugin's SNAT-related Neutron subnet.
        leg_subnet = self._make_subnet(
            self.fmt, leg_net_resp, '66.66.66.1', '66.66.66.0/24',
            enable_dhcp=False)['subnet']
        leg_subnet_id = leg_subnet['id']
        data = {'subnet': {'name': 'host-snat-pool-for-internal-use'}}
        leg_subnet = self._update('subnets', leg_subnet_id, data)['subnet']

        # Create legacy plugin's SNAT-related Neutron port.
        fixed_ips = [{'subnet_id': leg_subnet_id, 'ip_address': '66.66.66.5'}]
        leg_port = self._make_port(
            self.fmt, leg_net_id, fixed_ips=fixed_ips,
            name='host-snat-pool-port-for-internal-use',
            device_owner='host-snat-pool-port-device-owner-internal-use'
        )['port']
        leg_port_id = leg_port['id']

        # Delete all networks' mapping and extension records to
        # simulate migration use case.
        net_ids = [ext_net_id, int_net_id, leg_net_id]
        (self.db_session.query(db.NetworkMapping).
         filter(db.NetworkMapping.network_id.in_(net_ids)).
         delete(synchronize_session=False))
        (self.db_session.query(ext_db.NetworkExtensionDb).
         filter(ext_db.NetworkExtensionDb.network_id.in_(net_ids)).
         delete(synchronize_session=False))

        # Delete all subnets' extension records to simulate migration
        # use case.
        subnet_ids = [int_subnet_id, leg_subnet_id]
        (self.db_session.query(ext_db.SubnetExtensionDb).
         filter(ext_db.SubnetExtensionDb.subnet_id.in_(subnet_ids)).
         delete(synchronize_session=False))

        # Test migration.
        cfg.CONF.set_override(
            'migrate_ext_net_dns',
            {ext_net_id: 'uni/tn-common/out-l1/instP-n1'},
            group='ml2_apic_aim')
        self._validate_repair_validate()

        # Ensure legacy plugin's SNAT-related resources are gone.
        self._show(
            'ports', leg_port_id,
            expected_code=webob.exc.HTTPNotFound.code)
        self._show(
            'subnets', leg_subnet_id,
            expected_code=webob.exc.HTTPNotFound.code)
        self._show(
            'networks', leg_net_id,
            expected_code=webob.exc.HTTPNotFound.code)

        # Ensure new SNAT subnet was properly created on actual
        # external network.
        ext_subnets = self._show('networks', ext_net_id)['network']['subnets']
        self.assertEqual(1, len(ext_subnets))
        ext_subnet = self._show('subnets', ext_subnets[0])['subnet']
        self.assertEqual(leg_subnet['cidr'], ext_subnet['cidr'])
        self.assertEqual(leg_subnet['gateway_ip'], ext_subnet['gateway_ip'])
        self.assertEqual(leg_subnet['enable_dhcp'], ext_subnet['enable_dhcp'])
        self.assertEqual('SNAT host pool', ext_subnet['name'])
        self.assertTrue(ext_subnet['apic:snat_host_pool'])
        self.assertEqual(ext_net['project_id'], ext_subnet['project_id'])


class TestGbpMapping(AimValidationTestCase):

    def setUp(self):
        super(TestGbpMapping, self).setUp()

    def test_l3_policy(self):
        # REVISIT: Test validation of actual mapping once implemented.

        # Create L3P.
        self.create_l3_policy()

        # Test that validation fails.
        self._validate_unrepairable()

    def test_l2_policy(self):
        # REVISIT: Test validation of actual mapping once implemented.

        # Create L2P.
        l2p = self.create_l2_policy()['l2_policy']

        # Dissassociate and delete the implicitly-created L3P.
        self.db_session.query(gpdb.L2Policy).filter_by(id=l2p['id']).update(
            {'l3_policy_id': None})
        self.delete_l3_policy(l2p['l3_policy_id'])

        # Test that validation fails.
        self._validate_unrepairable()

    def test_policy_target_group(self):
        # REVISIT: Test validation of actual mapping once implemented.

        # Create PTG.
        self.create_policy_target_group()

        # Dissassociating and deleting the implicitly-created L3P and
        # L2P would require removing the router interface that has
        # been created, which is not worth the effort for this
        # temporary test implementation. Manual inspection of the
        # validation output shows that validation is failing due to
        # the PTG, as well as the other resources.

        # Test that validation fails.
        self._validate_unrepairable()

    def test_policy_target(self):
        # REVISIT: Test validation of actual mapping once implemented.

        # Create PTG.
        ptg = self.create_policy_target_group()['policy_target_group']

        # Create PT.
        self.create_policy_target(policy_target_group_id=ptg['id'])

        # Dissassociating and deleting the PTG, L3P and L2P is not
        # worth the effort for this temporary test
        # implementation. Manual inspection of the validation output
        # shows that validation is failing due to the PT, as well as
        # the other resources.

        # Test that validation fails.
        self._validate_unrepairable()

    def test_application_policy_group(self):
        # REVISIT: Test validation of actual mapping once implemented.

        # Create APG.
        self.create_application_policy_group()

        # Test that validation fails.
        self._validate_unrepairable()

    def test_policy_classifier(self):
        # REVISIT: Test validation of actual mapping once implemented.

        # Create PC.
        self.create_policy_classifier()

        # Test that validation fails.
        self._validate_unrepairable()

    def test_policy_rule_set(self):
        # REVISIT: Test validation of actual mapping once implemented.

        # Create PRS.
        self.create_policy_rule_set()

        # Test that validation fails.
        self._validate_unrepairable()

    def test_external_segment(self):
        # REVISIT: Test validation of actual mapping once
        # implemented. No AIM resources are created directly, but
        # external_routes maps to the cisco_apic.EXTERNAL_CIDRS
        # network extension.

        # Create external network and subnet.
        kwargs = {'router:external': True,
                  'apic:distinguished_names':
                  {'ExternalNetwork': 'uni/tn-common/out-l1/instP-n1'}}
        net_resp = self._make_network(
            self.fmt, 'ext_net', True, arg_list=self.extension_attributes,
            **kwargs)
        subnet = self._make_subnet(
            self.fmt, net_resp, '10.0.0.1', '10.0.0.0/24')['subnet']

        # Create ES.
        self.create_external_segment(
            subnet_id=subnet['id'],
            external_routes=[{'destination': '129.0.0.0/24', 'nexthop': None}])

        # Test that validation fails.
        self._validate_unrepairable()

    def test_external_policy(self):
        # REVISIT: Test validation of actual mapping once implemented.

        # Create EP.
        self.create_external_policy()

        # Test that validation fails.
        self._validate_unrepairable()


class TestSfcMapping(test_aim_sfc_driver.TestAIMServiceFunctionChainingBase,
                     AimValidationTestMixin):

    def setUp(self):
        super(TestSfcMapping, self).setUp()
        self.av_mgr = av.ValidationManager()
        self.aim_ctx = aim_context.AimContext(self.db_session)

    def test_flow_classifier(self):
        # REVISIT: Test validation of actual mapping once
        # implemented. This resource is currently not mapped to AIM
        # until used in a port chain, but there are plans to map it
        # more proactively.

        # Create FC.
        self._create_simple_flowc()

        # Test that validation fails.
        self._validate_unrepairable()

    def test_port_port_pair_group(self):
        # REVISIT: Test validation of actual mapping once
        # implemented. This resource is currently not mapped to AIM
        # until used in a port chain, but there are plans to map it
        # more proactively.

        # Create PPG.
        self._create_simple_ppg(pairs=1)

        # Test that validation fails.
        self._validate_unrepairable()

    def test_port_chain(self):
        # REVISIT: Test validation of actual mapping once
        # implemented.

        # Create PC (along with PPG and FC).
        self._create_simple_port_chain(ppgs=1)

        # Deleting the PPG and FC, if possible, would ensure that the
        # PC itself is causing validation to fail, but is not worth
        # the effort for this temporary test implementation. Manual
        # inspection of the validation output shows that validation is
        # failing due to the PC, as well as the other resources.

        # Test that validation fails.
        self._validate_unrepairable()
