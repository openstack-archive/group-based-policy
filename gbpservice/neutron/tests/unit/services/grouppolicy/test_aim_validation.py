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

from aim.api import resource as aim_resource
from aim import context as aim_context
from neutron_lib import context as n_context

from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import db
from gbpservice.neutron.services.grouppolicy.drivers.cisco.apic import (
    aim_validation as av)
from gbpservice.neutron.tests.unit.services.grouppolicy import (
    test_aim_mapping_driver)


class TestAimValidation(test_aim_mapping_driver.AIMBaseTestCase):

    def setUp(self):
        super(TestAimValidation, self).setUp()
        self.av_mgr = av.ValidationManager()
        self.aim_ctx = aim_context.AimContext(self.db_session)

    def _validate(self):
        # Validate should pass.
        self.assertEqual(av.VALIDATION_PASSED, self.av_mgr.validate())

    def _validate_repair_validate(self):
        # Validate should fail.
        self.assertEqual(av.VALIDATION_FAILED, self.av_mgr.validate())

        # Repair.
        self.assertEqual(
            av.VALIDATION_REPAIRED, self.av_mgr.validate(repair=True))

        # Validate should pass.
        self.assertEqual(av.VALIDATION_PASSED, self.av_mgr.validate())

    def _test_aim_resource(self, resource):
        resource = copy.copy(resource)

        # Delete the AIM resource and test.
        self.aim_mgr.delete(self.aim_ctx, resource)
        self._validate_repair_validate()

        # Modify the AIM resource and test.
        self.aim_mgr.update(
            self.aim_ctx, resource, display_name='not what it was')
        self._validate_repair_validate()

        # Add unexpected AIM resource and test.
        resource.name = "Unexpected"
        self.aim_mgr.create(self.aim_ctx, resource)
        self._validate_repair_validate()

        # Add unexpected monitored AIM resource and test.
        resource.monitored = True
        self.aim_mgr.create(self.aim_ctx, resource)
        self._validate()

    def _test_routed_subnet(self, subnet_id, gw_ip):
        # Get the AIM Subnet.
        subnet = self._show('subnets', subnet_id)['subnet']
        sn_dn = subnet['apic:distinguished_names'][gw_ip]
        sn = aim_resource.Subnet.from_dn(sn_dn)

        # Delete the AIM Subnet and test.
        self.aim_mgr.delete(self.aim_ctx, sn)
        self._validate_repair_validate()

        # Modify the AIM Subnet and test.
        self.aim_mgr.update(self.aim_ctx, sn, display_name='not what it was')
        self._validate_repair_validate()

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

        # REVISIT: Test the ARP/DHCP SecurityGroup.

    def test_project_resources(self):
        # REVISIT: Currently, a project's AIM Tenant and
        # ApplicationProfile are created in ensure_tenant just before
        # any Neutron/GBP resource is created using that project, and
        # are not cleaned up when the last Neutron/GBP resource
        # needing them is deleted. Instead, they are cleaned up when a
        # notification is received from Keystone that the project has
        # been deleted. We should consider managing these AIM
        # resources more dynamically. If we do, this test will need to
        # be reworked to make sure the AIM Tenant is
        # validated/repaired for all Neutron and GBP resource types,
        # and testing of the AIM ApplicationProfile may need to be
        # moved to test_unrouted_network.

        # Create address scope (any mapped Neutron/GBP resource should
        # do).
        scope = self._make_address_scope(
            self.fmt, 4, name='as1')['address_scope']
        vrf_dn = scope['apic:distinguished_names']['VRF']
        vrf = aim_resource.VRF.from_dn(vrf_dn)
        self._validate()

        # Test AIM Tenant.
        tenant = aim_resource.Tenant(name=vrf.tenant_name)
        self._test_aim_resource(tenant)

        # Test AIM ApplicationProfile.
        ap = aim_resource.ApplicationProfile(
            tenant_name=vrf.tenant_name, name='OpenStack')
        self._test_aim_resource(ap)

    def test_address_scope(self):
        # Create address scope.
        scope = self._make_address_scope(
            self.fmt, 4, name='as1')['address_scope']
        scope_id = scope['id']
        vrf_dn = scope['apic:distinguished_names']['VRF']
        self._validate()

        # Delete the address scope's mapping record and test.
        (self.db_session.query(db.AddressScopeMapping).
         filter_by(scope_id=scope_id).
         delete())
        self._validate_repair_validate()

        # Test AIM VRF.
        vrf = aim_resource.VRF.from_dn(vrf_dn)
        self._test_aim_resource(vrf)

    # REVISIT: Test isomorphic address scopes.

    def test_unrouted_network(self):
        # Create network.
        net_resp = self._make_network(self.fmt, 'net1', True)
        net = net_resp['network']
        net_id = net['id']
        bd_dn = net['apic:distinguished_names']['BridgeDomain']
        epg_dn = net['apic:distinguished_names']['EndpointGroup']
        self._validate()

        # Create unrouted subnet.
        subnet = self._make_subnet(
            self.fmt, net_resp, '10.0.2.1', '10.0.2.0/24')['subnet']
        self._validate()

        # Delete the network's mapping record and test.
        (self.db_session.query(db.NetworkMapping).
         filter_by(network_id=net_id).
         delete())
        self._validate_repair_validate()

        # Corrupt the network's mapping record's BD and test.
        with self.db_session.begin():
            mapping = (self.db_session.query(db.NetworkMapping).
                       filter_by(network_id=net_id).
                       one())
            mapping.bd_tenant_name = 'bad_bd_tenant_name'
        self._validate_repair_validate()

        # Corrupt the network's mapping record's EPG and test.
        with self.db_session.begin():
            mapping = (self.db_session.query(db.NetworkMapping).
                       filter_by(network_id=net_id).
                       one())
            mapping.epg_app_profile_name = 'bad_epg_app_profilename'
        self._validate_repair_validate()

        # Corrupt the network's mapping record's VRF and test.
        with self.db_session.begin():
            mapping = (self.db_session.query(db.NetworkMapping).
                       filter_by(network_id=net_id).
                       one())
            mapping.vrf_name = 'bad_vrf_name'
        self._validate_repair_validate()

        # Test AIM BridgeDomain.
        bd = aim_resource.BridgeDomain.from_dn(bd_dn)
        self._test_aim_resource(bd)

        # Test AIM EndpointGroup.
        epg = aim_resource.EndpointGroup.from_dn(epg_dn)
        self._test_aim_resource(epg)

        # Add unexpect AIM Subnet.
        sn = self.driver.aim_mech_driver._map_subnet(subnet, '10.0.2.1', bd)
        self.aim_mgr.create(self.aim_ctx, sn)
        self._validate_repair_validate()

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

        # Create router as tenant_2.
        router = self._make_router(
            self.fmt, 'tenant_2', 'router1')['router']
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

        # Create router as tenant_2.
        router = self._make_router(
            self.fmt, 'tenant_2', 'router1')['router']
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

    def test_external_network(self):
        # Create an external network.
        kwargs = {'router:external': True,
                  'apic:distinguished_names':
                  {'ExternalNetwork': 'uni/tn-common/out-l1/instP-n1'}}
        ext_net = self._make_network(
            self.fmt, 'ext_net', True, arg_list=self.extension_attributes,
            **kwargs)['network']
        print("ext_net: %s" % ext_net)  # TEMP
        self._validate()

        # REVISIT: Test resources and test with routers.
