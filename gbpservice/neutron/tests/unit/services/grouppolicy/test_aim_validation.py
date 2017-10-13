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

from aim.api import resource as aim_resource
from aim import context as aim_context

from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import db
from gbpservice.neutron.services.grouppolicy.drivers.cisco.apic import (
    aim_validation as av)
from gbpservice.neutron.tests.unit.services.grouppolicy import (
    test_aim_mapping_driver)


class TestAimValidation(test_aim_mapping_driver.AIMBaseTestCase):

    def setUp(self):
        super(TestAimValidation, self).setUp()
        self.av_mgr = av.Manager()
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

        # REVISIT: Test the any Filter.

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

        # Delete the network's mapping record and test.
        (self.db_session.query(db.NetworkMapping).
         filter_by(network_id=net_id).
         delete())
        self._validate_repair_validate()

        # Test AIM BridgeDomain.
        bd = aim_resource.BridgeDomain.from_dn(bd_dn)
        self._test_aim_resource(bd)

        # Test AIM EndpointGroup.
        epg = aim_resource.EndpointGroup.from_dn(epg_dn)
        self._test_aim_resource(epg)

        # REVISIT: Test with subnet and with unexpected AIM Subnet?

    def test_router(self):
        pass

    def test_scoped_routing(self):
        pass

    def test_unscoped_routing(self):
        pass
