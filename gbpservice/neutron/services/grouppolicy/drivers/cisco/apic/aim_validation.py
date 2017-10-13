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

from aim import context as aim_context
from neutron.db import api as db_api
from neutron_lib.plugins import directory
from oslo_log import log

LOG = log.getLogger(__name__)

VALIDATION_PASSED = "passed"
VALIDATION_REPAIRED = "repaired"
VALIDATION_FAILED = "failed"


class Manager(object):

    def __init__(self):
        # REVISIT: Defer until after validating config?
        self.core_plugin = directory.get_plugin()
        self.md = self.core_plugin.mechanism_manager.mech_drivers[
            'apic_aim'].obj
        self.pd = self.md.gbp_driver

    def validate(self, repair=False):
        print("Validating deployment")

        self.result = VALIDATION_PASSED
        self.repair = repair

        # REVISIT: Validate configuration.

        # Start transaction.
        #
        # REVISIT: Set session's isolation level to serializable?
        self.session = db_api.get_session()
        self.session.begin()

        # Validate & repair GBP->Neutron mappings.
        self.pd.validate_neutron_mapping(self)

        # Start with no expected AIM resources.
        self.expected_aim_resources = {}

        # Validate Neutron->AIM mapping records and get expected AIM
        # resources.
        self.md.validate_aim_mapping(self)

        # Validate GBP->AIM mapping records and get expected AIM
        # resources.
        self.pd.validate_aim_mapping(self)

        # Validate that actual AIM resources match expected AIM
        # resources.
        if self.result is not VALIDATION_FAILED:
            self._validate_aim_resources()

        # Commit or rollback transaction.
        if self.result is VALIDATION_REPAIRED:
            print("Committing repairs")
            self.session.commit()
        else:
            if self.repair and self.result is VALIDATION_FAILED:
                print("Rolling back attempted repairs")
            self.session.rollback()

        return self.result

    def expect_aim_resource(self, resource):
        expected_resources = self.expected_aim_resources.setdefault(
            resource.__class__, {})
        key = tuple(resource.identity)
        if key in expected_resources:
            # REVISIT: Allow if identical?
            raise "resource %s already expected" % resource
        expected_resources[key] = resource

    def expected_aim_resource(self, resource):
        expected_resources = self.expected_aim_resources.setdefault(
            resource.__class__, {})
        key = tuple(resource.identity)
        return expected_resources.get(key)

    def should_repair(self):
        if self.repair and self.result is not VALIDATION_FAILED:
            self.result = VALIDATION_REPAIRED
            return True
        else:
            self.result = VALIDATION_FAILED

    def repair_failed(self):
        self.result = VALIDATION_FAILED

    def _validate_aim_resources(self):
        self.aim_mgr = self.md.aim
        self.aim_ctx = aim_context.AimContext(self.session)

        for resource_class in self.expected_aim_resources.keys():
            self._validate_aim_resource_class(resource_class)

    def _validate_aim_resource_class(self, resource_class):
        print("processing resource class %s" % resource_class)
        expected_resources = self.expected_aim_resources[resource_class]
        # print("expected resources: %s" % expected_resources.values())
        actual_resources = self.aim_mgr.find(self.aim_ctx, resource_class)
        # print("actual resources: %s" % actual_resources)

        for actual_resource in actual_resources:
            self._validate_actual_aim_resource(
                actual_resource, expected_resources)

        for expected_resource in expected_resources.values():
            self._handle_missing_aim_resource(expected_resource)

    def _validate_actual_aim_resource(self, actual_resource,
                                      expected_resources):
        key = tuple(actual_resource.identity)
        expected_resource = expected_resources.get(key)
        # print("comparing actual resource %r with expected resource %r" %
        #       (actual_resource, expected_resource))
        if not expected_resource:
            if not actual_resource.monitored:
                self._handle_unexpected_aim_resource(actual_resource)
        else:
            if expected_resource.monitored:
                # REVISIT: Make sure actual resource is monitored, but
                # ignore other differences.
                pass
            else:
                if any(expected_resource.__dict__.get(x) !=
                       actual_resource.__dict__.get(x)
                       for x in expected_resource.other_attributes.keys()):
                    self._handle_incorrect_aim_resource(
                        expected_resource, actual_resource)
            del expected_resources[key]

    def _handle_unexpected_aim_resource(self, actual_resource):
        # print("unexpected AIM resource: %r" % actual_resource)
        if self.should_repair():
            self.aim_mgr.delete(self.aim_ctx, actual_resource)
            print("Deleted unexpected %(type)s: %(data)r" %
                  {'type': actual_resource._aci_mo_name,
                   'data': actual_resource})
        else:
            print("Failed due to unexpected %(type)s: %(data)r" %
                  {'type': actual_resource._aci_mo_name,
                   'data': actual_resource})

    def _handle_incorrect_aim_resource(self, expected_resource,
                                       actual_resource):
        # print("incorrect AIM resource %r should be %r" %
        #       (actual_resource, expected_resource))
        if self.should_repair():
            resource = self.aim_mgr.create(
                self.aim_ctx, expected_resource, overwrite=True)
            print("Repaired incorrect %(type)s: %(actual)r with: %(data)r" %
                  {'type': resource._aci_mo_name,
                   'actual': actual_resource,
                   'data': resource})
        else:
            print("Failed due to incorrect %(type)s: %(actual)r is: %(data)r" %
                  {'type': expected_resource._aci_mo_name,
                   'actual': actual_resource,
                   'data': expected_resource})

    def _handle_missing_aim_resource(self, expected_resource):
        # print("missing AIM resource: %r" % expected_resource)
        if self.should_repair():
            resource = self.aim_mgr.create(self.aim_ctx, expected_resource)
            print("Repaired missing %(type)s: %(data)r" %
                  {'type': resource._aci_mo_name, 'data': resource})
        else:
            print("Failed due to missing %(type)s: %(data)r" %
                  {'type': expected_resource._aci_mo_name,
                   'data': expected_resource})
