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

from aim import aim_store
from aim import context as aim_context
from neutron.db import api as db_api
from neutron_lib.plugins import directory
from oslo_log import log

LOG = log.getLogger(__name__)

VALIDATION_PASSED = "passed"
VALIDATION_REPAIRED = "repaired"
VALIDATION_FAILED = "failed"


class ValidationManager(object):

    def __init__(self):
        # REVISIT: Defer until after validating config?
        self.core_plugin = directory.get_plugin()
        self.md = self.core_plugin.mechanism_manager.mech_drivers[
            'apic_aim'].obj
        self.pd = self.md.gbp_driver

    def validate(self, repair=False):
        print("Validating deployment, repair: %s" % repair)

        self.result = VALIDATION_PASSED
        self.repair = repair

        # REVISIT: Validate configuration.

        # Start transaction.
        #
        # REVISIT: Set session's isolation level to serializable?
        self.session = (db_api.get_writer_session() if repair
                        else db_api.get_reader_session())
        self.session.begin()

        # Validate & repair GBP->Neutron mappings.
        if self.pd:
            self.pd.validate_neutron_mapping(self)

        # Start with no expected AIM resources.
        self._expected_aim_resources = {}
        self.aim_ctx = aim_context.AimContext(None, ValidationAimStore(self))

        # Validate Neutron->AIM mapping records and get expected AIM
        # resources.
        self.md.validate_aim_mapping(self)

        # Validate GBP->AIM mapping records and get expected AIM
        # resources.
        if self.pd:
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

        print("Validation result: %s" % self.result)
        return self.result

    def register_aim_resource_type(self, klass):
        self._expected_aim_resources.setdefault(klass, {})

    def expect_aim_resource(self, resource, replace=False):
        expected_resources = self._expected_aim_resources[resource.__class__]
        key = tuple(resource.identity)
        if not replace and key in expected_resources:
            # REVISIT: Allow if identical? Raise proper exception.
            raise "resource %s already expected" % resource
        expected_resources[key] = resource

    def expected_aim_resource(self, resource):
        expected_resources = self._expected_aim_resources[resource.__class__]
        key = tuple(resource.identity)
        return expected_resources.get(key)

    def expected_aim_resources(self, klass):
        return self._expected_aim_resources[klass].values()

    def should_repair(self, problem, action='Repairing'):
        if self.repair and self.result is not VALIDATION_FAILED:
            self.result = VALIDATION_REPAIRED
            print("%s %s" % (action, problem))
            return True
        else:
            self.result = VALIDATION_FAILED
            print("Failed due to %s" % problem)

    def repair_failed(self):
        self.result = VALIDATION_FAILED

    def _validate_aim_resources(self):
        self.aim_mgr = self.md.aim
        self.aim_ctx = aim_context.AimContext(self.session)

        for resource_class in self._expected_aim_resources.keys():
            self._validate_aim_resource_class(resource_class)

    def _validate_aim_resource_class(self, resource_class):
        # print("processing resource class %s" % resource_class)
        expected_resources = self._expected_aim_resources[resource_class]
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
                if not self._is_resource_correct(
                        expected_resource, actual_resource):
                    self._handle_incorrect_aim_resource(
                        expected_resource, actual_resource)
            del expected_resources[key]

    def _is_resource_correct(self, expected_resource, actual_resource):
        expected_values = expected_resource.__dict__
        actual_values = actual_resource.__dict__
        for attr_name, attr_type in expected_resource.other_attributes.items():
            expected_value = expected_values.get(attr_name)
            actual_value = actual_values.get(attr_name)
            if attr_type['type'] == 'array':
                # REVISIT: Order may be significant for some array attributes.
                expected_value = set(expected_value)
                actual_value = set(actual_value)
            if expected_value != actual_value:
                return False
        return True

    def _handle_unexpected_aim_resource(self, actual_resource):
        if self.should_repair(
                "unexpected %(type)s: %(actual)r" %
                {'type': actual_resource._aci_mo_name,
                 'actual': actual_resource},
                "Deleting"):
            self.aim_mgr.delete(self.aim_ctx, actual_resource)

    def _handle_incorrect_aim_resource(self, expected_resource,
                                       actual_resource):
        if self.should_repair(
                "incorrect %(type)s: %(actual)r which should be: "
                "%(expected)r" %
                {'type': expected_resource._aci_mo_name,
                 'actual': actual_resource,
                 'expected': expected_resource}):
            self.aim_mgr.create(
                self.aim_ctx, expected_resource, overwrite=True)

    def _handle_missing_aim_resource(self, expected_resource):
        if self.should_repair(
                "missing %(type)s: %(expected)r" %
                {'type': expected_resource._aci_mo_name,
                 'expected': expected_resource}):
            self.aim_mgr.create(self.aim_ctx, expected_resource)


class ValidationAimStore(aim_store.AimStore):

    def __init__(self, validation_mgr):
        self._mgr = validation_mgr

    def add(self, db_obj):
        # print("add")
        # print(" db_obj: %s" % db_obj)
        self._mgr.expect_aim_resource(db_obj, True)

    def delete(self, db_obj):
        print("delete")
        print(" db_obj: %s" % db_obj)
        assert(False)

    def query(self, db_obj_type, resource_klass, in_=None, notin_=None,
              order_by=None, lock_update=False, **filters):
        # print("query")
        # print(" db_obj_type: %s" % db_obj_type)
        # print(" resource_klass: %s" % resource_klass)
        # print(" in_: %s" % in_)
        # print(" notin_: %s" % notin_)
        # print(" order_by: %s" % order_by)
        # print(" lock_update: %s" % lock_update)
        # print(" filters: %s" % filters)
        if filters:
            # REVISIT: Can we assume always querying by identity when
            # there are filters? If not, we need to detect this and
            # match based on the filter fields.
            identity = resource_klass(**filters)
            # print(" identity: %s" % identity)
            resource = self._mgr.expected_aim_resource(identity)
            # print(" resource: %s" % resource)
            return [resource] if resource else []
        else:
            resources = self._mgr.expected_aim_resources(resource_klass)
            # print(" resources: %s" % resources)
            return resources

    def count(self, db_obj_type, resource_klass, in_=None, notin_=None,
              **filters):
        print("count")
        print(" db_obj_type: %s" % db_obj_type)
        print(" resource_klass: %s" % resource_klass)
        print(" in_: %s" % in_)
        print(" notin_: %s" % notin_)
        print(" filters: %s" % filters)
        assert(False)

    def delete_all(self, db_obj_type, resource_klass, in_=None, notin_=None,
                   **filters):
        print("delete_all")
        print(" db_obj_type: %s" % db_obj_type)
        print(" resource_klass: %s" % resource_klass)
        print(" in_: %s" % in_)
        print(" notin_: %s" % notin_)
        print(" filters: %s" % filters)
        assert(False)

    def from_attr(self, db_obj, resource_klass, attribute_dict):
        for k, v in attribute_dict.items():
            setattr(db_obj, k, v)

    def to_attr(self, resource_klass, db_obj):
        print("to_attr")
        print(" resource_klass: %s" % resource_klass)
        print(" db_obj: %s" % db_obj)
        assert(False)

    def make_resource(self, cls, db_obj, include_aim_id=False):
        return copy.deepcopy(db_obj)

    def make_db_obj(self, resource):
        return copy.deepcopy(resource)
