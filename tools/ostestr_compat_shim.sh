#!/bin/sh

# preserve old behavior of using an arg as a regex when '--' is not present
case $@ in
  (*--*) ostestr $@;;
  ('') ostestr --no-discover gbpservice.neutron.tests.unit.db.grouppolicy.test_group_policy_db.TestGroupResources;;
  (*) ostestr --no-discover gbpservice.neutron.tests.unit.db.grouppolicy.test_group_policy_db.TestGroupResources
esac
