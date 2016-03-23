# Copyright (c) 2016 Cisco Systems Inc.
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

from apic_ml2.neutron.plugins.ml2.drivers.cisco.apic import (
    apic_model as old_model)
from neutron._i18n import _LI
from oslo_log import log
from sqlalchemy import orm

LOG = log.getLogger(__name__)


# REVISIT(rkukura): Temporarily using ApicName model defined in old
# apic-ml2 driver with migration in neutron. We should define our
# own, and may want to switch to per-resource name mapping tables with
# foriegn keys.

class DbModel(object):

    def __init__(self):
        LOG.info(_LI("APIC AIM DbModel __init__"))

    def add_apic_name(self, session, neutron_id, neutron_type, apic_name):
        name = old_model.ApicName(neutron_id=neutron_id,
                                  neutron_type=neutron_type,
                                  apic_name=apic_name)
        with session.begin(subtransactions=True):
            session.add(name)

    def get_apic_name(self, session, neutron_id, neutron_type):
        return session.query(old_model.ApicName.apic_name).filter_by(
            neutron_id=neutron_id, neutron_type=neutron_type).first()

    def delete_apic_name(self, session, neutron_id):
        with session.begin(subtransactions=True):
            try:
                session.query(old_model.ApicName).filter_by(
                    neutron_id=neutron_id).delete()
            except orm.exc.NoResultFound:
                return

    def get_filtered_apic_names(self, session, neutron_id=None,
                                neutron_type=None, apic_name=None):
        query = session.query(old_model.ApicName.apic_name)
        if neutron_id:
            query = query.filter_by(neutron_id=neutron_id)
        if neutron_type:
            query = query.filter_by(neutron_type=neutron_type)
        if apic_name:
            query = query.filter_by(apic_name=apic_name)
        return query.all()
