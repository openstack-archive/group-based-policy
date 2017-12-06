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

# This module must import all modules from the GBP repo that define
# SQLAlchemy database models using Neutron's
# neutron_lib.db.model_base.BASEV2 base class. It also must itself be
# imported, directly or indirectly, by every test module for which
# Neutron's neutron.tests.unit.testlib_api.SqlFixture, or any derived
# class, manages the creation of the DB schema prior to running tests
# and the clearing of DB tables between tests.

from gbpservice.neutron.db.grouppolicy.extensions import (  # noqa
    apic_allowed_vm_name_db,
    apic_auto_ptg_db,
    apic_intra_ptg_db,
    apic_reuse_bd_db,
    apic_segmentation_label_db,
    group_proxy_db
)
from gbpservice.neutron.db.grouppolicy import (  # noqa
    group_policy_db,
    group_policy_mapping_db
)
from gbpservice.neutron.db import (  # noqa
    implicitsubnetpool_db,
    servicechain_db
)
from gbpservice.neutron.services.servicechain.plugins.ncp import (  # noqa
    model
)
