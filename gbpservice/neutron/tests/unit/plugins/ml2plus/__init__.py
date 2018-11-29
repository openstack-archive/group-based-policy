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

# The following are imported at the beginning to ensure that the
# patches are applied before any of the modules save a reference to
# the functions being patched. The order is also important.
from gbpservice.neutron.extensions import patch  # noqa

from gbpservice.neutron.plugins.ml2plus import patch_neutron  # noqa

from oslo_db.sqlalchemy import utils as sa_utils

# REVISIT: Remove this as soon as possible.
if not hasattr(sa_utils, '_get_unique_keys'):
    sa_utils._get_unique_keys = sa_utils.get_unique_keys


from neutron._i18n import _LI

from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import cache


# The following is to avoid excessive logging in the UTs
cache._LW = _LI
cache.LOG.warning = cache.LOG.info
