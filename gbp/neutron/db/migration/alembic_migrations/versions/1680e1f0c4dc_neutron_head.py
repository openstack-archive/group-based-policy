# Copyright 2014 OpenStack Foundation
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
#

""" neutron_head

This special revision file is needed by alembic, and has to match with the
revision number shown by querying the alembic_version table in Neutron's DB.

We assume the revision number is the HEAD of Neutron's migration patch, which
means that the GBP db upgrade can only start from there (or upwards).
"""

revision = '1680e1f0c4dc'
down_revision = None
