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

from neutron.api import extensions

from gbpservice.neutron.plugins.ml2plus import extension_overrides

# Monkeypatch Neutron to allow overriding its own extension
# descriptors. Note that extension descriptor classes cannot be
# monkeypatched directly because they are loaded explicitly by file
# name and then used immediately.

_real_get_extensions_path = extensions.get_extensions_path


def get_extensions_path(service_plugins=None):
    path = _real_get_extensions_path(service_plugins)
    return extension_overrides.__path__[0] + ':' + path

extensions.get_extensions_path = get_extensions_path


from neutron.db import models_v2
from neutron.plugins.ml2 import db as ml2_db
from neutron.plugins.ml2 import models
from oslo_log import log as logging
from sqlalchemy.orm import exc


LOG = logging.getLogger(__name__)


# REVISIT: This method gets decorated in Pike for removal in Queens. So this
# patching might need to be changed in Pike and removed in Queens.
def patched_get_locked_port_and_binding(session, port_id):
    """Get port and port binding records for update within transaction."""
    LOG.debug("Using patched_get_locked_port_and_binding")
    try:
        port = (session.query(models_v2.Port).
                enable_eagerloads(False).
                filter_by(id=port_id).
                one())
        binding = (session.query(models.PortBinding).
                   enable_eagerloads(False).
                   filter_by(port_id=port_id).
                   one())
        return port, binding
    except exc.NoResultFound:
        return None, None


ml2_db.get_locked_port_and_binding = patched_get_locked_port_and_binding
