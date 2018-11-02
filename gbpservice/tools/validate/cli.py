# Copyright (c) 2018 Cisco Systems Inc.
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

import sys

from oslo_config import cfg
from neutron.api.v2 import router
from neutron.common import config
from neutron import manager
from neutron_lib.plugins import directory

from gbpservice.neutron.services.grouppolicy import (
    group_policy_driver_api as api)

# Any policy-driver specific CLI options must be included here, since
# the CLI options must be registered before the GBP service plugin and
# the configured policy drivers can be loaded.
cli_opts = [
    cfg.BoolOpt('repair', default=False, help='Enable repair of invalid state.')
]


def main():
    cfg.CONF.register_cli_opts(cli_opts)
    config.init(sys.argv[1:])

    # Enable logging but prevent output to stderr.
    cfg.CONF.use_stderr = False
    config.setup_logging()

    if not cfg.CONF.config_file:
        sys.exit(_("ERROR: Unable to find configuration file via the default"
                   " search paths (~/.neutron/, ~/, /etc/neutron/, /etc/) and"
                   " the '--config-file' option!"))

    router.APIRouter.factory({})
    manager.init()

    gbp_plugin = directory.get_plugin('GROUP_POLICY')
    if not gbp_plugin:
        sys.exit("GBP service plugin not configured.")

    result = gbp_plugin.validate_state(cfg.CONF.repair)
    if result in [api.VALIDATION_FAILED_REPAIRABLE,
                  api.VALIDATION_FAILED_UNREPAIRABLE]:
        sys.exit(result)
    return 0
