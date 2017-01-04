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

from neutron.db.migration.cli import *  # noqa


def main():
    config = alembic_config.Config(
        os.path.join(os.path.dirname(__file__), 'alembic.ini'))
    config.set_main_option(
        'script_location',
        'gbpservice.neutron.db.migration:alembic_migrations')
    config.neutron_config = CONF
    CONF(project='neutron')
    CONF.command.func(config, CONF.command.name)
