# Copyright 2012 New Dream Network, LLC (DreamHost)
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

from logging import config as logging_config
import re

from alembic import context
from oslo.config import cfg
from oslo.db.sqlalchemy import session
import sqlalchemy as sa
from sqlalchemy import event

from neutron.db import model_base

# Mirror of the Neutron's env, plus some tweaks in order to set cross DB
# FKs.

MYSQL_ENGINE = None
config = context.config
neutron_config = config.neutron_config
logging_config.fileConfig(config.config_file_name)
target_metadata = model_base.BASEV2.metadata
neutron_db = re.split(r'[/?]', neutron_config.database.connection)[3]


def set_mysql_engine():
    try:
        mysql_engine = neutron_config.command.mysql_engine
    except cfg.NoSuchOptError:
        mysql_engine = None

    global MYSQL_ENGINE
    MYSQL_ENGINE = (mysql_engine or
                    model_base.BASEV2.__table_args__['mysql_engine'])


def run_migrations_offline():
    set_mysql_engine()

    kwargs = dict()
    if neutron_config.gbp_database.connection:
        kwargs['url'] = neutron_config.gbp_database.connection
    else:
        kwargs['dialect_name'] = neutron_config.gbp_database.engine
    context.configure(**kwargs)

    with context.begin_transaction():
        context.run_migrations(neutron_db=neutron_db)


@event.listens_for(sa.Table, 'after_parent_attach')
def set_storage_engine(target, parent):
    if MYSQL_ENGINE:
        target.kwargs['mysql_engine'] = MYSQL_ENGINE


def run_migrations_online():
    set_mysql_engine()
    engine = session.create_engine(neutron_config.gbp_database.connection)

    connection = engine.connect()
    context.configure(
        connection=connection,
        target_metadata=target_metadata
    )

    try:
        with context.begin_transaction():
            context.run_migrations(neutron_db=neutron_db)
    finally:
        connection.close()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()