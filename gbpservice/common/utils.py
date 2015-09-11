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

import contextlib

from neutron import context as n_ctx
from neutron.openstack.common import log as logging
from oslo.config import cfg
from oslo.utils import importutils
from stevedore import driver

LOG = logging.getLogger(__name__)


@contextlib.contextmanager
def clean_session(session):
    # Cleans session by expunging persisted object. This avoids inconsistency
    # when multiple transactions are called with the same context.
    session.expunge_all()
    yield
    session.expunge_all()


def get_resource_plural(resource):
    if resource.endswith('y'):
        resource_plural = resource.replace('y', 'ies')
    else:
        resource_plural = resource + 's'

    return resource_plural


def load_plugin(namespace, plugin):
    try:
        # Try to resolve plugin by name
        mgr = driver.DriverManager(namespace, plugin)
        plugin_class = mgr.driver
    except RuntimeError as e1:
        # fallback to class name
        try:
            plugin_class = importutils.import_class(plugin)
        except ImportError as e2:
            LOG.exception(_("Error loading plugin by name, %s"), e1)
            LOG.exception(_("Error loading plugin by class, %s"), e2)
            raise ImportError(_("Plugin not found."))
    return plugin_class()


def admin_context(context):
    admin_context = n_ctx.get_admin_context()
    admin_context._session = context.session
    return admin_context


class DictClass(dict):

    def __getattr__(self, item):
        return self[item]

    __setattr__ = dict.__setattr__
    __delattr__ = dict.__delattr__


def get_keystone_creds():
    keystone_conf = cfg.CONF.keystone_authtoken
    user = keystone_conf.admin_user
    pw = keystone_conf.admin_password
    tenant = keystone_conf.admin_tenant_name
    if keystone_conf.get('auth_uri'):
        auth_url = keystone_conf.auth_uri.rstrip('/')
        if not auth_url.endswith('/v2.0'):
            auth_url += '/v2.0'
    else:
        auth_url = ('%s://%s:%s/v2.0' % (
            keystone_conf.auth_protocol,
            keystone_conf.auth_host,
            keystone_conf.auth_port))
    return user, pw, tenant, auth_url + '/'


def set_difference(iterable_1, iterable_2):
    set1 = set(iterable_1)
    set2 = set(iterable_2)
    return (set1 - set2), (set2 - set1)
