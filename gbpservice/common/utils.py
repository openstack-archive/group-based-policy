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

from neutron_lib import context as n_context
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import importutils
from stevedore import driver

from gbpservice._i18n import _

LOG = logging.getLogger(__name__)
cfg.CONF.import_group('keystone_authtoken', 'keystonemiddleware.auth_token')


def get_obj_from_stack(cls):
    i = 1
    try:
        while True:
            for val in sys._getframe(i).f_locals.itervalues():
                if isinstance(val, cls):
                    return val
            i = i + 1
    except Exception:
        return


def get_current_context():
    return get_obj_from_stack(n_context.Context)


def get_current_session():
    ctx = get_current_context()
    if ctx:
        return ctx.session


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
            LOG.exception("Error loading plugin by name, %s", e1)
            LOG.exception("Error loading plugin by class, %s", e2)
            raise ImportError(_("Plugin not found."))
    return plugin_class()


def admin_context(context):
    admin_context = n_context.get_admin_context()
    admin_context._session = context.session
    return admin_context


class DictClass(dict):

    def __getattr__(self, item):
        return self[item]

    __setattr__ = dict.__setattr__
    __delattr__ = dict.__delattr__


def get_keystone_creds():
    keystone_conf = cfg.CONF.keystone_authtoken
    user = keystone_conf.username
    pw = keystone_conf.password
    tenant = keystone_conf.project_name
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
