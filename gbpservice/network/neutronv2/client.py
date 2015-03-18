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

from neutronclient.common import exceptions as neutron_client_exc
from neutronclient.v2_0 import client as clientv20
from oslo_concurrency import lockutils
from oslo_config import cfg


neutron_opts = [
    cfg.StrOpt('neutron_server_url',
               default='http://127.0.0.1:9696',
               help='URL for connecting to neutron'),
    cfg.IntOpt('url_timeout',
               default=30,
               help='Timeout value for connecting to neutron in seconds'),
    cfg.StrOpt('admin_user_id',
               help='User id for connecting to neutron in admin context'),
    cfg.StrOpt('admin_username',
               help='Username for connecting to neutron in admin context'),
    cfg.StrOpt('admin_password',
               help='Password for connecting to neutron in admin context',
               secret=True),
    cfg.StrOpt('admin_tenant_id',
               help='Tenant id for connecting to neutron in admin context'),
    cfg.StrOpt('admin_tenant_name',
               help='Tenant name for connecting to neutron in admin context. '
                    'This option will be ignored if neutron_admin_tenant_id '
                    'is set. Note that with Keystone V3 tenant names are '
                    'only unique within a domain.'),
    # region_name required?
    cfg.StrOpt('region_name',
               help='Region name for connecting to neutron in admin context'),
    cfg.StrOpt('admin_auth_url',
               default='http://localhost:5000/v2.0',
               help='Authorization URL for connecting to neutron in admin '
                    'context'),
    cfg.BoolOpt('api_insecure',
                default=False,
                help='If set, ignore any SSL validation issues'),
    cfg.StrOpt('auth_strategy',
               default='keystone',
               help='Authorization strategy for connecting to '
                    'neutron in admin context'),
    # extension_sync_interval required?
    cfg.IntOpt('extension_sync_interval',
               default=600,
               help='Number of seconds before querying neutron for '
                    'extensions'),
    cfg.StrOpt('ca_certificates_file',
               help='Location of CA certificates file to use for '
                    'neutron client requests.'),
]

CONF = cfg.CONF
CONF.register_opts(neutron_opts, 'neutron')


class AdminTokenStore(object):

    _instance = None

    def __init__(self):
        self.admin_auth_token = None

    @classmethod
    def get(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance


def _get_client(token=None, admin=False):
    params = {
        'endpoint_url': CONF.neutron.neutron_server_url,
        'timeout': CONF.neutron.url_timeout,
        'insecure': CONF.neutron.api_insecure,
        'ca_cert': CONF.neutron.ca_certificates_file,
        'auth_strategy': CONF.neutron.auth_strategy,
        'token': token,
    }

    if admin:
        if CONF.neutron.admin_user_id:
            params['user_id'] = CONF.neutron.admin_user_id
        else:
            params['username'] = CONF.neutron.admin_username
        if CONF.neutron.admin_tenant_id:
            params['tenant_id'] = CONF.neutron.admin_tenant_id
        else:
            params['tenant_name'] = CONF.neutron.admin_tenant_name
        params['password'] = CONF.neutron.admin_password
        params['auth_url'] = CONF.neutron.admin_auth_url
    return clientv20.Client(**params)


class ClientWrapper(clientv20.Client):
    '''A neutron client wrapper class.

       Wraps the callable methods, executes it and updates the token,
       as it might change when expires.
    '''

    def __init__(self, base_client):
        # Expose all attributes from the base_client instance
        self.__dict__ = base_client.__dict__
        self.base_client = base_client

    def __getattribute__(self, name):
        obj = object.__getattribute__(self, name)
        if callable(obj):
            obj = object.__getattribute__(self, 'proxy')(obj)
        return obj

    def proxy(self, obj):
        def wrapper(*args, **kwargs):
            ret = obj(*args, **kwargs)
            new_token = self.base_client.get_auth_info()['auth_token']
            _update_token(new_token)
            return ret
        return wrapper


def _update_token(new_token):
    with lockutils.lock('neutron_admin_auth_token_lock'):
        token_store = AdminTokenStore.get()
        token_store.admin_auth_token = new_token


def get_client(context, admin=False):
    if admin or (context.is_admin and not context.auth_token):
        with lockutils.lock('neutron_admin_auth_token_lock'):
            orig_token = AdminTokenStore.get().admin_auth_token
        client = _get_client(orig_token, admin=True)
        return ClientWrapper(client)

    # We got a user token that we can use as-is
    if context.auth_token:
        token = context.auth_token
        return _get_client(token=token)

    # We did not get a user token and we should not be using
    # an admin token so log an error
    raise neutron_client_exc.Unauthorized()
