# Copyright 2012 OpenStack Foundation
# All Rights Reserved
# Copyright (c) 2012 NEC Corporation
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


from neutron.openstack.common import lockutils
from neutron.openstack.common import log as logging
from neutronclient.common import exceptions as neutron_client_exc
from neutronclient.v2_0 import client as clientv20
from oslo.config import cfg

LOG = logging.getLogger(__name__)

neutron_opts = [
    cfg.StrOpt('url',
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
    # TODO(berrange) temporary hack until Neutron can pass over the
    # name of the OVS bridge it is configured with
    cfg.StrOpt('ovs_bridge',
               default='br-int',
               help='Name of Integration Bridge used by Open vSwitch'),
    cfg.IntOpt('extension_sync_interval',
               default=600,
               help='Number of seconds before querying neutron for '
                    'extensions'),
    cfg.StrOpt('ca_certificates_file',
               help='Location of CA certificates file to use for '
                    'neutron client requests.'),
    cfg.BoolOpt('allow_duplicate_networks',
                default=False,
                help='Allow an instance to have multiple vNICs attached to '
                     'the same Neutron network.'),
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
        'endpoint_url': CONF.neutron.url,
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
    # NOTE(Yi): As copied from Nova neutron client wrapper,
    # in the case where no auth_token is present
    # we allow use of neutron admin tenant credentials if
    # it is an admin context.
    # This is to support some services (metadata API) where
    # an admin context is used without an auth token.
    #
    # REVISIT(Yi): Do we need this for group based policy?
    if admin or (context.is_admin and not context.auth_token):
        with lockutils.lock('neutron_admin_auth_token_lock'):
            orig_token = AdminTokenStore.get().admin_auth_token
        client = _get_client(orig_token, admin=True)
        return ClientWrapper(client)

    # We got a user token that we can use that as-is
    if context.auth_token:
        token = context.auth_token
        return _get_client(token=token)

    # We did not get a user token and we should not be using
    # an admin token so log an error
    raise neutron_client_exc.Unauthorized()


class API(object):
    """API for interacting with the neutron 2.x API."""

    def _create_resource(self, context, resource, attrs):
        action = 'create_' + resource
        neutron = get_client(context)
        obj_creator = getattr(neutron, action)
        return obj_creator(attrs)[resource]

    def _show_resource(self, context, resource, resource_id):
        action = 'show_' + resource
        neutron = get_client(context)
        obj_method = getattr(neutron, action)
        return obj_method(resource_id)[resource]

    def _list_resources(self, context, resource, filters={}):
        resources = resource + 's'
        action = 'list_' + resources
        neutron = get_client(context)
        obj_lister = getattr(neutron, action)
        return obj_lister(**filters)[resources]

    def _update_resource(self, context, resource, resource_id, attrs):
        action = 'update_' + resource
        neutron = get_client(context)
        obj_updater = getattr(neutron, action)
        return obj_updater(resource_id, attrs)[resource]

    def _delete_resource(self, context, resource, resource_id):
        action = 'delete_' + resource
        neutron = get_client(context)
        obj_deleter = getattr(neutron, action)
        obj_deleter(resource_id)

    def create_network(self, context, network):
        return self._create_resource(context, 'network', network)

    def show_network(self, context, net_id):
        return self._show_resource(context, 'network', net_id)

    def list_networks(self, context, filters={}):
        return self._list_resources(context, 'network', filters)

    def update_network(self, context, net_id, network):
        return self._update_resource(context, 'network', net_id, network)

    def delete_network(self, context, net_id):
        self._delete_resource(context, 'network', net_id)

    def create_subnet(self, context, subnet):
        return self._create_resource(context, 'subnet', subnet)

    def show_subnet(self, context, subnet_id):
        return self._show_resource(context, 'subnet', subnet_id)

    def list_subnets(self, context, filters={}):
        return self._list_resources(context, 'subnet', filters)

    def update_subnet(self, context, subnet_id, subnet):
        return self._update_resource(context, 'subnet', subnet_id, subnet)

    def delete_subnet(self, context, subnet_id):
        self._delete_resource(context, 'subnet', subnet_id)

    def create_port(self, context, port):
        return self._create_resource(context, 'port', port)

    def show_port(self, context, port_id):
        return self._show_resource(context, 'port', port_id)

    def list_ports(self, context, filters={}):
        return self._list_resources(context, 'port', filters)

    def update_port(self, context, port_id, port):
        return self._update_resource(context, 'port', port_id, port)

    def delete_port(self, context, port_id):
        self._delete_resource(context, 'port', port_id)

    def create_security_group(self, context, sg):
        return self._create_resource(context, 'security_group', sg)

    def show_security_group(self, context, sg_id):
        return self._show_resource(context, 'security_group', sg_id)

    def list_security_groups(self, context, filters={}):
        return self._list_resources(context, 'security_group', filters)

    def update_security_group(self, context, sg_id, sg):
        return self._update_resource(context, 'security_group', sg_id, sg)

    def delete_security_group(self, context, sg_id):
        self._delete_resource(context, 'security_group', sg_id)

    def create_security_group_rule(self, context, rule):
        return self._create_resource(context, 'security_group_rule', rule)

    def show_security_group_rule(self, context, rule_id):
        return self._show_resource(context, 'security_group_rule', rule_id)

    def list_security_group_rules(self, context, filters={}):
        return self._list_resources(context, 'security_group_rule', filters)

    def update_security_group_rule(self, context, rule_id, rule):
        return self._update_resource(context,
                                     'security_group_rule',
                                     rule_id,
                                     rule)

    def delete_security_group_rule(self, context, rule_id):
        self._delete_resource(context, 'security_group_rule', rule_id)

    def create_router(self, context, router):
        return self._create_resource(context, 'router', router)

    def show_router(self, context, router_id):
        return self._show_resource(context, 'router', router_id)

    def list_routers(self, context, filters={}):
        return self._list_resources(context, 'router', filters)

    def update_router(self, context, router_id, router):
        return self._update_resource(context, 'router', router_id, router)

    def delete_router(self, context, router_id):
        self._delete_resource(context, 'router', router_id)

    def add_router_interface(self, context, router_id, interface):
        return get_client(context).add_interface_router(router_id, interface)

    def remove_router_interface(self, context, router_id, interface):
        return get_client(context).remove_interface_router(router_id,
                                                           interface)
