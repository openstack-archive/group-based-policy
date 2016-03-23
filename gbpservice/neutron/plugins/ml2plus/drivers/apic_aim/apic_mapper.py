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

import contextlib
import re

from neutron._i18n import _LI

LOG = None


NAMING_STRATEGY_UUID = 'use_uuid'
NAMING_STRATEGY_NAMES = 'use_name'
NAME_TYPE_TENANT = 'tenant'
NAME_TYPE_NETWORK = 'network'
NAME_TYPE_SUBNET = 'subnet'
NAME_TYPE_PORT = 'port'
NAME_TYPE_ROUTER = 'router'
NAME_TYPE_APP_PROFILE = 'app-profile'
NAME_TYPE_POLICY_TARGET_GROUP = 'policy_target_group'
NAME_TYPE_L3_POLICY = 'l3_policy'
NAME_TYPE_L2_POLICY = 'l2_policy'
NAME_TYPE_POLICY_RULE_SET = 'policy_rule_set'
NAME_TYPE_POLICY_RULE = 'policy_rule'
NAME_TYPE_EXTERNAL_SEGMENT = 'external_segment'
NAME_TYPE_EXTERNAL_POLICY = 'external_policy'
NAME_TYPE_NAT_POOL = 'nat_pool'

NAME_TYPES = set([
    NAME_TYPE_TENANT, NAME_TYPE_NETWORK, NAME_TYPE_SUBNET,
    NAME_TYPE_PORT, NAME_TYPE_ROUTER, NAME_TYPE_APP_PROFILE,
    NAME_TYPE_POLICY_TARGET_GROUP, NAME_TYPE_L3_POLICY,
    NAME_TYPE_L2_POLICY, NAME_TYPE_POLICY_RULE_SET,
    NAME_TYPE_POLICY_RULE, NAME_TYPE_EXTERNAL_SEGMENT,
    NAME_TYPE_EXTERNAL_POLICY, NAME_TYPE_NAT_POOL,
])

MAX_APIC_NAME_LENGTH = 46


# TODO(rkukura): This is name mapper is copied from the apicapi repo,
# and modified to pass in resource names rather than calling the core
# plugin to get them, and to use the existing DB session. We need
# decide whether to make these changes in apicapi (maybe on a branch),
# move this some other repo, or keep it here. The changes are not
# backwards compatible. The implementation should also be cleaned up
# and simplified. For example, sessions should be passed in place of
# contexts, and the core plugin calls eliminated.


@contextlib.contextmanager
def mapper_context(context):
    if context and (not hasattr(context, '_plugin_context') or
                    context._plugin_context is None):
        context._plugin_context = context  # temporary circular reference
        yield context
        context._plugin_context = None     # break circular reference
    else:
        yield context


def truncate(string, max_length):
    if max_length < 0:
        return ''
    return string[:max_length] if len(string) > max_length else string


class APICNameMapper(object):
    def __init__(self, db, log, keyclient, keystone_authtoken,
                 strategy=NAMING_STRATEGY_UUID, min_suffix=None):
        self.db = db
        self.strategy = strategy
        self.keystone = None
        self.keyclient = keyclient
        self.keystone_authtoken = keystone_authtoken
        self.tenants = {}
        self.min_suffix = min_suffix if min_suffix is not None else 5
        global LOG
        LOG = log.getLogger(__name__)

    def mapper(name_type):
        """Wrapper to land all the common operations between mappers."""
        def wrap(func):
            def inner(inst, session, resource_id, resource_name=None,
                      remap=False, prefix='', existing=False):
                if existing:
                    return ApicName(resource_id, resource_id, session, inst,
                                    func.__name__, existing=True)
                if remap:
                    inst.db.delete_apic_name(session, resource_id)
                else:
                    saved_name = inst.db.get_apic_name(session,
                                                       resource_id,
                                                       name_type)
                    if saved_name:
                        result = saved_name[0]
                        if prefix:
                            result = prefix + result
                            result = truncate(result, MAX_APIC_NAME_LENGTH)
                        return ApicName(result, resource_id, session,
                                        inst, func.__name__, prefix=prefix)
                name = ''
                try:
                    name = func(inst, session, resource_id, resource_name)
                except Exception as e:
                    LOG.warn(("Exception in looking up name %s"), name_type)
                    LOG.error(e.message)

                purged_id = re.sub(r"-+", "-", resource_id)
                result = purged_id[:inst.min_suffix]
                if name:
                    name = re.sub(r"-+", "-", name)
                    if inst.strategy == NAMING_STRATEGY_NAMES:
                        result = name
                    elif inst.strategy == NAMING_STRATEGY_UUID:
                        # Keep as many uuid chars as possible
                        id_suffix = "_" + result
                        max_name_length = MAX_APIC_NAME_LENGTH - len(id_suffix)
                        result = truncate(name, max_name_length) + id_suffix

                    result = truncate(result, MAX_APIC_NAME_LENGTH)
                    # Remove forbidden whitespaces
                    result = result.replace(' ', '')
                    if inst.strategy == NAMING_STRATEGY_UUID:
                        result = inst._grow_id_if_needed(
                            session, purged_id, name_type, result,
                            start=inst.min_suffix)
                else:
                    result = purged_id

                inst.db.update_apic_name(session, resource_id,
                                         name_type, result)
                if prefix:
                    result = prefix + result
                    result = truncate(result, MAX_APIC_NAME_LENGTH)
                return ApicName(result, resource_id, session, inst,
                                func.__name__, prefix=prefix)
            return inner
        return wrap

    def _grow_id_if_needed(self, session, resource_id, name_type,
                           current_result, start=0):
        result = current_result
        if result.endswith('_'):
            result = result[:-1]
        try:
            x = 0
            while True:
                if self.db.get_filtered_apic_names(session,
                                                   neutron_type=name_type,
                                                   apic_name=result):
                    if x == 0 and start == 0:
                        result += '_'
                    # This name overlaps, add more ID characters
                    result += resource_id[start + x]
                    x += 1
                else:
                    break
        except AttributeError:
            LOG.info(_LI("Current DB API doesn't support "
                         "get_filtered_apic_names."))
        except IndexError:
            LOG.debug("Ran out of ID characters.")
        return result

    @mapper(NAME_TYPE_TENANT)
    def tenant(self, session, tenant_id, tenant_name=None):
        if tenant_id in self.tenants:
            tenant_name = self.tenants.get(tenant_id)
        else:
            if self.keystone is None:
                try:
                    keystone_conf = self.keystone_authtoken
                    auth_url = self._get_keystone_url(keystone_conf)
                    user = (keystone_conf.get('admin_user') or
                            keystone_conf.username)
                    pw = (keystone_conf.get('admin_password') or
                          keystone_conf.password)
                    tenant = (keystone_conf.get('admin_tenant_name') or
                              keystone_conf.project_name)
                    self.keystone = self.keyclient.Client(
                        username=user, password=pw, tenant_name=tenant,
                        auth_url=auth_url)
                except Exception as ex:
                    LOG.exception(ex)
                    return tenant_id

            for tenant in self.keystone.tenants.list():
                self.tenants[tenant.id] = tenant.name
                if tenant.id == tenant_id:
                    tenant_name = tenant.name
        return tenant_name

    # REVISIT(rkukura): The get_network() call should be eliminated,
    # making this function nothing but something to be decorated.
    @mapper(NAME_TYPE_NETWORK)
    def network(self, session, network_id, network_name=None):
        return network_name

    @mapper(NAME_TYPE_SUBNET)
    def subnet(self, context, subnet_id):
        subnet = context._plugin.get_subnet(context._plugin_context, subnet_id)
        subnet_name = subnet['name']
        return subnet_name

    @mapper(NAME_TYPE_PORT)
    def port(self, context, port_id):
        port = context._plugin.get_port(context._plugin_context, port_id)
        port_name = port['name']
        return port_name

    @mapper(NAME_TYPE_ROUTER)
    def router(self, context, router_id):
        return context._plugin_context.session.execute(
            'SELECT * from routers WHERE id = :id',
            {'id': router_id}).fetchone().name

    @mapper(NAME_TYPE_POLICY_TARGET_GROUP)
    def policy_target_group(self, context, policy_target_group_id):
        epg = context._plugin.get_policy_target_group(context._plugin_context,
                                                 policy_target_group_id)
        return epg['name']

    @mapper(NAME_TYPE_L3_POLICY)
    def l3_policy(self, context, l3_policy_id):
        l3_policy = context._plugin.get_l3_policy(context._plugin_context,
                                                  l3_policy_id)
        return l3_policy['name']

    @mapper(NAME_TYPE_L2_POLICY)
    def l2_policy(self, context, l2_policy_id):
        l2_policy = context._plugin.get_l2_policy(context._plugin_context,
                                                  l2_policy_id)
        return l2_policy['name']

    @mapper(NAME_TYPE_POLICY_RULE_SET)
    def policy_rule_set(self, context, policy_rule_set_id):
        policy_rule_set = context._plugin.get_policy_rule_set(
            context._plugin_context, policy_rule_set_id)
        return policy_rule_set['name']

    @mapper(NAME_TYPE_POLICY_RULE)
    def policy_rule(self, context, policy_rule_id):
        policy_rule = context._plugin.get_policy_rule(context._plugin_context,
                                                      policy_rule_id)
        return policy_rule['name']

    @mapper(NAME_TYPE_EXTERNAL_SEGMENT)
    def external_segment(self, context, external_segment_id):
        external_segment = context._plugin.get_external_segment(
            context._plugin_context, external_segment_id)
        return external_segment['name']

    @mapper(NAME_TYPE_EXTERNAL_POLICY)
    def external_policy(self, context, external_policy_id):
        external_policy = context._plugin.get_external_policy(
            context._plugin_context, external_policy_id)
        return external_policy['name']

    @mapper(NAME_TYPE_NAT_POOL)
    def nat_pool(self, context, nat_pool_id):
        nat_pool = context._plugin.get_nat_pool(context._plugin_context,
                                                nat_pool_id)
        return nat_pool['name']

    def pre_existing(self, context, object_id):
        return ApicName(object_id, object_id, context, self,
                        self.pre_existing.__name__, existing=True)

    def echo(self, context, object_id):
        return ApicName(object_id, object_id, context, self,
                        self.echo.__name__)

    def app_profile(self, context, app_profile, remap=False):
        if remap:
            self.db.delete_apic_name(context.session, 'app_profile')
        # Check if a profile is already been used
        saved_name = self.db.get_apic_name(context.session, 'app_profile',
                                           NAME_TYPE_APP_PROFILE)
        if not saved_name:
            self.db.update_apic_name(context.session, 'app_profile',
                                     NAME_TYPE_APP_PROFILE, app_profile)
            result = app_profile
        else:
            result = saved_name[0]
        return ApicName(result, app_profile, None,
                        self, self.app_profile.__name__)

    def delete_apic_name(self, session, object_id):
        self.db.delete_apic_name(session, object_id)

    def is_valid_name_type(self, name_type):
        return name_type in NAME_TYPES

    def _get_keystone_url(self, keystone_conf):
        if keystone_conf.get('auth_uri'):
            auth_url = keystone_conf.auth_uri.rstrip('/')
            if not auth_url.endswith('/v2.0'):
                auth_url += '/v2.0'
        else:
            auth_url = ('%s://%s:%s/v2.0' % (
                keystone_conf.auth_protocol,
                keystone_conf.auth_host,
                keystone_conf.auth_port))
        return auth_url + '/'


class ApicName(object):

    def __init__(self, mapped, uid='', session=None, inst=None, fname='',
                 prefix='', existing=False):
        self.uid = uid
        self.session = session
        self.inst = inst
        self.fname = fname
        self.value = mapped
        self.prefix = prefix
        self.existing = existing

    def renew(self):
        if self.uid and self.inst and self.fname:
            # temporary circular reference
            with mapper_context(self.context) as ctx:
                result = getattr(self.inst, self.fname)(
                    ctx, self.uid, remap=True, prefix=self.prefix)
            self.value = result.value
            return self

    def __str__(self):
        return self.value
