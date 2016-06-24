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

import ast
import copy

from gbpservice.contrib.nfp.config_orchestrator.common import common
from gbpservice.nfp.common import constants as const
from gbpservice.nfp.core import log as nfp_logging
from gbpservice.nfp.lib import transport

from neutron_lbaas.db.loadbalancer import loadbalancer_db

from oslo_log import helpers as log_helpers
import oslo_messaging as messaging

LOG = nfp_logging.getLogger(__name__)

"""
RPC handler for Loadbalancer service
"""


class LbAgent(loadbalancer_db.LoadBalancerPluginDb):
    RPC_API_VERSION = const.LOADBALANCER_RPC_API_VERSION
    target = messaging.Target(version=RPC_API_VERSION)

    def __init__(self, conf, sc):
        super(LbAgent, self).__init__()
        self._conf = conf
        self._sc = sc
        self._db_inst = super(LbAgent, self)

    def _get_pools(self, **kwargs):
        context = kwargs.get('context')
        filters = {'tenant_id': [kwargs.get('tenant_id')],
                   'id': [kwargs.get('pool_id')]}
        args = {'context': context, 'filters': filters}
        pools = self._db_inst.get_pools(**args)
        for pool in pools:
            pool['description'] = kwargs.get('description')
        return pools

    def _get_vips(self, **kwargs):
        context = kwargs.get('context')
        filters = {'tenant_id': [kwargs.get('tenant_id')],
                   'pool_id': [kwargs.get('pool_id')]}
        args = {'context': context, 'filters': filters}
        vips = self._db_inst.get_vips(**args)
        for vip in vips:
            vip['description'] = kwargs.get('description')
        return vips

    def _get_members(self, **kwargs):
        context = kwargs.get('context')
        filters = {'tenant_id': [kwargs.get('tenant_id')],
                   'pool_id': [kwargs.get('pool_id')]}
        args = {'context': context, 'filters': filters}
        members = self._db_inst.get_members(**args)
        for member in members:
            member.update({'description': kwargs.get('description')})
        return members

    def _get_health_monitors(self, **kwargs):
        context = kwargs.get('context')
        filters = {'tenant_id': [kwargs.get('tenant_id')],
                   'pool_id': [kwargs.get('pool_id')]}
        args = {'context': context, 'filters': filters}
        health_monitors = self._db_inst.get_health_monitors(**args)
        for health_monitor in health_monitors:
            health_monitor.update({'description': kwargs.get('description')})
        return health_monitors

    def _get_lb_context(self, **kwargs):
        pools = self._get_pools(**kwargs)
        vips = self._get_vips(**kwargs)
        members = self._get_members(**kwargs)
        healthmonitors = self._get_health_monitors(**kwargs)
        return {'pools': pools,
                'vips': vips,
                'members': members,
                'health_monitors': healthmonitors}

    def _context(self, **kwargs):
        context = kwargs.get('context')
        if context.is_admin:
            kwargs['tenant_id'] = context.tenant_id
        lb_db = self._get_lb_context(**kwargs)
        return lb_db

    def _prepare_resource_context_dicts(self, **kwargs):
        # Prepare context_dict
        context = kwargs.get('context')
        ctx_dict = context.to_dict()
        # Collecting db entry required by configurator.
        # Addind service_info to neutron context and sending
        # dictionary format to the configurator.
        db = self._context(**kwargs)
        rsrc_ctx_dict = copy.deepcopy(ctx_dict)
        rsrc_ctx_dict.update({'service_info': db})
        return ctx_dict, rsrc_ctx_dict

    def _data_wrapper(self, context, tenant_id, name, reason, nf, **kwargs):
        nfp_context = {}
        description = ast.literal_eval((nf['description'].split('\n'))[1])
        if name.lower() == 'pool_health_monitor':
            pool_id = kwargs.get('pool_id')
            kwargs['health_monitor'].update({'description': str(description)})
        elif name.lower() == 'pool':
            pool_id = kwargs['pool'].get('id')
            kwargs['pool']['description'] = str(description)
        elif name.lower() == 'vip':
            pool_id = kwargs['vip'].get('pool_id')
            kwargs['vip']['description'] = str(description)
            nfp_context = {'network_function_id': nf['id'],
                           'vip_id': kwargs['vip']['id']}
        else:
            kwargs[name.lower()].update({'description': str(description)})
            pool_id = kwargs[name.lower()].get('pool_id')

        args = {'tenant_id': tenant_id,
                'pool_id': pool_id,
                'context': context,
                'description': str(description)}
        ctx_dict, rsrc_ctx_dict = self._prepare_resource_context_dicts(
            **args)

        nfp_context.update({'neutron_context': ctx_dict,
                            'requester': 'nas_service',
                            'logging_context':
                                nfp_logging.get_logging_context()})
        resource_type = 'loadbalancer'
        resource = name
        resource_data = {'neutron_context': rsrc_ctx_dict}
        resource_data.update(**kwargs)
        body = common.prepare_request_data(nfp_context, resource,
                                           resource_type, resource_data,
                                           description['service_vendor'])
        return body

    def _post(self, context, tenant_id, name, nf, **kwargs):
        body = self._data_wrapper(context, tenant_id, name,
                                  'CREATE', nf, **kwargs)
        transport.send_request_to_configurator(self._conf,
                                               context, body, "CREATE")

    def _put(self, context, tenant_id, name, nf, **kwargs):
        body = self._data_wrapper(context, tenant_id, name,
                                  'UPDATE', nf, **kwargs)
        transport.send_request_to_configurator(self._conf,
                                               context, body, "UPDATE")

    def _delete(self, context, tenant_id, name, nf, **kwargs):
        body = self._data_wrapper(context, tenant_id, name,
                                  'DELETE', nf, **kwargs)
        transport.send_request_to_configurator(self._conf,
                                               context, body, "DELETE")

    def _get_pool(self, context, pool_id):
        pool = None
        try:
            pool = self._db_inst.get_pool(context, pool_id)
        except Exception as e:
            msg = ("%s" % (e))
            LOG.error(msg)
        return pool

    def _fetch_nf_from_resource_desc(self, desc):
        desc_dict = ast.literal_eval(desc)
        nf_id = desc_dict['network_function_id']
        return nf_id

    @log_helpers.log_method_call
    def create_vip(self, context, vip):
        # Fetch nf_id from description of the resource
        nf_id = self._fetch_nf_from_resource_desc(vip["description"])
        nfp_logging.store_logging_context(meta_id=nf_id)
        nf = common.get_network_function_details(context, nf_id)
        self._post(context, vip['tenant_id'], 'vip', nf, vip=vip)
        nfp_logging.clear_logging_context()

    @log_helpers.log_method_call
    def update_vip(self, context, old_vip, vip):
        # Fetch nf_id from description of the resource
        nf_id = self._fetch_nf_from_resource_desc(vip["description"])
        nfp_logging.store_logging_context(meta_id=nf_id)
        nf = common.get_network_function_details(context, nf_id)
        self._put(context, vip['tenant_id'], 'vip', nf, olf_vip=old_vip,
                  vip=vip)
        nfp_logging.clear_logging_context()

    @log_helpers.log_method_call
    def delete_vip(self, context, vip):
        # Fetch nf_id from description of the resource
        nf_id = self._fetch_nf_from_resource_desc(vip["description"])
        nfp_logging.store_logging_context(meta_id=nf_id)
        nf = common.get_network_function_details(context, nf_id)
        self._delete(context, vip['tenant_id'], 'vip', nf, vip=vip)
        nfp_logging.clear_logging_context()

    @log_helpers.log_method_call
    def create_pool(self, context, pool, driver_name):
        # Fetch nf_id from description of the resource
        nf_id = self._fetch_nf_from_resource_desc(pool["description"])
        nfp_logging.store_logging_context(meta_id=nf_id)
        nf = common.get_network_function_details(context, nf_id)
        self._post(
            context, pool['tenant_id'],
            'pool', nf, pool=pool, driver_name=driver_name)
        nfp_logging.clear_logging_context()

    @log_helpers.log_method_call
    def update_pool(self, context, old_pool, pool):
        # Fetch nf_id from description of the resource
        nf_id = self._fetch_nf_from_resource_desc(pool["description"])
        nfp_logging.store_logging_context(meta_id=nf_id)
        nf = common.get_network_function_details(context, nf_id)
        self._put(context, pool['tenant_id'], 'pool', nf, old_pool=old_pool,
                  pool=pool)
        nfp_logging.clear_logging_context()

    @log_helpers.log_method_call
    def delete_pool(self, context, pool):
        # Fetch nf_id from description of the resource
        nf_id = self._fetch_nf_from_resource_desc(pool["description"])
        nfp_logging.store_logging_context(meta_id=nf_id)
        nf = common.get_network_function_details(context, nf_id)
        self._delete(context, pool['tenant_id'], 'pool', nf, pool=pool)
        nfp_logging.clear_logging_context()

    @log_helpers.log_method_call
    def create_member(self, context, member):
        # Fetch pool from pool_id
        pool = self._get_pool(context, member['pool_id'])
        # Fetch nf_id from description of the resource
        nf_id = self._fetch_nf_from_resource_desc(pool["description"])
        nfp_logging.store_logging_context(meta_id=nf_id)
        nf = common.get_network_function_details(context, nf_id)
        self._post(context, member['tenant_id'], 'member', nf, member=member)
        nfp_logging.clear_logging_context()

    @log_helpers.log_method_call
    def update_member(self, context, old_member, member):
        # Fetch pool from pool_id
        pool = self._get_pool(context, member['pool_id'])
        # Fetch nf_id from description of the resource
        nf_id = self._fetch_nf_from_resource_desc(pool["description"])
        nfp_logging.store_logging_context(meta_id=nf_id)
        nf = common.get_network_function_details(context, nf_id)
        self._put(context, member['tenant_id'], 'member', nf,
                  old_member=old_member, member=member)
        nfp_logging.clear_logging_context()

    @log_helpers.log_method_call
    def delete_member(self, context, member):
        # Fetch pool from pool_id
        pool = self._get_pool(context, member['pool_id'])
        # Fetch nf_id from description of the resource
        nf_id = self._fetch_nf_from_resource_desc(pool["description"])
        nfp_logging.store_logging_context(meta_id=nf_id)
        nf = common.get_network_function_details(context, nf_id)
        self._delete(
            context, member['tenant_id'], 'member',
            nf, member=member)
        nfp_logging.clear_logging_context()

    @log_helpers.log_method_call
    def create_pool_health_monitor(self, context, health_monitor, pool_id):
        # Fetch pool from pool_id
        pool = self._get_pool(context, pool_id)
        # Fetch nf_id from description of the resource
        nf_id = self._fetch_nf_from_resource_desc(pool["description"])
        nfp_logging.store_logging_context(meta_id=nf_id)
        nf = common.get_network_function_details(context, nf_id)
        self._post(context, health_monitor[
            'tenant_id'], 'pool_health_monitor',
            nf, health_monitor=health_monitor, pool_id=pool_id)
        nfp_logging.clear_logging_context()

    @log_helpers.log_method_call
    def update_pool_health_monitor(self, context, old_health_monitor,
                                   health_monitor, pool_id):
        # Fetch pool from pool_id
        pool = self._get_pool(context, pool_id)
        # Fetch nf_id from description of the resource
        nf_id = self._fetch_nf_from_resource_desc(pool["description"])
        nfp_logging.store_logging_context(meta_id=nf_id)
        nf = common.get_network_function_details(context, nf_id)
        self._put(context, health_monitor[
            'tenant_id'], 'pool_health_monitor',
            nf, old_health_monitor=old_health_monitor,
            health_monitor=health_monitor, pool_id=pool_id)
        nfp_logging.clear_logging_context()

    @log_helpers.log_method_call
    def delete_pool_health_monitor(self, context, health_monitor, pool_id):
        # Fetch pool from pool_id
        pool = self._get_pool(context, pool_id)
        # Fetch nf_id from description of the resource
        nf_id = self._fetch_nf_from_resource_desc(pool["description"])
        nfp_logging.store_logging_context(meta_id=nf_id)
        nf = common.get_network_function_details(context, nf_id)
        self._delete(
            context, health_monitor['tenant_id'], 'pool_health_monitor',
            nf, health_monitor=health_monitor, pool_id=pool_id)
        nfp_logging.clear_logging_context()
