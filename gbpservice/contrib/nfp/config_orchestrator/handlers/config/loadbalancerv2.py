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

from neutron_lbaas.db.loadbalancer import loadbalancer_dbv2

from oslo_log import helpers as log_helpers
import oslo_messaging as messaging

LOG = nfp_logging.getLogger(__name__)

"""
RPC handler for Loadbalancer service
"""


class Lbv2Agent(loadbalancer_dbv2.LoadBalancerPluginDbv2):
    target = messaging.Target(version=const.LOADBALANCERV2_RPC_API_VERSION)

    def __init__(self, conf, sc):
        super(Lbv2Agent, self).__init__()
        self._conf = conf
        self._sc = sc
        self._db_inst = super(Lbv2Agent, self)

    def _filter_service_info_with_resource(self, lb_db, core_db):
        updated_db = {'subnets': [],
                      'ports': []}
        for lb in lb_db['loadbalancers']:
            lb_port_id = lb['vip_port_id']
            lb_subnet_id = lb['vip_subnet_id']
            for subnet in core_db['subnets']:
                if subnet['id'] == lb_subnet_id:
                    updated_db['subnets'].append(subnet)
            for port in core_db['ports']:
                if port['id'] == lb_port_id:
                    updated_db['ports'].append(port)
        lb_db.update(updated_db)
        return lb_db

    def _to_api_dict(self, objs):
        ret_list = []
        for obj in objs:
            ret_list.append(obj.to_api_dict())
        return ret_list

    def _get_core_context(self, context, tenant_id):
        filters = {'tenant_id': [tenant_id]}
        core_context_dict = common.get_core_context(context,
                                                    filters,
                                                    self._conf.host)
        del core_context_dict['routers']
        return core_context_dict

    def _get_lb_context(self, context, filters):
        args = {'context': context, 'filters': filters}
        db_data = super(Lbv2Agent, self)
        return {'loadbalancers': self._to_api_dict(
                    db_data.get_loadbalancers(**args)),
                'listeners': self._to_api_dict(
                    db_data.get_listeners(**args)),
                'pools': self._to_api_dict(
                    db_data.get_pools(**args)),
                'pool_members': self._to_api_dict(
                    db_data.get_pool_members(**args)),
                'healthmonitors': self._to_api_dict(
                    db_data.get_healthmonitors(**args))}

    def _context(self, **kwargs):
        context = kwargs.get('context')
        if context.is_admin:
            kwargs['tenant_id'] = context.tenant_id
        core_db = self._get_core_context(context, kwargs['tenant_id'])
        # REVISIT(jiahao): _get_lb_context() fails for flavor_id, disable it
        # for now. Sent the whole core_db to cofigurator
        # lb_db = self._get_lb_context(**kwargs)
        # db = self._filter_service_info_with_resource(lb_db, core_db)
        db = core_db
        return db

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
        if name.lower() == 'loadbalancer':
            lb_id = kwargs['loadbalancer']['id']
            kwargs['loadbalancer'].update({'description': str(description)})
            nfp_context = {'network_function_id': nf['id'],
                           'loadbalancer_id': kwargs['loadbalancer']['id']}
        elif name.lower() == 'listener':
            lb_id = kwargs['listener'].get('loadbalancer_id')
            kwargs['listener']['description'] = str(description)
        elif name.lower() == 'pool':
            lb_id = kwargs['pool'].get('loadbalancer_id')
            kwargs['pool']['description'] = str(description)
        elif name.lower() == 'member':
            pool = kwargs['member'].get('pool')
            if pool:
                lb_id = pool.get('loadbalancer_id')
            kwargs['member']['description'] = str(description)
        elif name.lower() == 'healthmonitor':
            pool = kwargs['healthmonitor'].get('pool')
            if pool:
                lb_id = pool.get('loadbalancer_id')
            kwargs['healthmonitor']['description'] = str(description)
        else:
            kwargs[name.lower()].update({'description': str(description)})
            lb_id = kwargs[name.lower()].get('loadbalancer_id')

        args = {'tenant_id': tenant_id,
                'lb_id': lb_id,
                'context': context,
                'description': str(description)}

        ctx_dict, rsrc_ctx_dict = self._prepare_resource_context_dicts(**args)

        nfp_context.update({'neutron_context': ctx_dict,
                            'requester': 'nas_service',
                            'logging_context':
                                nfp_logging.get_logging_context()})
        resource_type = 'loadbalancerv2'
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

    def _delete(self, context, tenant_id, name, nf, **kwargs):
        body = self._data_wrapper(context, tenant_id, name,
                                  'DELETE', nf, **kwargs)
        transport.send_request_to_configurator(self._conf,
                                               context, body, "DELETE")

    def _fetch_nf_from_resource_desc(self, desc):
        desc_dict = ast.literal_eval(desc)
        nf_id = desc_dict['network_function_id']
        return nf_id

    # REVISIT(jiahao): Argument allocate_vip and
    # delete_vip_port are not implememnted.
    @log_helpers.log_method_call
    def create_loadbalancer(self, context, loadbalancer, driver_name,
                            allocate_vip=True):
        # Fetch nf_id from description of the resource
        nf_id = self._fetch_nf_from_resource_desc(loadbalancer["description"])
        nfp_logging.store_logging_context(meta_id=nf_id)
        nf = common.get_network_function_details(context, nf_id)
        self._post(
            context, loadbalancer['tenant_id'],
            'loadbalancer', nf,
            loadbalancer=loadbalancer, driver_name=driver_name)
        nfp_logging.clear_logging_context()

    @log_helpers.log_method_call
    def delete_loadbalancer(self, context, loadbalancer,
                            delete_vip_port=True):
        # Fetch nf_id from description of the resource
        nf_id = self._fetch_nf_from_resource_desc(loadbalancer["description"])
        nfp_logging.store_logging_context(meta_id=nf_id)
        nf = common.get_network_function_details(context, nf_id)
        self._delete(
            context, loadbalancer['tenant_id'],
            'loadbalancer', nf, loadbalancer=loadbalancer)
        nfp_logging.clear_logging_context()

    @log_helpers.log_method_call
    def create_listener(self, context, listener):
        loadbalancer = listener['loadbalancer']
        # Fetch nf_id from description of the resource
        nf_id = self._fetch_nf_from_resource_desc(loadbalancer["description"])
        nfp_logging.store_logging_context(meta_id=nf_id)
        nf = common.get_network_function_details(context, nf_id)
        self._post(
            context, listener['tenant_id'],
            'listener', nf, listener=listener)
        nfp_logging.clear_logging_context()

    @log_helpers.log_method_call
    def delete_listener(self, context, listener):
        loadbalancer = listener['loadbalancer']
        # Fetch nf_id from description of the resource
        nf_id = self._fetch_nf_from_resource_desc(loadbalancer["description"])
        nfp_logging.store_logging_context(meta_id=nf_id)
        nf = common.get_network_function_details(context, nf_id)
        self._delete(
            context, listener['tenant_id'],
            'listener', nf, listener=listener)
        nfp_logging.clear_logging_context()

    @log_helpers.log_method_call
    def create_pool(self, context, pool):
        loadbalancer = pool['loadbalancer']
        # Fetch nf_id from description of the resource
        nf_id = self._fetch_nf_from_resource_desc(loadbalancer["description"])
        nfp_logging.store_logging_context(meta_id=nf_id)
        nf = common.get_network_function_details(context, nf_id)
        self._post(
            context, pool['tenant_id'],
            'pool', nf, pool=pool)
        nfp_logging.clear_logging_context()

    @log_helpers.log_method_call
    def delete_pool(self, context, pool):
        loadbalancer = pool['loadbalancer']
        # Fetch nf_id from description of the resource
        nf_id = self._fetch_nf_from_resource_desc(loadbalancer["description"])
        nfp_logging.store_logging_context(meta_id=nf_id)
        nf = common.get_network_function_details(context, nf_id)
        self._delete(
            context, pool['tenant_id'],
            'pool', nf, pool=pool)
        nfp_logging.clear_logging_context()

    @log_helpers.log_method_call
    def create_member(self, context, member):
        loadbalancer = member['pool']['loadbalancer']
        # Fetch nf_id from description of the resource
        nf_id = self._fetch_nf_from_resource_desc(loadbalancer["description"])
        nfp_logging.store_logging_context(meta_id=nf_id)
        nf = common.get_network_function_details(context, nf_id)
        self._post(
            context, member['tenant_id'],
            'member', nf, member=member)
        nfp_logging.clear_logging_context()

    @log_helpers.log_method_call
    def delete_member(self, context, member):
        loadbalancer = member['pool']['loadbalancer']
        # Fetch nf_id from description of the resource
        nf_id = self._fetch_nf_from_resource_desc(loadbalancer["description"])
        nfp_logging.store_logging_context(meta_id=nf_id)
        nf = common.get_network_function_details(context, nf_id)
        self._delete(
            context, member['tenant_id'],
            'member', nf, member=member)
        nfp_logging.clear_logging_context()

    @log_helpers.log_method_call
    def create_healthmonitor(self, context, healthmonitor):
        loadbalancer = healthmonitor['pool']['loadbalancer']
        # Fetch nf_id from description of the resource
        nf_id = self._fetch_nf_from_resource_desc(loadbalancer["description"])
        nfp_logging.store_logging_context(meta_id=nf_id)
        nf = common.get_network_function_details(context, nf_id)
        self._post(
            context, healthmonitor['tenant_id'],
            'healthmonitor', nf, healthmonitor=healthmonitor)
        nfp_logging.clear_logging_context()

    @log_helpers.log_method_call
    def delete_healthmonitor(self, context, healthmonitor):
        loadbalancer = healthmonitor['pool']['loadbalancer']
        # Fetch nf_id from description of the resource
        nf_id = self._fetch_nf_from_resource_desc(loadbalancer["description"])
        nfp_logging.store_logging_context(meta_id=nf_id)
        nf = common.get_network_function_details(context, nf_id)
        self._delete(
            context, healthmonitor['tenant_id'],
            'healthmonitor', nf, healthmonitor=healthmonitor)
        nfp_logging.clear_logging_context()

    # REVISIT(jiahao): L7policy support not implemented
    # disable L7policy
    # def create_l7policy(self, context, l7policy):
    #     self._post(
    #         context, l7policy['tenant_id'],
    #         'l7policy', l7policy=l7policy)
    #
    # def delete_l7policy(self, context, l7policy):
    #     self._delete(
    #         context, l7policy['tenant_id'],
    #         'l7policy', l7policy=l7policy)
    #
    # def create_l7policy_rule(self, context, rule, l7policy_id):
    #     self._post(
    #         context, rule['tenant_id'],
    #         'rule', rule=rule)
    #
    # def delete_l7policy_rule(self, context, rule):
    #     self._delete(
    #         context, rule['tenant_id'],
    #         'rule', rule=rule)
    #
    # def _get_lb_context(self, context, filters):
    #     args = {'context': context, 'filters': filters}
    #     db_data = super(Lbv2Agent, self)
    #     return {'loadbalancers': db_data.get_loadbalancers(**args),
    #             'listeners': db_data.get_listeners(**args),
    #             'pools': db_data.get_pools(**args),
    #             'pool_members': db_data.get_pool_members(**args),
    #             'healthmonitors': db_data.get_healthmonitors(**args),
    #             'l7policies': db_data.get_l7policies(**args),
    #             'l7policy_rules': db_data.get_l7policy_rules(**args)}
