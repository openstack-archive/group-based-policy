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

from gbpservice._i18n import _LI
from gbpservice.contrib.nfp.config_orchestrator.common import common
from gbpservice.nfp.common import constants as const
from gbpservice.nfp.common import data_formatter as df
from gbpservice.nfp.common import utils
from gbpservice.nfp.core import context as module_context
from gbpservice.nfp.core import log as nfp_logging
from gbpservice.nfp.lib import transport

from neutron_vpnaas.db.vpn import vpn_db

from oslo_log import helpers as log_helpers
import oslo_messaging as messaging

LOG = nfp_logging.getLogger(__name__)

"""
RPC handler for VPN service
"""


class VpnAgent(vpn_db.VPNPluginDb, vpn_db.VPNPluginRpcDbMixin):
    RPC_API_VERSION = '1.0'
    target = messaging.Target(version=RPC_API_VERSION)

    def __init__(self, conf, sc):
        super(VpnAgent, self).__init__()
        self._conf = conf
        self._sc = sc
        self._db_inst = super(VpnAgent, self)

    def _get_vpn_context(self, context, tenant_id, vpnservice_id,
                         ikepolicy_id, ipsecpolicy_id,
                         ipsec_site_conn_id, desc):
        vpnservices = self._get_vpnservices(context, tenant_id,
                                            vpnservice_id, desc)
        ikepolicies = self._get_ikepolicies(context, tenant_id,
                                            ikepolicy_id)
        ipsecpolicies = self._get_ipsecpolicies(context, tenant_id,
                                                ipsecpolicy_id)
        ipsec_site_conns = self._get_ipsec_site_conns(context, tenant_id,
                                                      ipsec_site_conn_id, desc)

        return {'vpnservices': vpnservices,
                'ikepolicies': ikepolicies,
                'ipsecpolicies': ipsecpolicies,
                'ipsec_site_conns': ipsec_site_conns}

    def _context(self, context, tenant_id, resource, resource_data):
        if context.is_admin:
            tenant_id = context.tenant_id
        if resource.lower() == 'ipsec_site_connection':
            vpn_ctx_db = self._get_vpn_context(context,
                                               tenant_id,
                                               resource_data[
                                                   'vpnservice_id'],
                                               resource_data[
                                                   'ikepolicy_id'],
                                               resource_data[
                                                   'ipsecpolicy_id'],
                                               resource_data['id'],
                                               resource_data[
                                                   'description'])
            return vpn_ctx_db
        elif resource.lower() == 'vpn_service':
            return {'vpnservices': [resource_data]}
        else:
            return None

    def _prepare_resource_context_dicts(self, context, tenant_id,
                                        resource, resource_data,
                                        context_resource_data):
        # Prepare context_dict
        ctx_dict = context.to_dict()
        # Collecting db entry required by configurator.
        # Addind service_info to neutron context and sending
        # dictionary format to the configurator.
        db = self._context(context, tenant_id, resource,
                           resource_data)
        rsrc_ctx_dict = copy.deepcopy(ctx_dict)
        rsrc_ctx_dict.update({'service_info': db})
        rsrc_ctx_dict.update({'resource_data': context_resource_data})
        return ctx_dict, rsrc_ctx_dict

    def _get_resource_data(self, description, resource_type):
        resource_data = df.get_network_function_info(description,
                                                     resource_type)
        return resource_data

    def _update_request_data(self, body, description):
        pass

    def _data_wrapper(self, context, tenant_id, nf, **kwargs):
        nfp_context = {}
        description, str_description = (
            utils.get_vpn_description_from_nf(nf))
        description.update({'tenant_id': tenant_id})
        context_resource_data = self._get_resource_data(description,
                                                        const.VPN)
        resource = kwargs['rsrc_type']
        resource_data = kwargs['resource']
        # REVISIT(dpak): We need to avoid resource description
        # dependency in OTC and instead use neutron context description.
        resource_data['description'] = str_description
        if resource.lower() == 'ipsec_site_connection':
            nfp_context = {'network_function_id': nf['id'],
                           'ipsec_site_connection_id': kwargs[
                               'rsrc_id']}

        ctx_dict, rsrc_ctx_dict = self.\
            _prepare_resource_context_dicts(context, tenant_id,
                                            resource, resource_data,
                                            context_resource_data)
        service_vm_context = utils.get_service_vm_context(
                                                description['service_vendor'])
        nfp_context.update({'neutron_context': ctx_dict,
                            'service_vm_context': service_vm_context,
                            'requester': 'nas_service',
                            'logging_context':
                                module_context.get()['log_context']})
        resource_type = 'vpn'
        kwargs.update({'neutron_context': rsrc_ctx_dict})
        body = common.prepare_request_data(nfp_context, resource,
                                           resource_type, kwargs,
                                           description['service_vendor'])
        self._update_request_data(body, description)
        return body

    def _fetch_nf_from_resource_desc(self, desc):
        desc_dict = ast.literal_eval(desc)
        nf_id = desc_dict['network_function_id']
        return nf_id

    @log_helpers.log_method_call
    def vpnservice_updated(self, context, **kwargs):
        nfp_context = module_context.init()
        LOG.info(_LI("Received RPC VPN SERVICE UPDATED with data:%(data)s"),
                 {'data': kwargs})
        # Fetch nf_id from description of the resource
        nf_id = self._fetch_nf_from_resource_desc(kwargs[
            'resource']['description'])
        nfp_context['log_context']['meta_id'] = nf_id
        nf = common.get_network_function_details(context, nf_id)
        reason = kwargs['reason']
        body = self._data_wrapper(context, kwargs[
            'resource']['tenant_id'], nf, **kwargs)
        transport.send_request_to_configurator(self._conf,
                                               context, body,
                                               reason)

    def _proxy_subnet_cidr(self, description):
        tokens = description.split(';')
        return tokens[5].split('=')[1]

    def _get_vpnservices(self, context, tenant_id, vpnservice_id, desc):
        filters = {'tenant_id': [tenant_id],
                   'id': [vpnservice_id]}
        args = {'context': context, 'filters': filters}
        vpnservices = self._db_inst.get_vpnservices(**args)
        for vpnservice in vpnservices:
            vpnservice['description'] = desc
        return vpnservices

    def _get_ikepolicies(self, context, tenant_id, ikepolicy_id):
        filters = {'tenant_id': [tenant_id],
                   'id': [ikepolicy_id]}
        args = {'context': context, 'filters': filters}
        return self._db_inst.get_ikepolicies(**args)

    def _get_ipsecpolicies(self, context, tenant_id, ipsecpolicy_id):
        filters = {'tenant_id': [tenant_id],
                   'id': [ipsecpolicy_id]}
        args = {'context': context, 'filters': filters}
        return self._db_inst.get_ipsecpolicies(**args)

    def _get_ipsec_site_conns(self, context, tenant_id, ipsec_site_conn_id,
                              desc):
        filters = {'tenant_id': [tenant_id],
                   'id': [ipsec_site_conn_id]}
        args = {'context': context, 'filters': filters}
        ipsec_site_conns = self._db_inst.get_ipsec_site_connections(**args)
        for ipsec_site_conn in ipsec_site_conns:
            ipsec_site_conn['description'] = desc
        return ipsec_site_conns
