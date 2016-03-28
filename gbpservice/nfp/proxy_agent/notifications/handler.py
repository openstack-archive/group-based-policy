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


from gbpservice.nfp.lib.transport import RPCClient
from gbpservice.nfp.proxy_agent.lib import topics as a_topics
from neutron import context as n_context

"""Common class for handling notification"""


class NotificationHandler(object):

    def _get_dummy_context(self):
        context = {
            u'read_only': False,
            u'domain': None,
            u'project_name': None,
            u'user_id': None,
            u'show_deleted': False,
            u'roles': [],
            u'user_identity': u'',
            u'project_domain': None,
            u'tenant_name': None,
            u'auth_token': None,
            u'resource_uuid': None,
            u'project_id': None,
            u'tenant_id': None,
            u'is_admin': True,
            u'user': None,
            u'request_id': u'',
            u'user_domain': None,
            u'timestamp': u'',
            u'tenant': None,
            u'user_name': None}
        return context

    def set_firewall_status(self, resource, **kwargs):
        rpcClient = RPCClient(a_topics.FW_NFP_PLUGIN_TOPIC)
        context = kwargs.get('context')
        rpc_ctx = n_context.Context.from_dict(context)
        del kwargs['context']
        rpcClient.cctxt.cast(rpc_ctx, 'set_firewall_status',
                             host=kwargs['host'],
                             firewall_id=kwargs['firewall_id'],
                             status=kwargs['status'])

    def firewall_deleted(self, resource, **kwargs):
        rpcClient = RPCClient(a_topics.FW_NFP_PLUGIN_TOPIC)
        context = kwargs.get('context')
        rpc_ctx = n_context.Context.from_dict(context)
        del kwargs['context']
        rpcClient.cctxt.cast(rpc_ctx, 'firewall_deleted',
                             host=kwargs['host'],
                             firewall_id=kwargs['firewall_id'])

    def update_status(self, resource, **kwargs):
        if resource == 'vpn':
            self._update_status_vpn(**kwargs)
        else:
            self._update_status_lb(**kwargs)

    def _update_status_vpn(self, **kwargs):
        rpcClient = RPCClient(a_topics.VPN_NFP_PLUGIN_TOPIC)
        context = kwargs.get('context')
        rpc_ctx = n_context.Context.from_dict(context)
        del kwargs['context']
        rpcClient.cctxt.cast(rpc_ctx, 'update_status',
                             status=kwargs['status'])

    def _update_status_lb(self, **kwargs):
        rpcClient = RPCClient(a_topics.LB_NFP_PLUGIN_TOPIC)
        rpcClient.cctxt = rpcClient.client.prepare(version='2.0')
        context = kwargs.get('context')
        rpc_ctx = n_context.Context.from_dict(context)
        del kwargs['context']
        rpcClient.cctxt.cast(rpc_ctx, 'update_status',
                             obj_type=kwargs['obj_type'],
                             obj_id=kwargs['obj_id'],
                             status=kwargs['status'])

    def update_pool_stats(self, resource, **kwargs):
        rpcClient = RPCClient(a_topics.LB_NFP_PLUGIN_TOPIC)
        rpcClient.cctxt = rpcClient.client.prepare(version='2.0')
        context = kwargs.get('context')
        rpc_ctx = n_context.Context.from_dict(context)
        del kwargs['context']
        rpcClient.cctxt.cast(rpc_ctx, 'update_pool_stats',
                             pool_id=kwargs['pool_id'],
                             stats=kwargs['stats'],
                             host=kwargs['host'])

    def pool_destroyed(self, resource, **kwargs):
        rpcClient = RPCClient(a_topics.LB_NFP_PLUGIN_TOPIC)
        rpcClient.cctxt = rpcClient.client.prepare(version='2.0')
        context = kwargs.get('context')
        rpc_ctx = n_context.Context.from_dict(context)
        del kwargs['context']
        rpcClient.cctxt.cast(rpc_ctx, 'pool_destroyed',
                             pool_id=kwargs['pool_id'])

    def pool_deployed(self, resource, **kwargs):
        rpcClient = RPCClient(a_topics.LB_NFP_PLUGIN_TOPIC)
        rpcClient.cctxt = rpcClient.client.prepare(version='2.0')
        context = kwargs.get('context')
        rpc_ctx = n_context.Context.from_dict(context)
        del kwargs['context']
        rpcClient.cctxt.cast(rpc_ctx, 'pool_deployed',
                             pool_id=kwargs['pool_id'])

    def network_function_device_notification(self, resource,
                                             kwargs_list, device=True):
        context = self._get_dummy_context()
        topic = [
            a_topics.SERVICE_ORCHESTRATOR_TOPIC,
            a_topics.DEVICE_ORCHESTRATOR_TOPIC][device]
        rpcClient = RPCClient(topic)
        for ele in kwargs_list:
            if 'context' in ele:
                context = ele['context']
                break
        notification_data = {}
        notification_data.\
            update({'resource': resource,
                    'kwargs': kwargs_list})
        rpc_ctx = n_context.Context.from_dict(context)
        rpcClient.cctxt.cast(rpc_ctx, 'network_function_device_notification',
                             notification_data=notification_data)
