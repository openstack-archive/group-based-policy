# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import copy
import os
import six
import webob.exc

import mock
from neutron.api import extensions
from neutron import context
from neutron import manager
from neutron.plugins.common import constants
from neutron import policy
from neutron.services.trunk.rpc import server as trunk_server
from neutron.tests.unit.api import test_extensions
from neutron.tests.unit.db import test_db_base_plugin_v2
from oslo_utils import importutils
from oslo_utils import uuidutils

from gbpservice.neutron.db import all_models  # noqa
from gbpservice.neutron.db.grouppolicy import group_policy_db as gpdb
from gbpservice.neutron.db import servicechain_db as svcchain_db
from gbpservice.neutron.extensions import group_policy as gpolicy
from gbpservice.neutron.extensions import servicechain as service_chain
from gbpservice.neutron.services.grouppolicy.common import (
    constants as gp_constants)
import gbpservice.neutron.tests
from gbpservice.neutron.tests.unit import common as cm
from networking_sfc.extensions import flowclassifier
from networking_sfc.extensions import sfc


JSON_FORMAT = 'json'
_uuid = uuidutils.generate_uuid
TESTDIR = os.path.dirname(os.path.abspath(gbpservice.neutron.tests.__file__))
ETCDIR = os.path.join(TESTDIR, 'etc')
CHAIN_TENANT_ID = 'chain_owner'
AGENT_TYPE = 'Open vSwitch agent'
AGENT_CONF = {'alive': True, 'binary': 'somebinary',
              'topic': 'sometopic', 'agent_type': AGENT_TYPE,
              'configurations': {'bridge_mappings': {'physnet1': 'br-eth1'}}}

# There are some Neutron extensions which are designated as "required" for
# supporting the extensions which are needed to run the GBP UTs.
# For example, when using the router plugin, it supports the
# "router_availability' extension which requires the
# "availability_zone" extension, and which in turn requires the "agent"
# extension. For us to be able to use that router plugin as is, we add
# those required extensions to the list of "supported_extension_aliases"
# for our test plugins. This keeps the extensions framework happy and we
# it shouldn't cause a problem since we dont actually exercise those
# extensions. The following list contains all such extensions.
UNSUPPORTED_REQUIRED_EXTS = ['availability_zone', 'agent']


class ApiManagerMixin(object):

    agent_conf = AGENT_CONF

    def _test_list_resources(self, resource, items,
                             neutron_context=None,
                             query_params=None):
        resource_plural = cm.get_resource_plural(resource)

        res = self._list(resource_plural,
                         neutron_context=neutron_context,
                         query_params=query_params)
        resource = resource.replace('-', '_')
        self.assertEqual(sorted([i['id'] for i in res[resource_plural]]),
                         sorted([i[resource]['id'] for i in items]))

    def _create_resource(self, type, expected_res_status=None,
                         is_admin_context=False, deserialize=True, **kwargs):
        plural = cm.get_resource_plural(type)
        type = type.split('/')[-1]
        try:
            defaults = getattr(cm, 'get_create_%s_default_attrs' % type)()
            defaults.update(kwargs)
        except AttributeError:
            defaults = kwargs
        data = {type: {'tenant_id': self._tenant_id}}
        data[type].update(defaults)
        req = self.new_create_request(plural, data, self.fmt)
        req.environ['neutron.context'] = context.Context(
            '', kwargs.get('tenant_id', self._tenant_id) if not
            is_admin_context else self._tenant_id, is_admin_context)
        res = req.get_response(self.ext_api)
        if expected_res_status:
            self.assertEqual(expected_res_status, res.status_int)
        elif deserialize and res.status_int >= webob.exc.HTTPClientError.code:
            raise webob.exc.HTTPClientError(code=res.status_int)

        return self.deserialize(self.fmt, res) if deserialize else res

    def _update_resource(self, id, type, expected_res_status=None,
                         is_admin_context=False, api=None, deserialize=True,
                         **kwargs):
        plural = cm.get_resource_plural(type)
        type = type.split('/')[-1]
        data = {type: kwargs}
        tenant_id = kwargs.pop('tenant_id', self._tenant_id)
        # Create PT with bound port
        req = self.new_update_request(plural, data, id, self.fmt)
        req.environ['neutron.context'] = context.Context(
            '', tenant_id if not is_admin_context else self._tenant_id,
            is_admin_context)
        res = req.get_response(api or self.ext_api)

        if expected_res_status:
            self.assertEqual(expected_res_status, res.status_int)
        elif deserialize and res.status_int >= webob.exc.HTTPClientError.code:
            raise webob.exc.HTTPClientError(code=res.status_int)
        return self.deserialize(self.fmt, res) if deserialize else res

    def _show_resource(self, id, plural, expected_res_status=None,
                       is_admin_context=False, tenant_id=None,
                       deserialize=True):
        req = self.new_show_request(plural, id, fmt=self.fmt)
        req.environ['neutron.context'] = context.Context(
            '', tenant_id or self._tenant_id, is_admin_context)
        res = req.get_response(self.ext_api)

        if expected_res_status:
            self.assertEqual(expected_res_status, res.status_int)
        elif deserialize and res.status_int >= webob.exc.HTTPClientError.code:
            raise webob.exc.HTTPClientError(code=res.status_int)
        return self.deserialize(self.fmt, res) if deserialize else res

    def _delete_resource(self, id, plural, is_admin_context=False,
                         expected_res_status=None, tenant_id=None,
                         deserialize=True):
        req = self.new_delete_request(plural, id)
        req.environ['neutron.context'] = context.Context(
            '', tenant_id or self._tenant_id, is_admin_context)
        res = req.get_response(self.ext_api)
        if expected_res_status:
            self.assertEqual(expected_res_status, res.status_int)
        elif deserialize and res.status_int >= webob.exc.HTTPClientError.code:
            raise webob.exc.HTTPClientError(code=res.status_int)
        if res.status_int != 204:
            return self.deserialize(self.fmt, res) if deserialize else res

    def _get_object(self, type, id, api, expected_res_status=None):
        req = self.new_show_request(type, id, self.fmt)
        res = req.get_response(api)

        if expected_res_status:
            self.assertEqual(expected_res_status, res.status_int)
        elif res.status_int >= webob.exc.HTTPClientError.code:
            raise webob.exc.HTTPClientError(code=res.status_int)
        return self.deserialize(self.fmt, res)

    def _list_resource(self, plural, api, is_admin_context=False,
                       expected_res_status=None, tenant_id=None,
                       **kwargs):
        param_str = '&'.join(['%s=%s' % (k, v)
                              for k, v in six.iteritems(kwargs)])
        req = self.new_list_request(plural, self.fmt,
                                    params=param_str or None)
        req.environ['neutron.context'] = context.Context(
            '', tenant_id or self._tenant_id, is_admin_context)
        res = req.get_response(api)

        if expected_res_status:
            self.assertEqual(res.status_int, expected_res_status)
        elif res.status_int >= webob.exc.HTTPClientError.code:
            raise webob.exc.HTTPClientError(code=res.status_int)
        return self.deserialize(self.fmt, res)

    def _bind_port_to_host(self, port_id, host, data=None):
        plugin = manager.NeutronManager.get_plugin()
        ctx = context.get_admin_context()
        agent = {'host': host}
        agent.update(self.agent_conf)
        plugin.create_or_update_agent(ctx, agent)
        data = data or {'port': {'binding:host_id': host, 'device_owner': 'a',
                                 'device_id': 'b'}}
        # Create EP with bound port
        req = self.new_update_request('ports', data, port_id,
                                      self.fmt)
        return self.deserialize(self.fmt, req.get_response(self.api))

    def _bind_subport(self, ctx, trunk, port):
        with mock.patch.object(trunk_server.TrunkSkeleton, '__init__',
                               return_value=None):
            trunk_skeleton = trunk_server.TrunkSkeleton()
            port['trunk_id'] = trunk['trunk']['id']
            port['port_id'] = port['id']
            trunk_skeleton.update_subport_bindings(ctx, [port])

    def _unbind_port(self, port_id):
        data = {'port': {'binding:host_id': ''}}
        req = self.new_update_request('ports', data, port_id,
                                      self.fmt)
        return self.deserialize(self.fmt, req.get_response(self.api))


class GroupPolicyDBTestBase(ApiManagerMixin):
    resource_prefix_map = dict(
        (k, gp_constants.GBP_PREFIXES[constants.SERVICECHAIN])
        for k in service_chain.RESOURCE_ATTRIBUTE_MAP.keys())
    resource_prefix_map.update(dict(
        (k, gp_constants.GBP_PREFIXES[constants.GROUP_POLICY])
        for k in gpolicy.RESOURCE_ATTRIBUTE_MAP.keys()
    ))

    fmt = JSON_FORMAT

    def __getattr__(self, item):
        # Verify is an update of a proper GBP object

        def _is_sc_resource(plural):
            return plural in service_chain.RESOURCE_ATTRIBUTE_MAP

        def _is_gbp_resource(plural):
            return plural in gpolicy.RESOURCE_ATTRIBUTE_MAP

        def _is_sfc_resource(plural):
            return plural in sfc.RESOURCE_ATTRIBUTE_MAP

        def _is_flowc_resource(plural):
            return plural in flowclassifier.RESOURCE_ATTRIBUTE_MAP

        def _is_valid_resource(plural):
            return (_is_gbp_resource(plural) or _is_sc_resource(plural) or
                    _is_flowc_resource(plural) or _is_sfc_resource(plural))

        def _get_prefix(plural):
            if _is_flowc_resource(plural) or _is_sfc_resource(plural):
                return 'sfc/'
            return ''

        # Update Method
        if item.startswith('update_'):
            resource = item[len('update_'):]
            plural = cm.get_resource_plural(resource)
            if _is_valid_resource(plural):
                r = _get_prefix(plural) + resource

                def update_wrapper(id, **kwargs):
                    return self._update_resource(id, r, **kwargs)
                return update_wrapper
        # Show Method
        if item.startswith('show_'):
            resource = item[len('show_'):]
            plural = cm.get_resource_plural(resource)
            if _is_valid_resource(plural):
                def show_wrapper(id, **kwargs):
                    p = _get_prefix(plural) + plural
                    return self._show_resource(id, p, **kwargs)
                return show_wrapper
        # Create Method
        if item.startswith('create_'):
            resource = item[len('create_'):]
            plural = cm.get_resource_plural(resource)
            if _is_valid_resource(plural):
                def create_wrapper(**kwargs):
                    r = _get_prefix(plural) + resource
                    return self._create_resource(r, **kwargs)
                return create_wrapper
        # Delete Method
        if item.startswith('delete_'):
            resource = item[len('delete_'):]
            plural = cm.get_resource_plural(resource)
            if _is_valid_resource(plural):
                def delete_wrapper(id, **kwargs):
                    p = _get_prefix(plural) + plural
                    return self._delete_resource(id, p, **kwargs)
                return delete_wrapper

        raise AttributeError

    def _get_resource_plural(self, resource):
        if resource.endswith('y'):
            resource_plural = resource.replace('y', 'ies')
        else:
            resource_plural = resource + 's'

        return resource_plural

    def _get_resource_singular(self, resource_plural):
        if resource_plural.endswith('ies'):
            return resource_plural.replace('ies', 'y')
        else:
            return resource_plural[:-1]

    def _test_list_resources(self, resource, items,
                             neutron_context=None,
                             query_params=None):
        resource_plural = self._get_resource_plural(resource)

        res = self._list(resource_plural,
                         neutron_context=neutron_context,
                         query_params=query_params)
        params = None
        if query_params:
            params = query_params.split('&')
            params = dict((x.split('=')[0], x.split('=')[1].split(','))
                          for x in params)
        count = getattr(self.plugin, 'get_%s_count' % resource_plural)(
            neutron_context or context.get_admin_context(), params)
        self.assertEqual(len(res[resource_plural]), count)
        resource = resource.replace('-', '_')
        self.assertEqual(sorted([i['id'] for i in res[resource_plural]]),
                         sorted([i[resource]['id'] for i in items]))

    def _create_profiled_servicechain_node(
            self, service_type=constants.LOADBALANCERV2, shared_profile=False,
            profile_tenant_id=None, **kwargs):
        prof = self.create_service_profile(
            service_type=service_type,
            shared=shared_profile,
            tenant_id=profile_tenant_id or self._tenant_id)['service_profile']
        return self.create_servicechain_node(
            service_profile_id=prof['id'], **kwargs)

    def _set_notification_mocks(self):
        self.l3_notify_p = mock.patch(
            'neutron.extensions.l3agentscheduler.notify').start()
        self.l3_periodic_p = mock.patch(
            'neutron.db.l3_agentschedulers_db.L3AgentSchedulerDbMixin.'
            'add_periodic_l3_agent_status_check').start()
        self.dhcp_notify_p = mock.patch(
            'neutron.extensions.dhcpagentscheduler.notify').start()
        self.dhcp_notifier_schedule = mock.patch(
            'neutron.api.rpc.agentnotifiers.dhcp_rpc_agent_api.'
            'DhcpAgentNotifyAPI._schedule_network').start()

    def _unset_notification_mocks(self):
        self.l3_notify_p.stop()
        self.l3_periodic_p.stop()
        self.dhcp_notify_p.stop()
        self.dhcp_notifier_schedule.stop()


class GroupPolicyDBTestPlugin(gpdb.GroupPolicyDbPlugin):

    supported_extension_aliases = ['group-policy'] + UNSUPPORTED_REQUIRED_EXTS
    path_prefix = "/grouppolicy"


DB_GP_PLUGIN_KLASS = (GroupPolicyDBTestPlugin.__module__ + '.' +
                      GroupPolicyDBTestPlugin.__name__)


class ServiceChainDBTestPlugin(svcchain_db.ServiceChainDbPlugin):

    supported_extension_aliases = ['servicechain'] + UNSUPPORTED_REQUIRED_EXTS
    path_prefix = "/servicechain"


DB_SC_PLUGIN_KLASS = (ServiceChainDBTestPlugin.__module__ + '.' +
                      ServiceChainDBTestPlugin.__name__)


class GroupPolicyDbTestCase(GroupPolicyDBTestBase,
                            test_db_base_plugin_v2.NeutronDbPluginV2TestCase):

    def setUp(self, core_plugin=None, sc_plugin=None, service_plugins=None,
              ext_mgr=None, gp_plugin=None):
        sc_plugin = sc_plugin or DB_SC_PLUGIN_KLASS
        gp_plugin = gp_plugin or DB_GP_PLUGIN_KLASS

        if not service_plugins:
            service_plugins = {
                'l3_plugin_name': 'router',
                'flavors_plugin_name': 'neutron.services.flavors.'
                                       'flavors_plugin.FlavorsPlugin',
                'gp_plugin_name': gp_plugin,
                'sc_plugin_name': sc_plugin}

        # Always install SFC plugin for convenience
        service_plugins['sfc_plugin_name'] = 'sfc'
        service_plugins['flowc_plugin_name'] = 'flow_classifier'
        extensions.append_api_extensions_path(
            gbpservice.neutron.extensions.__path__)
        super(GroupPolicyDbTestCase, self).setUp(
            plugin=core_plugin, ext_mgr=ext_mgr,
            service_plugins=service_plugins
        )
        test_policy_file = ETCDIR + "/test-policy.json"
        policy.refresh(policy_file=test_policy_file)
        self.plugin = importutils.import_object(gp_plugin)
        self._sc_plugin = importutils.import_object(sc_plugin)
        if not ext_mgr:
            ext_mgr = extensions.PluginAwareExtensionManager.get_instance()
            self.ext_api = test_extensions.setup_extensions_middleware(ext_mgr)

        plugins = manager.NeutronManager.get_service_plugins()
        self._gbp_plugin = plugins.get(constants.GROUP_POLICY)
        self._sc_plugin = plugins.get(constants.SERVICECHAIN)
        self._l3_plugin = plugins.get(constants.L3_ROUTER_NAT)
        self._set_notification_mocks()

    def tearDown(self):
        self._unset_notification_mocks()
        super(GroupPolicyDbTestCase, self).tearDown()


class TestGroupResources(GroupPolicyDbTestCase):

    def _test_show_resource(self, resource, resource_id, attrs):
        resource_plural = cm.get_resource_plural(resource)
        req = self.new_show_request(resource_plural, resource_id,
                                    fmt=self.fmt)
        res = self.deserialize(self.fmt,
                               req.get_response(self.ext_api))

        for k, v in six.iteritems(attrs):
            self.assertEqual(res[resource][k], v)

    def test_create_and_show_policy_target(self):
        ptg_id = self.create_policy_target_group()['policy_target_group']['id']
        attrs = cm.get_create_policy_target_default_attrs(
            policy_target_group_id=ptg_id)

        pt = self.create_policy_target(policy_target_group_id=ptg_id)

        for k, v in six.iteritems(attrs):
            self.assertEqual(pt['policy_target'][k], v)

        req = self.new_show_request(
            'policy_target_groups', ptg_id, fmt=self.fmt)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))

        self.assertEqual(res['policy_target_group']['policy_targets'],
                         [pt['policy_target']['id']])

        self._test_show_resource(
            'policy_target', pt['policy_target']['id'], attrs)

    def test_list_policy_targets(self):
        pts = [self.create_policy_target(name='pt1', description='pt'),
               self.create_policy_target(name='pt2', description='pt'),
               self.create_policy_target(name='pt3', description='pt')]
        self._test_list_resources('policy_target', pts,
                                  query_params='description=pt')

    def test_update_policy_target(self):
        name = 'new_policy_target'
        description = 'new desc'
        attrs = cm.get_create_policy_target_default_attrs(
            name=name, description=description)

        pt = self.create_policy_target()

        data = {'policy_target': {'name': name, 'description': description}}
        req = self.new_update_request(
            'policy_targets', data, pt['policy_target']['id'])
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))

        for k, v in six.iteritems(attrs):
            self.assertEqual(res['policy_target'][k], v)

        self._test_show_resource(
            'policy_target', pt['policy_target']['id'], attrs)

    def test_delete_policy_target(self):
        ctx = context.get_admin_context()

        pt = self.create_policy_target()
        pt_id = pt['policy_target']['id']

        req = self.new_delete_request('policy_targets', pt_id)
        res = req.get_response(self.ext_api)

        self.assertEqual(webob.exc.HTTPNoContent.code, res.status_int)
        self.assertRaises(gpolicy.PolicyTargetNotFound,
                          self.plugin.get_policy_target, ctx, pt_id)

    def test_create_and_show_policy_target_group(self):
        name = "ptg1"
        l3p = self.create_l3_policy()
        l3p_id = l3p['l3_policy']['id']

        l2p = self.create_l2_policy(name=name, l3_policy_id=l3p_id)
        l2p_id = l2p['l2_policy']['id']

        provided_prs_id = (
            self.create_policy_rule_set()['policy_rule_set']['id'])
        consumed_prs_id = (
            self.create_policy_rule_set()['policy_rule_set']['id'])
        attrs = cm.get_create_policy_target_group_default_attrs(
            name=name, l2_policy_id=l2p_id,
            provided_policy_rule_sets=[provided_prs_id],
            consumed_policy_rule_sets=[consumed_prs_id])

        ptg = self.create_policy_target_group(
            name=name, l2_policy_id=l2p_id,
            provided_policy_rule_sets={provided_prs_id: None},
            consumed_policy_rule_sets={consumed_prs_id: None})

        for k, v in six.iteritems(attrs):
            self.assertEqual(ptg['policy_target_group'][k], v)

        self._test_show_resource(
            'policy_target_group', ptg['policy_target_group']['id'], attrs)

    def test_create_associate_nsp_with_ptgs(self):
        params = [{'type': 'ip_single', 'name': 'vip', 'value': 'self_subnet'}]
        attrs = cm.get_create_network_service_policy_default_attrs(
            network_service_params=params)

        nsp = self.create_network_service_policy(network_service_params=params)
        for k, v in six.iteritems(attrs):
            self.assertEqual(nsp['network_service_policy'][k], v)

        self._test_show_resource('network_service_policy',
                                 nsp['network_service_policy']['id'], attrs)

        # Create two PTGs that use this NSP
        name1 = "ptg1"
        provided_prs_id = (
            self.create_policy_rule_set()['policy_rule_set']['id'])
        consumed_prs_id = (
            self.create_policy_rule_set()['policy_rule_set']['id'])
        attrs = cm.get_create_policy_target_group_default_attrs(
            name=name1,
            network_service_policy_id=nsp['network_service_policy']['id'],
            provided_policy_rule_sets=[provided_prs_id],
            consumed_policy_rule_sets=[consumed_prs_id])

        ptg1 = self.create_policy_target_group(
            name=name1,
            network_service_policy_id=nsp['network_service_policy']['id'],
            provided_policy_rule_sets={provided_prs_id: None},
            consumed_policy_rule_sets={consumed_prs_id: None})
        for k, v in six.iteritems(attrs):
            self.assertEqual(ptg1['policy_target_group'][k], v)
        self._test_show_resource(
            'policy_target_group', ptg1['policy_target_group']['id'], attrs)

        name2 = "ptg2"
        attrs.update(name=name2)
        ptg2 = self.create_policy_target_group(
            name=name2,
            network_service_policy_id=nsp['network_service_policy']['id'],
            provided_policy_rule_sets={provided_prs_id: None},
            consumed_policy_rule_sets={consumed_prs_id: None})
        for k, v in six.iteritems(attrs):
            self.assertEqual(ptg2['policy_target_group'][k], v)
        self._test_show_resource(
            'policy_target_group', ptg2['policy_target_group']['id'], attrs)

        # Update the PTG and unset the NSP used
        data = {'policy_target_group': {
                            'name': name1, 'network_service_policy_id': None}}
        req = self.new_update_request(
            'policy_target_groups', data, ptg1['policy_target_group']['id'])
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))

        self.assertIsNone(
            res['policy_target_group']['network_service_policy_id'])

    def _test_create_and_show_application_policy_group(self):
        name = "apg1"
        attrs = cm.get_create_application_policy_group_default_attrs(
            name=name)

        apg = self.create_application_policy_group(
            name=name)

        for k, v in six.iteritems(attrs):
            self.assertEqual(apg['application_policy_group'][k], v)

        self._test_show_resource('application_policy_group',
                                 apg['application_policy_group']['id'], attrs)
        return apg

    def test_create_associate_apg_with_ptgs(self):
        apg = self._test_create_and_show_application_policy_group()
        apg_id = apg['application_policy_group']['id']

        # Create two PTGs that use this NSP
        name = "ptg1"
        attrs = cm.get_create_policy_target_group_default_attrs(
            name=name, application_policy_group_id=apg_id)
        attrs['provided_policy_rule_sets'] = []
        attrs['consumed_policy_rule_sets'] = []

        ptg1 = self.create_policy_target_group(
            name=name,
            application_policy_group_id=apg_id)['policy_target_group']
        for k, v in six.iteritems(attrs):
            self.assertEqual(v, ptg1[k])
        self._test_show_resource(
            'policy_target_group', ptg1['id'], attrs)

        apg = self._show_resource(apg_id, 'application_policy_groups')[
            'application_policy_group']
        self.assertEqual([ptg1['id']], apg['policy_target_groups'])

        ptg2 = self.create_policy_target_group(name=name)[
            'policy_target_group']
        del attrs['application_policy_group_id']
        for k, v in six.iteritems(attrs):
            self.assertEqual(v, ptg2[k])
        self._test_show_resource('policy_target_group', ptg2['id'], attrs)

        apg = self._show_resource(apg_id, 'application_policy_groups')[
            'application_policy_group']
        self.assertEqual([ptg1['id']], apg['policy_target_groups'])

        # Update the PTG to set the APG
        data = {'policy_target_group': {'application_policy_group_id': apg_id}}
        req = self.new_update_request('policy_target_groups', data, ptg2['id'])
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        self.assertEqual(
            apg_id, res['policy_target_group']['application_policy_group_id'])

        apg = self._show_resource(apg_id, 'application_policy_groups')[
            'application_policy_group']
        self.assertItemsEqual([ptg1['id'], ptg2['id']],
                              apg['policy_target_groups'])

        # Update the PTG to unset the APG
        data = {'policy_target_group': {'application_policy_group_id': None}}
        req = self.new_update_request('policy_target_groups', data, ptg2['id'])
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        self.assertIsNone(
            res['policy_target_group']['application_policy_group_id'])

        apg = self._show_resource(apg_id, 'application_policy_groups')[
            'application_policy_group']
        self.assertEqual([ptg1['id']], apg['policy_target_groups'])

    def test_list_policy_target_groups(self):
        ptgs = (
            [self.create_policy_target_group(name='ptg1', description='ptg'),
             self.create_policy_target_group(name='ptg2', description='ptg'),
             self.create_policy_target_group(name='ptg3', description='ptg')])
        self._test_list_resources('policy_target_group', ptgs,
                                  query_params='description=ptg')

    def test_update_policy_target_group(self):
        name = "new_policy_target_group1"
        description = 'new desc'
        l3p_id = self.create_l3_policy()['l3_policy']['id']
        l2p_id = self.create_l2_policy(l3_policy_id=l3p_id)['l2_policy']['id']
        attrs = cm.get_create_policy_target_group_default_attrs(
            name=name, description=description, l2_policy_id=l2p_id)
        ct1_id = self.create_policy_rule_set(
            name='policy_rule_set1')['policy_rule_set']['id']
        ct2_id = self.create_policy_rule_set(
            name='policy_rule_set2')['policy_rule_set']['id']
        ptg = self.create_policy_target_group(
            consumed_policy_rule_sets={ct1_id: 'scope'},
            provided_policy_rule_sets={ct2_id: 'scope'})
        ct3_id = self.create_policy_rule_set(
            name='policy_rule_set3')['policy_rule_set']['id']
        ct4_id = self.create_policy_rule_set(
            name='policy_rule_set4')['policy_rule_set']['id']
        data = {'policy_target_group':
                {'name': name, 'description': description,
                 'l2_policy_id': l2p_id,
                 'provided_policy_rule_sets': {ct3_id: 'scope'},
                 'consumed_policy_rule_sets': {ct4_id: 'scope'}}}
        req = self.new_update_request('policy_target_groups', data,
                                      ptg['policy_target_group']['id'])
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))

        attrs['provided_policy_rule_sets'] = [ct3_id]
        attrs['consumed_policy_rule_sets'] = [ct4_id]
        for k, v in six.iteritems(attrs):
            self.assertEqual(res['policy_target_group'][k], v)

        self._test_show_resource('policy_target_group',
                                 ptg['policy_target_group']['id'], attrs)

    def test_delete_policy_target_group(self):
        ctx = context.get_admin_context()

        ptg = self.create_policy_target_group()
        ptg_id = ptg['policy_target_group']['id']

        req = self.new_delete_request('policy_target_groups', ptg_id)
        res = req.get_response(self.ext_api)
        self.assertEqual(webob.exc.HTTPNoContent.code, res.status_int)
        self.assertRaises(gpolicy.PolicyTargetGroupNotFound,
                          self.plugin.get_policy_target_group, ctx, ptg_id)

    def test_create_and_show_application_policy_group(self):
        self._test_create_and_show_application_policy_group()

    def test_list_application_policy_groups(self):
        apgs = (
            [self.create_application_policy_group(name='apg1',
                                                  description='apg'),
             self.create_application_policy_group(name='apg2',
                                                  description='apg'),
             self.create_application_policy_group(name='apg3',
                                                  description='apg')])
        self._test_list_resources('application_policy_group', apgs,
                                  query_params='description=apg')

    def test_update_application_policy_group(self):
        name = "new_application_policy_group1"
        description = 'new desc'
        attrs = cm.get_create_application_policy_group_default_attrs(
            name=name, description=description)
        apg = self.create_application_policy_group()
        data = {'application_policy_group':
                {'name': name, 'description': description}}
        req = self.new_update_request('application_policy_groups', data,
                                      apg['application_policy_group']['id'])
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))

        for k, v in six.iteritems(attrs):
            self.assertEqual(res['application_policy_group'][k], v)

        self._test_show_resource('application_policy_group',
                                 apg['application_policy_group']['id'], attrs)

    def test_delete_application_policy_group(self):
        ctx = context.get_admin_context()

        apg = self.create_application_policy_group()
        apg_id = apg['application_policy_group']['id']

        req = self.new_delete_request('application_policy_groups', apg_id)
        res = req.get_response(self.ext_api)
        self.assertEqual(webob.exc.HTTPNoContent.code, res.status_int)
        self.assertRaises(gpolicy.ApplicationPolicyGroupNotFound,
                          self.plugin.get_application_policy_group, ctx,
                          apg_id)

    def test_create_and_show_l2_policy(self):
        l3p_id = self.create_l3_policy()['l3_policy']['id']
        attrs = cm.get_create_l2_policy_default_attrs(l3_policy_id=l3p_id)

        l2p = self.create_l2_policy(l3_policy_id=l3p_id)
        for k, v in six.iteritems(attrs):
            self.assertEqual(l2p['l2_policy'][k], v)

        self._test_show_resource('l2_policy', l2p['l2_policy']['id'], attrs)

    def test_list_l2_policies(self):
        l2_policies = [self.create_l2_policy(name='l2p1', description='l2p'),
                       self.create_l2_policy(name='l2p2', description='l2p'),
                       self.create_l2_policy(name='l2p3', description='l2p')]
        self._test_list_resources('l2_policy', l2_policies,
                                  query_params='description=l2p')

    def test_update_l2_policy(self):
        name = "new_l2_policy"
        description = 'new desc'
        l3p_id = self.create_l3_policy()['l3_policy']['id']
        attrs = cm.get_create_l2_policy_default_attrs(
            name=name, description=description, l3_policy_id=l3p_id)

        l2p = self.create_l2_policy()
        data = {'l2_policy': {'name': name, 'description': description,
                              'l3_policy_id': l3p_id}}
        req = self.new_update_request('l2_policies', data,
                                      l2p['l2_policy']['id'])
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))

        for k, v in six.iteritems(attrs):
            self.assertEqual(res['l2_policy'][k], v)

        self._test_show_resource('l2_policy', l2p['l2_policy']['id'], attrs)

    def test_delete_l2_policy(self):
        ctx = context.get_admin_context()

        l2p = self.create_l2_policy()
        l2p_id = l2p['l2_policy']['id']

        req = self.new_delete_request('l2_policies', l2p_id)
        res = req.get_response(self.ext_api)
        self.assertEqual(webob.exc.HTTPNoContent.code, res.status_int)
        self.assertRaises(gpolicy.L2PolicyNotFound, self.plugin.get_l2_policy,
                          ctx, l2p_id)

    def test_delete_l2_policy_in_use(self):
        ctx = context.get_admin_context()
        l2p = self.create_l2_policy()
        l2p_id = l2p['l2_policy']['id']
        self.create_policy_target_group(l2_policy_id=l2p_id)
        self.assertRaises(gpolicy.L2PolicyInUse,
                          self.plugin.delete_l2_policy, ctx, l2p_id)

    def test_create_and_show_l3_policy(self):
        es1 = self.create_external_segment()['external_segment']
        es2 = self.create_external_segment()['external_segment']
        es_dict = {es1['id']: ['172.16.0.2', '172.16.0.3'], es2['id']: ['']}
        attrs = cm.get_create_l3_policy_default_attrs(
            external_segments=es_dict)

        l3p = self.create_l3_policy(external_segments=es_dict)

        for k, v in six.iteritems(attrs):
            self.assertEqual(v, l3p['l3_policy'][k])

        req = self.new_show_request('l3_policies', l3p['l3_policy']['id'],
                                    fmt=self.fmt)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))

        for k, v in six.iteritems(attrs):
            self.assertEqual(v, res['l3_policy'][k])

        self._test_show_resource('l3_policy', l3p['l3_policy']['id'], attrs)

    def test_create_l3_policy_with_invalid_subnet_prefix_length(self):
        ctx = context.get_admin_context()
        data = {'l3_policy': {'name': 'l3p1', 'ip_version': 4,
                              'description': '', 'ip_pool': '1.1.1.0/24',
                              'subnet_prefix_length': 32}}

        self.assertRaises(gpolicy.InvalidDefaultSubnetPrefixLength,
                          self.plugin.create_l3_policy, ctx, data)

    def test_create_l3_policy_with_invalid_ippool(self):
        ctx = context.get_admin_context()
        data = {'l3_policy': {'name': 'l3p1', 'ip_version': 4,
                              'description': '', 'ip_pool': '0.0.0.0/0',
                              'subnet_prefix_length': 24}}

        self.assertRaises(gpolicy.InvalidIpPoolPrefixLength,
                          self.plugin.create_l3_policy, ctx, data)

        data = {'l3_policy': {'name': 'l3p1', 'ip_version': 4,
                              'description': '', 'ip_pool': '1.2.3.0/31',
                              'subnet_prefix_length': 30}}

        self.assertRaises(gpolicy.InvalidIpPoolSize,
                          self.plugin.create_l3_policy, ctx, data)

    def test_create_l3_policy_subnet_prefix_length_greater_than_ip_pool(self):
        ctx = context.get_admin_context()
        data = {'l3_policy': {'name': 'l3p1', 'ip_version': 4,
                              'description': '', 'ip_pool': '1.1.1.0/24',
                              'subnet_prefix_length': 16}}

        self.assertRaises(gpolicy.SubnetPrefixLengthExceedsIpPool,
                          self.plugin.create_l3_policy, ctx, data)

    def test_list_l3_policies(self):
        l3_policies = [self.create_l3_policy(name='l3p1', description='l3p'),
                       self.create_l3_policy(name='l3p2', description='l3p'),
                       self.create_l3_policy(name='l3p3', description='l3p')]
        self._test_list_resources('l3_policy', l3_policies,
                                  query_params='description=l3p')

    def test_update_l3_policy(self):
        name = "new_l3_policy"
        description = 'new desc'
        prefix_length = 24
        es1 = self.create_external_segment()['external_segment']
        es2 = self.create_external_segment()['external_segment']
        es_dict = {es1['id']: ['172.16.0.2', '172.16.0.3'], es2['id']: ['']}
        attrs = cm.get_create_l3_policy_default_attrs(
            name=name, description=description,
            subnet_prefix_length=prefix_length,
            external_segments=es_dict)

        l3p = self.create_l3_policy()
        data = {'l3_policy': {'name': name, 'description': description,
                              'subnet_prefix_length': prefix_length,
                              'external_segments': es_dict}}

        req = self.new_update_request('l3_policies', data,
                                      l3p['l3_policy']['id'])
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))

        for k, v in six.iteritems(attrs):
            self.assertEqual(res['l3_policy'][k], v)

        self._test_show_resource('l3_policy', l3p['l3_policy']['id'], attrs)

    def test_update_l3_policy_with_invalid_subnet_prefix_length(self):
        ctx = context.get_admin_context()

        l3p = self.create_l3_policy()

        for prefix_length in [0, 1, 32]:
            data = {'l3_policy': {'subnet_prefix_length': prefix_length}}
            self.assertRaises(gpolicy.InvalidDefaultSubnetPrefixLength,
                              self.plugin.update_l3_policy, ctx,
                              l3p['l3_policy']['id'], data)

        l3p = self.create_l3_policy(ip_version='4')

        for prefix_length in [0, 1, 128]:
            data = {'l3_policy': {'subnet_prefix_length': prefix_length}}
            self.assertRaises(gpolicy.InvalidDefaultSubnetPrefixLength,
                              self.plugin.update_l3_policy, ctx,
                              l3p['l3_policy']['id'], data)

    def test_update_l3_policy_subnet_prefix_length_greater_than_ip_pool(self):
        ctx = context.get_admin_context()
        l3p = self.create_l3_policy(ip_pool='1.1.0.0/8',
                                    subnet_prefix_length=24)
        data = {'l3_policy': {'subnet_prefix_length': 4}}

        self.assertRaises(gpolicy.SubnetPrefixLengthExceedsIpPool,
                          self.plugin.update_l3_policy, ctx,
                          l3p['l3_policy']['id'], data)

    def test_delete_l3_policy(self):
        ctx = context.get_admin_context()

        l3p = self.create_l3_policy()
        l3p_id = l3p['l3_policy']['id']

        req = self.new_delete_request('l3_policies', l3p_id)
        res = req.get_response(self.ext_api)
        self.assertEqual(webob.exc.HTTPNoContent.code, res.status_int)
        self.assertRaises(gpolicy.L3PolicyNotFound, self.plugin.get_l3_policy,
                          ctx, l3p_id)

    def test_delete_l3_policy_in_use(self):
        ctx = context.get_admin_context()
        l3p = self.create_l3_policy()
        l3p_id = l3p['l3_policy']['id']
        self.create_l2_policy(l3_policy_id=l3p_id)
        self.assertRaises(gpolicy.L3PolicyInUse,
                          self.plugin.delete_l3_policy, ctx, l3p_id)

    def test_create_and_show_network_service_policy(self):
        params = [{'type': 'ip_single', 'name': 'vip', 'value': 'self_subnet'}]
        attrs = cm.get_create_network_service_policy_default_attrs(
            network_service_params=params)

        nsp = self.create_network_service_policy(network_service_params=params)
        for k, v in six.iteritems(attrs):
            self.assertEqual(nsp['network_service_policy'][k], v)

        self._test_show_resource('network_service_policy',
                                 nsp['network_service_policy']['id'], attrs)

    def test_list_network_service_policies(self):
        network_service_policies = [
            self.create_network_service_policy(name='nsp1', description='nsp'),
            self.create_network_service_policy(name='nsp2', description='nsp'),
            self.create_network_service_policy(name='nsp3', description='nsp')]
        self._test_list_resources('network_service_policy',
                                  network_service_policies,
                                  query_params='description=nsp')

    def test_update_network_service_policy(self):
        name = "new_network_service_policy"
        description = 'new desc'
        attrs = cm.get_create_network_service_policy_default_attrs(
            name=name, description=description)

        nsp = self.create_network_service_policy()
        data = {'network_service_policy': {'name': name,
                                           'description': description}}
        req = self.new_update_request('network_service_policies', data,
                                      nsp['network_service_policy']['id'])
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))

        for k, v in six.iteritems(attrs):
            self.assertEqual(res['network_service_policy'][k], v)

        self._test_show_resource('network_service_policy',
                                 nsp['network_service_policy']['id'], attrs)

    def test_delete_network_service_policy(self):
        ctx = context.get_admin_context()

        nsp = self.create_network_service_policy()
        nsp_id = nsp['network_service_policy']['id']

        req = self.new_delete_request('network_service_policies', nsp_id)
        res = req.get_response(self.ext_api)
        self.assertEqual(webob.exc.HTTPNoContent.code, res.status_int)
        self.assertRaises(gpolicy.NetworkServicePolicyNotFound,
                          self.plugin.get_network_service_policy,
                          ctx, nsp_id)

    def test_delete_network_service_policy_in_use(self):
        ctx = context.get_admin_context()
        nsp = self.create_network_service_policy()
        nsp_id = nsp['network_service_policy']['id']
        ptg = self.create_policy_target_group(network_service_policy_id=nsp_id)
        ptg_id = ptg['policy_target_group']['id']

        # Deleting the NSP used by the PTG should be rejected
        self.assertRaises(gpolicy.NetworkServicePolicyInUse,
                          self.plugin.delete_network_service_policy,
                          ctx, nsp_id)

        # After deleting the PTG, NSP delete should succeed
        req = self.new_delete_request('policy_target_groups', ptg_id)
        res = req.get_response(self.ext_api)
        self.assertEqual(webob.exc.HTTPNoContent.code, res.status_int)
        req = self.new_delete_request('network_service_policies', nsp_id)
        res = req.get_response(self.ext_api)
        self.assertEqual(webob.exc.HTTPNoContent.code, res.status_int)
        self.assertRaises(gpolicy.NetworkServicePolicyNotFound,
                          self.plugin.get_network_service_policy,
                          ctx, nsp_id)

    def test_delete_network_service_policy_with_params(self):
        ctx = context.get_admin_context()
        params = [{'type': 'ip_single', 'name': 'vip', 'value': 'self_subnet'}]

        nsp = self.create_network_service_policy(network_service_params=params)
        nsp_id = nsp['network_service_policy']['id']

        req = self.new_delete_request('network_service_policies', nsp_id)
        res = req.get_response(self.ext_api)
        self.assertEqual(webob.exc.HTTPNoContent.code, res.status_int)
        self.assertRaises(gpolicy.NetworkServicePolicyNotFound,
                          self.plugin.get_network_service_policy,
                          ctx, nsp_id)

    def test_create_and_show_policy_classifier(self):
        name = "pc1"
        attrs = cm.get_create_policy_classifier_default_attrs(name=name)

        pc = self.create_policy_classifier(name=name)

        for k, v in six.iteritems(attrs):
            self.assertEqual(pc['policy_classifier'][k], v)

        req = self.new_show_request('policy_classifiers',
                                    pc['policy_classifier']['id'],
                                    fmt=self.fmt)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))

        for k, v in six.iteritems(attrs):
            self.assertEqual(res['policy_classifier'][k], v)

        self._test_show_resource('policy_classifier',
                                 pc['policy_classifier']['id'], attrs)

    def test_classifier_with_protocol_number(self):
        name = 'pc1'
        protocol = '55'

        attrs = cm.get_create_policy_classifier_default_attrs(
            name=name, protocol=protocol)
        pc = self.create_policy_classifier(name=name, protocol=protocol)

        for k, v in six.iteritems(attrs):
            self.assertEqual(pc['policy_classifier'][k], v)

        req = self.new_show_request('policy_classifiers',
                                    pc['policy_classifier']['id'],
                                    fmt=self.fmt)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))

        for k, v in six.iteritems(attrs):
            self.assertEqual(res['policy_classifier'][k], v)

        self._test_show_resource('policy_classifier',
                                 pc['policy_classifier']['id'], attrs)

    def test_list_policy_classifiers(self):
        policy_classifiers = [
            self.create_policy_classifier(name='pc1', description='pc'),
            self.create_policy_classifier(name='pc2', description='pc'),
            self.create_policy_classifier(name='pc3', description='pc')]
        self._test_list_resources('policy_classifier', policy_classifiers,
                                  query_params='description=pc')

    def test_update_policy_classifier(self):
        name = "new_policy_classifier"
        description = 'new desc'
        protocol = 'tcp'
        port_range = '100:200'
        direction = 'in'
        attrs = cm.get_create_policy_classifier_default_attrs(
            name=name, description=description, protocol=protocol,
            port_range=port_range, direction=direction)

        pc = self.create_policy_classifier()
        data = {'policy_classifier': {'name': name, 'description': description,
                                      'protocol': protocol, 'port_range':
                                      port_range, 'direction': direction}}

        req = self.new_update_request('policy_classifiers', data,
                                      pc['policy_classifier']['id'])
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))

        for k, v in six.iteritems(attrs):
            self.assertEqual(res['policy_classifier'][k], v)

        self._test_show_resource('policy_classifier',
                                 pc['policy_classifier']['id'], attrs)

    def test_update_policy_classifier_with_protocol_number(self):
        name = "new_policy_classifier"
        description = 'new desc'
        protocol = '50'
        port_range = '100:200'
        direction = 'in'
        attrs = cm.get_create_policy_classifier_default_attrs(
            name=name, description=description, protocol=protocol,
            port_range=port_range, direction=direction)

        pc = self.create_policy_classifier()
        data = {'policy_classifier': {'name': name, 'description': description,
                                      'protocol': protocol, 'port_range':
                                      port_range, 'direction': direction}}

        req = self.new_update_request('policy_classifiers', data,
                                      pc['policy_classifier']['id'])
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))

        for k, v in six.iteritems(attrs):
            self.assertEqual(res['policy_classifier'][k], v)

        self._test_show_resource('policy_classifier',
                                 pc['policy_classifier']['id'], attrs)

    def test_delete_policy_classifier(self):
        ctx = context.get_admin_context()

        pc = self.create_policy_classifier()
        pc_id = pc['policy_classifier']['id']

        req = self.new_delete_request('policy_classifiers', pc_id)
        res = req.get_response(self.ext_api)
        self.assertEqual(webob.exc.HTTPNoContent.code, res.status_int)
        self.assertRaises(gpolicy.PolicyClassifierNotFound,
                          self.plugin.get_policy_classifier, ctx, pc_id)

    def test_delete_policy_classifier_in_use(self):
        ctx = context.get_admin_context()
        pc = self.create_policy_classifier()
        pc_id = pc['policy_classifier']['id']
        pr = self.create_policy_rule(policy_classifier_id=pc_id)
        pr_id = pr['policy_rule']['id']
        self.create_policy_rule_set(policy_rules=[pr_id])
        self.assertRaises(gpolicy.PolicyClassifierInUse,
                          self.plugin.delete_policy_classifier, ctx, pc_id)

    def test_create_and_show_policy_action(self):
        name = "pa1"
        attrs = cm.get_create_policy_action_default_attrs(name=name)

        pa = self.create_policy_action(name=name)

        for k, v in six.iteritems(attrs):
            self.assertEqual(pa['policy_action'][k], v)

        req = self.new_show_request('policy_actions',
                                    pa['policy_action']['id'],
                                    fmt=self.fmt)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))

        for k, v in six.iteritems(attrs):
            self.assertEqual(res['policy_action'][k], v)

        self._test_show_resource('policy_action',
                                 pa['policy_action']['id'], attrs)

    def test_list_policy_actions(self):
        policy_actions = [
            self.create_policy_action(name='pa1', description='pa'),
            self.create_policy_action(name='pa2', description='pa'),
            self.create_policy_action(name='pa3', description='pa')]
        self._test_list_resources('policy_action', policy_actions,
                                  query_params='description=pa')

    def test_update_policy_action(self):
        name = "new_policy_action"
        description = 'new desc'
        action_value = _uuid()
        attrs = cm.get_create_policy_action_default_attrs(
            name=name, description=description, action_value=action_value)

        pa = self.create_policy_action()
        data = {'policy_action': {'name': name, 'description': description,
                                  'action_value': action_value}}

        req = self.new_update_request('policy_actions', data,
                                      pa['policy_action']['id'])
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))

        for k, v in six.iteritems(attrs):
            self.assertEqual(res['policy_action'][k], v)

        self._test_show_resource('policy_action',
                                 pa['policy_action']['id'], attrs)

    def test_delete_policy_action(self):
        ctx = context.get_admin_context()

        pa = self.create_policy_action()
        pa_id = pa['policy_action']['id']

        req = self.new_delete_request('policy_actions', pa_id)
        res = req.get_response(self.ext_api)
        self.assertEqual(webob.exc.HTTPNoContent.code, res.status_int)
        self.assertRaises(gpolicy.PolicyActionNotFound,
                          self.plugin.get_policy_action, ctx, pa_id)

    def test_delete_policy_action_in_use(self):
        ctx = context.get_admin_context()
        pc = self.create_policy_classifier()
        pc_id = pc['policy_classifier']['id']
        pa = self.create_policy_action()
        pa_id = pa['policy_action']['id']
        self.create_policy_rule(policy_classifier_id=pc_id,
                                policy_actions=[pa_id])
        self.assertRaises(gpolicy.PolicyActionInUse,
                          self.plugin.delete_policy_action, ctx, pa_id)

    def test_create_and_show_policy_rule(self):
        name = "pr1"
        pc = self.create_policy_classifier()
        pc_id = pc['policy_classifier']['id']
        attrs = cm.get_create_policy_rule_default_attrs(
            name=name, policy_classifier_id=pc_id)

        pr = self.create_policy_rule(
            name=name, policy_classifier_id=pc_id)

        for k, v in six.iteritems(attrs):
            self.assertEqual(pr['policy_rule'][k], v)

        req = self.new_show_request('policy_rules', pr['policy_rule']['id'],
                                    fmt=self.fmt)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))

        for k, v in six.iteritems(attrs):
            self.assertEqual(res['policy_rule'][k], v)

        self._test_show_resource('policy_rule',
                                 pr['policy_rule']['id'], attrs)

    def test_list_policy_rules(self):
        pcs = [self.create_policy_classifier()['policy_classifier']['id'],
               self.create_policy_classifier()['policy_classifier']['id'],
               self.create_policy_classifier()['policy_classifier']['id']]
        policy_rules = [
            self.create_policy_rule(name='pr1', description='pr',
                                    policy_classifier_id=pcs[0]),
            self.create_policy_rule(name='pr2', description='pr',
                                    policy_classifier_id=pcs[1]),
            self.create_policy_rule(name='pr3', description='pr',
                                    policy_classifier_id=pcs[2])]
        self._test_list_resources('policy_rule', policy_rules,
                                  query_params='description=pr')

    def test_update_policy_rule(self):
        name = "new_policy_rule"
        description = 'new desc'
        enabled = False
        pc = self.create_policy_classifier()
        pc_id = pc['policy_classifier']['id']
        pa = self.create_policy_action()
        pa_id = pa['policy_action']['id']
        attrs = cm.get_create_policy_rule_default_attrs(
            name=name, description=description, policy_classifier_id=pc_id,
            policy_actions=[pa_id], enabled=enabled)

        pr = self.create_policy_rule(policy_classifier_id=pc_id)
        data = {'policy_rule': {'name': name, 'description': description,
                                'policy_classifier_id': pc_id,
                                'policy_actions': [pa_id], 'enabled': enabled}}

        req = self.new_update_request('policy_rules', data,
                                      pr['policy_rule']['id'])
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))

        for k, v in six.iteritems(attrs):
            self.assertEqual(res['policy_rule'][k], v)

        self._test_show_resource('policy_rule',
                                 pr['policy_rule']['id'], attrs)

    def test_update_policy_rule_replace_policy_action(self):
        pc = self.create_policy_classifier()
        pc_id = pc['policy_classifier']['id']
        pa1_id = self.create_policy_action()['policy_action']['id']
        pa2_id = self.create_policy_action()['policy_action']['id']
        pr = self.create_policy_rule(policy_classifier_id=pc_id,
                                     policy_actions=[pa1_id, pa2_id])
        npa1_id = self.create_policy_action()['policy_action']['id']
        npa2_id = self.create_policy_action()['policy_action']['id']
        actions_list = [npa1_id, npa2_id]
        attrs = cm.get_create_policy_rule_default_attrs(
            policy_actions=actions_list)

        data = {'policy_rule': {'policy_actions': actions_list}}

        req = self.new_update_request('policy_rules', data,
                                      pr['policy_rule']['id'])
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))

        self.assertItemsEqual(actions_list,
                              res['policy_rule']['policy_actions'])
        del attrs['policy_actions']
        for k, v in six.iteritems(attrs):
            self.assertEqual(v, res['policy_rule'][k])

    def test_delete_policy_rule(self):
        ctx = context.get_admin_context()
        pc = self.create_policy_classifier()
        pc_id = pc['policy_classifier']['id']
        pr = self.create_policy_rule(policy_classifier_id=pc_id)
        pr_id = pr['policy_rule']['id']

        req = self.new_delete_request('policy_rules', pr_id)
        res = req.get_response(self.ext_api)
        self.assertEqual(webob.exc.HTTPNoContent.code, res.status_int)
        self.assertRaises(gpolicy.PolicyRuleNotFound,
                          self.plugin.get_policy_rule, ctx, pr_id)

    def test_delete_policy_rule_in_use(self):
        ctx = context.get_admin_context()
        pc = self.create_policy_classifier()
        pc_id = pc['policy_classifier']['id']
        pr = self.create_policy_rule(policy_classifier_id=pc_id)
        pr_id = pr['policy_rule']['id']
        self.create_policy_rule_set(policy_rules=[pr_id])
        self.assertRaises(gpolicy.PolicyRuleInUse,
                          self.plugin.delete_policy_rule, ctx, pr_id)

    def test_create_and_show_policy_rule_set(self):
        name = "policy_rule_set1"
        attrs = cm.get_create_policy_rule_set_default_attrs(name=name)

        prs = self.create_policy_rule_set(name=name)

        for k, v in six.iteritems(attrs):
            self.assertEqual(prs['policy_rule_set'][k], v)

        req = self.new_show_request(
            'policy_rule_sets', prs['policy_rule_set']['id'], fmt=self.fmt)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))

        for k, v in six.iteritems(attrs):
            self.assertEqual(res['policy_rule_set'][k], v)

        self._test_show_resource('policy_rule_set',
                                 prs['policy_rule_set']['id'], attrs)

    def test_create_prs_with_multiple_rules_children(self, **kwargs):
        policy_classifiers = [
            self.create_policy_classifier()['policy_classifier']['id'],
            self.create_policy_classifier()['policy_classifier']['id']]
        policy_rules = sorted([
            self.create_policy_rule(
                policy_classifier_id=
                policy_classifiers[0])['policy_rule']['id'],
            self.create_policy_rule(
                policy_classifier_id=
                policy_classifiers[1])['policy_rule']['id']])
        child_policy_rule_sets = sorted(
            [self.create_policy_rule_set()['policy_rule_set']['id'],
             self.create_policy_rule_set()['policy_rule_set']['id']])
        attrs = cm.get_create_policy_rule_set_default_attrs(
            policy_rules=policy_rules,
            child_policy_rule_sets=child_policy_rule_sets)
        prs = self.create_policy_rule_set(
            policy_rules=policy_rules,
            child_policy_rule_sets=child_policy_rule_sets)

        req = self.new_show_request('policy_rule_sets',
                                    prs['policy_rule_set']['id'],
                                    fmt=self.fmt)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))

        parent_id = res['policy_rule_set']['id']
        res['policy_rule_set']['policy_rules'] = sorted(
            res['policy_rule_set']['policy_rules'])
        res['policy_rule_set']['child_policy_rule_sets'] = sorted(
            res['policy_rule_set']['child_policy_rule_sets'])
        for k, v in six.iteritems(attrs):
            self.assertEqual(res['policy_rule_set'][k], v)

        req = self.new_show_request('policy_rule_sets',
                                    child_policy_rule_sets[0],
                                    fmt=self.fmt)
        c1 = self.deserialize(self.fmt, req.get_response(self.ext_api))
        self.assertEqual(c1['policy_rule_set']['parent_id'], parent_id)
        req = self.new_show_request('policy_rule_sets',
                                    child_policy_rule_sets[1],
                                    fmt=self.fmt)
        c2 = self.deserialize(self.fmt, req.get_response(self.ext_api))
        self.assertEqual(c2['policy_rule_set']['parent_id'], parent_id)

    def test_create_child_prs_fail(self, **kwargs):
        self.create_policy_rule_set(child_policy_rule_sets=[
            '00000000-ffff-ffff-ffff-000000000000'],
            expected_res_status=webob.exc.HTTPNotFound.code)

    def test_list_policy_rule_sets(self):
        policy_rule_sets = [
            self.create_policy_rule_set(name='ct1', description='ct'),
            self.create_policy_rule_set(name='ct2', description='ct'),
            self.create_policy_rule_set(name='ct3', description='ct')]
        self._test_list_resources('policy_rule_set', policy_rule_sets,
                                  query_params='description=ct')

    def test_update_policy_rule_set(self):
        name = "new_policy_rule_set"
        description = 'new desc'
        pc_id = self.create_policy_classifier()['policy_classifier']['id']
        policy_rules = [self.create_policy_rule(
            policy_classifier_id=pc_id)['policy_rule']['id']]
        child_policy_rule_sets = [
            self.create_policy_rule_set()['policy_rule_set']['id']]
        prs = self.create_policy_rule_set(
            child_policy_rule_sets=child_policy_rule_sets,
            policy_rules=policy_rules)
        child_policy_rule_sets = [
            self.create_policy_rule_set()['policy_rule_set']['id']]
        policy_rules = [self.create_policy_rule(
            policy_classifier_id=pc_id)['policy_rule']['id']]
        attrs = cm.get_create_policy_rule_set_default_attrs(
            name=name, description=description, policy_rules=policy_rules,
            child_policy_rule_sets=child_policy_rule_sets)
        data = {'policy_rule_set':
                {'name': name, 'description': description,
                 'policy_rules': policy_rules,
                 'child_policy_rule_sets': child_policy_rule_sets}}

        req = self.new_update_request('policy_rule_sets', data,
                                      prs['policy_rule_set']['id'])
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))

        for k, v in six.iteritems(attrs):
            self.assertEqual(res['policy_rule_set'][k], v)

        self._test_show_resource('policy_rule_set',
                                 prs['policy_rule_set']['id'], attrs)

    def test_delete_policy_rule_set(self):
        ctx = context.get_admin_context()
        prs = self.create_policy_rule_set()
        prs_id = prs['policy_rule_set']['id']

        req = self.new_delete_request('policy_rule_sets', prs_id)
        res = req.get_response(self.ext_api)
        self.assertEqual(webob.exc.HTTPNoContent.code, res.status_int)
        self.assertRaises(gpolicy.PolicyRuleSetNotFound,
                          self.plugin.get_policy_rule_set, ctx, prs_id)

    def test_delete_policy_rule_set_in_use_by_ptg(self):
        ctx = context.get_admin_context()
        l3p = self.create_l3_policy()
        l3p_id = l3p['l3_policy']['id']

        l2p = self.create_l2_policy(l3_policy_id=l3p_id)
        l2p_id = l2p['l2_policy']['id']

        provided_prs_id = (
            self.create_policy_rule_set()['policy_rule_set']['id'])
        consumed_prs_id = (
            self.create_policy_rule_set()['policy_rule_set']['id'])

        self.create_policy_target_group(
            l2_policy_id=l2p_id,
            provided_policy_rule_sets={provided_prs_id: None},
            consumed_policy_rule_sets={consumed_prs_id: None})

        self.assertRaises(gpolicy.PolicyRuleSetInUse,
                          self.plugin.delete_policy_rule_set, ctx,
                          provided_prs_id)

        self.assertRaises(gpolicy.PolicyRuleSetInUse,
                          self.plugin.delete_policy_rule_set, ctx,
                          consumed_prs_id)

    def test_delete_policy_rule_set_in_use_by_ep(self):
        ctx = context.get_admin_context()

        provided_prs_id = (
            self.create_policy_rule_set()['policy_rule_set']['id'])
        consumed_prs_id = (
            self.create_policy_rule_set()['policy_rule_set']['id'])

        self.create_external_policy(
            provided_policy_rule_sets={provided_prs_id: None},
            consumed_policy_rule_sets={consumed_prs_id: None})

        self.assertRaises(gpolicy.PolicyRuleSetInUse,
                          self.plugin.delete_policy_rule_set, ctx,
                          provided_prs_id)

        self.assertRaises(gpolicy.PolicyRuleSetInUse,
                          self.plugin.delete_policy_rule_set, ctx,
                          consumed_prs_id)

    def test_prs_one_hierarchy_children(self):
        child = self.create_policy_rule_set()['policy_rule_set']
        parent = self.create_policy_rule_set(
            child_policy_rule_sets=[child['id']])['policy_rule_set']
        self.create_policy_rule_set(
            child_policy_rule_sets=[parent['id']],
            expected_res_status=webob.exc.HTTPBadRequest.code)

    def test_prs_one_hierarchy_parent(self):
        child = self.create_policy_rule_set()['policy_rule_set']
        # parent
        self.create_policy_rule_set(
            child_policy_rule_sets=[child['id']])['policy_rule_set']
        nephew = self.create_policy_rule_set()['policy_rule_set']
        data = {'policy_rule_set': {'child_policy_rule_sets': [nephew['id']]}}
        req = self.new_update_request('policy_rule_sets', data, child['id'])
        res = req.get_response(self.ext_api)
        self.assertEqual(webob.exc.HTTPBadRequest.code, res.status_int)

    def test_prs_parent_no_loop(self):
        prs = self.create_policy_rule_set()['policy_rule_set']
        data = {'policy_rule_set': {'child_policy_rule_sets': [prs['id']]}}
        req = self.new_update_request('policy_rule_sets', data, prs['id'])
        res = req.get_response(self.ext_api)
        self.assertEqual(webob.exc.HTTPBadRequest.code, res.status_int)

    def _test_create_and_show(self, type, attrs, expected=None):
        plural = cm.get_resource_plural(type)
        res = self._create_resource(type, None, False, **attrs)
        expected = expected or attrs
        for k, v in six.iteritems(expected):
            self.assertEqual(v, res[type][k])

        req = self.new_show_request(plural, res[type]['id'], fmt=self.fmt)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        for k, v in six.iteritems(expected):
            self.assertEqual(v, res[type][k])
        self._test_show_resource(type, res[type]['id'], expected)

    def test_create_and_show_ep(self):
        es = self.create_external_segment()['external_segment']
        prs = self.create_policy_rule_set()['policy_rule_set']
        attrs = {'external_segments': [es['id']],
                 'provided_policy_rule_sets': {prs['id']: None},
                 'consumed_policy_rule_sets': {prs['id']: None}}
        body = cm.get_create_external_policy_default_attrs()
        body.update(attrs)
        expected = copy.deepcopy(body)
        expected['provided_policy_rule_sets'] = [prs['id']]
        expected['consumed_policy_rule_sets'] = [prs['id']]
        self._test_create_and_show('external_policy', body,
                                   expected=expected)

    def test_create_and_show_es(self):
        route = {'destination': '0.0.0.0/0', 'nexthop': '172.16.0.1'}
        attrs = cm.get_create_external_segment_default_attrs(
            external_routes=[route])
        self._test_create_and_show('external_segment', attrs)

    def test_create_and_show_np(self):
        es = self.create_external_segment()['external_segment']
        attrs = cm.get_create_nat_pool_default_attrs(
            external_segment_id=es['id'])
        self._test_create_and_show('nat_pool', attrs)

    def test_list_ep(self):
        external_policies = [
            self.create_external_policy(name='ep1', description='ep'),
            self.create_external_policy(name='ep2', description='ep'),
            self.create_external_policy(name='ep3', description='ep')]
        self._test_list_resources('external_policy',
                                  external_policies,
                                  query_params='description=ep')

    def test_list_es(self):
        external_segments = [
            self.create_external_segment(name='es1', description='es'),
            self.create_external_segment(name='es2', description='es'),
            self.create_external_segment(name='es3', description='es')]
        self._test_list_resources('external_segment',
                                  external_segments,
                                  query_params='description=es')

    def test_update_external_policy(self):
        name = 'new_ep'
        description = 'new desc'
        es = self.create_external_segment()['external_segment']
        prs = self.create_policy_rule_set()['policy_rule_set']
        cm.get_create_external_policy_default_attrs(
            name=name, description=description,
            external_segments=[es['id']],
            provided_policy_rule_sets={prs['id']: None},
            consumed_policy_rule_sets={prs['id']: None})
        ep = self.create_external_policy()['external_policy']
        data = {'external_policy': {
            'name': name, 'description': description}}

        req = self.new_update_request('external_policies', data,
                                      ep['id'])
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        res = res['external_policy']
        for k, v in six.iteritems(data['external_policy']):
            self.assertEqual(v, res[k])

        self._test_show_resource('external_policy', ep['id'],
                                 data['external_policy'])

    def test_update_external_segment(self):
        name = 'new_es'
        description = 'new desc'
        route = {'destination': '0.0.0.0/0', 'nexthop': '172.16.0.1'}
        attrs = cm.get_create_external_segment_default_attrs(
            name=name, description=description, external_routes=[route])
        es = self.create_external_segment()['external_segment']
        data = {'external_segment': {
            'name': name, 'description': description,
            'external_routes': [route]}}

        req = self.new_update_request('external_segments', data,
                                      es['id'])
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        res = res['external_segment']
        for k, v in six.iteritems(attrs):
            self.assertEqual(res[k], v)

        self._test_show_resource('external_segment', es['id'], attrs)

    def test_update_nat_pool(self):
        name = 'new_np'
        description = 'new desc'
        es = self.create_external_segment()['external_segment']

        attrs = cm.get_create_nat_pool_default_attrs(
            name=name, description=description, external_segment_id=es['id'])
        np = self.create_nat_pool()['nat_pool']
        data = {'nat_pool': {
            'name': name, 'description': description,
            'external_segment_id': es['id']}}

        req = self.new_update_request('nat_pools', data,
                                      np['id'])
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        res = res['nat_pool']
        for k, v in six.iteritems(attrs):
            self.assertEqual(v, res[k])

        self._test_show_resource('nat_pool', np['id'], attrs)

    def test_delete_ep(self):
        ctx = context.get_admin_context()
        ep = self.create_external_policy()
        ep_id = ep['external_policy']['id']

        req = self.new_delete_request('external_policies', ep_id)
        res = req.get_response(self.ext_api)
        self.assertEqual(webob.exc.HTTPNoContent.code, res.status_int)
        self.assertRaises(gpolicy.ExternalPolicyNotFound,
                          self.plugin.get_external_policy, ctx, ep_id)

    def test_delete_es(self):
        ctx = context.get_admin_context()
        ep = self.create_external_segment()
        ep_id = ep['external_segment']['id']

        req = self.new_delete_request('external_segments', ep_id)
        res = req.get_response(self.ext_api)
        self.assertEqual(webob.exc.HTTPNoContent.code, res.status_int)
        self.assertRaises(gpolicy.ExternalSegmentNotFound,
                          self.plugin.get_external_segment, ctx, ep_id)

    def test_delete_np(self):
        ctx = context.get_admin_context()
        ep = self.create_nat_pool()
        ep_id = ep['nat_pool']['id']

        req = self.new_delete_request('nat_pools', ep_id)
        res = req.get_response(self.ext_api)
        self.assertEqual(webob.exc.HTTPNoContent.code, res.status_int)
        self.assertRaises(gpolicy.NATPoolNotFound,
                          self.plugin.get_nat_pool, ctx, ep_id)

    def test_get_l3p_ptgs(self):
        ctx = context.get_admin_context()
        # Create 1 PTG in one L3P
        l3p1 = self.create_l3_policy()['l3_policy']
        l2p1_1 = self.create_l2_policy(l3_policy_id=l3p1['id'])['l2_policy']
        ptg1_1 = self.create_policy_target_group(
            l2_policy_id=l2p1_1['id'])['policy_target_group']

        # Create 1 PTG in another L3P
        l3p2 = self.create_l3_policy()['l3_policy']
        l2p2_1 = self.create_l2_policy(l3_policy_id=l3p2['id'])['l2_policy']
        ptg2_1 = self.create_policy_target_group(
            l2_policy_id=l2p2_1['id'])['policy_target_group']

        # Verify only the right PTG is retrieved from L3P1
        ptgs = self._gbp_plugin._get_l3p_ptgs(ctx, l3p1['id'])
        self.assertEqual(1, len(ptgs))
        self.assertEqual(ptg1_1['id'], ptgs[0]['id'])

        # Verify only the right PTG is retrieved from L3P2
        ptgs = self._gbp_plugin._get_l3p_ptgs(ctx, l3p2['id'])
        self.assertEqual(1, len(ptgs))
        self.assertEqual(ptg2_1['id'], ptgs[0]['id'])

        # Create 2 more PTGs on L3P1, same L2P and different L2P
        ptg1_2 = self.create_policy_target_group(
            l2_policy_id=l2p1_1['id'])['policy_target_group']
        l2p1_2 = self.create_l2_policy(l3_policy_id=l3p1['id'])['l2_policy']
        ptg1_3 = self.create_policy_target_group(
            l2_policy_id=l2p1_2['id'])['policy_target_group']

        # Verify all 3 PTGs are retrieved
        ptgs = self._gbp_plugin._get_l3p_ptgs(ctx, l3p1['id'])
        self.assertEqual(3, len(ptgs))
        found = set(x['id'] for x in ptgs)
        expected = set([ptg1_1['id'], ptg1_2['id'], ptg1_3['id']])
        self.assertEqual(expected, found)

    def test_multiple_l3p_in_es_default_address(self):
        es = self.create_external_segment()['external_segment']
        es_dict = {es['id']: []}
        self.create_l3_policy(external_segments=es_dict,
                              expected_res_status=201)
        self.create_l3_policy(external_segments=es_dict,
                              expected_res_status=201)
        es_dict = {es['id']: ['172.16.0.1', '172.16.0.2']}
        self.create_l3_policy(external_segments=es_dict,
                              expected_res_status=201)
        # First address is overlapping
        es_dict = {es['id']: ['172.16.0.1', '172.16.0.3']}
        res = self.create_l3_policy(external_segments=es_dict,
                                    expected_res_status=400)
        self.assertEqual('IpAddressOverlappingInExternalSegment',
                         res['NeutronError']['type'])


class TestStatusAttributesForResources(GroupPolicyDbTestCase):

    def _test_set_status_attrs(self, resource_name, plugin_ref):
        all_statuses = []
        status_details = 'something'
        none_status_dict = {resource_name: {'status': None,
                                            'status_details': None}}
        for status in gp_constants.STATUS_STATES:
            status_dict = {'status': status,
                           'status_details': status_details}
            all_statuses.append(status_dict)
        operation_name = ''.join(['get_create_', resource_name,
                                  '_default_attrs'])
        attrs = {resource_name: cm.__getattribute__(operation_name)()}

        if resource_name == 'policy_rule':
            pc_id = self.create_policy_classifier()['policy_classifier']['id']
            attrs[resource_name]['policy_classifier_id'] = pc_id

        for status in all_statuses:
            attrs[resource_name]['status'] = status['status']
            attrs[resource_name]['status_details'] = (
                status['status_details'])

            update_dict = {resource_name: status}

            neutron_context = context.Context('', self._tenant_id)
            operation_name = ''.join(['create_', resource_name])
            res = plugin_ref.__getattribute__(operation_name)(
                neutron_context, attrs)
            self.assertEqual(status['status'], res['status'])
            self.assertEqual(status_details, res['status_details'])
            operation_name = ''.join(['update_', resource_name])
            res = plugin_ref.__getattribute__(operation_name)(
                neutron_context, res['id'], none_status_dict)
            self.assertIsNone(res['status'])
            self.assertIsNone(res['status_details'])
            operation_name = ''.join(['update_', resource_name])
            res = plugin_ref.__getattribute__(operation_name)(
                neutron_context, res['id'], update_dict)
            self.assertEqual(status['status'], res['status'])
            self.assertEqual(status_details, res['status_details'])

    def test_set_status_attrs(self):
        for resource_name in gpolicy.RESOURCE_ATTRIBUTE_MAP:
            self._test_set_status_attrs(self._get_resource_singular(
                resource_name), self._gbp_plugin)
