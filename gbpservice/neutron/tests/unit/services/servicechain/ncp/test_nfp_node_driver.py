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

import mock
from neutron.db import api as db_api
from neutron.db import model_base
from neutron.plugins.common import constants
from oslo_serialization import jsonutils
import webob


from gbpservice.neutron.services.servicechain.plugins.ncp import (
    plugin as ncp_plugin)
from gbpservice.neutron.services.servicechain.plugins.ncp import config  # noqa
from gbpservice.neutron.services.servicechain.plugins.ncp.node_drivers import (
    nfp_node_driver as nfp_node_driver)
# from gbpservice.neutron.tests.unit.db.grouppolicy import test_group_policy_db
from gbpservice.neutron.tests.unit.services.grouppolicy import (
    test_resource_mapping as test_gp_driver)
from gbpservice.neutron.tests.unit.services.servicechain import (
    test_servicechain_plugin as test_base)
from gbpservice.neutron.tests.unit.services.servicechain.ncp import (
    test_ncp_plugin as test_ncp_plugin)

SERVICE_DELETE_TIMEOUT = 15
SVC_MANAGEMENT_PTG = 'foo'


class ServiceChainNCPTestPlugin(ncp_plugin.NodeCompositionPlugin):

    # supported_extension_aliases = ['servicechain'] + (
    #    test_group_policy_db.UNSUPPORTED_REQUIRED_EXTS)
    supported_extension_aliases = ['servicechain']
    path_prefix = "/servicechain"


SC_PLUGIN_KLASS = (ServiceChainNCPTestPlugin.__module__ + '.' +
                   ServiceChainNCPTestPlugin.__name__)
CORE_PLUGIN = test_gp_driver.CORE_PLUGIN
GP_PLUGIN_KLASS = (
    "gbpservice.neutron.services.grouppolicy.plugin.GroupPolicyPlugin"
)


class NFPNodeDriverTestCase(
        test_base.TestGroupPolicyPluginGroupResources,
        test_ncp_plugin.NodeCompositionPluginTestMixin):

    DEFAULT_VPN_CONFIG_DICT = {
            "heat_template_version": "2013-05-23",
            "description": "Creates new vpn service",
            "parameters": {
                "RouterId": {
                     "type": "string", "description": "Router ID"
                },
                "Subnet": {
                     "type": "string", "description": "Subnet id"
                },
                "ClientAddressPoolCidr": {
                     "type": "string", "description": "Pool"
                },
                "ServiceDescription": {
                     "type": "string", "description": "fip;tunnel_local-cidr"
                }
            },
            "resources": {
                "SSLVPNConnection": {
                    "type": "OS::Neutron::SSLVPNConnection",
                    "properties": {
                        "credential_id": "",
                        "client_address_pool_cidr": {
                            "get_param": "ClientAddressPoolCidr"
                        },
                        "name": "vtun0",
                        "vpnservice_id": {
                             "get_resource": "VPNService"
                        },
                        "admin_state_up": 'true'
                    }
                },
                "VPNService": {
                    "type": "OS::Neutron::VPNService",
                    "properties": {
                        "router_id": {
                            "get_param": "RouterId"
                        },
                        "subnet_id": {
                            "get_param": "Subnet"
                        },
                        "admin_state_up": 'true',
                        "description": {
                            "get_param": "ServiceDescription"
                        },
                        "name": "VPNService"
                    }
                }
            }
    }
    DEFAULT_VPN_CONFIG = jsonutils.dumps(DEFAULT_VPN_CONFIG_DICT)
    DEFAULT_LB_CONFIG_DICT = {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "test_pool": {
                    "Type": "OS::Neutron::Pool",
                    "Properties": {
                        "admin_state_up": True,
                        "description": "Haproxy pool from teplate",
                        "lb_method": "ROUND_ROBIN",
                        "monitors": [{"Ref": "HttpHM"}],
                        "name": "Haproxy pool",
                        "protocol": "HTTP",
                        "subnet_id": {"Ref": "Subnet"},
                        "vip": {
                            "subnet": {"Ref": "192.168.100.0"},
                            "address": {"Ref": "192.168.100.2"},
                            "name": "Haproxy vip",
                            "protocol_port": 80,
                            "connection_limit": -1,
                            "admin_state_up": True,
                            "description": "Haproxy vip from template"
                        }
                    }
                },
                "test_lb": {
                    "Type": "OS::Neutron::LoadBalancer",
                    "Properties": {
                        "pool_id": {"Ref": "HaproxyPool"},
                        "protocol_port": 80
                    }
                }
            }
    }
    DEFAULT_LB_CONFIG = jsonutils.dumps(DEFAULT_LB_CONFIG_DICT)
    DEFAULT_FW_CONFIG_DICT = {
            "heat_template_version": "2013-05-23",
            "resources": {
                'test_fw': {
                    "type": "OS::Neutron::Firewall",
                    "properties": {
                        "admin_state_up": True,
                        "firewall_policy_id": {
                            "get_resource": "Firewall_policy"},
                        "name": "testFirewall",
                        "description": "test Firewall"
                    }
                },
                'test_fw_policy': {
                    "type": "OS::Neutron::FirewallPolicy",
                    "properties": {
                        "shared": False,
                        "description": "test firewall policy",
                        "name": "testFWPolicy",
                        "firewall_rules": [{
                                "get_resource": "Rule_1"}],
                        "audited": True
                    }
                }
            }
    }
    DEFAULT_FW_CONFIG = jsonutils.dumps(DEFAULT_FW_CONFIG_DICT)
    SERVICE_PROFILE_VENDOR = 'NFP'

    def _create_service_profile(self, **kwargs):
        if not kwargs.get('insertion_mode'):
            kwargs['insertion_mode'] = 'l3'
        if not kwargs.get('service_flavor'):
            if kwargs['service_type'] == 'LOADBALANCER':
                kwargs['service_flavor'] = 'haproxy'
            else:
                kwargs['service_flavor'] = 'vyos'
        return super(NFPNodeDriverTestCase, self)._create_service_profile(
            **kwargs)

    def setUp(self):
        config.cfg.CONF.set_override('service_delete_timeout',
                                     SERVICE_DELETE_TIMEOUT,
                                     group='nfp_node_driver')

        config.cfg.CONF.set_override(
            'extension_drivers', ['proxy_group'], group='group_policy')
        config.cfg.CONF.set_override('node_drivers', ['nfp_node_driver'],
                                     group='node_composition_plugin')
        config.cfg.CONF.set_override('node_plumber', 'stitching_plumber',
                                     group='node_composition_plugin')
        config.cfg.CONF.set_override('policy_drivers',
                                     ['implicit_policy', 'resource_mapping',
                                      'chain_mapping'],
                                     group='group_policy')
        super(NFPNodeDriverTestCase, self).setUp(
            core_plugin=CORE_PLUGIN,
            gp_plugin=GP_PLUGIN_KLASS,
            sc_plugin=SC_PLUGIN_KLASS)
        engine = db_api.get_engine()
        model_base.BASEV2.metadata.create_all(engine)

    def test_manager_initialized(self):
        mgr = self.plugin.driver_manager
        self.assertIsInstance(mgr.ordered_drivers[0].obj,
                              nfp_node_driver.NFPNodeDriver)
        for driver in mgr.ordered_drivers:
            self.assertTrue(driver.obj.initialized)

    def _nfp_create_profiled_servicechain_node(
            self, service_type=constants.LOADBALANCER, shared_profile=False,
            profile_tenant_id=None, profile_id=None,
            service_flavor=None, **kwargs):
        if not profile_id:
            prof = self.create_service_profile(
                service_type=service_type,
                shared=shared_profile,
                vendor=self.SERVICE_PROFILE_VENDOR,
                insertion_mode='l3', service_flavor='haproxy',
                tenant_id=profile_tenant_id or self._tenant_id)[
                                                    'service_profile']
        else:
            prof = self.get_service_profile(profile_id)
        service_config = kwargs.get('config')
        if not service_config or service_config == '{}':
            if service_type == constants.FIREWALL:
                kwargs['config'] = self.DEFAULT_FW_CONFIG
            else:
                kwargs['config'] = self.DEFAULT_LB_CONFIG
        return self.create_servicechain_node(
            service_profile_id=prof['id'], **kwargs)

    def _create_simple_fw_service_chain(self, number_of_nodes=1,
                                     service_type='FIREWALL'):
        prof = self.create_service_profile(
            service_type=service_type,
            vendor=self.SERVICE_PROFILE_VENDOR,
            insertion_mode='l3', service_flavor='vyos')['service_profile']
        node_ids = []
        for x in xrange(number_of_nodes):
            node_ids.append(self.create_servicechain_node(
                service_profile_id=prof['id'],
                config=self.DEFAULT_FW_CONFIG,
                expected_res_status=201)['servicechain_node']['id'])
        return self._nfp_create_chain_with_nodes(node_ids)

    def _nfp_create_chain_with_nodes(self, node_ids=None):
        node_ids = node_ids or []
        spec = self.create_servicechain_spec(
            nodes=node_ids,
            expected_res_status=201)['servicechain_spec']
        prs = self._create_redirect_prs(spec['id'])['policy_rule_set']
        provider = self.create_policy_target_group(
            provided_policy_rule_sets={prs['id']: ''})['policy_target_group']
        with mock.patch.object(nfp_node_driver.NFPClientApi,
                          "consumer_ptg_added_notification") as ptg_added:
            consumer = self.create_policy_target_group(
                consumed_policy_rule_sets={prs['id']: ''})[
                'policy_target_group']
            ptg_added.assert_called_once_with(mock.ANY,
                        mock.ANY, mock.ANY)
        return provider, consumer, prs

    def test_spec_parameters(self):
        pass

    def test_spec_ordering_list_servicechain_instances(self):
        pass


class TestServiceChainInstance(NFPNodeDriverTestCase):

    def test_node_create(self):
        with mock.patch.object(nfp_node_driver.NFPClientApi,
                               "create_network_function") as create_nf:
            with mock.patch.object(nfp_node_driver.NFPClientApi,
                               "get_network_function") as get_nf:
                create_nf.return_value = {
                    'id': '126231632163'
                }
                get_nf.return_value = {
                    'id': '126231632163',
                    'status': 'ACTIVE'
                }
                self._create_simple_fw_service_chain()
                create_nf.assert_called_once_with(
                        mock.ANY,
                        network_function=mock.ANY)
                get_nf.assert_called_with(mock.ANY, mock.ANY)

    def _test_node_update(self):
        with mock.patch.object(nfp_node_driver.NFPClientApi,
                               "create_network_function") as create_nf:
            with mock.patch.object(nfp_node_driver.NFPClientApi,
                               "get_network_function") as get_nf:
                with mock.patch.object(nfp_node_driver.NFPClientApi,
                               "update_service_config") as update_svc_config:
                    create_nf.return_value = {
                        'id': '126231632163'
                    }
                    get_nf.return_value = {
                        'id': '126231632163',
                        'status': 'ACTIVE'
                    }
                    prof = self.create_service_profile(
                                service_type=constants.FIREWALL,
                                vendor=self.SERVICE_PROFILE_VENDOR,
                                insertion_mode='l3',
                                service_flavor='vyos')['service_profile']

                    self.create_policy_target_group(
                                name='foo')['policy_target_group']
                    node = self.create_servicechain_node(
                                service_profile_id=prof['id'],
                                config=self.DEFAULT_FW_CONFIG,
                                expected_res_status=201)['servicechain_node']

                    self._nfp_create_chain_with_nodes(node_ids=[node['id']])
                    self.update_servicechain_node(
                                node['id'],
                                name='newname',
                                expected_res_status=200)
                    create_nf.assert_called_once_with(
                        mock.ANY,
                        network_function=mock.ANY)
                    get_nf.assert_called_once_with(mock.ANY, mock.ANY)
                    update_svc_config.assert_called_once_with()

    def test_node_delete(self):
        with mock.patch.object(nfp_node_driver.NFPClientApi,
                               "create_network_function") as create_nf:
            with mock.patch.object(nfp_node_driver.NFPClientApi,
                                   'get_network_function') as get_nf:
                get_nf.return_value = {
                    'id': '126231632163',
                    'status': 'ACTIVE'
                }
                create_nf.return_value = {
                    'id': '126231632163'
                }

                prof = self.create_service_profile(
                                service_type=constants.FIREWALL,
                                vendor=self.SERVICE_PROFILE_VENDOR,
                                insertion_mode='l3',
                                service_flavor='vyos')['service_profile']
                node_id = self.create_servicechain_node(
                                service_profile_id=prof['id'],
                                config=self.DEFAULT_FW_CONFIG,
                                expected_res_status=201)['servicechain_node'][
                                'id']

                spec = self.create_servicechain_spec(
                    nodes=[node_id],
                    expected_res_status=201)['servicechain_spec']
                prs = self._create_redirect_prs(spec['id'])['policy_rule_set']
                provider = self.create_policy_target_group(
                    provided_policy_rule_sets={prs['id']: ''})[
                    'policy_target_group']
                create_nf.assert_called_once_with(
                        mock.ANY,
                        network_function=mock.ANY)
        with mock.patch.object(nfp_node_driver.NFPClientApi,
                               "get_network_function") as get_nf:
            with mock.patch.object(nfp_node_driver.NFPClientApi,
                               "delete_network_function") as delete_nf:
                get_nf.return_value = None
                self.delete_policy_target_group(
                              provider['id'], expected_res_status=204)
                expected_plugin_context = mock.ANY
                expected_network_function_id = mock.ANY
                expected_plugin_context = mock.ANY
                get_nf.assert_called_once_with(
                              expected_plugin_context,
                              expected_network_function_id)
                delete_nf.assert_called_once_with(
                          context=mock.ANY,
                          network_function_id=mock.ANY)

    def test_wait_for_network_function_delete_completion(self):
        with mock.patch.object(nfp_node_driver.NFPClientApi,
                               "create_network_function") as create_nf:
            with mock.patch.object(nfp_node_driver.NFPClientApi,
                                   'get_network_function') as get_nf:
                get_nf.return_value = {
                    'id': '126231632163',
                    'status': 'ACTIVE'
                }
                create_nf.return_value = {
                    'id': '126231632163'
                }
                prof = self.create_service_profile(
                                service_type=constants.FIREWALL,
                                vendor=self.SERVICE_PROFILE_VENDOR,
                                insertion_mode='l3',
                                service_flavor='vyos')['service_profile']
                node_id = self.create_servicechain_node(
                                service_profile_id=prof['id'],
                                config=self.DEFAULT_FW_CONFIG,
                                expected_res_status=201)['servicechain_node'][
                                'id']

                spec = self.create_servicechain_spec(
                                nodes=[node_id],
                                expected_res_status=201)['servicechain_spec']
                prs = self._create_redirect_prs(spec['id'])['policy_rule_set']
                provider = self.create_policy_target_group(
                                provided_policy_rule_sets={prs['id']: ''})[
                                'policy_target_group']
                create_nf.assert_called_once_with(
                        mock.ANY,
                        network_function=mock.ANY)

            with mock.patch.object(nfp_node_driver.NFPClientApi,
                                   'delete_network_function') as delete_nf:
                with mock.patch.object(nfp_node_driver.NFPClientApi,
                                   'get_network_function') as get_nf:
                    delete_nf.return_value = None
                    get_nf.return_value = None
                    # Removing the PRSs will make the PTG deletable again
                    self.update_policy_target_group(
                                       provider['id'],
                                       provided_policy_rule_sets={},
                                       expected_res_status=200)
                    self.delete_policy_target_group(provider['id'],
                                       expected_res_status=204)
                    delete_nf.assert_called_once_with(context=mock.ANY,
                                       network_function_id=mock.ANY)
                    get_nf.assert_called_once_with(mock.ANY, mock.ANY)

    def _create_policy_target_port(self, policy_target_group_id):
        pt = self.create_policy_target(
                policy_target_group_id=policy_target_group_id)['policy_target']
        req = self.new_show_request('ports', pt['port_id'], fmt=self.fmt)
        port = self.deserialize(self.fmt,
                                req.get_response(self.api))['port']
        return (pt, port)

    def test_lb_node_create(self, consumer_external=False):
        with mock.patch.object(nfp_node_driver.NFPClientApi,
                               "create_network_function") as create_nf:
            with mock.patch.object(nfp_node_driver.NFPClientApi,
                                   'get_network_function') as get_nf:
                get_nf.return_value = {
                    'id': '126231632163',
                    'status': 'ACTIVE'
                }
                create_nf.return_value = {
                    'id': '126231632163'
                }

                node_id = self._nfp_create_profiled_servicechain_node(
                    service_type=constants.LOADBALANCER)['servicechain_node'][
                    'id']
                spec = self.create_servicechain_spec(
                    nodes=[node_id],
                    expected_res_status=201)['servicechain_spec']

                prs = self._create_redirect_prs(spec['id'])['policy_rule_set']
                params = [{'type': 'ip_single', 'name': 'vip_ip',
                           'value': 'self_subnet'}]

                nsp = self.create_network_service_policy(
                           network_service_params=params)
                network_service_policy_id = nsp['network_service_policy']['id']
                provider = self.create_policy_target_group(
                           network_service_policy_id=network_service_policy_id,
                           provided_policy_rule_sets={prs['id']: ''})[
                           'policy_target_group']

                with mock.patch.object(nfp_node_driver.NFPClientApi,
                          "policy_target_added_notification") as pt_added:
                    # Verify notification issued for created PT in the provider
                    _, port = self._create_policy_target_port(provider['id'])
                    pt_added.assert_called_once_with(mock.ANY, mock.ANY,
                           mock.ANY)

                if consumer_external:
                    self._create_external_policy(prs['id'])
                else:
                    self.create_policy_target_group(
                          consumed_policy_rule_sets={prs['id']: ''})

                create_nf.assert_called_once_with(
                          mock.ANY,
                          network_function=mock.ANY)
                get_nf.assert_called_with(mock.ANY, mock.ANY)

    def test_invalid_service_type_rejected(self):
        node_used = self._nfp_create_profiled_servicechain_node(
            service_type="test")['servicechain_node']
        spec_used = self.create_servicechain_spec(
            nodes=[node_used['id']])['servicechain_spec']
        provider = self.create_policy_target_group()['policy_target_group']
        classifier = self.create_policy_classifier()['policy_classifier']
        res = self.create_servicechain_instance(
            provider_ptg_id=provider['id'],
            classifier_id=classifier['id'],
            servicechain_specs=[spec_used['id']],
            expected_res_status=webob.exc.HTTPBadRequest.code)
        self.assertEqual('NoDriverAvailableForAction',
                         res['NeutronError']['type'])

    def test_is_node_order_in_spec_supported(self):
        lb_prof = self.create_service_profile(
                    service_type=constants.LOADBALANCER,
                    vendor=self.SERVICE_PROFILE_VENDOR,
                    insertion_mode='l3',
                    service_flavor='haproxy')['service_profile']
        vpn_prof = self.create_service_profile(
                    service_type=constants.VPN,
                    vendor=self.SERVICE_PROFILE_VENDOR,
                    insertion_mode='l3',
                    service_flavor='vyos')['service_profile']
        vpn_node = self.create_servicechain_node(
                    service_profile_id=vpn_prof['id'],
                    config=self.DEFAULT_VPN_CONFIG,
                    expected_res_status=201)['servicechain_node']
        lb_node = self.create_servicechain_node(
                    service_profile_id=lb_prof['id'],
                    config=self.DEFAULT_LB_CONFIG,
                    expected_res_status=201)['servicechain_node']
        node_ids = [lb_node['id'], vpn_node['id']]
        spec = self.create_servicechain_spec(
                    nodes=node_ids,
                    expected_res_status=201)['servicechain_spec']

        provider = self.create_policy_target_group()['policy_target_group']
        classifier = self.create_policy_classifier()['policy_classifier']
        res = self.create_servicechain_instance(
                    provider_ptg_id=provider['id'],
                    classifier_id=classifier['id'],
                    servicechain_specs=[spec['id']],
                    expected_res_status=webob.exc.HTTPBadRequest.code)
        self.assertEqual('NoDriverAvailableForAction',
                    res['NeutronError']['type'])

    def test_validate_update(self):
        with mock.patch.object(nfp_node_driver.NFPClientApi,
                               "create_network_function") as create_nf:
            with mock.patch.object(nfp_node_driver.NFPClientApi,
                               "get_network_function") as get_nf:
                create_nf.return_value = {
                    'id': '126231632163'
                }
                get_nf.return_value = {
                    'id': '126231632163',
                    'status': 'ACTIVE'
                }
                fw_prof = self.create_service_profile(
                            service_type=constants.FIREWALL,
                            vendor=self.SERVICE_PROFILE_VENDOR,
                            insertion_mode='l3',
                            service_flavor='vyos')['service_profile']
                fw_node = self.create_servicechain_node(
                            service_profile_id=fw_prof['id'],
                            config=self.DEFAULT_FW_CONFIG,
                            expected_res_status=201)['servicechain_node']
                node_ids = [fw_node['id']]
                spec = self.create_servicechain_spec(
                            nodes=node_ids,
                            expected_res_status=201)['servicechain_spec']
                provider = self.create_policy_target_group()[
                            'policy_target_group']
                classifier = self.create_policy_classifier()[
                            'policy_classifier']
                servicechain_instance = self.create_servicechain_instance(
                            provider_ptg_id=provider['id'],
                            classifier_id=classifier['id'],
                            servicechain_specs=[spec['id']])[
                            'servicechain_instance']
                fw_prof = self.create_service_profile(
                            service_type='test',
                            vendor=self.SERVICE_PROFILE_VENDOR,
                            insertion_mode='l3',
                            service_flavor='vyos')['service_profile']
                fw_node = self.create_servicechain_node(
                            service_profile_id=fw_prof['id'],
                            config=self.DEFAULT_FW_CONFIG,
                            expected_res_status=201)['servicechain_node']
                node_ids = [fw_node['id']]
                spec = self.create_servicechain_spec(
                            nodes=node_ids,
                            expected_res_status=201)['servicechain_spec']
                create_nf.assert_called_once_with(
                        mock.ANY,
                        network_function=mock.ANY)
            with mock.patch.object(nfp_node_driver.NFPClientApi,
                               "get_network_function") as get_nf:
                with mock.patch.object(nfp_node_driver.NFPClientApi,
                               "delete_network_function") as delete_nf:
                    get_nf.return_value = None
                    res = self.update_servicechain_instance(
                            servicechain_instance['id'],
                            servicechain_specs=[spec['id']],
                            expected_res_status=webob.exc.HTTPBadRequest.code)
                    get_nf.assert_called_once_with(mock.ANY, mock.ANY)
                    delete_nf.assert_called_once_with(context=mock.ANY,
                            network_function_id=mock.ANY)
                    self.assertEqual('NoDriverAvailableForAction',
                            res['NeutronError']['type'])

    def test_update_node_consumer_ptg_added(self):
        with mock.patch.object(nfp_node_driver.NFPClientApi,
                               "create_network_function") as create_nf:
            with mock.patch.object(nfp_node_driver.NFPClientApi,
                                   'get_network_function') as get_nf:
                get_nf.return_value = {
                    'id': '126231632163',
                    'status': 'ACTIVE'
                }
                create_nf.return_value = {
                    'id': '126231632163'
                }

                prof = self.create_service_profile(
                                service_type=constants.FIREWALL,
                                vendor=self.SERVICE_PROFILE_VENDOR,
                                insertion_mode='l3',
                                service_flavor='vyos')['service_profile']
                node_id = self.create_servicechain_node(
                                service_profile_id=prof['id'],
                                config=self.DEFAULT_FW_CONFIG,
                                expected_res_status=201)['servicechain_node'][
                                'id']

                spec = self.create_servicechain_spec(
                    nodes=[node_id],
                    expected_res_status=201)['servicechain_spec']
                prs = self._create_redirect_prs(spec['id'])['policy_rule_set']
                self.create_policy_target_group(
                    provided_policy_rule_sets={prs['id']: ''})[
                    'policy_target_group']
                create_nf.assert_called_once_with(
                        mock.ANY,
                        network_function=mock.ANY)
                get_nf.assert_called_once_with(mock.ANY, mock.ANY)
                with mock.patch.object(nfp_node_driver.NFPClientApi,
                          "consumer_ptg_added_notification") as ptg_added:
                    self.create_policy_target_group(
                        consumed_policy_rule_sets={prs['id']: ''})[
                        'policy_target_group']
                    ptg_added.assert_called_once_with(mock.ANY,
                        mock.ANY, mock.ANY)

    def _test_update_node_consumer_ptg_removed(self):
        with mock.patch.object(nfp_node_driver.NFPClientApi,
                               "create_network_function") as create_nf:
            with mock.patch.object(nfp_node_driver.NFPClientApi,
                                   'get_network_function') as get_nf:
                get_nf.return_value = {
                    'id': '126231632163',
                    'status': 'ACTIVE'
                }
                create_nf.return_value = {
                    'id': '126231632163'
                }

                prof = self.create_service_profile(
                                service_type=constants.FIREWALL,
                                vendor=self.SERVICE_PROFILE_VENDOR,
                                insertion_mode='l3',
                                service_flavor='vyos')['service_profile']
                node_id = self.create_servicechain_node(
                                service_profile_id=prof['id'],
                                config=self.DEFAULT_FW_CONFIG,
                                expected_res_status=201)['servicechain_node'][
                                'id']

                spec = self.create_servicechain_spec(
                    nodes=[node_id],
                    expected_res_status=201)['servicechain_spec']
                prs = self._create_redirect_prs(spec['id'])['policy_rule_set']
                self.create_policy_target_group(
                    provided_policy_rule_sets={prs['id']: ''})[
                    'policy_target_group']
                with mock.patch.object(nfp_node_driver.NFPClientApi,
                    "consumer_ptg_added_notification") as ptg_added:
                    consumer = self.create_policy_target_group(
                        consumed_policy_rule_sets={prs['id']: ''})[
                        'policy_target_group']
                    ptg_added.assert_called_once_with(mock.ANY, mock.ANY,
                        mock.ANY)
                create_nf.assert_called_once_with(
                        mock.ANY,
                        network_function=mock.ANY)
                get_nf.assert_called_once_with(mock.ANY, mock.ANY)

        with mock.patch.object(nfp_node_driver.NFPClientApi,
            "consumer_ptg_removed_notification") as ptg_removed:
            self.delete_policy_target_group(
                    consumer['id'], expected_res_status=204)
            ptg_removed.assert_called_once_with(mock.ANY, mock.ANY, mock.ANY)

    def test_policy_target_add_remove(self):
        prof = self._create_service_profile(
            service_type='LOADBALANCER',
            vendor=self.SERVICE_PROFILE_VENDOR,
            insertion_mode='l3', service_flavor='haproxy')['service_profile']
        node = self.create_servicechain_node(
            service_profile_id=prof['id'],
            config=self.DEFAULT_LB_CONFIG,
            expected_res_status=201)['servicechain_node']

        spec = self.create_servicechain_spec(
            nodes=[node['id']],
            expected_res_status=201)['servicechain_spec']
        prs = self._create_redirect_prs(spec['id'])['policy_rule_set']
        with mock.patch.object(nfp_node_driver.NFPClientApi,
                               "create_network_function") as create_nf:
            with mock.patch.object(nfp_node_driver.NFPClientApi,
                                   'get_network_function') as get_nf:
                get_nf.return_value = {
                    'id': '126231632163',
                    'status': 'ACTIVE'
                }
                create_nf.return_value = {
                    'id': '126231632163'
                }
                params = [{'type': 'ip_single', 'name': 'vip_ip',
                           'value': 'self_subnet'}]
                nsp = self.create_network_service_policy(
                           network_service_params=params)
                network_service_policy_id = nsp['network_service_policy'][
                           'id']
                provider = self.create_policy_target_group(
                      network_service_policy_id=network_service_policy_id,
                      provided_policy_rule_sets={prs['id']: ''})[
                      'policy_target_group']
                self.create_policy_target_group(
                      consumed_policy_rule_sets={prs['id']: ''})

                with mock.patch.object(nfp_node_driver.NFPClientApi,
                          "policy_target_added_notification") as pt_added:
                    # Verify notification issued for created PT in the provider
                    pt = self.create_policy_target(
                         policy_target_group_id=provider['id'])[
                         'policy_target']
                    create_nf.assert_called_once_with(
                            mock.ANY,
                            network_function=mock.ANY)
                    get_nf.assert_called_with(mock.ANY, mock.ANY)
                    pt_added.assert_called_once_with(mock.ANY, mock.ANY,
                            mock.ANY)

        # Verify notification issued for deleted PT in the provider
        with mock.patch.object(nfp_node_driver.NFPClientApi,
                          "policy_target_removed_notification") as pt_removed:
            self.delete_policy_target(pt['id'])
            pt_removed.assert_called_once_with(mock.ANY, mock.ANY, mock.ANY)
