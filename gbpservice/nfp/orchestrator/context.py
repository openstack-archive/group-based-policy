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


class Subnet(object):

    def __init__(self, data):
        self.data = data

    def purge(self):
        if self.data:
            return {
                'cidr': self.data.get('cidr'),
                'id': self.data.get('id'),
                'gateway_ip': self.data.get('gateway_ip'),
                'name': self.data.get('name')
            }
        return self.data


class Port(object):

    def __init__(self, data):
        self.data = data

    def purge(self):
        if self.data:
            return {
                'id': self.data.get('id'),
                'ip_address': self.data.get('ip_address'),
                'mac_address': self.data.get('mac_address'),
                'mac': self.data.get('mac'),
                'name': self.data.get('name'),
                'fixed_ips': self.data.get('fixed_ips'),
                'gateway_ip': self.data.get('gateway_ip'),
                'neutron_port': self.data.get('neutron_port'),
                'cidr': self.data.get('cidr')
            }
        return self.data


class Pt(object):

    def __init__(self, data):
        self.data = data

    def purge(self):
        if self.data:
            return {
                'id': self.data.get('id'),
                'port_id': self.data.get('port_id'),
                'policy_target_group_id': self.data.get(
                    'policy_target_group_id'),
                'group_default_gateway': self.data.get(
                    'group_default_gateway'),
                'proxy_gateway': self.data.get(
                    'proxy_gateway')
            }
        return self.data


class Ptg(object):

    def __init__(self, data):
        self.data = data

    def purge(self):
        if self.data:
            return {
                'id': self.data.get('id'),
                'name': self.data.get('name'),
                'provided_policy_rule_sets': self.data.get(
                    'provided_policy_rule_sets'),
                'proxied_group_id': self.data.get(
                    'proxied_group_id'),
                'policy_targets': self.data.get('policy_targets'),
                'tenant_id': self.data.get('tenant_id'),
                'subnets': self.data.get('subnets'),
                'l2_policy_id': self.data.get('l2_policy_id')
            }
        return self.data


class NetworkFunctionDevice(object):

    def __init__(self, data):
        self.data = data

    def purge(self):
        if self.data:
            return {
                'id': self.data.get('id'),
                'interfaces_in_use': self.data.get('interfaces_in_use'),
                'status': self.data.get('status'),
                'mgmt_ip_address': self.data.get('mgmt_ip_address'),
                'monitoring_port_id': self.data.get('monitoring_port_id'),
                'reference_count': self.data.get('reference_count'),
                'mgmt_port_id': self.data.get('mgmt_port_id'),
                'tenant_id': self.data.get('tenant_id'),
            }
        return self.data


class NetworkFunctionInstance(object):

    def __init__(self, data):
        self.data = data

    def purge(self):
        if self.data:
            return {
                'id': self.data.get('id'),
                'status': self.data.get('status'),
                'port_info': self.data.get('port_info'),
                'network_function_device_id': self.data.get(
                    'network_function_device_id'),
                'tenant_id': self.data.get('tenant_id'),
                'name': self.data.get('name')
            }
        return self.data


class NetworkFunction(object):

    def __init__(self, data):
        self.data = data

    def purge(self):
        if self.data:
            return {
                'name': self.data.get('name'),
                'status': self.data.get('status'),
                'service_id': self.data.get('service_id'),
                'config_policy_id': self.data.get('config_policy_id'),
                'service_profile_id': self.data.get('service_profile_id'),
                'service_chain_id': self.data.get('service_chain_id'),
                'id': self.data.get('id'),
                'tenant_id': self.data.get('tenant_id'),
                'network_function_instances': self.data.get(
                    'network_function_instances'),
                'description': self.data.get('description')
            }
        return self.data


class ResourceOwnerContext(object):

    def __init__(self, data):
        self.data = data

    def purge(self):
        if self.data:
            return {
                'admin_token': self.data.get('admin_token'),
                'admin_tenant_id': self.data.get('admin_tenant_id'),
                'tenant_name': self.data.get('tenant_name'),
                'tenant': self.data.get('tenant')
            }
        return self.data


class Management(object):

    def __init__(self, data):
        self.data = data

    def purge(self):
        if self.data:
            return {
                'port': self.data.get('port')
            }
        return self.data


class Provider(object):

    def __init__(self, data):
        self.data = data

    def purge(self):
        if self.data:
            context = {
                'subnet': Subnet(
                    self.data.get('subnet')).purge(),
                'port_model': self.data.get('port_model'),
                'port_classification': self.data.get('port_classification')
            }

            if type(self.data.get('pt')) is list:
                pt_list = []
                for pt in self.data['pt']:
                    pt_list.append(Pt(pt).purge())
                context['pt'] = pt_list
            else:
                context['pt'] = Pt(self.data.get('pt')).purge()

            if type(self.data.get('ptg')) is list:
                ptg_list = []
                for ptg in self.data['ptg']:
                    ptg_list.append(Ptg(ptg).purge())
                context['ptg'] = ptg_list
            else:
                context['ptg'] = Ptg(self.data.get('ptg')).purge()

            if type(self.data.get('port')) is list:
                port_list = []
                for port in self.data['port']:
                    port_list.append(Port(port).purge())
                context['port'] = port_list
            else:
                context['port'] = Port(self.data.get('port')).purge()

            return context
        return self.data


class Consumer(object):

    def __init__(self, data):
        self.data = data

    def purge(self):
        if self.data:
            context = {
                'subnet': Subnet(
                    self.data.get('subnet')).purge(),
                'port_model': self.data.get('port_model'),
                'port_classification': self.data.get('port_classification')
            }
            if type(self.data.get('pt')) is list:
                pt_list = []
                for pt in self.data['pt']:
                    pt_list.append(Pt(pt).purge())
                context['pt'] = pt_list
            else:
                context['pt'] = Pt(self.data.get('pt')).purge()

            if type(self.data.get('ptg')) is list:
                ptg_list = []
                for ptg in self.data['ptg']:
                    ptg_list.append(Ptg(ptg).purge())
                context['ptg'] = ptg_list
            else:
                context['ptg'] = Ptg(self.data.get('ptg')).purge()

            if type(self.data.get('port')) is list:
                port_list = []
                for port in self.data['port']:
                    port_list.append(Port(port).purge())
                context['port'] = port_list
            else:
                context['port'] = Port(self.data.get('port')).purge()

            return context
        return self.data


class ScNodes(object):

    def __init__(self, data):
        self.data = data

    def purge(self):
        if self.data:
            sc_service_profile = self.data.get('sc_service_profile')
            context = {'sc_service_profile': {}}
            if sc_service_profile:
                context['sc_service_profile'][
                    'service_type'] = sc_service_profile.get('service_type')
            return context
        return self.data


class ServiceChainSpecs(object):

    def __init__(self, data):
        self.data = data

    def purge(self):
        if self.data:
            sc_nodes = self.data.get('sc_nodes')
            if type(sc_nodes) is list:
                context = []
                for sc_node in sc_nodes:
                    context.append(ScNodes(sc_node).purge())
                return {
                    'sc_nodes': context
                }
            else:
                return {
                    'sc_nodes': ScNodes(sc_nodes).purge()
                }
        return self.data


class ServiceChainInstance(object):

    def __init__(self, data):
        self.data = data

    def purge(self):
        if self.data:
            return {
                'id': self.data.get('id'),
                'config_param_values': self.data.get('config_param_values'),
                'name': self.data.get('name')
            }
        return self.data


class ConsumingPtgsDetails(object):

    def __init__(self, data):
        self.data = data

    def purge(self):
        if self.data:
            context = {}
            context['ptg'] = Ptg(self.data.get('ptg')).purge()
            subnets = self.data.get('subnets')
            if type(subnets) is list:
                subnet_ctxt = []
                for subnet in subnets:
                    subnet_ctxt.append(Subnet(subnet).purge())
                context['subnets'] = subnet_ctxt
            else:
                context['subnets'] = Subnet(subnets).purge()
            return context
        return self.data


class ServiceChainNode(object):

    def __init__(self, data):
        self.data = data

    def purge(self):
        if self.data:
            return {
                'service_profile_id': self.data.get('service_profile_id'),
                'service_type': self.data.get('service_type'),
                'config': self.data.get('config'),
                'name': self.data.get('name'),
                'id': self.data.get('id')
            }
        return self.data


class ServiceDetails(object):

    def __init__(self, data):
        self.data = data

    def purge(self):
        if self.data:
            return {
                'service_vendor': self.data.get('service_vendor'),
                'service_type': self.data.get('service_type'),
                'network_mode': self.data.get('network_mode'),
                'image_name': self.data.get('image_name'),
                'device_type': self.data.get('device_type'),
            }
        return self.data


class ConsumingEpsDetails(object):

    def __init__(self, data):
        self.data = data

    def purge(self):
        if self.data:
            return {
                'id': self.data.get('id')
            }
        return self.data


class ServerGrpId(object):

    def __init__(self, data):
        self.data = data

    def purge(self):
        if self.data:
            return {
                'result': self.data.get('result')
            }
        return self.data


class ServiceProfile(object):

    def __init__(self, data):
        self.data = data

    def purge(self):
        if self.data:
            return {
                'id': self.data.get('id'),
                'service_flavor': self.data.get('service_flavor'),
                'service_type': self.data.get('service_type')
            }
        return self.data


class LogContext(object):

    def __init__(self, data):
        self.data = data

    def purge(self):
        if self.data:
            return {
                'meta_id': self.data.get('meta_id', '-'),
                'nfi_id': self.data.get('nfi_id', '-'),
                'nfd_id': self.data.get('nfd_id', '-'),
                'path': self.data.get('path'),
                'auth_token': self.data.get('auth_token'),
                'namespace': self.data.get('namespace')
            }
        return self.data


class NfpContext(object):

    def __init__(self, data):
        self.data = data

    def purge(self):

        context = {
            'active_nfd_ids': self.data.get('active_nfd_ids'),
            'device_without_plugging': self.data.get(
                'device_without_plugging'),
            'id': self.data.get('id'),      # event id
            'key': self.data.get('key'),    # event key
            'admin_token': self.data.get('admin_token'),
            'event_desc': self.data.get('event_desc'),
            'config_policy_id': self.data.get('config_policy_id'),
            'management_ptg_id': self.data.get('management_ptg_id'),
            'network_function_mode': self.data.get('network_function_mode'),
            'files': self.data.get('files'),
            'base_mode_support': self.data.get('base_mode_support'),
            'share_existing_device': self.data.get('share_existing_device'),
            'tenant_id': self.data.get('tenant_id'),
            'binding_key': self.data.get('binding_key'),
            'provider_metadata': self.data.get('provider_metadata'),
            'admin_tenant_id': self.data.get('admin_tenant_id'),
            'is_nfi_in_graph': self.data.get('is_nfi_in_graph'),
            'network_function_device': NetworkFunctionDevice(
                self.data.get('network_function_device')).purge(),
            'network_function_instance': NetworkFunctionInstance(
                self.data.get('network_function_instance')).purge(),
            'network_function': NetworkFunction(
                self.data.get('network_function')).purge(),
            'resource_owner_context': ResourceOwnerContext(
                self.data.get('resource_owner_context')).purge(),
            'management': Management(
                self.data.get('management')).purge(),
            'provider': Provider(
                self.data.get('provider')).purge(),
            'consumer': Consumer(
                self.data.get('consumer')).purge(),
            'service_chain_instance': ServiceChainInstance(
                self.data.get('service_chain_instance')).purge(),
            'service_details': ServiceDetails(
                self.data.get('service_details')).purge(),
            'service_chain_node': ServiceChainNode(
                self.data.get('service_chain_node')).purge(),
            'server_grp_id': ServerGrpId(
                self.data.get('server_grp_id')).purge(),
            'service_profile': ServiceProfile(
                self.data.get('service_profile')).purge(),
            'log_context': LogContext(self.data.get('log_context')).purge(),
            'enable_port_security': self.data.get('enable_port_security')
        }

        service_chain_specs = self.data.get('service_chain_specs')
        if type(service_chain_specs) is list:
            ctxt = []
            for sc_specs in service_chain_specs:
                ctxt.append(ServiceChainSpecs(sc_specs).purge())
            context['service_chain_specs'] = ctxt
        else:
            context['service_chain_specs'] = ServiceChainSpecs(
                service_chain_specs).purge()

        consuming_ptgs_details = self.data.get('consuming_ptgs_details')
        if type(consuming_ptgs_details) is list:
            ctxt = []
            for ptgs_details in consuming_ptgs_details:
                ctxt.append(ConsumingPtgsDetails(ptgs_details).purge())
            context['consuming_ptgs_details'] = ctxt
        else:
            context['consuming_ptgs_details'] = ConsumingPtgsDetails(
                consuming_ptgs_details).purge()

        consuming_eps_details = self.data.get('consuming_eps_details')
        if type(consuming_eps_details) is list:
            ctxt = []
            for eps_details in consuming_eps_details:
                ctxt.append(ConsumingEpsDetails(eps_details).purge())
            context['consuming_eps_details'] = ctxt
        else:
            context['consuming_eps_details'] = ConsumingEpsDetails(
                consuming_eps_details).purge()

        return context
