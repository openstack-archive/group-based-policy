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


from gbpservice.nfp.common import constants as nfp_constants

NEUTRON_ML2_CONF = "/etc/neutron/plugins/ml2/ml2_conf.ini"


def _parse_service_flavor_string(service_flavor_str):
    service_details = {}
    if ',' not in service_flavor_str:
        service_details['device_type'] = 'nova'
        service_details['service_vendor'] = service_flavor_str
    else:
        service_flavor_dict = dict(item.split('=') for item
                                   in service_flavor_str.split(','))
        service_details = {key.strip(): value.strip() for key, value
                           in service_flavor_dict.iteritems()}
        return service_details


def _get_dict_desc_from_string(vpn_svc):
    svc_desc = vpn_svc.split(";")
    desc = {}
    for ele in svc_desc:
        s_ele = ele.split("=")
        desc.update({s_ele[0]: s_ele[1]})
    return desc


def get_vpn_description_from_nf(network_function):
    str_description = network_function['description'].split('\n')[1]
    description = _get_dict_desc_from_string(
            str_description)
    return description, str_description


def is_vpn_in_service_chain(sc_specs):
    for spec in sc_specs:
        nodes = spec['sc_nodes']
        for node in nodes:
            service_type = node['sc_service_profile']['service_type']
            if service_type.lower() == nfp_constants.VPN:
                return True
    return False
