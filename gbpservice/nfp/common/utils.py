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

import os
import yaml

from gbpservice.nfp.common import constants as nfp_constants
from gbpservice.nfp.core import log as nfp_logging

LOG = nfp_logging.getLogger(__name__)

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


def get_config_file(service_vendor):
    file_name = service_vendor + '.day0'
    return file_name


def get_service_vm_context(service_vendor, tenant_name=None):
        """ Load day0 config file
            :param service_vendor: service vendor name
            :param tenant_name

            - Day0 file name must start with service vendor name followed by
              string '.day0'
              e.g Vyos day0 file name must be vyos.day0
            - File format can be of any type like text file, json file etc

            - service vendor specific default day0 config file
                /etc/nfp/<service_vendor>/<day0_file>
                e.g /etc/nfp/vyos/vyos.day0
            - tenant specific vendor day0 config file
                /etc/nfp/<service_vendor>/<tenant_name>/<day0_file>
                e.g /etc/nfp/vyos/services/vyos.day0

            Returns - day0 config file
        """
        try:
            file_name = ''
            default_config_dir = nfp_constants.CONFIG_DIR
            vendor_day0_dir = default_config_dir + service_vendor + '/'
            if tenant_name:
                tenant_day0_dir = vendor_day0_dir + tenant_name + '/'
                if os.path.isdir(tenant_day0_dir):
                    file_name = get_config_file(service_vendor)
            if file_name:
                day0_config_file = tenant_day0_dir + file_name
            else:
                if os.path.isdir(vendor_day0_dir):
                    file_name = get_config_file(service_vendor)
                    day0_config_file = vendor_day0_dir + file_name
                else:
                    day0_config_file = '/fake_file_path'

            with open(day0_config_file) as _file:
                try:
                    svm_context = yaml.load(_file)
                except Exception as e:
                    msg = ("Failed yaml load file %s. Reason: %s"
                           % (day0_config_file, e))
                    raise Exception(msg)

            msg = ("Loaded day0 config file %s for service_vendor %s,"
                   "tenant_name %s" % (day0_config_file, service_vendor,
                                       tenant_name))
            LOG.info(msg)
            return svm_context
        except Exception as ex:
            msg = ("Failed to read day0 config file, ERROR: %s" % ex)
            LOG.error(msg)
            return None
