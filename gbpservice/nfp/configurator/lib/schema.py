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

"""Defines schema of the resource.This file contains all the generic config
   resources. Schema name defined here must be same as resource name in the
   request_data.
   Format of request data for network function device configuration API:

   request_data {
        info {
            version: <v1/v2/v3>
        }
        config [
            {
                'resource': <healthmonitor/routes/interfaces>,
                'kwargs': <resource parameters>
            },
            {
            'resource': <healthmonitor/routes/interfaces>,
            'kwargs': <resource parameters>
            }, ...
        ]
    }

"""


""" Request data schema.
"""

request_data = {'info': {},
                'config': []
                }


""" Request data info schema.
    This is a key of request data which also needs to be validated.
"""

request_data_info = {'context': "",
                     'service_type': "",
                     'service_vendor': ""}


""" Request data config schema.
    This is a key of request data which also needs to be validated.
"""

request_data_config = {'resource': "",
                       'resource_data': ""
                       }


"""Interface resource schema.
   This resource is used by orchestrator to attach/detach interfaces after
   service vm is launched successfully.
"""

interfaces = {'mgmt_ip': "",
              'provider_ip': "",
              'provider_cidr': "",
              'provider_interface_index': "",
              'stitching_ip': "",
              'stitching_cidr': "",
              'stitching_interface_index': "",
              'provider_mac': "",
              'stitching_mac': ""
              }


"""Routes resource schema.
   This resource is used by orchestrator to configure routes after service
   vm is launched successfully.
"""

routes = {'mgmt_ip': "",
          'source_cidrs': "",
          'destination_cidr': "",
          'gateway_ip': "",
          'provider_mac': "",
          'provider_interface_index': "",
          }


"""Health monitor resource schema.
   This resource is used by orchestrator to check service vm health after
   service vm is launched successfully.
"""

healthmonitor = {'vmid': "",
                 'mgmt_ip': "",
                 'periodicity': "",
                 }
