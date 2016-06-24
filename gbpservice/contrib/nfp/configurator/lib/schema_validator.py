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

from gbpservice.nfp.core import log as nfp_logging

from gbpservice.contrib.nfp.configurator.lib import constants as const
import gbpservice.contrib.nfp.configurator.lib.schema as schema
LOG = nfp_logging.getLogger(__name__)


class SchemaValidator(object):
    """ Validates request data against standard resource schemas given in schema.py

        Validation is focused on keys. It cross checks if resources in
        request_data has all the keys given in the schema of that resource.
    """

    def decode(self, request_data, is_generic_config):
        """ Validate request data against resource schema.

        :param: request_data

        Returns: True - If schema validation is successful.
                 False - If schema validation fails.

        """
        try:
            if not self.validate_schema(request_data, schema.request_data):
                return False

            if ('service_type' in request_data['info'] and
                    'service_vendor' in request_data['info'] and
                    'context' in request_data['info']):
                pass
            elif not self.validate_schema(request_data['info'],
                                          schema.request_data_info):
                return False

            for config in request_data['config']:
                if not self.validate_schema(config,
                                            schema.request_data_config):
                    return False

                resource_type = config['resource']
                resource = config['resource_data']

                """Do not validate kwargs for
                   1) *aaS apis
                   2) generic config of loadbalancer for resource
                      interfaces and routes
                """
                if (not is_generic_config or
                        (request_data['info'][
                                'service_type'] in [const.LOADBALANCER,
                                                    const.LOADBALANCERV2] and
                            resource_type != const.HEALTHMONITOR)):
                        continue

                resource_schema = getattr(schema, resource_type)
                if not self.validate_schema(resource, resource_schema):
                    return False
        except Exception as e:
            LOG.error(e)
            return False

        return True

    def validate_schema(self, resource, resource_schema):
        """ Validate resource against resource_schema

        :param resource
        :param resource_schema

        Returns: True/False
        """
        diff = set(resource_schema.keys()) - set(resource.keys())

        # If resource has unexpected extra keywords
        if len(resource.keys()) > len(resource_schema.keys()):
            diff = set(resource.keys()) - set(resource_schema.keys())
            msg = ("FAILED: resource=%s has unexpected extra keys=%s,"
                   " expected keys are= %s " % (resource, list(diff),
                                                resource_schema.keys()))
            LOG.error(msg)
            return False
        elif len(diff) == 0:
            return True
        else:
            msg = ("FAILED: resource=%s does not contain keys=%s,"
                   " expected keys are= %s " % (resource, list(diff),
                                                resource_schema.keys()))
            LOG.error(msg)
            return False
