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

# NOTE(ivar): right now, the flowclassifier plugin doesn't support
# notifications right now. Adding our own using the proper resource name
# could be dangerous for compatibility once they suddenly start supporting
# them. We create our own resource type and make sure to modify it once
# support is added to the SFC project.
GBP_FLOW_CLASSIFIER = 'gbp_flowclassifier'
SUPPORTED_FC_PARAMS = ['logical_source_port', 'logical_destination_port',
                       'source_ip_prefix', 'destination_ip_prefix']