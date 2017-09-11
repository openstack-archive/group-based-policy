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

import six

from oslo_config import cfg

from gbpservice.neutron.services.grouppolicy.common import constants as const


def convert_ip_pool_list_to_string(ip_pool):
    if type(ip_pool) is not list:
        msg = ("The type of %(ip_pool)s is not a list" %
               {'ip_pool': ip_pool})
        raise ValueError(msg)
    return ', '.join(ip_pool)


def convert_ip_pool_string_to_list(ip_pool_string):
    if ip_pool_string and not isinstance(ip_pool_string, six.string_types):
        msg = ("The type of %(ip_pool_string)s is not a string "
               "or unicode" % {'ip_pool_string': ip_pool_string})
        raise ValueError(msg)
    if ip_pool_string:
        return [prefix.strip() for prefix in ip_pool_string.split(',')]
    else:
        return []


def is_precommit_policy_driver_configured():
    # This method checks if exactly one of the policy drivers designated
    # as a "pre-commit" driver, and defined in:
    # const.PRECOMMIT_POLICY_DRIVERS
    # is present in the list of configured policy drivers.
    a = set(cfg.CONF.group_policy.policy_drivers)
    if len(set(a) & set(const.PRECOMMIT_POLICY_DRIVERS)) == 1:
        return True
    return False
