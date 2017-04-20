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
