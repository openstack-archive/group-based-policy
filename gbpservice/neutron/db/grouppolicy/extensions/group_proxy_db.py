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

from neutron.db import model_base
import sqlalchemy as sa


class GroupProxyMapping(model_base.BASEV2):
    __tablename__ = 'group_proxy_mapping'
    policy_target_group_id = sa.Column(
        sa.String(36), sa.ForeignKey('gp_policy_target_groups.id',
                                     ondelete="CASCADE"), primary_key=True)
    # A group can only be proxied by one single group
    proxied_group_id = sa.Column(sa.String(36),
                                 sa.ForeignKey('gp_policy_target_groups.id'),
                                 unique=True)
    # A group can only proxy one single other group
    # REVISIT(ivar): Can a backref be put here instead?
    proxy_group_id = sa.Column(sa.String(36),
                               sa.ForeignKey('gp_policy_target_groups.id',
                                             ondelete="SET NULL"),
                               unique=True)


class ProxyIPPoolMapping(model_base.BASEV2):
    __tablename__ = 'proxy_ip_pool_mapping'

    l3_policy_id = sa.Column(sa.String(36), sa.ForeignKey('gp_l3_policies.id'),
                             primary_key=True)
    proxy_ip_pool = sa.Column(sa.String(64), nullable=False)
    proxy_subnet_prefix_length = sa.Column(sa.Integer, nullable=False)
