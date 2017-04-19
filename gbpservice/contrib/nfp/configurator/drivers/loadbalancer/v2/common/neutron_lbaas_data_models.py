# Copyright (c) 2014 OpenStack Foundation.
# All Rights Reserved.
#
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
"""
This module holds the data models for the load balancer service plugin.  These
are meant simply as replacement data structures for dictionaries and
SQLAlchemy models.  Using dictionaries as data containers for many components
causes readability issues and does not intuitively give the benefits of what
classes and OO give.  Using SQLAlchemy models as data containers for many
components can become an issue if you do not want to give certain components
access to the database.

These data models do provide methods for instantiation from SQLAlchemy models
and also converting to dictionaries.
"""

from gbpservice.contrib.nfp.configurator.lib import lbv2_constants as l_const


class BaseDataModel(object):

    # NOTE(ihrachys): we could reuse the list to provide a default __init__
    # implementation. That would require handling custom default values though.
    fields = []

    def to_dict(self, **kwargs):
        ret = {}
        for attr in self.__dict__:
            if attr.startswith('_') or not kwargs.get(attr, True):
                continue
            if isinstance(getattr(self, attr), list):
                ret[attr] = []
                for item in self.__dict__[attr]:
                    if isinstance(item, BaseDataModel):
                        ret[attr].append(item.to_dict())
                    else:
                        ret[attr] = item
            elif isinstance(getattr(self, attr), BaseDataModel):
                ret[attr] = self.__dict__[attr].to_dict()
            elif isinstance(self.__dict__[attr], unicode):
                ret[attr.encode('utf8')] = self.__dict__[attr].encode('utf8')
            else:
                ret[attr] = self.__dict__[attr]
        return ret

    def to_api_dict(self, **kwargs):
        return {}

    @classmethod
    def from_dict(cls, model_dict):
        fields = {k: v for k, v in model_dict.items()
                  if k in cls.fields}
        return cls(**fields)

    @property
    def root_loadbalancer(self):
        """Returns the loadbalancer this instance is attached to."""
        if isinstance(self, LoadBalancer):
            lb = self
        elif isinstance(self, Listener):
            lb = self.loadbalancer
        elif isinstance(self, L7Policy):
            lb = self.listener.loadbalancer
        elif isinstance(self, L7Rule):
            lb = self.policy.listener.loadbalancer
        elif isinstance(self, Pool):
            lb = self.loadbalancer
        elif isinstance(self, SNI):
            lb = self.listener.loadbalancer
        else:
            # Pool Member or Health Monitor
            lb = self.pool.loadbalancer
        return lb


# NOTE(brandon-logan) AllocationPool, HostRoute, Subnet, IPAllocation, Port,
# and ProviderResourceAssociation are defined here because there aren't any
# data_models defined in core neutron or neutron services.  Instead of jumping
# through the hoops to create those I've just defined them here.  If ever
# data_models or similar are defined in those packages, those should be used
# instead of these.
class AllocationPool(BaseDataModel):

    fields = ['start', 'end']

    def __init__(self, start=None, end=None):
        self.start = start
        self.end = end


class HostRoute(BaseDataModel):

    fields = ['destination', 'nexthop']

    def __init__(self, destination=None, nexthop=None):
        self.destination = destination
        self.nexthop = nexthop


class Subnet(BaseDataModel):

    fields = ['id', 'name', 'tenant_id', 'network_id', 'ip_version', 'cidr',
              'gateway_ip', 'enable_dhcp', 'ipv6_ra_mode', 'ipv6_address_mode',
              'shared', 'dns_nameservers', 'host_routes', 'allocation_pools',
              'subnetpool_id']

    def __init__(self, id=None, name=None, tenant_id=None, network_id=None,
                 ip_version=None, cidr=None, gateway_ip=None, enable_dhcp=None,
                 ipv6_ra_mode=None, ipv6_address_mode=None, shared=None,
                 dns_nameservers=None, host_routes=None, allocation_pools=None,
                 subnetpool_id=None):
        self.id = id
        self.name = name
        self.tenant_id = tenant_id
        self.network_id = network_id
        self.ip_version = ip_version
        self.cidr = cidr
        self.gateway_ip = gateway_ip
        self.enable_dhcp = enable_dhcp
        self.ipv6_ra_mode = ipv6_ra_mode
        self.ipv6_address_mode = ipv6_address_mode
        self.shared = shared
        self.dns_nameservers = dns_nameservers
        self.host_routes = host_routes
        self.allocation_pools = allocation_pools
        self.subnetpool_id = subnetpool_id

    @classmethod
    def from_dict(cls, model_dict):
        host_routes = model_dict.pop('host_routes', [])
        allocation_pools = model_dict.pop('allocation_pools', [])
        model_dict['host_routes'] = [HostRoute.from_dict(route)
                                     for route in host_routes]
        model_dict['allocation_pools'] = [AllocationPool.from_dict(ap)
                                          for ap in allocation_pools]
        return super(Subnet, cls).from_dict(model_dict)


class IPAllocation(BaseDataModel):

    fields = ['port_id', 'ip_address', 'subnet_id', 'network_id']

    def __init__(self, port_id=None, ip_address=None, subnet_id=None,
                 network_id=None):
        self.port_id = port_id
        self.ip_address = ip_address
        self.subnet_id = subnet_id
        self.network_id = network_id

    @classmethod
    def from_dict(cls, model_dict):
        subnet = model_dict.pop('subnet', None)
        # TODO(blogan): add subnet to __init__.  Can't do it yet because it
        # causes issues with converting SA models into data models.
        instance = super(IPAllocation, cls).from_dict(model_dict)
        setattr(instance, 'subnet', None)
        if subnet:
            setattr(instance, 'subnet', Subnet.from_dict(subnet))
        return instance


class Port(BaseDataModel):

    fields = ['id', 'tenant_id', 'name', 'network_id', 'mac_address',
              'admin_state_up', 'status', 'device_id', 'device_owner',
              'fixed_ips']

    def __init__(self, id=None, tenant_id=None, name=None, network_id=None,
                 mac_address=None, admin_state_up=None, status=None,
                 device_id=None, device_owner=None, fixed_ips=None):
        self.id = id
        self.tenant_id = tenant_id
        self.name = name
        self.network_id = network_id
        self.mac_address = mac_address
        self.admin_state_up = admin_state_up
        self.status = status
        self.device_id = device_id
        self.device_owner = device_owner
        self.fixed_ips = fixed_ips or []

    @classmethod
    def from_dict(cls, model_dict):
        fixed_ips = model_dict.pop('fixed_ips', [])
        model_dict['fixed_ips'] = [IPAllocation.from_dict(fixed_ip)
                                   for fixed_ip in fixed_ips]
        return super(Port, cls).from_dict(model_dict)


class ProviderResourceAssociation(BaseDataModel):

    fields = ['provider_name', 'resource_id']

    def __init__(self, provider_name=None, resource_id=None):
        self.provider_name = provider_name
        self.resource_id = resource_id

    @classmethod
    def from_dict(cls, model_dict):
        device_driver = model_dict.pop('device_driver', None)
        instance = super(ProviderResourceAssociation, cls).from_dict(
            model_dict)
        setattr(instance, 'device_driver', device_driver)
        return instance


class SessionPersistence(BaseDataModel):

    fields = ['pool_id', 'type', 'cookie_name', 'pool']

    def __init__(self, pool_id=None, type=None, cookie_name=None,
                 pool=None):
        self.pool_id = pool_id
        self.type = type
        self.cookie_name = cookie_name
        self.pool = pool

    def to_api_dict(self):
        return super(SessionPersistence, self).to_dict(pool=False,
                                                       pool_id=False)

    @classmethod
    def from_dict(cls, model_dict):
        pool = model_dict.pop('pool', None)
        if pool:
            model_dict['pool'] = Pool.from_dict(
                pool)
        return super(SessionPersistence, cls).from_dict(model_dict)


class LoadBalancerStatistics(BaseDataModel):

    fields = ['loadbalancer_id', 'bytes_in', 'bytes_out', 'active_connections',
              'total_connections', 'loadbalancer']

    def __init__(self, loadbalancer_id=None, bytes_in=None, bytes_out=None,
                 active_connections=None, total_connections=None,
                 loadbalancer=None):
        self.loadbalancer_id = loadbalancer_id
        self.bytes_in = bytes_in
        self.bytes_out = bytes_out
        self.active_connections = active_connections
        self.total_connections = total_connections
        self.loadbalancer = loadbalancer

    def to_api_dict(self):
        return super(LoadBalancerStatistics, self).to_dict(
            loadbalancer_id=False, loadbalancer=False)


class HealthMonitor(BaseDataModel):

    fields = ['id', 'tenant_id', 'type', 'delay', 'timeout', 'max_retries',
              'http_method', 'url_path', 'expected_codes',
              'provisioning_status', 'admin_state_up', 'pool', 'name']

    def __init__(self, id=None, tenant_id=None, type=None, delay=None,
                 timeout=None, max_retries=None, http_method=None,
                 url_path=None, expected_codes=None, provisioning_status=None,
                 admin_state_up=None, pool=None, name=None):
        self.id = id
        self.tenant_id = tenant_id
        self.type = type
        self.delay = delay
        self.timeout = timeout
        self.max_retries = max_retries
        self.http_method = http_method
        self.url_path = url_path
        self.expected_codes = expected_codes
        self.provisioning_status = provisioning_status
        self.admin_state_up = admin_state_up
        self.pool = pool
        self.name = name

    def attached_to_loadbalancer(self):
        return bool(self.pool and self.pool.loadbalancer)

    def to_api_dict(self):
        ret_dict = super(HealthMonitor, self).to_dict(
            provisioning_status=False, pool=False)
        ret_dict['pools'] = []
        if self.pool:
            ret_dict['pools'].append({'id': self.pool.id})
        if self.type in [l_const.HEALTH_MONITOR_TCP,
                         l_const.HEALTH_MONITOR_PING]:
            ret_dict.pop('http_method')
            ret_dict.pop('url_path')
            ret_dict.pop('expected_codes')
        return ret_dict

    @classmethod
    def from_dict(cls, model_dict):
        pool = model_dict.pop('pool', None)
        if pool:
            model_dict['pool'] = Pool.from_dict(
                pool)
        return super(HealthMonitor, cls).from_dict(model_dict)


class Pool(BaseDataModel):

    fields = ['id', 'tenant_id', 'name', 'description', 'healthmonitor_id',
              'protocol', 'lb_algorithm', 'admin_state_up', 'operating_status',
              'provisioning_status', 'members', 'healthmonitor',
              'session_persistence', 'loadbalancer_id', 'loadbalancer',
              'listener', 'listeners', 'l7_policies']

    # Map deprecated attribute names to new ones.
    attr_mapping = {'sessionpersistence': 'session_persistence'}

    def __init__(self, id=None, tenant_id=None, name=None, description=None,
                 healthmonitor_id=None, protocol=None, lb_algorithm=None,
                 admin_state_up=None, operating_status=None,
                 provisioning_status=None, members=None, healthmonitor=None,
                 session_persistence=None, loadbalancer_id=None,
                 loadbalancer=None, listener=None, listeners=None,
                 l7_policies=None):
        self.id = id
        self.tenant_id = tenant_id
        self.name = name
        self.description = description
        self.healthmonitor_id = healthmonitor_id
        self.protocol = protocol
        self.lb_algorithm = lb_algorithm
        self.admin_state_up = admin_state_up
        self.operating_status = operating_status
        self.provisioning_status = provisioning_status
        self.members = members or []
        self.healthmonitor = healthmonitor
        self.session_persistence = session_persistence
        # NOTE(eezhova): Old attribute name is kept for backwards
        # compatibility with out-of-tree drivers.
        self.sessionpersistence = self.session_persistence
        self.loadbalancer_id = loadbalancer_id
        self.loadbalancer = loadbalancer
        self.listener = listener
        self.listeners = listeners or []
        self.l7_policies = l7_policies or []

    def attached_to_loadbalancer(self):
        return bool(self.loadbalancer)

    def to_api_dict(self):
        ret_dict = super(Pool, self).to_dict(
            provisioning_status=False, operating_status=False,
            healthmonitor=False, session_persistence=False,
            loadbalancer_id=False, loadbalancer=False, listener_id=False)
        ret_dict['loadbalancers'] = []
        if self.loadbalancer:
            ret_dict['loadbalancers'].append({'id': self.loadbalancer.id})
        ret_dict['session_persistence'] = None
        if self.session_persistence:
            ret_dict['session_persistence'] = (
                self.session_persistence.to_api_dict())
        ret_dict['members'] = [{'id': member.id} for member in self.members]
        ret_dict['listeners'] = [{'id': listener.id}
                                 for listener in self.listeners]
        if self.listener:
            ret_dict['listener_id'] = self.listener.id
        else:
            ret_dict['listener_id'] = None
        ret_dict['l7_policies'] = [{'id': l7_policy.id}
                                   for l7_policy in self.l7_policies]
        return ret_dict

    @classmethod
    def from_dict(cls, model_dict):
        healthmonitor = model_dict.pop('healthmonitor', None)
        session_persistence = model_dict.pop('session_persistence', None)
        model_dict.pop('sessionpersistence', None)
        loadbalancer = model_dict.pop('loadbalancer', None)
        members = model_dict.pop('members', [])
        model_dict['members'] = [Member.from_dict(member)
                                 for member in members]
        listeners = model_dict.pop('listeners', [])
        model_dict['listeners'] = [Listener.from_dict(listener)
                                   for listener in listeners]
        l7_policies = model_dict.pop('l7_policies', [])
        model_dict['l7_policies'] = [L7Policy.from_dict(policy)
                                     for policy in l7_policies]

        # handle old attribute for out of tree drivers
        listener = model_dict.pop('listener', None)
        if listener:
            model_dict['listener'] = Listener.from_dict(listener)

        if healthmonitor:
            model_dict['healthmonitor'] = HealthMonitor.from_dict(
                healthmonitor)
        if session_persistence:
            model_dict['session_persistence'] = SessionPersistence.from_dict(
                session_persistence)
        if loadbalancer:
            model_dict['loadbalancer'] = LoadBalancer.from_dict(loadbalancer)
        return super(Pool, cls).from_dict(model_dict)


class Member(BaseDataModel):

    fields = ['id', 'tenant_id', 'pool_id', 'address', 'protocol_port',
              'weight', 'admin_state_up', 'subnet_id', 'operating_status',
              'provisioning_status', 'pool', 'name']

    def __init__(self, id=None, tenant_id=None, pool_id=None, address=None,
                 protocol_port=None, weight=None, admin_state_up=None,
                 subnet_id=None, operating_status=None,
                 provisioning_status=None, pool=None, name=None):
        self.id = id
        self.tenant_id = tenant_id
        self.pool_id = pool_id
        self.address = address
        self.protocol_port = protocol_port
        self.weight = weight
        self.admin_state_up = admin_state_up
        self.subnet_id = subnet_id
        self.operating_status = operating_status
        self.provisioning_status = provisioning_status
        self.pool = pool
        self.name = name

    def attached_to_loadbalancer(self):
        return bool(self.pool and self.pool.loadbalancer)

    def to_api_dict(self):
        return super(Member, self).to_dict(
            provisioning_status=False, operating_status=False, pool=False)

    @classmethod
    def from_dict(cls, model_dict):
        pool = model_dict.pop('pool', None)
        if pool:
            model_dict['pool'] = Pool.from_dict(
                pool)
        return super(Member, cls).from_dict(model_dict)


class SNI(BaseDataModel):

    fields = ['listener_id', 'tls_container_id', 'position', 'listener']

    def __init__(self, listener_id=None, tls_container_id=None,
                 position=None, listener=None):
        self.listener_id = listener_id
        self.tls_container_id = tls_container_id
        self.position = position
        self.listener = listener

    def attached_to_loadbalancer(self):
        return bool(self.listener and self.listener.loadbalancer)

    def to_api_dict(self):
        return super(SNI, self).to_dict(listener=False)


class TLSContainer(BaseDataModel):

    fields = ['id', 'certificate', 'private_key', 'passphrase',
              'intermediates', 'primary_cn']

    def __init__(self, id=None, certificate=None, private_key=None,
                 passphrase=None, intermediates=None, primary_cn=None):
        self.id = id
        self.certificate = certificate
        self.private_key = private_key
        self.passphrase = passphrase
        self.intermediates = intermediates
        self.primary_cn = primary_cn


class L7Rule(BaseDataModel):

    fields = ['id', 'tenant_id', 'l7policy_id', 'type', 'compare_type',
              'invert', 'key', 'value', 'provisioning_status',
              'admin_state_up', 'policy']

    def __init__(self, id=None, tenant_id=None,
                 l7policy_id=None, type=None, compare_type=None, invert=None,
                 key=None, value=None, provisioning_status=None,
                 admin_state_up=None, policy=None):
        self.id = id
        self.tenant_id = tenant_id
        self.l7policy_id = l7policy_id
        self.type = type
        self.compare_type = compare_type
        self.invert = invert
        self.key = key
        self.value = value
        self.provisioning_status = provisioning_status
        self.admin_state_up = admin_state_up
        self.policy = policy

    def attached_to_loadbalancer(self):
        return bool(self.policy.listener.loadbalancer)

    def to_api_dict(self):
        ret_dict = super(L7Rule, self).to_dict(
            provisioning_status=False,
            policy=False, l7policy_id=False)
        ret_dict['policies'] = []
        if self.policy:
            ret_dict['policies'].append({'id': self.policy.id})
        return ret_dict

    @classmethod
    def from_dict(cls, model_dict):
        policy = model_dict.pop('policy', None)
        if policy:
            model_dict['policy'] = L7Policy.from_dict(policy)
        return super(L7Rule, cls).from_dict(model_dict)


class L7Policy(BaseDataModel):

    fields = ['id', 'tenant_id', 'name', 'description', 'listener_id',
              'action', 'redirect_pool_id', 'redirect_url', 'position',
              'admin_state_up', 'provisioning_status', 'listener', 'rules',
              'redirect_pool']

    def __init__(self, id=None, tenant_id=None, name=None, description=None,
                 listener_id=None, action=None, redirect_pool_id=None,
                 redirect_url=None, position=None,
                 admin_state_up=None, provisioning_status=None,
                 listener=None, rules=None, redirect_pool=None):
        self.id = id
        self.tenant_id = tenant_id
        self.name = name
        self.description = description
        self.listener_id = listener_id
        self.action = action
        self.redirect_pool_id = redirect_pool_id
        self.redirect_pool = redirect_pool
        self.redirect_url = redirect_url
        self.position = position
        self.admin_state_up = admin_state_up
        self.provisioning_status = provisioning_status
        self.listener = listener
        self.rules = rules or []

    def attached_to_loadbalancer(self):
        return bool(self.listener.loadbalancer)

    def to_api_dict(self):
        ret_dict = super(L7Policy, self).to_dict(
            listener=False, listener_id=False,
            provisioning_status=False, redirect_pool=False)
        ret_dict['listeners'] = []
        if self.listener:
            ret_dict['listeners'].append({'id': self.listener.id})
        ret_dict['rules'] = [{'id': rule.id} for rule in self.rules]
        return ret_dict

    @classmethod
    def from_dict(cls, model_dict):
        listener = model_dict.pop('listener', None)
        redirect_pool = model_dict.pop('redirect_pool', None)
        rules = model_dict.pop('rules', [])
        if listener:
            model_dict['listener'] = Listener.from_dict(listener)
        if redirect_pool:
            model_dict['redirect_pool'] = Pool.from_dict(redirect_pool)
        model_dict['rules'] = [L7Rule.from_dict(rule)
                               for rule in rules]
        return super(L7Policy, cls).from_dict(model_dict)


class Listener(BaseDataModel):

    fields = ['id', 'tenant_id', 'name', 'description', 'default_pool_id',
              'loadbalancer_id', 'protocol', 'default_tls_container_id',
              'sni_containers', 'protocol_port', 'connection_limit',
              'admin_state_up', 'provisioning_status', 'operating_status',
              'default_pool', 'loadbalancer', 'l7_policies']

    def __init__(self, id=None, tenant_id=None, name=None, description=None,
                 default_pool_id=None, loadbalancer_id=None, protocol=None,
                 default_tls_container_id=None, sni_containers=None,
                 protocol_port=None, connection_limit=None,
                 admin_state_up=None, provisioning_status=None,
                 operating_status=None, default_pool=None, loadbalancer=None,
                 l7_policies=None):
        self.id = id
        self.tenant_id = tenant_id
        self.name = name
        self.description = description
        self.default_pool_id = default_pool_id
        self.loadbalancer_id = loadbalancer_id
        self.protocol = protocol
        self.default_tls_container_id = default_tls_container_id
        self.sni_containers = sni_containers or []
        self.protocol_port = protocol_port
        self.connection_limit = connection_limit
        self.admin_state_up = admin_state_up
        self.operating_status = operating_status
        self.provisioning_status = provisioning_status
        self.default_pool = default_pool
        self.loadbalancer = loadbalancer
        self.l7_policies = l7_policies or []

    def attached_to_loadbalancer(self):
        return bool(self.loadbalancer)

    def to_api_dict(self):
        ret_dict = super(Listener, self).to_dict(
            loadbalancer=False, loadbalancer_id=False, default_pool=False,
            operating_status=False, provisioning_status=False,
            sni_containers=False)
        # NOTE(blogan): Returning a list to future proof for M:N objects
        # that are not yet implemented.
        ret_dict['loadbalancers'] = []
        if self.loadbalancer:
            ret_dict['loadbalancers'].append({'id': self.loadbalancer.id})
        ret_dict['sni_container_refs'] = [container.tls_container_id
                                          for container in self.sni_containers]
        ret_dict['default_tls_container_ref'] = self.default_tls_container_id
        ret_dict['l7_policies'] = [{'id': l7_policy.id}
                                   for l7_policy in self.l7_policies]
        return ret_dict

    @classmethod
    def from_dict(cls, model_dict):
        default_pool = model_dict.pop('default_pool', None)
        loadbalancer = model_dict.pop('loadbalancer', None)
        sni_containers = model_dict.pop('sni_containers', [])
        model_dict['sni_containers'] = [SNI.from_dict(sni)
                                        for sni in sni_containers]
        l7_policies = model_dict.pop('l7_policies', [])
        if default_pool:
            model_dict['default_pool'] = Pool.from_dict(default_pool)
        if loadbalancer:
            model_dict['loadbalancer'] = LoadBalancer.from_dict(loadbalancer)
        model_dict['l7_policies'] = [L7Policy.from_dict(policy)
                                     for policy in l7_policies]
        return super(Listener, cls).from_dict(model_dict)


class LoadBalancer(BaseDataModel):

    fields = ['id', 'tenant_id', 'name', 'description', 'vip_subnet_id',
              'vip_port_id', 'vip_address', 'provisioning_status',
              'operating_status', 'admin_state_up', 'vip_port', 'stats',
              'provider', 'listeners', 'pools', 'flavor_id']

    def __init__(self, id=None, tenant_id=None, name=None, description=None,
                 vip_subnet_id=None, vip_port_id=None, vip_address=None,
                 provisioning_status=None, operating_status=None,
                 admin_state_up=None, vip_port=None, stats=None,
                 provider=None, listeners=None, pools=None, flavor_id=None):
        self.id = id
        self.tenant_id = tenant_id
        self.name = name
        self.description = description
        self.vip_subnet_id = vip_subnet_id
        self.vip_port_id = vip_port_id
        self.vip_address = vip_address
        self.operating_status = operating_status
        self.provisioning_status = provisioning_status
        self.admin_state_up = admin_state_up
        self.vip_port = vip_port
        self.stats = stats
        self.provider = provider
        self.listeners = listeners or []
        self.flavor_id = flavor_id
        self.pools = pools or []

    def attached_to_loadbalancer(self):
        return True

    def to_api_dict(self):
        ret_dict = super(LoadBalancer, self).to_dict(
            vip_port=False, stats=False, listeners=False)
        ret_dict['listeners'] = [{'id': listener.id}
                                 for listener in self.listeners]
        ret_dict['pools'] = [{'id': pool.id} for pool in self.pools]
        if self.provider:
            ret_dict['provider'] = self.provider.provider_name

        if not self.flavor_id:
            del ret_dict['flavor_id']

        return ret_dict

    @classmethod
    def from_dict(cls, model_dict):
        listeners = model_dict.pop('listeners', [])
        pools = model_dict.pop('pools', [])
        vip_port = model_dict.pop('vip_port', None)
        provider = model_dict.pop('provider', None)
        model_dict.pop('stats', None)
        model_dict['listeners'] = [Listener.from_dict(listener)
                                   for listener in listeners]
        model_dict['pools'] = [Pool.from_dict(pool)
                               for pool in pools]
        if vip_port:
            model_dict['vip_port'] = Port.from_dict(vip_port)
        if provider:
            model_dict['provider'] = ProviderResourceAssociation.from_dict(
                provider)
        return super(LoadBalancer, cls).from_dict(model_dict)


NAME_TO_DATA_MODEL_MAP = {
    "loadbalancer": LoadBalancer,
    "healthmonitor": HealthMonitor,
    "listener": Listener,
    "sni": SNI,
    "pool": Pool,
    "member": Member,
    "loadbalancerstatistics": LoadBalancerStatistics,
    "sessionpersistence": SessionPersistence,
    "ipallocation": IPAllocation,
    "port": Port,
    "providerresourceassociation": ProviderResourceAssociation
}
